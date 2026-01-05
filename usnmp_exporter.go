/*
SPDX-License-Identifier: LGPL-2.1-or-later
(c) 2024, Denys Fedoryshchenko <denys.f@collabora.com>

usnmp_exporter is a simple snmp exporter for prometheus. It can be used to get interface metrics from a snmp device.
It can be used in two ways:
- by GET parameters: ip, community, version
- by config file: usnmp_exporter.yml

The config file should be in yaml format and should contain the snmp devices to get the metrics from.
Example:
- ip: 1.2.3.4
  community: secret
  version: 2c

  TODO:
  - ignore metrics retrieved with less than minperiod
  - investigate 4x rate reporting discrepancy (possible causes):
    * Counter resets/wraparounds
    * Unit confusion (bits vs bytes)
    * Prometheus rate() function behavior with counter resets
    * Bundle interface specific behavior in Cisco XR
    * Sampling interval timing issues

*/

package main

import (
	"flag"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp" // https://github.com/gosnmp/gosnmp
	"gopkg.in/yaml.v2"         //
)

var (
	// Command-line flags
	// exporter listening address:port
	listenAddress = flag.String("listen-address", ":9116", "Address on which to expose metrics and web interface.")
	cfgFile       = flag.String("config", "usnmp_exporter.yml", "Path to configuration file.")
	verbose       = flag.Bool("verbose", false, "Verbose output")
	minperiod     = flag.Int("minperiod", 15, "Minimum period to get metrics from the snmp device")
	instance      = flag.String("instance", "usnmp", "Instance name")
)

// internal metrics
var (
	Statrequests    int64
	Staterrors      int64
	lastDevUptime   = make(map[string]uint64)
	lastCounters    = make(map[string]map[string]uint64) // deviceIP -> interfaceName -> lastValue
	warned32BitOnly = make(map[string]bool)              // deviceIP -> warned about 32-bit counters
	stateMu         sync.Mutex
)

type ifMetric struct {
	ifname        string
	ifIndex       string
	ifdescr       string
	ifhcInOctets  uint64
	ifhcOutOctets uint64
	ifMiscCtr     []uint64
	ifMiscName    []string
	timeStamp     int64
}

type myOids struct {
	oid      string
	ifIndex  string // interface index extracted from the OID
	valueStr string
	valueInt uint64
}

/*
Additional counters polled, related to interfaces
For example: ifInBroadcastPkts
BaseOID: .1.3.6.1.2.1.31.1.1.1.3
Name: ifInBroadcastPkts
*/
type ifMiscOID struct {
	BaseOID string `yaml:"BaseOID"`
	Name    string `yaml:"Name"`
}

type KV struct {
	Key   string `yaml:"key"`   // Key for the tag
	Value string `yaml:"value"` // Value for the tag
}

type oidMisc struct {
	OID  string `yaml:"oid"`  // OID to poll
	Name string `yaml:"name"` // Name of the OID
	Tags []KV   `yaml:"tags"` // Tags for the OID
}

type snmpDevice struct {
	Ip        string      `yaml:"ip"`
	Community string      `yaml:"community"`
	Version   string      `yaml:"version"`
	IFMisc    []ifMiscOID `yaml:"ifmisc"`  // Additional interface counters
	OIDMisc   []oidMisc   `yaml:"oidmisc"` // Additional OIDs
}

type uptimeTooShortError struct {
	device    string
	minperiod int
}

func (e *uptimeTooShortError) Error() string {
	return fmt.Sprintf("device %s uptime less than %d seconds", e.device, e.minperiod)
}

// 1.3.6.1.2.1.31.1.1.1.6.35
const (
	// Basic ifTable (RFC 1213) - 32-bit counters
	IfDescrOID  = "1.3.6.1.2.1.2.2.1.2"
	IfInOctets  = "1.3.6.1.2.1.2.2.1.10"
	IfOutOctets = "1.3.6.1.2.1.2.2.1.16"

	// ifXTable extension (RFC 2863) - 64-bit HC counters
	ifName           = "1.3.6.1.2.1.31.1.1.1.1"
	IfHCInUcastPkts  = "1.3.6.1.2.1.31.1.1.1.7"
	IfHCOutUcastPkts = "1.3.6.1.2.1.31.1.1.1.11"
	IfHCInOctets     = "1.3.6.1.2.1.31.1.1.1.6"
	IfHCOutOctets    = "1.3.6.1.2.1.31.1.1.1.10"

	SysUpTimeOID = "1.3.6.1.2.1.1.3"
)

// If we have 1.2.3.4.5.6 oid, then interface index is 6
func getIfIdxOid(oid string) (string, error) {
	// Check if the OID is valid
	if oid == "" {
		return "", fmt.Errorf("empty OID provided")
	}
	// split by dots
	oidParts := strings.Split(oid, ".")
	if len(oidParts) < 2 {
		return "", fmt.Errorf("invalid OID format: %s", oid)
	}
	ifIndex := oidParts[len(oidParts)-1]
	return ifIndex, nil
}

// getIfName gets the interface name from the snmp device
func getIfName(goSnmp *gosnmp.GoSNMP, oid string) ([]ifMetric, error) {
	var ifMetrics []ifMetric
	incRequests()
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	// our oid base is 1.3.6.1.2.1.31.1.1.1.1. , after that interface index
	for _, variable := range result {
		oid := variable.Name
		// get the interface index
		ifIndex, err := getIfIdxOid(oid)
		if err != nil {
			log.Printf("Warning: Could not get interface index for %s: %v", oid, err)
			continue
		}
		valueStr := string(variable.Value.([]uint8))
		ifMetrics = append(ifMetrics, ifMetric{valueStr, ifIndex, "", 0, 0, nil, nil, 0})
	}
	return ifMetrics, nil
}

func getOIDUint64(goSnmp *gosnmp.GoSNMP, oid string) (uint64, error) {
	incRequests()
	result, err := goSnmp.Get([]string{oid})
	if err != nil {
		incErrors()
		return 0, fmt.Errorf("error getting metrics: %s", err)
	}
	if len(result.Variables) == 0 {
		incErrors()
		return 0, fmt.Errorf("no result for OID: %s", oid)
	}
	pdu := result.Variables[0]
	if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView {
		incErrors()
		if *verbose {
			log.Printf("Warning: OID %s returned %v", oid, pdu.Type)
		}
		return 0, nil
	}
	if pdu.Value == nil {
		incErrors()
		if *verbose {
			log.Printf("Warning: OID %s returned nil value", oid)
		}
		return 0, nil
	}
	// Handle different integer types that SNMP might return
	var value uint64
	switch v := pdu.Value.(type) {
	case uint64:
		value = v
	case uint32:
		value = uint64(v)
	case uint:
		value = uint64(v)
	case int64:
		value = uint64(v)
	case int32:
		value = uint64(v)
	case int:
		value = uint64(v)
	default:
		incErrors()
		return 0, fmt.Errorf("unexpected type for OID %s: %T", oid, pdu.Value)
	}
	return value, nil
}

// getIfCtr gets the interface counter from the snmp device
func getIfCtr(goSnmp *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	var ifMetrics []myOids
	incRequests()
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	for _, variable := range result {
		oid := variable.Name
		var value uint64

		// Handle different integer types that SNMP might return
		switch v := variable.Value.(type) {
		case uint64:
			value = v
		case uint32:
			value = uint64(v)
		case uint:
			value = uint64(v)
		case int64:
			value = uint64(v)
		case int32:
			value = uint64(v)
		case int:
			value = uint64(v)
		default:
			log.Printf("Warning: Unexpected type %T for OID %s, value: %v", variable.Value, oid, variable.Value)
			value = 0
		}
		ifIdx, err := getIfIdxOid(oid)
		if err != nil {
			log.Printf("Warning: Could not get interface index for %s: %v", oid, err)
			continue
		}
		ifMetrics = append(ifMetrics, myOids{oid, ifIdx, "", value})
	}
	return ifMetrics, nil
}

// getIfStr gets the interface string from the snmp device
func getIfStr(goSnmp *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	var ifMetrics []myOids
	incRequests()
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	for _, variable := range result {
		oid := variable.Name
		ifIdx, err := getIfIdxOid(oid)
		if err != nil {
			log.Printf("Warning: Could not get interface index for %s: %v", oid, err)
			continue
		}
		value := string(variable.Value.([]uint8))
		ifMetrics = append(ifMetrics, myOids{oid, ifIdx, value, 0})
	}
	return ifMetrics, nil
}

// detectCounterReset checks if a counter has reset and logs it
func detectCounterReset(device, ifname string, inOctets, outOctets uint64) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if lastCounters[device] == nil {
		lastCounters[device] = make(map[string]uint64)
	}

	inKey := ifname + "_in"
	outKey := ifname + "_out"

	if lastIn, exists := lastCounters[device][inKey]; exists {
		if inOctets < lastIn {
			log.Printf("COUNTER RESET detected: %s %s InOctets: %d < %d (diff: %d)",
				device, ifname, inOctets, lastIn, lastIn-inOctets)
		}
	}

	if lastOut, exists := lastCounters[device][outKey]; exists {
		if outOctets < lastOut {
			log.Printf("COUNTER RESET detected: %s %s OutOctets: %d < %d (diff: %d)",
				device, ifname, outOctets, lastOut, lastOut-outOctets)
		}
	}

	lastCounters[device][inKey] = inOctets
	lastCounters[device][outKey] = outOctets
}

// sanitizeLabel sanitizes a string for use in Prometheus labels by replacing quotes with underscores
func sanitizeLabel(s string) string {
	return strings.ReplaceAll(s, "\"", "_")
}

// get system uptime to calculate the time difference
func getSysUpTime(goSnmp *gosnmp.GoSNMP) (uint64, error) {
	var sysUpTime uint64
	incRequests()
	result, err := goSnmp.Get([]string{SysUpTimeOID})
	if err != nil {
		incErrors()
		return 0, fmt.Errorf("error getting metrics: %s", err)
	}
	// make sure we have the result
	if len(result.Variables) == 0 {
		incErrors()
		// emulate uptime by getting the current time
		return uint64(time.Now().Unix()), nil
	}
	// prevent "interface conversion: interface {} is nil, not uint64"
	if result.Variables[0].Value == nil {
		incErrors()
		log.Printf("Warning: getting sysUpTime: Value is nil\n")
		return uint64(time.Now().Unix()), nil
	}

	// Handle different integer types that SNMP might return for sysUpTime
	switch v := result.Variables[0].Value.(type) {
	case uint64:
		sysUpTime = v
	case uint32:
		sysUpTime = uint64(v)
	case uint:
		sysUpTime = uint64(v)
	case int64:
		sysUpTime = uint64(v)
	case int32:
		sysUpTime = uint64(v)
	case int:
		sysUpTime = uint64(v)
	default:
		log.Printf("Warning: Unexpected type %T for sysUpTime, value: %v", result.Variables[0].Value, result.Variables[0].Value)
		return uint64(time.Now().Unix()), nil
	}

	return sysUpTime, nil
}

/*
Final format should be similar to prometheus snmp_exporter
ifHCOutOctets{ifAlias="",ifDescr="eth0",ifIndex="2",ifName="eth0"} 1000
*/
func formatMetrics(ifMetrics []ifMetric, hostname string) []string {
	var metrics []string
	for _, metric := range ifMetrics {
		//log.Printf("DEBUG: Metric for %s: %s %s %d %d", metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcInOctets, metric.ifhcOutOctets)
		metrics = append(metrics, fmt.Sprintf("ifHCInOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcInOctets))
		metrics = append(metrics, fmt.Sprintf("ifHCOutOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcOutOctets))
		// Also add misc metrics from config
		nummusc := len(metric.ifMiscCtr)
		for i := 0; i < nummusc; i++ {
			metrics = append(metrics, fmt.Sprintf("%s{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"} %d", metric.ifMiscName[i], hostname, metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifMiscCtr[i]))
		}
	}
	return metrics
}

func getByIfIndexStr(ifIndex string, metrics []myOids) string {
	for _, metric := range metrics {
		if metric.ifIndex == ifIndex {
			return metric.valueStr
		}
	}
	return ""
}

func getByIfIndexInt(ifIndex string, metrics []myOids) uint64 {
	for _, metric := range metrics {
		if metric.ifIndex == ifIndex {
			return metric.valueInt
		}
	}
	return 0
}

// func snmpWalk(device string, community string, version string, ifMisc []ifMiscOID) ([]string, error) {
func snmpWalk(snmpdev snmpDevice) ([]string, error) {
	device := snmpdev.Ip
	community := snmpdev.Community
	version := snmpdev.Version
	ifMisc := snmpdev.IFMisc
	oidMisc := snmpdev.OIDMisc

	var ifMetricsTotal []ifMetric
	var snmpVersion gosnmp.SnmpVersion
	// uint64 map by interface index
	var miscMyOIDs [][]myOids
	var miscName []string

	switch version {
	case "1":
		snmpVersion = gosnmp.Version1
	case "2c":
		snmpVersion = gosnmp.Version2c
	default:
		return nil, fmt.Errorf("unknown snmp version: %s", version)
	}

	// set the snmp parameters
	params := &gosnmp.GoSNMP{
		Target:    device,
		Port:      161,
		Community: community,
		Version:   snmpVersion,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
	}

	// connect to the snmp device
	err := params.Connect()
	if err != nil {
		return nil, fmt.Errorf("error connecting to device: %s", err)
	}
	defer params.Conn.Close()

	// TODO(nuclearcat): maybe we can do this in one go?

	// retrieve uptime
	sysUpTime, err := getSysUpTime(params)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get sysUpTime for %s: %v", device, err)
	}
	// check if diff is less than minperiod
	stateMu.Lock()
	lastUp := lastDevUptime[device]
	if lastUp != 0 && sysUpTime-lastUp < uint64(*minperiod) {
		stateMu.Unlock()
		return nil, &uptimeTooShortError{device: device, minperiod: *minperiod}
	}
	lastDevUptime[device] = sysUpTime
	stateMu.Unlock()

	// Use ifDescr as primary source for interface discovery (more universal, especially on Nokia SROS)
	ifMetricsDescr, err := getIfStr(params, IfDescrOID)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	// Build initial interface list from ifDescr
	for _, metric := range ifMetricsDescr {
		ifMetricsTotal = append(ifMetricsTotal, ifMetric{
			ifname:  sanitizeLabel(metric.valueStr), // Use ifDescr as default name
			ifIndex: metric.ifIndex,
			ifdescr: sanitizeLabel(metric.valueStr),
		})
	}

	// Try to get ifName (IF-MIB extension) - use as better interface name if available
	ifMetricsName, err := getIfStr(params, ifName)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get ifName for %s (will use ifDescr): %v", device, err)
	}

	// Try HC (64-bit) counters first from ifXTable
	ifMetricsInOctets, err := getIfCtr(params, IfHCInOctets)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get HC InOctets for %s, will try basic counters: %v", device, err)
	}
	ifMetricsOutOctets, err := getIfCtr(params, IfHCOutOctets)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get HC OutOctets for %s, will try basic counters: %v", device, err)
	}

	// Get basic 32-bit counters from ifTable as fallback
	ifMetricsInOctetsBasic, err := getIfCtr(params, IfInOctets)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get basic InOctets for %s: %v", device, err)
	}
	ifMetricsOutOctetsBasic, err := getIfCtr(params, IfOutOctets)
	if err != nil && *verbose {
		log.Printf("Warning: Could not get basic OutOctets for %s: %v", device, err)
	}

	// get misc as getIfCtr
	if ifMisc != nil {
		miscnum := len(ifMisc)
		if miscnum > 0 {
			// first fill myOIDs
			miscMyOIDs = make([][]myOids, miscnum)
			miscName = make([]string, miscnum)
			for i := 0; i < miscnum; i++ {
				miscName[i] = ifMisc[i].Name
				miscMyOIDs[i], err = getIfCtr(params, ifMisc[i].BaseOID)
				if err != nil {
					return nil, fmt.Errorf("error getting metrics: %s", err)
				}
			}
		}
	}

	// merge the metrics
	usedBasicCounters := false
	for i := range ifMetricsTotal {
		ifIdx := ifMetricsTotal[i].ifIndex
		// Try to use ifName if available, otherwise keep ifDescr as the interface name
		if ifName := getByIfIndexStr(ifIdx, ifMetricsName); ifName != "" {
			ifMetricsTotal[i].ifname = sanitizeLabel(ifName)
		}
		// Fill counters - try HC (64-bit) first, fallback to basic (32-bit) if not available
		inOctets := getByIfIndexInt(ifIdx, ifMetricsInOctets)
		outOctets := getByIfIndexInt(ifIdx, ifMetricsOutOctets)

		// If HC counters are 0, try basic counters as fallback
		if inOctets == 0 {
			inOctets = getByIfIndexInt(ifIdx, ifMetricsInOctetsBasic)
			if inOctets > 0 {
				usedBasicCounters = true
			}
		}
		if outOctets == 0 {
			outOctets = getByIfIndexInt(ifIdx, ifMetricsOutOctetsBasic)
			if outOctets > 0 {
				usedBasicCounters = true
			}
		}

		ifMetricsTotal[i].ifhcInOctets = inOctets
		ifMetricsTotal[i].ifhcOutOctets = outOctets
		// Note: ifdescr is already set from ifMetricsDescr during initialization
		if len(miscMyOIDs) > 0 {
			// append one by one to ifMetricsTotal[i].ifMiscCtrs , ifMetricsTotal[i].ifMiscNames
			for j := range miscMyOIDs {
				ctr := getByIfIndexInt(ifIdx, miscMyOIDs[j])
				ifMetricsTotal[i].ifMiscCtr = append(ifMetricsTotal[i].ifMiscCtr, ctr)
				ifMetricsTotal[i].ifMiscName = append(ifMetricsTotal[i].ifMiscName, miscName[j])
			}
		}

		ifMetricsTotal[i].timeStamp = time.Now().Unix()
	}

	// Warn once per device if using 32-bit counters (may wrap at 4GB)
	if usedBasicCounters {
		stateMu.Lock()
		if !warned32BitOnly[device] {
			log.Printf("Warning: Device %s does not support 64-bit HC counters for some interfaces, using 32-bit counters (may wrap at 4GB)", device)
			warned32BitOnly[device] = true
		}
		stateMu.Unlock()
	}

	if *verbose {
		//log.Printf("Metrics for %s: %v\n", device, ifMetricsTotal)
		// Detect counter resets for all interfaces
		for _, metric := range ifMetricsTotal {
			detectCounterReset(device, metric.ifname, metric.ifhcInOctets, metric.ifhcOutOctets)
		}
	}

	mymetrics := formatMetrics(ifMetricsTotal, device)
	// now process oid
	for _, oid := range oidMisc {
		name := oid.Name
		value, err := getOIDUint64(params, oid.OID)
		if err != nil {
			log.Printf("Warning: Could not get OID %s for %s: %v", oid.OID, device, err)
			continue
		}
		tags := ""
		for _, tag := range oid.Tags {
			tags += fmt.Sprintf(",%s=\"%s\"", tag.Key, tag.Value)
		}
		if value != 0 {
			metric := fmt.Sprintf("%s{host=\"%s\"%s} %d", name, device, tags, value)
			mymetrics = append(mymetrics, metric)
		}
	}

	return mymetrics, nil
}

/*
// getMetrics gets the metrics from the snmp device
func getMetricsbyGET(r *http.Request) ([]string, error) {
	// device is set as GET parameter IP
	device := r.URL.Query().Get("ip")
	if device == "" {
		return nil, fmt.Errorf("no device specified")
	}
	// v2c community as GET parameter community
	community := r.URL.Query().Get("community")
	if community == "" {
		return nil, fmt.Errorf("no community specified")
	}
	// snmp version as GET parameter version
	version := r.URL.Query().Get("version")
	if version == "" {
		return nil, fmt.Errorf("no version specified")
	}
	// get the metrics from the snmp device
	return snmpWalk(
}
*/

/* config sample:
- ip:
  community:
  version:
*/

func loadConfig(cfgFile string) ([]snmpDevice, error) {
	var snmpDevices []snmpDevice
	// load the config file
	yamlFile, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %s", err)
	}
	// parse the yaml file
	err = yaml.Unmarshal(yamlFile, &snmpDevices)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %s", err)
	}
	if len(snmpDevices) == 0 {
		return nil, fmt.Errorf("no snmp devices in config file")
	}
	if *verbose {
		for _, device := range snmpDevices {
			log.Printf("Config file: %s %s\n", device.Ip, device.Version)
		}
	}
	return snmpDevices, nil
}

// getMetricsCFG gets the metrics from the snmp devices in the config file
func getMetricsbyCFG() ([]string, error) {
	metrics := []string{}
	// load from yaml file snmp devices
	snmpDevices, err := loadConfig(*cfgFile)
	if err != nil {
		return nil, fmt.Errorf("error loading config file: %s", err)
	}
	var (
		wg        sync.WaitGroup
		metricsMu sync.Mutex
		errMu     sync.Mutex
		firstErr  error
	)
	for _, device := range snmpDevices {
		dev := device
		wg.Add(1)
		go func() {
			defer wg.Done()
			if *verbose {
				log.Printf("Getting metrics for %s version %s\n", dev.Ip, dev.Version)
			}
			start := time.Now()
			devmetric, err := snmpWalk(dev)
			elapsed := time.Since(start)
			if err != nil {
				var ute *uptimeTooShortError
				if errors.As(err, &ute) {
					log.Printf("Skipping device %s: %s\n", ute.device, ute.Error())
					return
				}
				log.Printf("Device %s failed after %s\n", dev.Ip, elapsed)
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			log.Printf("Device %s: %d metrics in %s\n", dev.Ip, len(devmetric), elapsed)
			metricsMu.Lock()
			metrics = append(metrics, devmetric...)
			metricsMu.Unlock()
		}()
	}
	wg.Wait()
	if firstErr != nil {
		if len(metrics) == 0 {
			return nil, fmt.Errorf("error getting metrics: %s", firstErr)
		}
		return metrics, firstErr
	}
	return metrics, nil
}

func incRequests() {
	atomic.AddInt64(&Statrequests, 1)
}

func incErrors() {
	atomic.AddInt64(&Staterrors, 1)
}

func loadRequests() int64 {
	return atomic.LoadInt64(&Statrequests)
}

func loadErrors() int64 {
	return atomic.LoadInt64(&Staterrors)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics := []string{}
	// is cfgFile existing?
	if _, err := os.Stat(*cfgFile); err == nil {
		if *verbose {
			log.Printf("Using config file %s for request %s\n", *cfgFile, r.URL)
		}
		// get the metrics from the snmp devices in the config file
		metrics, err = getMetricsbyCFG()
		if err != nil && len(metrics) == 0 {
			log.Printf("Error getting metrics: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err != nil {
			log.Printf("Partial scrape: %s\n", err)
		}
	} else {
		if *verbose {
			log.Printf("Using GET parameters for request %s\n", r.URL)
		}
		// get the metrics from the snmp device set over GET request params
		//metrics, err = getMetricsbyGET(r)
		//if err != nil {
		//	http.Error(w, err.Error(), http.StatusInternalServerError)
		//	return
		//}
		http.Error(w, "GET parameters are not supported yet, please use config file", http.StatusNotImplemented)
		return
	}

	// Add internal metrics once per scrape.
	metrics = append(metrics, fmt.Sprintf("usnmp_requests{instance=\"%s\"} %d", *instance, loadRequests()))
	metrics = append(metrics, fmt.Sprintf("usnmp_errors{instance=\"%s\"} %d", *instance, loadErrors()))
	metrics = append(metrics, fmt.Sprintf("usnmp_scrape_duration_seconds{instance=\"%s\"} %.6f", *instance, time.Since(start).Seconds()))

	// write the metrics to the http response
	for _, metric := range metrics {
		fmt.Fprintf(w, "%s\n", metric)
	}
	// verbose
	if *verbose {
		metricslen := len(metrics)
		log.Printf("Metrics for request %s (%d total)\n", r.URL, metricslen)
	}
}

func main() {
	flag.Parse()
	log.Printf("Starting up usnmp_exporter v1.2\n")

	// spin up the http server
	http.HandleFunc("/metrics", metricsHandler)
	// not found default log
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Not found: %s\n", r.URL)
		http.NotFound(w, r)
	})
	log.Printf("Listening on %s\n", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}
