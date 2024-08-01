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


*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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
)

type ifMetric struct {
	ifname        string
	ifIndex       string
	ifdescr       string
	ifhcInOctets  uint64
	ifhcOutOctets uint64
	timeStamp     int64
}

type myOids struct {
	oid      string
	valueStr string
	valueInt uint64
}

type snmpDevice struct {
	Ip        string `yaml:"ip"`
	Community string `yaml:"community"`
	Version   string `yaml:"version"`
}

const (
	IfDescrOID       = "1.3.6.1.2.1.2.2.1.2"
	ifName           = "1.3.6.1.2.1.31.1.1.1.1"
	IfHCInUcastPkts  = "1.3.6.1.2.1.31.1.1.1.7"
	IfHCOutUcastPkts = "1.3.6.1.2.1.31.1.1.1.11"
	IfHCInOctets     = "1.3.6.1.2.1.31.1.1.1.6"
	IfHCOutOctets    = "1.3.6.1.2.1.31.1.1.1.10"
	SysUpTimeOID     = "1.3.6.1.2.1.1.3"
)

// getIfName gets the interface name from the snmp device
func getIfName(goSnmp *gosnmp.GoSNMP, oid string) ([]ifMetric, error) {
	var ifMetrics []ifMetric
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	// our oid base is 1.3.6.1.2.1.31.1.1.1.1. , after that interface index
	for _, variable := range result {
		oid := variable.Name
		// get the interface index
		ifIndex := oid[len(ifName):]
		valueStr := string(variable.Value.([]uint8))
		ifMetrics = append(ifMetrics, ifMetric{valueStr, ifIndex, "", 0, 0, 0})
	}
	return ifMetrics, nil
}

// getIfCtr gets the interface counter from the snmp device
func getIfCtr(goSnmp *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	var ifMetrics []myOids
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	for _, variable := range result {
		oid := variable.Name
		value := variable.Value.(uint64)
		ifMetrics = append(ifMetrics, myOids{oid, "", value})
	}
	return ifMetrics, nil
}

// getIfStr gets the interface string from the snmp device
func getIfStr(goSnmp *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	var ifMetrics []myOids
	result, err := goSnmp.BulkWalkAll(oid)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	for _, variable := range result {
		oid := variable.Name
		value := string(variable.Value.([]uint8))
		ifMetrics = append(ifMetrics, myOids{oid, value, 0})
	}
	return ifMetrics, nil
}

/*
Final format should be similar to prometheus snmp_exporter
ifHCOutOctets{ifAlias="",ifDescr="eth0",ifIndex="2",ifName="eth0"} 1000
*/
func formatMetrics(ifMetrics []ifMetric, hostname string) []string {
	var metrics []string
	for _, metric := range ifMetrics {
		metrics = append(metrics, fmt.Sprintf("ifHCInOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcInOctets))
		metrics = append(metrics, fmt.Sprintf("ifHCOutOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcOutOctets))
	}
	return metrics
}

func snmpWalk(device string, community string, version string) ([]string, error) {
	var ifMetricsTotal []ifMetric
	var snmpVersion gosnmp.SnmpVersion

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

	ifMetricsTotal, err = getIfName(params, ifName)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}
	ifMetricsDescr, err := getIfStr(params, IfDescrOID)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}
	ifMetricsInOctets, err := getIfCtr(params, IfHCInOctets)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}
	ifMetricsOutOctets, err := getIfCtr(params, IfHCOutOctets)
	if err != nil {
		return nil, fmt.Errorf("error getting metrics: %s", err)
	}

	// verify if other metrics are available and have the same length
	totLen := len(ifMetricsTotal)
	descrLen := len(ifMetricsDescr)
	inOctetsLen := len(ifMetricsInOctets)
	outOctetsLen := len(ifMetricsOutOctets)
	if totLen != descrLen || totLen != inOctetsLen || totLen != outOctetsLen {
		return nil, fmt.Errorf("error getting metrics: different length of metrics")
	}

	// merge the metrics
	for i := range ifMetricsTotal {
		ifMetricsTotal[i].ifdescr = ifMetricsDescr[i].valueStr
		ifMetricsTotal[i].ifhcInOctets = ifMetricsInOctets[i].valueInt
		ifMetricsTotal[i].ifhcOutOctets = ifMetricsOutOctets[i].valueInt
		ifMetricsTotal[i].timeStamp = time.Now().Unix()
	}

	if *verbose {
		log.Printf("Metrics for %s: %v\n", device, ifMetricsTotal)
	}

	return formatMetrics(ifMetricsTotal, device), nil
}

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
	return snmpWalk(device, community, version)
}

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
			log.Printf("Config file: %s %s %s\n", device.Ip, device.Community, device.Version)
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
	for _, device := range snmpDevices {
		// get the metrics from the snmp device
		if *verbose {
			log.Printf("Getting metrics for %s community %s version %s\n", device.Ip, device.Community, device.Version)
		}
		devmetric, err := snmpWalk(device.Ip, device.Community, device.Version)
		if err != nil {
			return nil, fmt.Errorf("error getting metrics: %s", err)
		}
		// append the metrics to the metrics slice
		metrics = append(metrics, devmetric...)
	}
	return metrics, nil
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := []string{}
	// is cfgFile existing?
	if _, err := os.Stat(*cfgFile); err == nil {
		if *verbose {
			log.Printf("Using config file %s for request %s\n", *cfgFile, r.URL)
		}
		// get the metrics from the snmp devices in the config file
		metrics, err = getMetricsbyCFG()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if *verbose {
			log.Printf("Using GET parameters for request %s\n", r.URL)
		}
		// get the metrics from the snmp device set over GET request params
		metrics, err = getMetricsbyGET(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// write the metrics to the http response
	for _, metric := range metrics {
		fmt.Fprintf(w, "%s\n", metric)
	}
}

func main() {
	log.Println("Starting usnmp_exporter v1.0 at ", *listenAddress)
	flag.Parse()

	// spin up the http server
	http.HandleFunc("/metrics", metricsHandler)
	// not found default log
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Not found: %s\n", r.URL)
		http.NotFound(w, r)
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
