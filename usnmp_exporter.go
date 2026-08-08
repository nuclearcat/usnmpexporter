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
	"errors"
	"flag"
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

const appVersion = "2.3"

var (
	// Command-line flags
	// exporter listening address:port
	listenAddress = flag.String("listen-address", ":9116", "Address on which to expose metrics and web interface.")
	cfgFile       = flag.String("config", "usnmp_exporter.yml", "Path to configuration file.")
	verbose       = flag.Bool("verbose", false, "Verbose output")
	minperiod     = flag.Int("minperiod", 15, "Minimum period to get metrics from the snmp device")
	instance      = flag.String("instance", "usnmp", "Instance name")
	// Worst case time spent on a single unanswered request is timeout*(1+retries).
	// Slow devices (Juniper EX series in particular) can take several seconds to
	// answer a GETBULK over a large ifTable, so the timeout is generous. Retries
	// cost nothing on a dead device — the liveness probe in snmpWalk runs with
	// retries disabled and bails out first — so they only ever pay for genuine
	// UDP packet loss on a device that is answering.
	timeout        = flag.Int("timeout", 20, "SNMP request timeout in seconds")
	retries        = flag.Int("retries", 2, "SNMP request retries")
	maxRepetitions = flag.Int("max-repetitions", 50, "GETBULK max-repetitions (lower it if the device drops large replies)")
)

// internal metrics
var (
	Statrequests    int64
	Staterrors      int64
	Statdropped     int64 // retained for metric stability; no longer incremented
	lastDevUptime   = make(map[string]uint64)
	lastCounters    = make(map[string]map[string]uint64) // deviceIP -> interfaceName -> lastValue
	warned32BitOnly = make(map[string]bool)              // deviceIP -> warned about 32-bit counters
	// counterSource caches the chosen counter source per (deviceIP, ifIndex) so we don't
	// flip between 64-bit HC and 32-bit basic counters between scrapes, which would emit
	// massive fake spikes to Prometheus. Values: "hc" or "basic".
	counterSource = make(map[string]map[string]string)
	// walkModeCache remembers the SNMP walk mode that last worked
	// for a given device IP. First scrape after startup tries
	// BulkWalk at the configured max-repetitions; if that fails with
	// a parse / decoding error (a "buggy GETBULK encoder" symptom
	// seen on old NX-OS 6.0(2)U / Catalyst builds) or with a timeout
	// (an oversized reply that never makes it back, seen on Juniper
	// EX) the helper falls back to a smaller bulk window, then to
	// non-bulk GETNEXT, and caches whichever worked. Subsequent
	// scrapes skip straight to the cached mode — no re-paying the
	// retry cost every cycle.
	// In-memory only by design: process restart re-learns once,
	// which also picks up devices the operator has just upgraded.
	walkModeCache = make(map[string]walkMode)
	stateMu       sync.Mutex
)

// walkMode picks how walkAllAdaptive talks to a given device.
//
//   - walkBulkDefault: GETBULK at the configured max-repetitions
//     (-max-repetitions, default 50). Fast, works for nearly all
//     modern agents.
//   - walkBulkSmall:   GETBULK with max-repetitions=5. Recovers
//     agents that truncate UDP responses bigger than ~1400 bytes
//     (string-heavy tables overflow the buffer).
//   - walkGetNext:     non-bulk WalkAll (one GETNEXT per row). Slow
//     but bypasses the agent's GETBULK encoder entirely. Last-resort
//     fallback for agents that mangle BER on bulk responses no
//     matter the size.
type walkMode int

const (
	walkBulkDefault walkMode = iota
	walkBulkSmall
	walkGetNext
)

// safeBulkReps is the max-repetitions value used in the
// walkBulkSmall tier. Picked to keep responses comfortably under
// the 1500-byte safe MTU for the table widths we typically walk.
const safeBulkReps uint32 = 5

// bulkWalkWithReps runs a GETBULK walk at a specific max-repetitions
// and restores the caller's value afterwards. It never raises the
// window: an operator who pinned max_repetitions below safeBulkReps
// did so because the device needed it, so the fallback tier must not
// undo that.
func bulkWalkWithReps(g *gosnmp.GoSNMP, oid string, reps uint32) ([]gosnmp.SnmpPDU, error) {
	orig := g.MaxRepetitions
	if orig > 0 && orig < reps {
		reps = orig
	}
	g.MaxRepetitions = reps
	defer func() { g.MaxRepetitions = orig }()
	return g.BulkWalkAll(oid)
}

// degradeWalkMode pins a device to a slower walk tier. Degradation is
// one-way — a mode is never walked back up within a process — so
// concurrent walks against the same device can't fight each other.
func degradeWalkMode(ip string, to walkMode, from, toName string, cause error) {
	stateMu.Lock()
	if walkModeCache[ip] >= to {
		stateMu.Unlock()
		return
	}
	walkModeCache[ip] = to
	stateMu.Unlock()
	log.Printf("walk_adaptive: %s degraded %s → %s (%v)", ip, from, toName, cause)
}

// walkAllAdaptive walks a subtree starting at oid, escalating through
// fallback strategies and caching whichever one worked for `ip` so
// future scrapes skip the retry cost.
//
// Timeouts degrade the mode too, not just parse errors. An agent whose
// GETBULK reply is too large for the path never answers at all, which
// is indistinguishable from an unreachable device at this layer — and
// that is exactly the case the smaller bulk window exists to fix.
// Treating a timeout as fatal left the fallback unreachable for the
// most common way GETBULK actually fails. snmpWalk probes sysObjectID
// before any walk runs and bails out with deviceDeadError, so a device
// reaching this function has already proven it answers SNMP.
//
// A timeout has already cost timeout*(1+retries), so we step down one
// tier and return the error rather than paying it again in the same
// scrape. The next scrape starts at the lower tier. That trades one
// failed scrape for automatic recovery instead of a permanently dead
// device. Parse errors are cheap by comparison and still retry
// immediately.
func walkAllAdaptive(g *gosnmp.GoSNMP, ip, oid string) ([]gosnmp.SnmpPDU, error) {
	stateMu.Lock()
	mode := walkModeCache[ip]
	stateMu.Unlock()

	if mode == walkGetNext {
		return g.WalkAll(oid)
	}

	if mode == walkBulkSmall {
		rows, err := bulkWalkWithReps(g, oid, safeBulkReps)
		if err == nil {
			return rows, nil
		}
		degradeWalkMode(ip, walkGetNext, "bulk-small", "getnext", err)
		if isTimeout(err) {
			return rows, err
		}
		// Parse error — GETNEXT is cheap enough to try right away.
		return g.WalkAll(oid)
	}

	// walkBulkDefault — first scrape, or the device has only ever
	// been bulk-friendly. Try the fast path.
	rows, err := g.BulkWalkAll(oid)
	if err == nil {
		return rows, nil
	}
	if isTimeout(err) {
		degradeWalkMode(ip, walkBulkSmall, "bulk-default", "bulk-small", err)
		return rows, err
	}

	// Step 2: smaller bulk window.
	rows2, err2 := bulkWalkWithReps(g, oid, safeBulkReps)
	if err2 == nil {
		degradeWalkMode(ip, walkBulkSmall, "bulk-default", "bulk-small", err)
		return rows2, nil
	}
	if isTimeout(err2) {
		degradeWalkMode(ip, walkGetNext, "bulk-small", "getnext", err2)
		return rows2, err2
	}

	// Step 3: non-bulk GETNEXT.
	rows3, err3 := g.WalkAll(oid)
	if err3 == nil {
		degradeWalkMode(ip, walkGetNext, "bulk-default", "getnext", err2)
		return rows3, nil
	}
	return rows3, err3
}

// isTimeout returns true for errors that mean "device unreachable"
// — pointless to retry. Matches gosnmp's "request timeout" wording
// (marshal.go:206) plus the standard net package phrasings.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no route to host")
}

type ifMetric struct {
	ifname        string
	ifIndex       string
	ifdescr       string
	ifalias       string
	ifhcInOctets  uint64
	ifhcOutOctets uint64
	ifOperStatus  uint64 // IF-MIB ifOperStatus, polled by default
	hasOperStatus bool   // false → omit from output (device didn't expose it)
	ifInDiscards  uint64
	ifOutDiscards uint64
	ifInErrors    uint64
	ifOutErrors   uint64
	hasDiscErrs   bool // false → omit discards/errors from output
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

/*
Walk a tabular OID subtree and emit one Prometheus sample per varbind. The
remaining sub-OID after BaseOID becomes a single label whose name is
IndexLabel (default "index") — we deliberately don't try to decode the
suffix into named index dimensions because that would require shipping a
MIB compiler. Admins (or upstream tooling) can rename or alias series in
Prometheus / Grafana once they see the index strings.

Use case: vendor chassis tables (jnxOperatingTemp on JunOS, tmnxHwTemperature
on Nokia TiMOS). Integer-valued varbinds only; non-integer types are skipped.
Unlike oidMisc, zero values are emitted (a chassis temp legitimately can be 0).
*/
type oidWalk struct {
	BaseOID     string   `yaml:"BaseOID"`    // base OID of the subtree to walk
	Name        string   `yaml:"Name"`       // metric name emitted for each varbind
	IndexLabel  string   `yaml:"IndexLabel"` // label name for the OID suffix (default "index"; ignored when IndexLabels is set)
	IndexLabels []string `yaml:"IndexLabels"`
	// IndexLabels splits the post-base OID suffix on `.` and assigns the
	// pieces to each label name in order — for tables with composite
	// indices like jnxDomCurrentLaneTable {ifIndex, laneIndex} or Nokia
	// tmnxDDMLaneTable {chassisIndex, tmnxPortPortID, laneId}. If the
	// suffix has more components than label names, the extras are joined
	// into the final label with `.` separators (preserves data without
	// silently dropping). Fewer components than labels → unused labels
	// are emitted with empty values, which makes the "data malformed"
	// case obvious in PromQL rather than swallowed.
	Tags []KV `yaml:"tags"` // static tags applied to every emitted sample
}

type snmpDevice struct {
	Ip           string      `yaml:"ip"`
	Community    string      `yaml:"community"`
	Version      string      `yaml:"version"`
	FetchIfAlias bool        `yaml:"fetch_ifalias"` // Fetch ifAlias (interface description set by admin)
	IFMisc       []ifMiscOID `yaml:"ifmisc"`        // Additional interface counters
	OIDMisc      []oidMisc   `yaml:"oidmisc"`       // Additional OIDs
	OIDWalk      []oidWalk   `yaml:"oidwalk"`       // Tabular subtree walks (non-ifIndex tables)
	Tags         []KV        `yaml:"tags"`          // Tags applied to all metrics for the device
	// Bulk: nil (unset) → adaptive (GETBULK with fallback, default).
	// false → force GETNEXT (no GETBULK ever issued); for agents that
	// mishandle bulk regardless of max-repetitions. true is reserved
	// for future "force bulk, never degrade" semantics — currently a no-op.
	Bulk *bool `yaml:"bulk"`
	// Per device overrides of the global flags, for devices with a slow SNMP
	// engine. Unset (zero/nil) means "use the flag value".
	Timeout        int  `yaml:"timeout"`         // seconds
	Retries        *int `yaml:"retries"`         // pointer, 0 retries is a valid setting
	MaxRepetitions int  `yaml:"max_repetitions"` // GETBULK max-repetitions
}

type uptimeTooShortError struct {
	device    string
	minperiod int
}

func (e *uptimeTooShortError) Error() string {
	return fmt.Sprintf("device %s uptime less than %d seconds", e.device, e.minperiod)
}

type deviceDeadError struct {
	device string
}

func (e *deviceDeadError) Error() string {
	return fmt.Sprintf("device %s is dead (sysObjectID probe failed)", e.device)
}

// 1.3.6.1.2.1.31.1.1.1.6.35
const (
	// Basic ifTable (RFC 1213) - 32-bit counters
	IfDescrOID      = "1.3.6.1.2.1.2.2.1.2"
	IfOperStatusOID = "1.3.6.1.2.1.2.2.1.8" // 1=up, 2=down, 3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown
	IfInOctets      = "1.3.6.1.2.1.2.2.1.10"
	IfInDiscards    = "1.3.6.1.2.1.2.2.1.13"
	IfInErrors      = "1.3.6.1.2.1.2.2.1.14"
	IfOutOctets     = "1.3.6.1.2.1.2.2.1.16"
	IfOutDiscards   = "1.3.6.1.2.1.2.2.1.19"
	IfOutErrors     = "1.3.6.1.2.1.2.2.1.20"

	// ifXTable extension (RFC 2863) - 64-bit HC counters
	ifName           = "1.3.6.1.2.1.31.1.1.1.1"
	ifAlias          = "1.3.6.1.2.1.31.1.1.1.18" // Interface alias/description set by admin
	IfHCInUcastPkts  = "1.3.6.1.2.1.31.1.1.1.7"
	IfHCOutUcastPkts = "1.3.6.1.2.1.31.1.1.1.11"
	IfHCInOctets     = "1.3.6.1.2.1.31.1.1.1.6"
	IfHCOutOctets    = "1.3.6.1.2.1.31.1.1.1.10"

	// Scalar, so it needs the .0 instance suffix. A GET on the bare 1.3.6.1.2.1.1.3
	// returns noSuchObject with a nil value, which silently fell back to wall clock.
	SysUpTimeOID   = "1.3.6.1.2.1.1.3.0"
	SysObjectIDOID = "1.3.6.1.2.1.1.2.0"
)

// isBaselineOID reports whether `oid` (with optional leading dot) is one of
// the OIDs the exporter polls by default. Used to filter ifmisc entries
// that would otherwise emit a duplicate series in the same scrape.
func isBaselineOID(oid string) bool {
	o := strings.TrimPrefix(oid, ".")
	switch o {
	case IfDescrOID, IfOperStatusOID, IfInOctets, IfOutOctets,
		IfInDiscards, IfInErrors, IfOutDiscards, IfOutErrors,
		ifName, IfHCInOctets, IfHCOutOctets:
		return true
	}
	return false
}

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

// logWalk reports which table walk took how long, so a slow or stalling OID can
// be identified from the log instead of guessed at. Verbose only.
func logWalk(oid string, start time.Time, count int, err error) {
	if !*verbose {
		return
	}
	if err != nil {
		log.Printf("Walk %s failed after %s: %v", oid, time.Since(start), err)
		return
	}
	log.Printf("Walk %s: %d values in %s", oid, count, time.Since(start))
}

// getIfName gets the interface name from the snmp device
func getIfName(goSnmp *gosnmp.GoSNMP, oid string) ([]ifMetric, error) {
	var ifMetrics []ifMetric
	incRequests()
	start := time.Now()
	result, err := walkAllAdaptive(goSnmp, goSnmp.Target, oid)
	logWalk(oid, start, len(result), err)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("walk %s: %s", oid, err)
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
		ifMetrics = append(ifMetrics, ifMetric{ifname: valueStr, ifIndex: ifIndex})
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
	start := time.Now()
	result, err := walkAllAdaptive(goSnmp, goSnmp.Target, oid)
	logWalk(oid, start, len(result), err)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("walk %s: %s", oid, err)
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
	start := time.Now()
	result, err := walkAllAdaptive(goSnmp, goSnmp.Target, oid)
	logWalk(oid, start, len(result), err)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("walk %s: %s", oid, err)
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

// sanitizeLabel sanitizes a string for use in Prometheus labels by replacing
// backslash, double quote, and newline with underscores.
func sanitizeLabel(s string) string {
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "\"", "_")
	s = strings.ReplaceAll(s, "\n", "_")
	return s
}

func renderTags(tags []KV) string {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for _, tag := range tags {
		b.WriteString(fmt.Sprintf(",%s=\"%s\"", tag.Key, sanitizeLabel(tag.Value)))
	}
	return b.String()
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
		return 0, fmt.Errorf("sysUpTime: empty result")
	}
	// prevent "interface conversion: interface {} is nil, not uint64"
	if result.Variables[0].Value == nil {
		incErrors()
		return 0, fmt.Errorf("sysUpTime: value is nil")
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
		return 0, fmt.Errorf("sysUpTime: unexpected type %T, value: %v", result.Variables[0].Value, result.Variables[0].Value)
	}

	return sysUpTime, nil
}

/*
Final format should be similar to prometheus snmp_exporter
ifHCOutOctets{ifAlias="",ifDescr="eth0",ifIndex="2",ifName="eth0"} 1000
*/
func formatMetrics(ifMetrics []ifMetric, hostname string, tags []KV) []string {
	var metrics []string
	tagStr := renderTags(tags)
	for _, metric := range ifMetrics {
		// Include ifAlias label only if it was fetched (non-empty)
		aliasLabel := ""
		if metric.ifalias != "" {
			aliasLabel = fmt.Sprintf(",ifAlias=\"%s\"", metric.ifalias)
		}
		//log.Printf("DEBUG: Metric for %s: %s %s %d %d", metric.ifname, metric.ifdescr, metric.ifIndex, metric.ifhcInOctets, metric.ifhcOutOctets)
		metrics = append(metrics, fmt.Sprintf("ifHCInOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifhcInOctets))
		metrics = append(metrics, fmt.Sprintf("ifHCOutOctets{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifhcOutOctets))
		if metric.hasOperStatus {
			metrics = append(metrics, fmt.Sprintf("ifOperStatus{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifOperStatus))
		}
		if metric.hasDiscErrs {
			metrics = append(metrics, fmt.Sprintf("ifInDiscards{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifInDiscards))
			metrics = append(metrics, fmt.Sprintf("ifOutDiscards{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifOutDiscards))
			metrics = append(metrics, fmt.Sprintf("ifInErrors{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifInErrors))
			metrics = append(metrics, fmt.Sprintf("ifOutErrors{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifOutErrors))
		}
		// Also add misc metrics from config
		nummusc := len(metric.ifMiscCtr)
		for i := 0; i < nummusc; i++ {
			metrics = append(metrics, fmt.Sprintf("%s{host=\"%s\",ifName=\"%s\",ifDescr=\"%s\",ifIndex=\"%s\"%s%s} %d", metric.ifMiscName[i], hostname, metric.ifname, metric.ifdescr, metric.ifIndex, aliasLabel, tagStr, metric.ifMiscCtr[i]))
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

// hasIfIndex returns true if the walk result contains a PDU for this ifIndex.
// This is how we detect HC counter support per interface: if ifIndex appears in
// the HC walk result, the device supports HC for that interface (value may still
// legitimately be 0 on idle interfaces). If absent, fall back to 32-bit.
func hasIfIndex(ifIndex string, metrics []myOids) bool {
	for _, metric := range metrics {
		if metric.ifIndex == ifIndex {
			return true
		}
	}
	return false
}

// needBasicCounters reports whether the 32-bit ifTable walks are still required
// for this device: either an interface is already pinned to the basic counters,
// or it is still undecided and did not show up in the HC walk.
func needBasicCounters(device string, ifaces []ifMetric, hcIn, hcOut []myOids) bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	sources := counterSource[device]
	for _, iface := range ifaces {
		src, decided := sources[iface.ifIndex]
		if !decided {
			if !hasIfIndex(iface.ifIndex, hcIn) || !hasIfIndex(iface.ifIndex, hcOut) {
				return true
			}
			continue
		}
		if src == "basic" {
			return true
		}
	}
	return false
}

// func snmpWalk(device string, community string, version string, ifMisc []ifMiscOID) ([]string, error) {
func snmpWalk(snmpdev snmpDevice) ([]string, error) {
	device := snmpdev.Ip
	community := snmpdev.Community
	version := snmpdev.Version
	ifMisc := snmpdev.IFMisc
	oidMisc := snmpdev.OIDMisc
	deviceTags := snmpdev.Tags

	// Per-device "bulk: false" → pin walkAllAdaptive to GETNEXT before
	// any walk runs. Idempotent across scrapes.
	if snmpdev.Bulk != nil && !*snmpdev.Bulk {
		stateMu.Lock()
		walkModeCache[device] = walkGetNext
		stateMu.Unlock()
	}

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

	devTimeout := *timeout
	if snmpdev.Timeout > 0 {
		devTimeout = snmpdev.Timeout
	}
	devRetries := *retries
	if snmpdev.Retries != nil {
		devRetries = *snmpdev.Retries
	}
	devMaxReps := *maxRepetitions
	if snmpdev.MaxRepetitions > 0 {
		devMaxReps = snmpdev.MaxRepetitions
	}

	// set the snmp parameters
	params := &gosnmp.GoSNMP{
		Target:         device,
		Port:           161,
		Community:      community,
		Version:        snmpVersion,
		Timeout:        time.Duration(devTimeout) * time.Second,
		Retries:        devRetries,
		MaxRepetitions: uint32(devMaxReps),
	}

	// connect to the snmp device
	err := params.Connect()
	if err != nil {
		return nil, fmt.Errorf("error connecting to device: %s", err)
	}
	defer params.Conn.Close()

	// Probe: check if device is alive by querying sysObjectID (mandatory on all SNMP devices)
	savedRetries := params.Retries
	params.Retries = 0
	incRequests()
	_, err = params.Get([]string{SysObjectIDOID})
	params.Retries = savedRetries
	if err != nil {
		incErrors()
		return nil, &deviceDeadError{device: device}
	}

	// retrieve uptime; if unavailable, skip the minperiod check (we can't
	// enforce a rule about uptime we don't know) but still proceed with the scrape
	sysUpTime, upErr := getSysUpTime(params)
	if upErr != nil {
		if *verbose {
			log.Printf("Warning: Could not get sysUpTime for %s: %v — skipping minperiod check", device, upErr)
		}
	} else {
		// check if diff is less than minperiod
		stateMu.Lock()
		lastUp := lastDevUptime[device]
		if lastUp != 0 && sysUpTime-lastUp < uint64(*minperiod) {
			stateMu.Unlock()
			return nil, &uptimeTooShortError{device: device, minperiod: *minperiod}
		}
		lastDevUptime[device] = sysUpTime
		stateMu.Unlock()
	}

	// Use ifDescr as primary source for interface discovery (more universal, especially on Nokia SROS)
	ifMetricsDescr, err := getIfStr(params, IfDescrOID)
	if err != nil {
		return nil, fmt.Errorf("device %s: ifDescr: %s", device, err)
	}

	// Build initial interface list from ifDescr
	for _, metric := range ifMetricsDescr {
		ifMetricsTotal = append(ifMetricsTotal, ifMetric{
			ifname:  sanitizeLabel(metric.valueStr), // Use ifDescr as default name
			ifIndex: metric.ifIndex,
			ifdescr: sanitizeLabel(metric.valueStr),
		})
	}

	// Baseline walk failures below are logged unconditionally (NOT gated on
	// *verbose). They tell operators why a device is missing core metrics
	// like ifOperStatus or ifHCInOctets in Prometheus — silent failures
	// here turn into "no interfaces showing in the dashboard" mysteries
	// that are impossible to diagnose without restarting the exporter
	// with a non-default flag.
	ifMetricsName, err := getIfStr(params, ifName)
	if err != nil {
		log.Printf("Warning: Could not get ifName for %s (will use ifDescr): %v", device, err)
	}

	// Optionally fetch ifAlias (admin-set interface description)
	var ifMetricsAlias []myOids
	if snmpdev.FetchIfAlias {
		ifMetricsAlias, err = getIfStr(params, ifAlias)
		if err != nil && *verbose {
			log.Printf("Warning: Could not get ifAlias for %s: %v", device, err)
		}
	}

	// Try HC (64-bit) counters first from ifXTable
	ifMetricsInOctets, err := getIfCtr(params, IfHCInOctets)
	if err != nil {
		log.Printf("Warning: Could not get HC InOctets for %s, will try basic counters: %v", device, err)
	}
	ifMetricsOutOctets, err := getIfCtr(params, IfHCOutOctets)
	if err != nil {
		log.Printf("Warning: Could not get HC OutOctets for %s, will try basic counters: %v", device, err)
	}

	// Get basic 32-bit counters from ifTable as fallback. These are two extra full
	// table walks, so only do them when at least one interface actually needs them:
	// on a device where every interface answered the HC walk and is already pinned
	// to "hc", they are pure overhead on every scrape.
	var ifMetricsInOctetsBasic, ifMetricsOutOctetsBasic []myOids
	if needBasicCounters(device, ifMetricsTotal, ifMetricsInOctets, ifMetricsOutOctets) {
		ifMetricsInOctetsBasic, err = getIfCtr(params, IfInOctets)
		if err != nil {
			log.Printf("Warning: Could not get basic InOctets for %s: %v", device, err)
		}
		ifMetricsOutOctetsBasic, err = getIfCtr(params, IfOutOctets)
		if err != nil {
			log.Printf("Warning: Could not get basic OutOctets for %s: %v", device, err)
		}
	}

	// ifOperStatus — polled by default so consumers (e.g. maasmonitor's
	// Interfaces panel, IfaceDown alerts) see operational state without
	// the operator having to opt in via ifmisc.
	ifMetricsOperStatus, err := getIfCtr(params, IfOperStatusOID)
	if err != nil {
		log.Printf("Warning: Could not get ifOperStatus for %s: %v", device, err)
	}

	// IF-MIB drop/error counters (32-bit Counter32 — no HC variants exist).
	// Polled by default so dashboards/alerts have access without ifmisc.
	ifMetricsInDiscards, err := getIfCtr(params, IfInDiscards)
	if err != nil {
		log.Printf("Warning: Could not get ifInDiscards for %s: %v", device, err)
	}
	ifMetricsOutDiscards, err := getIfCtr(params, IfOutDiscards)
	if err != nil {
		log.Printf("Warning: Could not get ifOutDiscards for %s: %v", device, err)
	}
	ifMetricsInErrors, err := getIfCtr(params, IfInErrors)
	if err != nil {
		log.Printf("Warning: Could not get ifInErrors for %s: %v", device, err)
	}
	ifMetricsOutErrors, err := getIfCtr(params, IfOutErrors)
	if err != nil {
		log.Printf("Warning: Could not get ifOutErrors for %s: %v", device, err)
	}

	// get misc as getIfCtr
	//
	// Baseline OIDs (ifHCInOctets/Out, ifInOctets/Out, ifDescr, ifName,
	// ifOperStatus) are walked unconditionally above as part of every
	// scrape. If an operator-supplied ifmisc entry duplicates one of those,
	// skip the walk entirely — the format-time filter would drop the
	// resulting samples anyway and it's wasteful to make the device
	// service a redundant BulkWalk every scrape. Also catches old
	// orchestrator-generated configs that pre-date the prefab cleanup.
	if ifMisc != nil {
		miscnum := len(ifMisc)
		if miscnum > 0 {
			miscMyOIDs = make([][]myOids, miscnum)
			miscName = make([]string, miscnum)
			for i := 0; i < miscnum; i++ {
				miscName[i] = ifMisc[i].Name
				if isBaselineOID(ifMisc[i].BaseOID) {
					if *verbose {
						log.Printf("Skipping ifmisc walk on %s: %s (%s) is already polled as a baseline OID",
							device, ifMisc[i].BaseOID, ifMisc[i].Name)
					}
					// leave miscMyOIDs[i] nil; the format-time loop also
					// short-circuits on isBaselineOID so nothing is emitted.
					continue
				}
				miscMyOIDs[i], err = getIfCtr(params, ifMisc[i].BaseOID)
				if err != nil {
					return nil, fmt.Errorf("device %s: ifmisc %s: %s", device, ifMisc[i].Name, err)
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
		// Set ifAlias if fetched
		if ifAliasVal := getByIfIndexStr(ifIdx, ifMetricsAlias); ifAliasVal != "" {
			ifMetricsTotal[i].ifalias = sanitizeLabel(ifAliasVal)
		}
		// Pick counter source per (device, ifIndex) and cache it so we don't flip
		// between HC and basic across scrapes. Prior logic fell back on value==0,
		// which caused huge fake spikes whenever an HC counter legitimately read 0
		// or the source swapped between scrapes.
		stateMu.Lock()
		if counterSource[device] == nil {
			counterSource[device] = make(map[string]string)
		}
		src, decided := counterSource[device][ifIdx]
		if !decided {
			switch {
			case hasIfIndex(ifIdx, ifMetricsInOctets) && hasIfIndex(ifIdx, ifMetricsOutOctets):
				src = "hc"
			case hasIfIndex(ifIdx, ifMetricsInOctetsBasic) && hasIfIndex(ifIdx, ifMetricsOutOctetsBasic):
				src = "basic"
			default:
				src = "none"
			}
			counterSource[device][ifIdx] = src
		}
		stateMu.Unlock()

		var inOctets, outOctets uint64
		switch src {
		case "hc":
			inOctets = getByIfIndexInt(ifIdx, ifMetricsInOctets)
			outOctets = getByIfIndexInt(ifIdx, ifMetricsOutOctets)
		case "basic":
			inOctets = getByIfIndexInt(ifIdx, ifMetricsInOctetsBasic)
			outOctets = getByIfIndexInt(ifIdx, ifMetricsOutOctetsBasic)
			usedBasicCounters = true
		}

		ifMetricsTotal[i].ifhcInOctets = inOctets
		ifMetricsTotal[i].ifhcOutOctets = outOctets
		// Note: ifdescr is already set from ifMetricsDescr during initialization
		if hasIfIndex(ifIdx, ifMetricsOperStatus) {
			ifMetricsTotal[i].ifOperStatus = getByIfIndexInt(ifIdx, ifMetricsOperStatus)
			ifMetricsTotal[i].hasOperStatus = true
		}
		if hasIfIndex(ifIdx, ifMetricsInDiscards) || hasIfIndex(ifIdx, ifMetricsOutDiscards) ||
			hasIfIndex(ifIdx, ifMetricsInErrors) || hasIfIndex(ifIdx, ifMetricsOutErrors) {
			ifMetricsTotal[i].ifInDiscards = getByIfIndexInt(ifIdx, ifMetricsInDiscards)
			ifMetricsTotal[i].ifOutDiscards = getByIfIndexInt(ifIdx, ifMetricsOutDiscards)
			ifMetricsTotal[i].ifInErrors = getByIfIndexInt(ifIdx, ifMetricsInErrors)
			ifMetricsTotal[i].ifOutErrors = getByIfIndexInt(ifIdx, ifMetricsOutErrors)
			ifMetricsTotal[i].hasDiscErrs = true
		}
		if len(miscMyOIDs) > 0 {
			// append one by one to ifMetricsTotal[i].ifMiscCtrs , ifMetricsTotal[i].ifMiscNames
			for j := range miscMyOIDs {
				// Skip ifmisc entries that duplicate a baseline OID — emitting
				// the same series twice from one scrape is a Prometheus
				// scrape error. Existing operator configs that pre-date the
				// baseline addition keep working.
				if isBaselineOID(ifMisc[j].BaseOID) {
					continue
				}
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

	mymetrics := formatMetrics(ifMetricsTotal, device, deviceTags)
	// now process oid
	for _, oid := range oidMisc {
		name := oid.Name
		value, err := getOIDUint64(params, oid.OID)
		if err != nil {
			log.Printf("Warning: Could not get OID %s for %s: %v", oid.OID, device, err)
			continue
		}
		tags := renderTags(deviceTags) + renderTags(oid.Tags)
		if value != 0 {
			metric := fmt.Sprintf("%s{host=\"%s\"%s} %d", name, device, tags, value)
			mymetrics = append(mymetrics, metric)
		}
	}

	// process oidwalk: walk the subtree, emit one sample per varbind with
	// the post-base suffix as a single label.
	for _, w := range snmpdev.OIDWalk {
		walkMetrics, err := walkOidSubtree(params, device, deviceTags, w)
		if err != nil {
			log.Printf("Warning: oidwalk %s on %s failed: %v", w.BaseOID, device, err)
			continue
		}
		mymetrics = append(mymetrics, walkMetrics...)
	}

	return mymetrics, nil
}

// walkOidSubtree implements the `oidwalk` config entry: BulkWalk a base OID
// and emit one Prometheus sample per integer-valued varbind, labeled by
// the OID suffix that remains after stripping BaseOID. Non-integer values
// (strings, OctetString, OID, etc.) are skipped — the same restriction as
// oidmisc, since the exposition format is plain `metric{labels} <integer>`.
func walkOidSubtree(g *gosnmp.GoSNMP, device string, deviceTags []KV, w oidWalk) ([]string, error) {
	if w.BaseOID == "" || w.Name == "" {
		return nil, fmt.Errorf("oidwalk entry missing BaseOID or Name")
	}
	// IndexLabels (plural) wins when set; falls back to IndexLabel (singular)
	// or "index" otherwise. Splitting only happens when ≥2 labels are listed —
	// a single-element IndexLabels behaves like IndexLabel.
	labels := w.IndexLabels
	if len(labels) == 0 {
		single := w.IndexLabel
		if single == "" {
			single = "index"
		}
		labels = []string{single}
	}
	base := strings.TrimPrefix(w.BaseOID, ".")

	incRequests()
	result, err := walkAllAdaptive(g, device, w.BaseOID)
	if err != nil {
		incErrors()
		return nil, fmt.Errorf("walk: %w", err)
	}

	out := make([]string, 0, len(result))
	staticTags := renderTags(deviceTags) + renderTags(w.Tags)
	for _, v := range result {
		oid := strings.TrimPrefix(v.Name, ".")
		// Suffix is whatever is left after removing the base + the dot.
		// If the walked OID happens to equal the base exactly (rare, scalar
		// case), the suffix is empty — we still emit it so the operator at
		// least sees the value land under a known metric name.
		suffix := ""
		switch {
		case oid == base:
			suffix = ""
		case strings.HasPrefix(oid, base+"."):
			suffix = oid[len(base)+1:]
		default:
			// gosnmp shouldn't return varbinds outside the requested
			// subtree, but if it does, ignore them rather than emit a
			// misleading suffix.
			continue
		}

		// Sign-aware integer cast. SNMP Integer32 columns (e.g. JNX-OPT-IF-MIB
		// Rx laser power, signed dBm × 100) come through gosnmp as int32 and
		// can be negative; casting straight to uint64 wraps to 2^64-N which
		// is garbage in Prometheus exposition. Use int64 throughout so signed
		// values print correctly via %d. Counter64 values up to 2^63 still
		// fit; nothing real reaches that.
		var value int64
		switch x := v.Value.(type) {
		case uint64:
			value = int64(x)
		case uint32:
			value = int64(x)
		case uint:
			value = int64(x)
		case int64:
			value = x
		case int32:
			value = int64(x) // sign-extend; -2890 → -2890, not 2^64-2890
		case int:
			value = int64(x)
		default:
			// Strings, OctetStrings, IP addresses, etc. — skip silently.
			// Operators wanting those need to wait for a future extension.
			continue
		}

		labelStr := buildIndexLabels(labels, suffix)
		metric := fmt.Sprintf("%s{host=\"%s\"%s%s} %d",
			w.Name, device, labelStr, staticTags, value)
		out = append(out, metric)
	}
	return out, nil
}

// buildIndexLabels splits suffix on `.` and emits one `<label>="<value>"`
// pair per entry in labels (comma-separated, leading comma when non-empty).
// More suffix components than labels → extras concatenate into the last
// label with `.` separators (no data loss, no silent truncation). Fewer
// components than labels → trailing labels emit empty strings (PromQL filter
// for "" makes malformed rows obvious instead of swallowed).
func buildIndexLabels(labels []string, suffix string) string {
	parts := strings.Split(suffix, ".")
	if suffix == "" {
		parts = nil
	}
	var b strings.Builder
	for i, name := range labels {
		var val string
		switch {
		case i == len(labels)-1 && len(parts) > i:
			// Last label — absorb any extra components.
			val = strings.Join(parts[i:], ".")
		case i < len(parts):
			val = parts[i]
		default:
			val = ""
		}
		b.WriteString(",")
		b.WriteString(name)
		b.WriteString("=\"")
		b.WriteString(sanitizeLabel(val))
		b.WriteString("\"")
	}
	return b.String()
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
				var dde *deviceDeadError
				if errors.As(err, &dde) {
					log.Printf("Skipping device %s: %s\n", dde.device, dde.Error())
					return
				}
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
	metrics = append(metrics, fmt.Sprintf("usnmp_dropped_octets{instance=\"%s\"} %d", *instance, atomic.LoadInt64(&Statdropped)))
	metrics = append(metrics, fmt.Sprintf("usnmp_exporter_scrape_duration_seconds{instance=\"%s\"} %.6f", *instance, time.Since(start).Seconds()))

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
	log.Printf("Starting up usnmp_exporter v%s\n", appVersion)

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
