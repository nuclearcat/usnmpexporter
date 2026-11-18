package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	ifHighSpeedOID       = "1.3.6.1.2.1.31.1.1.1.15"
	ifNumberOID          = "1.3.6.1.2.1.2.1.0"
	ifTableLastChangeOID = "1.3.6.1.2.1.31.1.5.0"
)

// Only inventory properties may be reused. Never cache counters, link/admin
// status, arbitrary ifmisc values, or vendor OID walks.
func isMetadataOID(oid string) bool {
	switch strings.TrimPrefix(oid, ".") {
	case IfDescrOID, ifName, ifAlias, ifHighSpeedOID:
		return true
	}
	return false
}

type metadataIdentity struct {
	uptime                uint64
	number, changed       uint64
	hasNumber, hasChanged bool
}

type metadataTable struct {
	rows   []myOids
	loaded time.Time
}

type deviceMetadata struct {
	community, version string
	identity           metadataIdentity
	tables             map[string]metadataTable
}

type interfaceMetadataCache struct {
	mu      sync.Mutex
	devices map[string]*deviceMetadata
}

var interfaceMetadata = interfaceMetadataCache{devices: make(map[string]*deviceMetadata)}

type metadataPoll struct {
	cache  *interfaceMetadataCache
	device string
	entry  *deviceMetadata
	ttl    time.Duration
}

// Call only after a successful, numeric uptime read. Identity changes invalidate
// every column together, including cached interface indices. Optional IF-MIB
// markers detect interface changes between inventory refreshes; unsupported
// markers fall back to TTL plus reboot detection.
func (c *interfaceMetadataCache) begin(dev snmpDevice, identity metadataIdentity, ttl time.Duration) *metadataPoll {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		delete(c.devices, dev.Ip)
		return nil
	}
	e := c.devices[dev.Ip]
	if e == nil || e.community != dev.Community || e.version != dev.Version ||
		identity.uptime < e.identity.uptime ||
		identity.hasNumber != e.identity.hasNumber || identity.number != e.identity.number ||
		identity.hasChanged != e.identity.hasChanged || identity.changed != e.identity.changed {
		e = &deviceMetadata{community: dev.Community, version: dev.Version, tables: make(map[string]metadataTable)}
		c.devices[dev.Ip] = e
	}
	e.identity = identity
	if *verbose {
		log.Printf("Metadata cache identity %s: uptime=%d ifNumber=%d supported=%t ifTableLastChange=%d supported=%t", dev.Ip, identity.uptime, identity.number, identity.hasNumber, identity.changed, identity.hasChanged)
	}
	return &metadataPoll{cache: c, device: dev.Ip, entry: e, ttl: ttl}
}

// A failed refresh is an error, never an excuse to emit expired metadata. A
// failed/cancelled walk cannot poison the next poll's inventory. Copying rows
// keeps callers from mutating shared state.
func (p *metadataPoll) get(ctx context.Context, oid string, now time.Time, load func() ([]myOids, error)) ([]myOids, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || !isMetadataOID(oid) {
		return load()
	}
	key := strings.TrimPrefix(oid, ".")
	p.cache.mu.Lock()
	table, ok := p.entry.tables[key]
	if ok && !now.Before(table.loaded) && now.Sub(table.loaded) < p.ttl {
		rows := append([]myOids(nil), table.rows...)
		p.cache.mu.Unlock()
		if *verbose {
			log.Printf("Metadata cache hit %s OID %s: %d values, age %s", p.device, key, len(rows), now.Sub(table.loaded).Round(time.Second))
		}
		return rows, nil
	}
	p.cache.mu.Unlock()
	rows, err := load()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Empty tables are retried next poll rather than hiding discovery failures.
	if len(rows) > 0 {
		p.cache.mu.Lock()
		if p.cache.devices[p.device] == p.entry {
			p.entry.tables[key] = metadataTable{rows: append([]myOids(nil), rows...), loaded: now}
		}
		p.cache.mu.Unlock()
	}
	return rows, nil
}

func (p *metadataPoll) getStr(ctx context.Context, g *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	return p.get(ctx, oid, time.Now(), func() ([]myOids, error) { return getIfStr(g, oid) })
}

func (p *metadataPoll) getCtr(ctx context.Context, g *gosnmp.GoSNMP, oid string) ([]myOids, error) {
	return p.get(ctx, oid, time.Now(), func() ([]myOids, error) { return getIfCtr(g, oid) })
}

func metadataUint(pdu gosnmp.SnmpPDU) (uint64, bool) {
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Counter64:
	default:
		return 0, false
	}
	switch v := pdu.Value.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint:
		return uint64(v), true
	case int:
		return uint64(v), v >= 0
	case int32:
		return uint64(v), v >= 0
	case int64:
		return uint64(v), v >= 0
	}
	return 0, false
}

func parseMetadataIdentity(rows []gosnmp.SnmpPDU) (metadataIdentity, error) {
	var identity metadataIdentity
	var hasUptime bool
	for _, pdu := range rows {
		value, ok := metadataUint(pdu)
		switch strings.TrimPrefix(pdu.Name, ".") {
		case SysUpTimeOID:
			identity.uptime, hasUptime = value, ok
		case ifNumberOID:
			identity.number, identity.hasNumber = value, ok
		case ifTableLastChangeOID:
			identity.changed, identity.hasChanged = value, ok
		}
	}
	if !hasUptime {
		return identity, fmt.Errorf("sysUpTime: missing or non-numeric result")
	}
	return identity, nil
}

// Replaces the existing uptime GET with one GET containing three scalars.
// Legacy/v1 agents rejecting optional IF-MIB scalars retain the uptime-only path.
func getMetadataIdentity(g *gosnmp.GoSNMP) (metadataIdentity, error) {
	incRequests()
	packet, err := g.Get([]string{SysUpTimeOID, ifNumberOID, ifTableLastChangeOID})
	if err == nil && packet.Error == gosnmp.NoError {
		return parseMetadataIdentity(packet.Variables)
	}
	incErrors()
	uptime, err := getSysUpTime(g)
	return metadataIdentity{uptime: uptime}, err
}
