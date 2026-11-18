package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func newTestMetadataCache() *interfaceMetadataCache {
	return &interfaceMetadataCache{devices: make(map[string]*deviceMetadata)}
}

func TestMetadataWarmPollKeepsLiveCountersAndStatus(t *testing.T) {
	c := newTestMetadataCache()
	dev := snmpDevice{Ip: "192.0.2.1", Community: "a", Version: "2c"}
	identity := metadataIdentity{uptime: 10000, number: 2, hasNumber: true, hasChanged: true}
	now := time.Now()
	calls := map[string]int{}
	read := func(p *metadataPoll, oid string) []myOids {
		t.Helper()
		rows, err := p.get(context.Background(), oid, now, func() ([]myOids, error) {
			calls[oid]++
			return []myOids{{ifIndex: "1", valueInt: uint64(calls[oid]), valueStr: "port1"}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	oids := []string{IfDescrOID, ifName, ifAlias, "." + ifHighSpeedOID,
		IfHCInOctets, IfHCOutOctets, IfOperStatusOID, IfInDiscards, IfOutDiscards,
		IfInErrors, IfOutErrors, IfHCInUcastPkts, IfHCOutUcastPkts, "1.3.6.1.2.1.2.2.1.7"}
	for poll := 0; poll < 2; poll++ {
		identity.uptime += 12000
		p := c.begin(dev, identity, 10*time.Minute)
		for _, oid := range oids {
			rows := read(p, oid)
			if len(rows) != 1 || rows[0].ifIndex != "1" {
				t.Fatal("lost interface")
			}
			if !isMetadataOID(oid) && rows[0].valueInt != uint64(poll+1) {
				t.Fatalf("stale %s: %v", oid, rows)
			}
			rows[0].valueStr = "caller mutation"
		}
		now = now.Add(2 * time.Minute)
	}
	for _, oid := range oids {
		want := 2
		if isMetadataOID(oid) {
			want = 1
		}
		if calls[oid] != want {
			t.Fatalf("%s loaded %d times, want %d", oid, calls[oid], want)
		}
	}
	p := c.begin(dev, identity, 10*time.Minute)
	if rows := read(p, ifName); rows[0].valueStr != "port1" {
		t.Fatal("caller mutated cache")
	}
}

func TestMetadataInvalidatesOnIdentityAndTTL(t *testing.T) {
	base := metadataIdentity{uptime: 10000, number: 2, changed: 500, hasNumber: true, hasChanged: true}
	for _, reason := range []string{"ttl", "reboot", "number", "table-change", "community", "version", "marker-unavailable", "disabled"} {
		t.Run(reason, func(t *testing.T) {
			c := newTestMetadataCache()
			dev := snmpDevice{Ip: "192.0.2.1", Community: "a", Version: "2c"}
			identity := base
			now := time.Now()
			calls := 0
			fetch := func() ([]myOids, error) { calls++; return []myOids{{ifIndex: fmt.Sprint(calls)}}, nil }
			p := c.begin(dev, identity, 10*time.Minute)
			if _, err := p.get(context.Background(), IfDescrOID, now, fetch); err != nil {
				t.Fatal(err)
			}
			ttl := 10 * time.Minute
			switch reason {
			case "ttl":
				now = now.Add(ttl)
			case "reboot":
				identity.uptime = 10
			case "number":
				identity.number++
			case "table-change":
				identity.changed++
			case "community":
				dev.Community = "b"
			case "version":
				dev.Version = "1"
			case "marker-unavailable":
				identity.hasChanged = false
			case "disabled":
				ttl = 0
			}
			p = c.begin(dev, identity, ttl)
			rows, err := p.get(context.Background(), IfDescrOID, now, fetch)
			if err != nil || calls != 2 || rows[0].ifIndex != "2" {
				t.Fatalf("stale inventory: %v %v calls=%d", rows, err, calls)
			}
		})
	}
}

func TestMetadataFailedOrCancelledRefreshNeverReturnsStaleRows(t *testing.T) {
	c := newTestMetadataCache()
	p := c.begin(snmpDevice{Ip: "192.0.2.1"}, metadataIdentity{}, time.Minute)
	now := time.Now()
	loader := func() ([]myOids, error) { return []myOids{{ifIndex: "old"}}, nil }
	if _, err := p.get(context.Background(), IfDescrOID, now, loader); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("agent timeout")
	rows, err := p.get(context.Background(), IfDescrOID, now.Add(time.Minute), func() ([]myOids, error) { return nil, failure })
	if !errors.Is(err, failure) || len(rows) != 0 {
		t.Fatal("reused expired metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	rows, err = p.get(ctx, IfDescrOID, now.Add(time.Minute), func() ([]myOids, error) {
		cancel()
		return []myOids{{ifIndex: "cancelled"}}, nil
	})
	if !errors.Is(err, context.Canceled) || len(rows) != 0 {
		t.Fatalf("%v %v", rows, err)
	}
	rows, err = p.get(context.Background(), IfDescrOID, now.Add(time.Minute), func() ([]myOids, error) { return []myOids{{ifIndex: "new"}}, nil })
	if err != nil || rows[0].ifIndex != "new" {
		t.Fatalf("cancelled refresh poisoned cache: %v %v", rows, err)
	}
}

func TestMetadataIdentityRequiresUptimeAndAcceptsUnsupportedMarkers(t *testing.T) {
	rows := []gosnmp.SnmpPDU{
		{Name: "." + SysUpTimeOID, Type: gosnmp.TimeTicks, Value: uint32(100)},
		{Name: ifNumberOID, Type: gosnmp.Integer, Value: 318},
		{Name: ifTableLastChangeOID, Type: gosnmp.NoSuchObject},
	}
	id, err := parseMetadataIdentity(rows)
	if err != nil || id.uptime != 100 || id.number != 318 || !id.hasNumber || id.hasChanged {
		t.Fatalf("%+v %v", id, err)
	}
	rows[0].Type = gosnmp.NoSuchInstance
	if _, err := parseMetadataIdentity(rows); err == nil {
		t.Fatal("accepted invalid uptime")
	}
	if _, err := parseMetadataIdentity(rows[1:]); err == nil {
		t.Fatal("accepted missing uptime")
	}
}

func TestMetadataCacheConcurrentDevices(t *testing.T) {
	c := newTestMetadataCache()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := c.begin(snmpDevice{Ip: fmt.Sprint(i)}, metadataIdentity{uptime: 100}, time.Minute)
			for j := 0; j < 10; j++ {
				if _, err := p.get(context.Background(), ifName, time.Now(), func() ([]myOids, error) { return []myOids{{ifIndex: "1"}}, nil }); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
}
