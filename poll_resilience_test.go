package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestRequestTimeoutDoesNotPermanentlyDegradeBulk(t *testing.T) {
	for _, mode := range []walkMode{walkBulkDefault, walkBulkSmall} {
		const ip = "192.0.2.99"
		walkModeCache[ip] = mode
		calls := 0
		fail := func(string) ([]gosnmp.SnmpPDU, error) { calls++; return nil, os.ErrDeadlineExceeded }
		unexpected := func(string) ([]gosnmp.SnmpPDU, error) {
			t.Fatal("timeout triggered a slower fallback")
			return nil, nil
		}
		bulk, small := subtreeWalker(fail), subtreeWalker(unexpected)
		if mode == walkBulkSmall {
			bulk, small = subtreeWalker(unexpected), subtreeWalker(fail)
		}
		rows, err := adaptiveWalk(context.Background(), ip, IfHCInOctets, bulk, small, unexpected)
		if !errors.Is(err, os.ErrDeadlineExceeded) || len(rows) != 0 || calls != 1 {
			t.Fatalf("unexpected timeout result %v %v calls=%d", rows, err, calls)
		}
		if walkModeCache[ip] != mode {
			t.Fatal("temporary failure permanently downgraded the device")
		}
		delete(walkModeCache, ip)
	}
}

func TestMissingCounterColumnsAreOmittedAndRealZeroIsPreserved(t *testing.T) {
	rows := formatMetrics([]ifMetric{{ifname: "port1", ifIndex: "1", hasOctets: true, ifhcInOctets: 0, ifhcOutOctets: 123, hasOperStatus: true, ifOperStatus: 1, hasOutErrors: true, ifOutErrors: 0}}, "192.0.2.1", nil)
	joined := strings.Join(rows, "\n")
	if len(rows) != 4 {
		t.Fatalf("unexpected metrics: %v", rows)
	}
	for _, prefix := range []string{"ifHCInOctets{", "ifHCOutOctets{", "ifOperStatus{", "ifOutErrors{"} {
		if !strings.Contains(joined, prefix) {
			t.Fatalf("missing valid column %s", prefix)
		}
	}
	for _, prefix := range []string{"ifInDiscards{", "ifOutDiscards{", "ifInErrors{"} {
		if strings.Contains(joined, prefix) {
			t.Fatalf("invented zero for absent column %s", prefix)
		}
	}
	if !strings.HasSuffix(rows[0], " 0") || !strings.HasSuffix(rows[3], " 0") {
		t.Fatal("legitimate zero counters were lost")
	}
	rows = formatMetrics([]ifMetric{{ifname: "port1", ifIndex: "1", hasOperStatus: true, ifOperStatus: 1}}, "192.0.2.1", nil)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "ifOperStatus{") {
		t.Fatalf("missing octet counters became zero samples: %v", rows)
	}
}

func TestDecodeFailureStillLearnsWorkingSmallBulkMode(t *testing.T) {
	const ip = "192.0.2.100"
	defer delete(walkModeCache, ip)
	want := []gosnmp.SnmpPDU{{Name: IfHCInOctets + ".1", Type: gosnmp.Counter64, Value: uint64(42)}}
	bulkCalls, smallCalls := 0, 0
	bulk := func(string) ([]gosnmp.SnmpPDU, error) {
		bulkCalls++
		return nil, errors.New("unmarshal: invalid ASN.1 reply")
	}
	small := func(string) ([]gosnmp.SnmpPDU, error) { smallCalls++; return want, nil }
	next := func(string) ([]gosnmp.SnmpPDU, error) { t.Fatal("unnecessary GETNEXT fallback"); return nil, nil }
	for i := 0; i < 2; i++ {
		rows, err := adaptiveWalk(context.Background(), ip, IfHCInOctets, bulk, small, next)
		if err != nil || len(rows) != 1 || rows[0].Value != uint64(42) {
			t.Fatalf("fallback lost data: %v %v", rows, err)
		}
	}
	if bulkCalls != 1 || smallCalls != 2 || walkModeCache[ip] != walkBulkSmall {
		t.Fatal("working decode fallback was not cached")
	}
}
