package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// A silent UDP agent must not consume the per-request timeout or retry budget
// after the whole-poll deadline, or after its HTTP client goes away.
func TestPollContextStopsOutstandingSNMP(t *testing.T) {
	for _, mode := range []string{"deadline", "client-cancel"} {
		t.Run(mode, func(t *testing.T) {
			conn, agent := net.Pipe()
			defer agent.Close()
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				time.AfterFunc(80*time.Millisecond, cancel)
			}
			defer cancel()
			start := time.Now()
			closeSNMP := closeOnPollCancellation(ctx, conn)
			defer closeSNMP()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(make([]byte, 1024)); err == nil {
				t.Fatal("silent connection unexpectedly succeeded")
			}
			if ctx.Err() == nil {
				t.Fatal("request stopped without context cancellation")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("poll took %s despite 80ms budget", elapsed)
			}
		})
	}
}

func TestCancelledWalkDoesNotDegradeOrEmitMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const ip = "192.0.2.44"
	_, err := walkAllAdaptive(&gosnmp.GoSNMP{Context: ctx}, ip, IfDescrOID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, exists := walkModeCache[ip]; exists {
		t.Fatal("cancellation changed the adaptive walk mode")
	}
	metrics, err := snmpWalk(ctx, snmpDevice{Ip: ip, Version: "2c"})
	if len(metrics) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("metrics=%v error=%v", metrics, err)
	}
}

func TestDevicePollDoesNotOverlap(t *testing.T) {
	const ip = "192.0.2.45"
	activePolls[ip] = true
	defer delete(activePolls, ip)
	metrics, err := snmpWalk(context.Background(), snmpDevice{Ip: ip, Version: "2c"})
	if len(metrics) != 0 || err == nil {
		t.Fatalf("overlapping poll accepted: %v %v", metrics, err)
	}
}

func TestParsePollLimits(t *testing.T) {
	limits, err := parsePollTimeouts("10.0.25.1=30s,192.0.2.1=1m")
	if err != nil || limits["10.0.25.1"] != 30*time.Second || limits["192.0.2.1"] != time.Minute {
		t.Fatalf("%v %v", limits, err)
	}
	for _, value := range []string{"10.0.25.1", "10.0.25.1=0s", "10.0.25.1=-1s", "=30s", "10.0.25.1=foo"} {
		if _, err := parsePollTimeouts(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
