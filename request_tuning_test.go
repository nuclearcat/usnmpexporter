package main

import (
	"github.com/gosnmp/gosnmp"
	"testing"
	"time"
)

func TestRequestTuningScopedOverridesAndProbeRestorationInputs(t *testing.T) {
	old := requestTunings
	defer func() { requestTunings = old }()
	var err error
	requestTunings, err = parseRequestTunings("10.0.25.1=3s", "10.0.25.1=2s", "10.0.25.1=2,192.0.2.2=0", "10.0.25.1=10")
	if err != nil {
		t.Fatal(err)
	}
	p := &gosnmp.GoSNMP{Timeout: 30 * time.Second, Retries: 2, MaxRepetitions: 50}
	probe, retries := applyRequestTuning("10.0.25.1", p, 10*time.Second, 0)
	if p.Timeout != 3*time.Second || p.Retries != 2 || p.MaxRepetitions != 10 || probe != 2*time.Second || retries != 2 {
		t.Fatalf("wrong scoped settings: request=%v retries=%d bulk=%d probe=%v probe-retries=%d", p.Timeout, p.Retries, p.MaxRepetitions, probe, retries)
	}
	// A different device keeps all values supplied by YAML/global flags.
	p = &gosnmp.GoSNMP{Timeout: 17 * time.Second, Retries: 4, MaxRepetitions: 25}
	probe, retries = applyRequestTuning("192.0.2.1", p, 8*time.Second, 1)
	if p.Timeout != 17*time.Second || p.Retries != 4 || p.MaxRepetitions != 25 || probe != 8*time.Second || retries != 1 {
		t.Fatal("unconfigured device changed")
	}
	probe, retries = applyRequestTuning("192.0.2.2", p, 8*time.Second, 1)
	if probe != 8*time.Second || retries != 0 {
		t.Fatal("explicit zero probe retries was lost")
	}
}

func TestRequestTuningValidation(t *testing.T) {
	for _, c := range []struct{ request, probe, retries, bulk string }{
		{request: "192.0.2.1=0s"}, {probe: "192.0.2.1=-1s"},
		{request: "192.0.2.1=bad"}, {retries: "192.0.2.1=-1"},
		{retries: "192.0.2.1=11"}, {retries: "192.0.2.1=1,192.0.2.1=2"},
		{bulk: "192.0.2.1=0"}, {bulk: "192.0.2.1=65536"}, {bulk: "=10"},
	} {
		if _, err := parseRequestTunings(c.request, c.probe, c.retries, c.bulk); err == nil {
			t.Errorf("accepted invalid settings: %+v", c)
		}
	}
	if x, err := parseRequestTunings("", "", "", ""); err != nil || len(x) != 0 {
		t.Fatalf("empty flags: %v %v", x, err)
	}
}
