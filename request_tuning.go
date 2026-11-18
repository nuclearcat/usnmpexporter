package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Compose-level overrides survive regeneration of the device YAML by an
// orchestrator. Unconfigured devices retain their existing YAML/flag settings.
var (
	deviceRequestTimeout = flag.String("device-request-timeout", "", "Per-device request timeout: comma-separated IP=duration")
	deviceProbeTimeout   = flag.String("device-probe-timeout", "", "Per-device liveness timeout: comma-separated IP=duration")
	deviceProbeRetries   = flag.String("device-probe-retries", "", "Per-device liveness retries: comma-separated IP=count (0 allowed)")
	deviceMaxRepetitions = flag.String("device-max-repetitions", "", "Per-device GETBULK max-repetitions: comma-separated IP=count")
	requestTunings       = map[string]requestTuning{}
)

type requestTuning struct {
	timeout        time.Duration
	probeTimeout   time.Duration
	probeRetries   *int
	maxRepetitions int
}

func parseDeviceInts(value string, min, max int) (map[string]int, error) {
	out := map[string]int{}
	if value == "" {
		return out, nil
	}
	for _, entry := range strings.Split(value, ",") {
		ip, raw, ok := strings.Cut(entry, "=")
		ip = strings.TrimSpace(ip)
		n, err := strconv.Atoi(raw)
		if !ok || ip == "" || err != nil || n < min || n > max {
			return nil, fmt.Errorf("invalid device setting %q: expected IP=integer in [%d,%d]", entry, min, max)
		}
		if _, exists := out[ip]; exists {
			return nil, fmt.Errorf("duplicate device setting for %s", ip)
		}
		out[ip] = n
	}
	return out, nil
}

func parseRequestTunings(request, probe, retries, bulk string) (map[string]requestTuning, error) {
	out := map[string]requestTuning{}
	for _, spec := range []struct {
		raw, name string
		probe     bool
	}{
		{request, "device-request-timeout", false}, {probe, "device-probe-timeout", true},
	} {
		values, err := parsePollTimeouts(spec.raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec.name, err)
		}
		for ip, duration := range values {
			t := out[ip]
			if spec.probe {
				t.probeTimeout = duration
			} else {
				t.timeout = duration
			}
			out[ip] = t
		}
	}
	values, err := parseDeviceInts(retries, 0, 10)
	if err != nil {
		return nil, fmt.Errorf("device-probe-retries: %w", err)
	}
	for ip, count := range values {
		t := out[ip]
		n := count
		t.probeRetries = &n
		out[ip] = t
	}
	values, err = parseDeviceInts(bulk, 1, 65535)
	if err != nil {
		return nil, fmt.Errorf("device-max-repetitions: %w", err)
	}
	for ip, count := range values {
		t := out[ip]
		t.maxRepetitions = count
		out[ip] = t
	}
	return out, nil
}

func applyRequestTuning(ip string, params *gosnmp.GoSNMP, probeTimeout time.Duration, probeRetries int) (time.Duration, int) {
	t := requestTunings[ip]
	if t.timeout > 0 {
		params.Timeout = t.timeout
	}
	if t.probeTimeout > 0 {
		probeTimeout = t.probeTimeout
	}
	if t.probeRetries != nil {
		probeRetries = *t.probeRetries
	}
	if t.maxRepetitions > 0 {
		params.MaxRepetitions = uint32(t.maxRepetitions)
	}
	return probeTimeout, probeRetries
}
