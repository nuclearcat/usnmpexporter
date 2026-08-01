package main

import (
	"errors"
	"testing"
)

// A timeout must degrade the walk mode: a GETBULK reply too large for
// the path never arrives, which looks exactly like an unreachable
// device but is fixed by a smaller window. Degradation is one-way, so
// a later cheaper failure can't promote a device back to a tier that
// is already known broken.
func TestDegradeWalkMode(t *testing.T) {
	const ip = "192.0.2.1"
	defer func() {
		stateMu.Lock()
		delete(walkModeCache, ip)
		stateMu.Unlock()
	}()

	cause := errors.New("request timeout (after 1 retries)")

	degradeWalkMode(ip, walkBulkSmall, "bulk-default", "bulk-small", cause)
	if got := walkModeCache[ip]; got != walkBulkSmall {
		t.Fatalf("after first degrade: got %v, want walkBulkSmall", got)
	}

	degradeWalkMode(ip, walkGetNext, "bulk-small", "getnext", cause)
	if got := walkModeCache[ip]; got != walkGetNext {
		t.Fatalf("after second degrade: got %v, want walkGetNext", got)
	}

	// Never walks back up.
	degradeWalkMode(ip, walkBulkSmall, "bulk-default", "bulk-small", cause)
	if got := walkModeCache[ip]; got != walkGetNext {
		t.Fatalf("after attempted upgrade: got %v, want walkGetNext", got)
	}
}

// isTimeout drives the degradation path, so it has to recognise the
// exact wording gosnmp produces as well as the net package phrasings.
func TestIsTimeout(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("request timeout (after 1 retries)"), true},
		{errors.New("read udp 10.0.0.1:161: i/o timeout"), true},
		{errors.New("dial udp 10.0.0.1:161: connection refused"), true},
		{errors.New("dial udp 10.0.0.1:161: no route to host"), true},
		{errors.New("unmarshal: unknown ASN.1 type 0xff"), false},
	}
	for _, c := range cases {
		if got := isTimeout(c.err); got != c.want {
			t.Errorf("isTimeout(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// IndexLabels (plural) splits the post-base suffix into named labels.
// One label → behaves like the legacy IndexLabel (singular). Two-component
// suffixes split cleanly. More suffix components than labels → last label
// absorbs the tail (preserves data). Fewer components → trailing labels
// emit empty strings so malformed rows surface in PromQL filters.
func TestBuildIndexLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels []string
		suffix string
		want   string
	}{
		{"single label, simple", []string{"index"}, "545", `,index="545"`},
		{"single label, dotted", []string{"index"}, "545.0", `,index="545.0"`},
		{"two labels, exact split", []string{"ifindex", "lane"}, "545.0", `,ifindex="545",lane="0"`},
		{"three labels, Nokia shape", []string{"chassis", "port", "lane"}, "1.1610899520.1", `,chassis="1",port="1610899520",lane="1"`},
		{"more components than labels — tail joins last", []string{"a", "b"}, "1.2.3.4", `,a="1",b="2.3.4"`},
		{"fewer components than labels — trailing empty", []string{"a", "b", "c"}, "1.2", `,a="1",b="2",c=""`},
		{"empty suffix — all labels empty", []string{"a", "b"}, "", `,a="",b=""`},
	}
	for _, c := range cases {
		got := buildIndexLabels(c.labels, c.suffix)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
