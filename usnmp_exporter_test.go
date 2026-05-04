package main

import "testing"

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
