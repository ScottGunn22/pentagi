package schema

import "testing"

func TestHostTargetRef(t *testing.T) {
	got := (&Host{IP: "10.1.2.3"}).TargetRef(443, "tcp")
	if got != "ip:10.1.2.3:443/tcp" {
		t.Fatalf("want ip:10.1.2.3:443/tcp, got %s", got)
	}
}

func TestContainerTargetRef(t *testing.T) {
	c := Container{Image: "nginx", Digest: "sha256:abc123"}
	if got := c.TargetRef(); got != "img:nginx@sha256:abc123" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestSeverityParse(t *testing.T) {
	cases := map[string]Severity{
		// canonical names, mixed casing
		"Info": SeverityInfo, "LOW": SeverityLow, "Medium": SeverityMedium,
		"high": SeverityHigh, "CRITICAL": SeverityCritical,
		// aliases
		"informational": SeverityInfo, "moderate": SeverityMedium,
		"med": SeverityMedium, "crit": SeverityCritical,
		// numeric (Qualys 1-5 convention)
		"0": SeverityInfo, "1": SeverityLow,
		"2": SeverityMedium, "3": SeverityMedium,
		"4": SeverityHigh, "5": SeverityCritical,
		// whitespace tolerance
		"  High  ": SeverityHigh,
		// fallthrough: empty and unknown both map to info (documents default)
		"":      SeverityInfo,
		"bogus": SeverityInfo,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q)=%v, want %v", in, got, want)
		}
	}
}
