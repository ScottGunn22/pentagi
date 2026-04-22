package parsers

import (
	"errors"
	"os"
	"strings"
	"testing"

	"pentagi/pkg/ingestion/schema"
)

func TestQualys_Minimal(t *testing.T) {
	f, err := os.Open("testdata/qualys/minimal.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := (&QualysParser{}).Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SourceType != schema.SourceQualys {
		t.Fatalf("source: %v", got.SourceType)
	}
	if len(got.Hosts) != 1 {
		t.Fatalf("hosts: %d", len(got.Hosts))
	}
	if got.Hosts[0].IP != "10.1.2.3" {
		t.Fatalf("ip: %s", got.Hosts[0].IP)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings: %d", len(got.Findings))
	}
	f0 := got.Findings[0]
	if f0.CVE != "CVE-2023-48795" {
		t.Fatalf("cve: %s", f0.CVE)
	}
	if f0.Severity != schema.SeverityHigh {
		t.Fatalf("severity (qualys 4 → high): %v", f0.Severity)
	}
	if f0.SourceID != "38170" {
		t.Fatalf("qid: %s", f0.SourceID)
	}
	if f0.CVSSScore == nil || *f0.CVSSScore != 5.9 {
		t.Fatalf("cvss: %v", f0.CVSSScore)
	}
	if f0.Type != schema.TypeVulnerability {
		t.Fatalf("type: %v", f0.Type)
	}
	if f0.Target.Kind != schema.TargetHost {
		t.Fatalf("target kind: %v", f0.Target.Kind)
	}
	// Target ref is "ip:<ip>" for Qualys (no port info in this finding shape)
	if f0.Target.Ref != "ip:10.1.2.3" {
		t.Fatalf("target ref: %s", f0.Target.Ref)
	}
}

func TestQualys_Partial(t *testing.T) {
	// Truncate the closing tags off the happy-path fixture to force a parse error
	// AFTER one valid VULN_INFO has been extracted. The parser must return both
	// the partial bundle (with the one finding) and an ErrPartial-wrapped error.
	raw, err := os.ReadFile("testdata/qualys/minimal.xml")
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(string(raw), "</SCAN_SUMMARY>", "<VULN_INFO><QID><!-- truncated", 1)

	got, err := (&QualysParser{}).Parse(strings.NewReader(corrupt))
	if !errors.Is(err, ErrPartial) {
		t.Fatalf("expected ErrPartial, got %v", err)
	}
	if got == nil || len(got.Findings) == 0 {
		t.Fatal("partial parse should still return the recovered finding(s)")
	}
}

func TestMapQualysSeverity(t *testing.T) {
	cases := map[string]schema.Severity{
		"5":     schema.SeverityCritical,
		"4":     schema.SeverityHigh,
		"3":     schema.SeverityMedium,
		"2":     schema.SeverityLow,
		"1":     schema.SeverityInfo,
		"0":     schema.SeverityInfo,
		"":      schema.SeverityInfo,
		"bogus": schema.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapQualysSeverity(in); got != want {
			t.Errorf("mapQualysSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}
