package parsers

import (
	"os"
	"testing"

	"pentagi/pkg/ingestion/schema"
)

func TestBurp_Minimal(t *testing.T) {
	f, err := os.Open("testdata/burp/minimal.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := (&BurpParser{}).Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceType != schema.SourceBurp {
		t.Fatalf("source: %v", got.SourceType)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings: %d", len(got.Findings))
	}
	f0 := got.Findings[0]
	if f0.Severity != schema.SeverityHigh {
		t.Fatalf("severity: %v", f0.Severity)
	}
	if f0.Confidence != schema.ConfidenceCertain {
		t.Fatalf("confidence: %v", f0.Confidence)
	}
	if f0.Target.Kind != schema.TargetWebEndpoint {
		t.Fatalf("target kind: %v", f0.Target.Kind)
	}
	if f0.Title != "SQL injection" {
		t.Fatalf("title: %s", f0.Title)
	}
	if f0.SourceID != "1" {
		t.Fatalf("source id: %s", f0.SourceID)
	}
	// Round-trip JSON for stability
	if len(f0.Evidence) == 0 {
		t.Fatal("empty evidence")
	}
	// WebEndpoints should also be populated
	if len(got.WebEndpoints) != 1 {
		t.Fatalf("web endpoints: %d", len(got.WebEndpoints))
	}
}

func TestBurpConfidence(t *testing.T) {
	cases := map[string]schema.Confidence{
		"Certain":   schema.ConfidenceCertain,
		"certain":   schema.ConfidenceCertain,
		"Firm":      schema.ConfidenceFirm,
		"firm":      schema.ConfidenceFirm,
		"Tentative": schema.ConfidenceTentative,
		"":          schema.ConfidenceTentative, // unknown defaults to tentative
	}
	for in, want := range cases {
		if got := burpConfidence(in); got != want {
			t.Errorf("burpConfidence(%q) = %v, want %v", in, got, want)
		}
	}
}
