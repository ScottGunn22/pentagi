package parsers

import (
	"os"
	"testing"

	"pentagi/pkg/ingestion/schema"
)

func TestTwistlock_Minimal(t *testing.T) {
	f, err := os.Open("testdata/twistlock/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := (&TwistlockParser{}).Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceType != schema.SourceTwistlock {
		t.Fatalf("source: %v", got.SourceType)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("containers: %d", len(got.Containers))
	}
	c := got.Containers[0]
	if c.Image != "app" || c.Tag != "v1.2.3" || c.Digest != "sha256:abc123def456" || c.Registry != "registry.acme.internal" {
		t.Fatalf("container fields: %+v", c)
	}
	// 2 vulns + 1 compliance = 3 findings
	if len(got.Findings) != 3 {
		t.Fatalf("findings: %d", len(got.Findings))
	}
	// Check the critical vuln
	var crit *schema.Finding
	for i := range got.Findings {
		if got.Findings[i].CVE == "CVE-2024-67890" {
			crit = &got.Findings[i]
			break
		}
	}
	if crit == nil {
		t.Fatal("expected CVE-2024-67890")
	}
	if crit.Severity != schema.SeverityCritical {
		t.Fatalf("critical sev: %v", crit.Severity)
	}
	if crit.CVSSScore == nil || *crit.CVSSScore != 9.8 {
		t.Fatalf("cvss: %v", crit.CVSSScore)
	}
	if crit.Type != schema.TypeContainerCVE {
		t.Fatalf("type: %v", crit.Type)
	}
	if crit.Target.Kind != schema.TargetContainer {
		t.Fatalf("target kind: %v", crit.Target.Kind)
	}
	// Compliance finding present
	var comp *schema.Finding
	for i := range got.Findings {
		if got.Findings[i].Type == schema.TypeContainerCompliance {
			comp = &got.Findings[i]
			break
		}
	}
	if comp == nil {
		t.Fatal("expected compliance finding")
	}
	if comp.SourceID != "CIS-001" {
		t.Fatalf("compliance source id: %s", comp.SourceID)
	}
}

func TestSplitImage(t *testing.T) {
	cases := []struct {
		full, wantReg, wantImg string
	}{
		{"registry.acme.internal/app", "registry.acme.internal", "app"},
		{"docker.io/library/nginx", "docker.io", "library/nginx"},
		{"nginx", "", "nginx"}, // bare image, no registry
	}
	for _, tc := range cases {
		reg, img := splitImage(tc.full)
		if reg != tc.wantReg || img != tc.wantImg {
			t.Errorf("splitImage(%q) = (%q, %q), want (%q, %q)", tc.full, reg, img, tc.wantReg, tc.wantImg)
		}
	}
}
