package parsers

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"pentagi/pkg/ingestion/schema"
)

func TestNmap_Minimal(t *testing.T) {
	f, err := os.Open("testdata/nmap/minimal.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := (&NmapParser{}).Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SourceType != schema.SourceNmap {
		t.Fatalf("source: %v", got.SourceType)
	}
	if len(got.Hosts) != 1 {
		t.Fatalf("hosts: %d", len(got.Hosts))
	}
	h := got.Hosts[0]
	if h.IP != "10.1.2.3" {
		t.Fatalf("ip: %s", h.IP)
	}
	if len(h.Services) != 2 {
		t.Fatalf("services: %d", len(h.Services))
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings: %d", len(got.Findings))
	}
	titles := []string{got.Findings[0].Title, got.Findings[1].Title}
	if !strings.Contains(strings.Join(titles, " "), "OpenSSH 9.6p1") {
		t.Fatalf("expected OpenSSH finding, got %v", titles)
	}
	// Round-trip through JSON for stability smoke
	if _, err := json.Marshal(got); err != nil {
		t.Fatal(err)
	}
}

func TestNmap_EmptyFile(t *testing.T) {
	_, err := (&NmapParser{}).Parse(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestBuildExposedServiceTitle(t *testing.T) {
	cases := []struct {
		in   nmapService
		want string
	}{
		{nmapService{Name: "dns"}, "Exposed service dns"},
		{nmapService{Name: "https", Product: "nginx", Version: "1.24.0"}, "Exposed service https nginx 1.24.0"},
		{nmapService{Name: "ssh", Product: "OpenSSH"}, "Exposed service ssh OpenSSH"},
	}
	for _, tc := range cases {
		if got := buildExposedServiceTitle(tc.in); got != tc.want {
			t.Errorf("buildExposedServiceTitle(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNmapConfidence(t *testing.T) {
	cases := map[string]schema.Confidence{
		"probed":  schema.ConfidenceCertain,
		"table":   schema.ConfidenceTentative,
		"":        schema.ConfidenceFirm,
		"unknown": schema.ConfidenceFirm,
	}
	for in, want := range cases {
		if got := nmapConfidence(in); got != want {
			t.Errorf("nmapConfidence(%q) = %v, want %v", in, got, want)
		}
	}
}
