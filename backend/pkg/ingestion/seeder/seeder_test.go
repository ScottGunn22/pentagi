package seeder

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"pentagi/pkg/graphiti"
	"pentagi/pkg/ingestion/schema"
)

type fakeClient struct{ calls []graphiti.AddMessagesRequest }

func (f *fakeClient) AddMessages(_ context.Context, req graphiti.AddMessagesRequest) error {
	f.calls = append(f.calls, req)
	return nil
}

func TestSeeder_HappyPath(t *testing.T) {
	c := &fakeClient{}
	s := NewSeeder(c)

	raw, _ := json.Marshal(map[string]string{"source": "nmap"})
	now := time.Now()
	bundle := &schema.ReportBundle{
		SourceType: schema.SourceNmap,
		ScanDate:   &now,
		Hosts: []schema.Host{{IP: "10.1.2.3", Services: []schema.Service{
			{Port: 443, Protocol: "tcp", Name: "https", Product: "nginx", Version: "1.24"},
		}}},
		Findings: []schema.Finding{{
			Type:       schema.TypeVulnerability,
			CVE:        "CVE-2024-1234",
			Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: "ip:10.1.2.3:443/tcp"},
			Title:      "Demo",
			Severity:   schema.SeverityHigh,
			Confidence: schema.ConfidenceCertain,
		}},
		RawEvidence: raw,
	}

	if err := s.Seed(context.Background(), bundle, "eng-abc"); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) == 0 {
		t.Fatal("no episodes written")
	}
	for _, call := range c.calls {
		if call.GroupID != "eng-abc" {
			t.Fatalf("wrong group id: %s", call.GroupID)
		}
		if len(call.Messages) == 0 {
			t.Fatalf("empty messages for call")
		}
	}

	// Check host and finding episodes present.
	var sawHost, sawFinding bool
	for _, call := range c.calls {
		for _, m := range call.Messages {
			switch {
			case m.Name == "host:10.1.2.3":
				sawHost = true
			case m.Name == "finding:ip:10.1.2.3:443/tcp:CVE-2024-1234":
				sawFinding = true
			}
		}
	}
	if !sawHost {
		t.Fatal("expected host episode")
	}
	if !sawFinding {
		t.Fatal("expected finding episode with CVE-derived name")
	}
}

func TestSeeder_RequiresGroupID(t *testing.T) {
	s := NewSeeder(&fakeClient{})
	err := s.Seed(context.Background(), &schema.ReportBundle{}, "")
	if err == nil {
		t.Fatal("expected error on empty groupID")
	}
}
