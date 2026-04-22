package seeder

import (
	"context"
	"strings"
	"testing"
	"time"

	"pentagi/pkg/database"
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

	now := time.Now()
	in := SeedInput{
		SourceType: schema.SourceNmap,
		ScanDate:   &now,
		Hosts: []schema.Host{{IP: "10.1.2.3", Services: []schema.Service{
			{Port: 443, Protocol: "tcp", Name: "https", Product: "nginx", Version: "1.24"},
		}}},
		Findings: []database.Finding{{
			ID:           42,
			EngagementID: 7,
			TargetRef:    "ip:10.1.2.3:443/tcp",
			Title:        "Demo",
		}},
	}

	if err := s.Seed(context.Background(), in, "eng-abc"); err != nil {
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
	wantFinding := findingEpisodeName("ip:10.1.2.3:443/tcp", 42)
	var sawHost, sawFinding bool
	for _, call := range c.calls {
		for _, m := range call.Messages {
			switch m.Name {
			case "host:10.1.2.3":
				sawHost = true
			case wantFinding:
				sawFinding = true
			}
		}
	}
	if !sawHost {
		t.Fatal("expected host episode")
	}
	if !sawFinding {
		t.Fatalf("expected finding episode %q", wantFinding)
	}
}

func TestSeeder_RequiresGroupID(t *testing.T) {
	s := NewSeeder(&fakeClient{})
	err := s.Seed(context.Background(), SeedInput{}, "")
	if err == nil {
		t.Fatal("expected error on empty groupID")
	}
}

func TestSeeder_SkipsFindingsWithEmptyTargetRef(t *testing.T) {
	c := &fakeClient{}
	s := NewSeeder(c)

	in := SeedInput{
		Findings: []database.Finding{
			{ID: 1, EngagementID: 10, TargetRef: ""},                        // must be skipped
			{ID: 2, EngagementID: 10, TargetRef: "ip:10.0.0.2:80/tcp"},      // must be written
		},
	}

	err := s.Seed(context.Background(), in, "eng-xyz")
	if err == nil {
		t.Fatal("expected aggregated error for finding with empty target_ref")
	}
	if !strings.Contains(err.Error(), "empty target_ref") {
		t.Fatalf("error should mention empty target_ref: %v", err)
	}

	// Only the finding with a target_ref should have been written.
	if len(c.calls) != 1 {
		t.Fatalf("want exactly 1 graphiti call, got %d", len(c.calls))
	}
	want := findingEpisodeName("ip:10.0.0.2:80/tcp", 2)
	got := c.calls[0].Messages[0].Name
	if got != want {
		t.Fatalf("wrong episode name: got %q want %q", got, want)
	}
}
