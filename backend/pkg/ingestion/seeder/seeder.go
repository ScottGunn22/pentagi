// Package seeder writes parsed scanner bundles into Graphiti as episodes,
// scoped to a per-engagement group_id. Graphiti extracts entities/edges from
// each episode's content automatically; the seeder's job is to produce
// stable, deterministic episode names so that a re-seed with identical
// bundle data is idempotent (Graphiti dedups on name within a group).
package seeder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/graphiti"
	"pentagi/pkg/ingestion/schema"
)

// EpisodeWriter is the slice of the Graphiti client that the seeder needs.
// This matches the real signature on *graphiti.Client — see the compile-time
// assertion below so the interface stays in sync with the real client.
type EpisodeWriter interface {
	AddMessages(ctx context.Context, req graphiti.AddMessagesRequest) error
}

// Compile-time check: the real graphiti client must satisfy EpisodeWriter.
var _ EpisodeWriter = (*graphiti.Client)(nil)

// Seeder writes ReportBundles as sequences of graphiti episodes.
type Seeder struct{ client EpisodeWriter }

// NewSeeder returns a Seeder backed by the given EpisodeWriter (typically
// *graphiti.Client).
func NewSeeder(c EpisodeWriter) *Seeder { return &Seeder{client: c} }

// Seed writes a bundle as a series of episodes. Episode names are derived
// deterministically from content so a re-seed with identical bundle data
// presents the same episode keys to Graphiti — its native dedup logic
// then treats the call as a no-op rather than producing duplicate edges.
//
// Per-episode errors are collected and surfaced as a single aggregated
// error so one failing host doesn't abort the rest of the bundle.
func (s *Seeder) Seed(ctx context.Context, b *schema.ReportBundle, groupID string) error {
	if groupID == "" {
		return fmt.Errorf("seeder: groupID required")
	}
	if b == nil {
		return nil
	}

	var errs []string
	ts := time.Now().UTC()
	if b.ScanDate != nil {
		ts = b.ScanDate.UTC()
	}
	sourceDesc := fmt.Sprintf("scanner:%s", b.SourceType)

	writeEpisode := func(name, body string) error {
		return s.client.AddMessages(ctx, graphiti.AddMessagesRequest{
			GroupID: groupID,
			Messages: []graphiti.Message{{
				Name:              name,
				Author:            "scanner-ingestion",
				Content:           body,
				Timestamp:         ts,
				SourceDescription: sourceDesc,
			}},
		})
	}

	for _, h := range b.Hosts {
		body, _ := json.Marshal(h)
		name := fmt.Sprintf("host:%s", h.IP)
		if err := writeEpisode(name, string(body)); err != nil {
			errs = append(errs, fmt.Sprintf("host %s: %v", h.IP, err))
		}
	}
	for _, c := range b.Containers {
		body, _ := json.Marshal(c)
		name := "container:" + c.TargetRef()
		if err := writeEpisode(name, string(body)); err != nil {
			errs = append(errs, fmt.Sprintf("container %s: %v", c.Image, err))
		}
	}
	for _, w := range b.WebEndpoints {
		body, _ := json.Marshal(w)
		name := "endpoint:" + w.TargetRef()
		if err := writeEpisode(name, string(body)); err != nil {
			errs = append(errs, fmt.Sprintf("endpoint %s: %v", w.URL, err))
		}
	}
	for i, f := range b.Findings {
		body, _ := json.Marshal(f)
		name := fmt.Sprintf("finding:%s:%d", f.Target.Ref, i)
		if f.CVE != "" {
			name = fmt.Sprintf("finding:%s:%s", f.Target.Ref, f.CVE)
		}
		if err := writeEpisode(name, string(body)); err != nil {
			errs = append(errs, fmt.Sprintf("finding %s: %v", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("seeder: %s", strings.Join(errs, "; "))
	}
	return nil
}
