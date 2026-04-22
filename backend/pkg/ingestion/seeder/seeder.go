// Package seeder writes parsed scanner bundles into Graphiti as episodes,
// scoped to a per-engagement group_id. Graphiti extracts entities/edges from
// each episode's content automatically; the seeder's job is to produce
// stable, deterministic episode names so that a re-seed with identical
// bundle data is idempotent (Graphiti dedups on name within a group).
package seeder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"pentagi/pkg/database"
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

// SeedInput is the payload passed to Seed. It carries parser-derived entities
// (hosts, containers, endpoints) plus findings that have already been
// persisted to the DB. Findings come from the DB (not the parser bundle) so
// that the episode names can key off the primary-key ID — the only identifier
// the reconciler can reproduce when it retries a failed write.
type SeedInput struct {
	SourceType   schema.ScanSourceType
	ScanDate     *time.Time
	Hosts        []schema.Host
	Containers   []schema.Container
	WebEndpoints []schema.WebEndpoint
	Findings     []database.Finding
}

// Seeder writes scanner ingest results as sequences of graphiti episodes.
type Seeder struct{ client EpisodeWriter }

// NewSeeder returns a Seeder backed by the given EpisodeWriter (typically
// *graphiti.Client).
func NewSeeder(c EpisodeWriter) *Seeder { return &Seeder{client: c} }

// Seed writes the SeedInput as a series of episodes. Episode names are
// derived deterministically so a retry with the same inputs presents the
// same episode keys to Graphiti — its native name+group_id dedup then treats
// the call as a no-op rather than producing duplicate edges.
//
// For findings, the episode name is built by findingEpisodeName(targetRef,
// dbID) so that the reconciler (which only has DB rows) and the synchronous
// seed path agree on the same name.
//
// Per-episode errors are collected and surfaced as a single aggregated
// error via errors.Join so one failing host doesn't abort the rest of the
// input, and callers can later use errors.Is to classify transients.
func (s *Seeder) Seed(ctx context.Context, in SeedInput, groupID string) error {
	if groupID == "" {
		return fmt.Errorf("seeder: groupID required")
	}

	var errs []error
	ts := time.Now().UTC()
	if in.ScanDate != nil {
		ts = in.ScanDate.UTC()
	}
	sourceDesc := fmt.Sprintf("scanner:%s", in.SourceType)

	writeEpisode := func(name string, payload any) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		return s.client.AddMessages(ctx, graphiti.AddMessagesRequest{
			GroupID: groupID,
			Messages: []graphiti.Message{{
				Name:              name,
				Author:            "scanner-ingestion",
				Content:           string(body),
				Timestamp:         ts,
				SourceDescription: sourceDesc,
			}},
		})
	}

	for _, h := range in.Hosts {
		name := fmt.Sprintf("host:%s", h.IP)
		if err := writeEpisode(name, h); err != nil {
			errs = append(errs, fmt.Errorf("host %s: %w", h.IP, err))
		}
	}
	for _, c := range in.Containers {
		name := "container:" + c.TargetRef()
		if err := writeEpisode(name, c); err != nil {
			errs = append(errs, fmt.Errorf("container %s: %w", c.Image, err))
		}
	}
	for _, w := range in.WebEndpoints {
		name := "endpoint:" + w.TargetRef()
		if err := writeEpisode(name, w); err != nil {
			errs = append(errs, fmt.Errorf("endpoint %s: %w", w.URL, err))
		}
	}
	for _, f := range in.Findings {
		if f.TargetRef == "" {
			errs = append(errs, fmt.Errorf("finding %d: empty target_ref", f.ID))
			continue
		}
		name := findingEpisodeName(f.TargetRef, f.ID)
		if err := writeEpisode(name, f); err != nil {
			errs = append(errs, fmt.Errorf("finding %d: %w", f.ID, err))
		}
	}

	return errors.Join(errs...)
}
