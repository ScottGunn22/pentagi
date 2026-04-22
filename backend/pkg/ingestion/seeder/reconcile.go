package seeder

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"pentagi/pkg/database"
	"pentagi/pkg/graphiti"
)

// FindingRepo is the slice of the generated SQLC Queries that the
// reconciler needs. Kept as an interface so tests can inject a fake.
type FindingRepo interface {
	FindingsPendingGraphSync(ctx context.Context, limit int64) ([]database.Finding, error)
	MarkFindingGraphSeeded(ctx context.Context, id int64) error
}

// GroupLookup resolves an engagement ID to its graphiti group_id.
// Typically backed by the engagement repo introduced in Phase 3.
type GroupLookup interface {
	GroupID(ctx context.Context, engagementID int64) (string, error)
}

// Reconciler retries Graphiti writes for findings whose initial seed
// at ingest-time failed (graph_seeded_at IS NULL).
//
// Logger is optional: when non-nil the reconciler emits a Warn entry for
// every per-finding AddMessages failure so operators have a signal that
// Graphiti is misbehaving. Call sites should normally supply one; the
// nil-guarded call path is kept so unit tests can construct a bare
// Reconciler literal without plumbing a logger through.
type Reconciler struct {
	Repo        FindingRepo
	GroupLookup GroupLookup
	Client      EpisodeWriter
	Logger      *logrus.Entry
}

// ReconcileOnce processes up to `limit` pending findings. Findings whose
// AddMessages call fails are left unmarked so a future tick retries them;
// the failure is logged (if Logger is set) but does not surface as an
// error from ReconcileOnce. Only hard repo/lookup failures that prevent
// further progress are returned.
func (r *Reconciler) ReconcileOnce(ctx context.Context, limit int64) error {
	rows, err := r.Repo.FindingsPendingGraphSync(ctx, limit)
	if err != nil {
		return fmt.Errorf("reconciler: list pending: %w", err)
	}
	for _, row := range rows {
		grp, err := r.GroupLookup.GroupID(ctx, row.EngagementID)
		if err != nil {
			return fmt.Errorf("reconciler: group for finding %d: %w", row.ID, err)
		}
		body, _ := json.Marshal(row)
		name := findingEpisodeName(row.TargetRef, row.ID)
		req := graphiti.AddMessagesRequest{
			GroupID: grp,
			Messages: []graphiti.Message{{
				Name:              name,
				Author:            "scanner-ingestion",
				Content:           string(body),
				Timestamp:         time.Now().UTC(),
				SourceDescription: "reconciler",
			}},
		}
		if err := r.Client.AddMessages(ctx, req); err != nil {
			if r.Logger != nil {
				r.Logger.WithFields(logrus.Fields{
					"finding_id":    row.ID,
					"engagement_id": row.EngagementID,
					"target_ref":    row.TargetRef,
				}).WithError(err).Warn("graphiti seed retry failed; will retry next tick")
			}
			continue // leave unseeded; next tick retries
		}
		if err := r.Repo.MarkFindingGraphSeeded(ctx, row.ID); err != nil {
			return fmt.Errorf("reconciler: mark seeded %d: %w", row.ID, err)
		}
	}
	return nil
}

// Compile-time check: the generated SQLC Queries must satisfy FindingRepo.
// If a schema change renames a field, this will fail at build time.
var _ FindingRepo = (*database.Queries)(nil)
