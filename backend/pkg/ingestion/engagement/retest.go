package engagement

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
)

// retestRepo is the narrow slice of database.Querier the retest diff
// computation needs. An interface rather than *database.Queries keeps the
// unit test in retest_test.go free of a real DB.
type retestRepo interface {
	GetFlow(ctx context.Context, id int64) (database.Flow, error)
	FindingsFirstSeenBefore(ctx context.Context, arg database.FindingsFirstSeenBeforeParams) ([]database.Finding, error)
	FindingsByEngagement(ctx context.Context, engagementID int64) ([]database.Finding, error)
}

// ComputeRetestDiff diffs the engagement's findings as of baselineFlow's
// created_at against the current finding set. It returns rows ready for
// InsertFlowRetestDiff — the caller (controller/flow.go) is responsible for
// wrapping them in a transaction with the new flow row.
//
// Set semantics (see spec §5.2):
//
//	baseline   = findings whose first_seen_at <= baselineFlow.created_at
//	current    = all findings now
//	fixed      = baseline \ current  (present at baseline, absent now)
//	persistent = baseline ∩ current  (still there)
//	new        = current \ baseline  (added since baseline)
//	regressed  = persistent ∩ {findings whose verification flipped from
//	             'confirmed' → 'false_positive'/'not_exploitable' before
//	             baseline AND back to non-resolved now}
//
// v1 scope: the regressed bucket stays empty. The data model has the column;
// populating it requires verification history (Phase 15+). Fixed / persistent
// / new are sufficient to tell the agent what changed.
func ComputeRetestDiff(
	ctx context.Context,
	q retestRepo,
	engagementID int64,
	baselineFlowID int64,
) ([]database.InsertFlowRetestDiffParams, error) {
	baselineFlow, err := q.GetFlow(ctx, baselineFlowID)
	if err != nil {
		return nil, fmt.Errorf("retest: fetch baseline flow %d: %w", baselineFlowID, err)
	}
	if !baselineFlow.CreatedAt.Valid {
		return nil, fmt.Errorf("retest: baseline flow %d has no created_at", baselineFlowID)
	}
	// Baseline: every finding first seen at or before the baseline flow's
	// created_at. We use the flow timestamp (not NOW()) so re-running the
	// diff yields the same buckets.
	baseline, err := q.FindingsFirstSeenBefore(ctx, database.FindingsFirstSeenBeforeParams{
		EngagementID: engagementID,
		FirstSeenAt:  baselineFlow.CreatedAt.Time,
	})
	if err != nil {
		return nil, fmt.Errorf("retest: fetch baseline findings: %w", err)
	}
	// Current: everything in the engagement today.
	current, err := q.FindingsByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("retest: fetch current findings: %w", err)
	}

	baselineIDs := make(map[int64]struct{}, len(baseline))
	for _, f := range baseline {
		baselineIDs[f.ID] = struct{}{}
	}
	currentIDs := make(map[int64]struct{}, len(current))
	for _, f := range current {
		currentIDs[f.ID] = struct{}{}
	}

	// Pre-size to the larger of the two sets; worst case every row is new
	// or every row is fixed.
	max := len(baseline)
	if len(current) > max {
		max = len(current)
	}
	out := make([]database.InsertFlowRetestDiffParams, 0, max)

	// fixed: in baseline, missing from current.
	for id := range baselineIDs {
		if _, ok := currentIDs[id]; !ok {
			out = append(out, database.InsertFlowRetestDiffParams{
				FindingID: id,
				DiffState: database.DiffStateFixed,
			})
		}
	}
	// persistent: in both.
	for id := range baselineIDs {
		if _, ok := currentIDs[id]; ok {
			out = append(out, database.InsertFlowRetestDiffParams{
				FindingID: id,
				DiffState: database.DiffStatePersistent,
			})
		}
	}
	// new: in current, not in baseline.
	for id := range currentIDs {
		if _, ok := baselineIDs[id]; !ok {
			out = append(out, database.InsertFlowRetestDiffParams{
				FindingID: id,
				DiffState: database.DiffStateNew,
			})
		}
	}

	// regressed: v1 leaves this empty. The column exists in the schema;
	// the next iteration will populate it when verification history
	// lands.

	return out, nil
}
