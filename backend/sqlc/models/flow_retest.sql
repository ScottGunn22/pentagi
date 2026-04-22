-- Flow retest queries.
--
-- Two tables feed the retest lifecycle:
--   flow_retest_targets — explicit list of finding IDs for
--     targeted_reverify flows (the agent should only examine these).
--   flow_retest_diff — computed diff rows for retest_diff flows
--     (fixed / persistent / new / regressed buckets).
--
-- All queries are flow-scoped; the caller provides the flow ID.

-- name: InsertFlowRetestTarget :exec
INSERT INTO flow_retest_targets (flow_id, finding_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: ListFlowRetestTargets :many
SELECT finding_id FROM flow_retest_targets WHERE flow_id = $1 ORDER BY finding_id;

-- name: InsertFlowRetestDiff :exec
INSERT INTO flow_retest_diff (flow_id, finding_id, diff_state)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: ListFlowRetestDiff :many
SELECT * FROM flow_retest_diff WHERE flow_id = $1 ORDER BY finding_id;

-- name: FindingsFirstSeenBefore :many
-- Findings in the engagement whose first_seen_at is at or before the given
-- cutoff. Used by the retest diff to compute the baseline set.
SELECT * FROM findings
WHERE engagement_id = $1 AND first_seen_at <= $2
ORDER BY id;

-- name: FindingsByEngagement :many
-- All findings for the engagement. Used by the retest diff to compute the
-- current set.
SELECT * FROM findings
WHERE engagement_id = $1
ORDER BY id;

-- name: UpdateFlowEngagement :exec
-- Populate engagement_id, flow_type, baseline_flow_id after the initial
-- CreateFlow insert. CreateFlow has a fixed parameter list (title/model/…)
-- that predates Phase 1; this :exec runs as a follow-up.
UPDATE flows
SET engagement_id    = $2,
    flow_type        = $3,
    baseline_flow_id = $4
WHERE id = $1;
