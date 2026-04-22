-- name: UpsertFinding :one
INSERT INTO findings (
  engagement_id, scan_report_id, finding_type, target_kind, target_ref,
  title, cve, cvss_score, severity, confidence, source_id, evidence, in_scope
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (engagement_id, target_ref, COALESCE(cve, ''), COALESCE(source_id, ''))
DO UPDATE SET
  last_seen_at = CURRENT_TIMESTAMP,
  cvss_score   = EXCLUDED.cvss_score,
  severity     = EXCLUDED.severity,
  confidence   = EXCLUDED.confidence,
  title        = EXCLUDED.title,
  evidence     = EXCLUDED.evidence,
  in_scope     = EXCLUDED.in_scope
RETURNING *, (xmax = 0) AS is_new;

-- name: AttachFindingSource :exec
INSERT INTO finding_sources (finding_id, scan_report_id, source_evidence)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: GetFinding :one
SELECT * FROM findings WHERE id = $1;

-- name: ListFindings :many
SELECT * FROM findings
WHERE engagement_id = $1
  AND (sqlc.narg('severity')::SEVERITY_LEVEL          IS NULL OR severity            = sqlc.narg('severity')::SEVERITY_LEVEL)
  AND (sqlc.narg('cve')::text                          IS NULL OR cve                 = sqlc.narg('cve'))
  AND (sqlc.narg('target_kind')::TARGET_KIND           IS NULL OR target_kind         = sqlc.narg('target_kind')::TARGET_KIND)
  AND (sqlc.narg('in_scope')::boolean                  IS NULL OR in_scope            = sqlc.narg('in_scope')::boolean)
  AND (sqlc.narg('verification_status')::VERIFICATION_STATUS IS NULL OR verification_status = sqlc.narg('verification_status')::VERIFICATION_STATUS)
ORDER BY
  CASE severity
    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
    WHEN 'low' THEN 2 ELSE 1
  END DESC,
  cvss_score DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: TopFindingsByCVSS :many
SELECT * FROM findings
WHERE engagement_id = $1 AND in_scope = true
ORDER BY cvss_score DESC NULLS LAST, severity DESC
LIMIT $2;

-- name: FindingsByTargetKind :many
SELECT * FROM findings
WHERE engagement_id = $1 AND target_kind = $2 AND in_scope = true
ORDER BY severity DESC, cvss_score DESC NULLS LAST;

-- name: UpdateFindingVerification :one
UPDATE findings
SET verification_status = $2,
    verification_notes  = $3,
    verified_by         = $4,
    verified_at         = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: MarkFindingGraphSeeded :exec
UPDATE findings SET graph_seeded_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: FindingsPendingGraphSync :many
SELECT * FROM findings WHERE graph_seeded_at IS NULL LIMIT $1;
