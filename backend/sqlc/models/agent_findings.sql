-- name: GetOrCreateAgentScanReport :one
-- Returns the scan_report row that holds agent-recorded findings for the
-- given (engagement_id, flow-deterministic sha256) pair, creating one on
-- the first call. Re-entrant tool calls within the same flow share the
-- same scan_report so the findings table stays tidy (one agent-source row
-- per flow, not one per finding).
WITH existing AS (
    SELECT id, engagement_id, source_type, original_filename, storage_uri,
           sha256, scan_date, ingested_at, parser_version, parse_status,
           parse_error, finding_count, uploaded_by
    FROM scan_reports
    WHERE engagement_id = sqlc.arg('engagement_id')::bigint
      AND sha256        = sqlc.arg('sha256')::text
      AND source_type   = 'agent'
    LIMIT 1
), inserted AS (
    INSERT INTO scan_reports (
        engagement_id, source_type, original_filename, storage_uri,
        sha256, parser_version, uploaded_by, parse_status
    )
    SELECT sqlc.arg('engagement_id')::bigint, 'agent',
           sqlc.arg('original_filename')::text,
           sqlc.arg('storage_uri')::text,
           sqlc.arg('sha256')::text, 'agent-v1',
           sqlc.arg('uploaded_by')::bigint, 'succeeded'
    WHERE NOT EXISTS (SELECT 1 FROM existing)
    RETURNING id, engagement_id, source_type, original_filename, storage_uri,
              sha256, scan_date, ingested_at, parser_version, parse_status,
              parse_error, finding_count, uploaded_by
)
SELECT id, engagement_id, source_type, original_filename, storage_uri,
       sha256, scan_date, ingested_at, parser_version, parse_status,
       parse_error, finding_count, uploaded_by
FROM existing
UNION ALL
SELECT id, engagement_id, source_type, original_filename, storage_uri,
       sha256, scan_date, ingested_at, parser_version, parse_status,
       parse_error, finding_count, uploaded_by
FROM inserted;
