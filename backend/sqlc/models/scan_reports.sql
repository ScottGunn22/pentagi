-- name: CreateScanReport :one
INSERT INTO scan_reports (
  engagement_id, source_type, original_filename, storage_uri,
  sha256, scan_date, parser_version, uploaded_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetScanReport :one
SELECT * FROM scan_reports WHERE id = $1;

-- name: GetScanReportBySha :one
SELECT * FROM scan_reports
WHERE engagement_id = $1 AND sha256 = $2;

-- name: ListScanReports :many
SELECT * FROM scan_reports
WHERE engagement_id = $1
ORDER BY ingested_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateScanReportStatus :exec
UPDATE scan_reports
SET parse_status = $2, parse_error = $3, finding_count = $4
WHERE id = $1;
