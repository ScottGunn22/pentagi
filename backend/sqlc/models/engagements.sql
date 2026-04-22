-- name: CreateEngagement :one
INSERT INTO engagements (
  name, client, description, graphiti_group_id,
  starts_at, ends_at, created_by, updated_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
RETURNING *;

-- name: GetEngagement :one
SELECT * FROM engagements
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListEngagements :many
SELECT * FROM engagements
WHERE deleted_at IS NULL
  AND (sqlc.narg('status')::ENGAGEMENT_STATUS IS NULL OR status = sqlc.narg('status')::ENGAGEMENT_STATUS)
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateEngagement :one
UPDATE engagements
SET name        = COALESCE(sqlc.narg('name'), name),
    client      = COALESCE(sqlc.narg('client'), client),
    description = COALESCE(sqlc.narg('description'), description),
    status      = COALESCE(sqlc.narg('status'), status),
    starts_at   = COALESCE(sqlc.narg('starts_at'), starts_at),
    ends_at     = COALESCE(sqlc.narg('ends_at'), ends_at),
    updated_by  = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteEngagement :exec
UPDATE engagements SET deleted_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL;

-- name: AddScopeRule :one
INSERT INTO engagement_scope_rules
  (engagement_id, rule_type, value, direction, note)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListScopeRules :many
SELECT * FROM engagement_scope_rules
WHERE engagement_id = $1
ORDER BY id;

-- name: DeleteScopeRule :exec
DELETE FROM engagement_scope_rules
WHERE id = $1 AND engagement_id = $2;

-- name: EngagementFindingStats :one
SELECT
  count(*) FILTER (WHERE severity = 'critical') AS critical_count,
  count(*) FILTER (WHERE severity = 'high')     AS high_count,
  count(*) FILTER (WHERE severity = 'medium')   AS medium_count,
  count(*) FILTER (WHERE severity = 'low')      AS low_count,
  count(*) FILTER (WHERE severity = 'info')     AS info_count,
  count(*) FILTER (WHERE in_scope = false)      AS oos_count,
  count(*) FILTER (WHERE verification_status = 'confirmed') AS confirmed_count
FROM findings WHERE engagement_id = $1;
