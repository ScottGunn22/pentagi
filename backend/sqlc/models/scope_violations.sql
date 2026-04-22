-- name: RecordScopeViolation :exec
INSERT INTO scope_violations (flow_id, engagement_id, tool_name, target)
VALUES ($1, $2, $3, $4);

-- name: ListScopeViolations :many
SELECT * FROM scope_violations
WHERE engagement_id = $1
ORDER BY occurred_at DESC
LIMIT $2 OFFSET $3;
