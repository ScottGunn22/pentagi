-- +goose Up
-- +goose NO TRANSACTION
-- Adds the 'agent' source type used for findings that an LLM agent recorded
-- live during a flow (as opposed to parsed from an uploaded scanner report).
-- Postgres disallows ADD VALUE inside a transaction block, so we disable the
-- implicit tx goose wraps around migrations.
ALTER TYPE SCAN_SOURCE_TYPE ADD VALUE IF NOT EXISTS 'agent';

-- +goose Down
-- +goose StatementBegin
-- Postgres does not support DROP VALUE on an enum. Leaving 'agent' in place
-- on rollback is safe: the application side simply stops producing it.
SELECT 1;
-- +goose StatementEnd
