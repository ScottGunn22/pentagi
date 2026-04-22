-- +goose Up
-- +goose StatementBegin

-- Enums
CREATE TYPE engagement_status    AS ENUM ('active', 'on_hold', 'completed', 'archived');
CREATE TYPE scope_rule_type      AS ENUM ('cidr', 'ip', 'domain', 'domain_glob', 'url_prefix', 'container_image', 'container_registry');
CREATE TYPE scope_direction      AS ENUM ('include', 'exclude');
CREATE TYPE scan_source_type     AS ENUM ('qualys', 'twistlock', 'nmap', 'burp');
CREATE TYPE parse_status         AS ENUM ('pending', 'parsing', 'succeeded', 'failed', 'partial');
CREATE TYPE finding_type         AS ENUM ('vulnerability', 'web_issue', 'exposed_service', 'container_cve', 'container_compliance', 'secret_exposure');
CREATE TYPE target_kind          AS ENUM ('host', 'web_endpoint', 'container');
CREATE TYPE severity_level       AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE finding_confidence   AS ENUM ('certain', 'firm', 'tentative');
CREATE TYPE verification_status  AS ENUM ('unverified', 'verifying', 'confirmed', 'false_positive', 'not_exploitable');
CREATE TYPE flow_type            AS ENUM ('new_test', 'retest_diff', 'targeted_reverify');
CREATE TYPE diff_state           AS ENUM ('fixed', 'persistent', 'new', 'regressed');

-- Engagements
CREATE TABLE engagements (
  id                 BIGINT              PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  name               TEXT                NOT NULL,
  client             TEXT                NOT NULL,
  description        TEXT,
  status             engagement_status   NOT NULL DEFAULT 'active',
  graphiti_group_id  TEXT                NOT NULL UNIQUE,
  starts_at          DATE,
  ends_at            DATE,
  created_by         BIGINT              NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  updated_by         BIGINT              NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  team_id            BIGINT,
  created_at         TIMESTAMPTZ         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         TIMESTAMPTZ         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at         TIMESTAMPTZ,

  CONSTRAINT engagements_name_not_empty   CHECK (length(trim(name)) > 0),
  CONSTRAINT engagements_client_not_empty CHECK (length(trim(client)) > 0)
);
CREATE INDEX engagements_client_idx        ON engagements(client);
CREATE INDEX engagements_status_idx        ON engagements(status) WHERE deleted_at IS NULL;
CREATE INDEX engagements_created_by_idx    ON engagements(created_by);
CREATE INDEX engagements_deleted_at_idx    ON engagements(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TRIGGER update_engagements_modified
  BEFORE UPDATE ON engagements
  FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

-- Scope rules
CREATE TABLE engagement_scope_rules (
  id             BIGINT            PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  engagement_id  BIGINT            NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  rule_type      scope_rule_type   NOT NULL,
  value          TEXT              NOT NULL,
  direction      scope_direction   NOT NULL DEFAULT 'include',
  note           TEXT,
  created_at     TIMESTAMPTZ       NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT engagement_scope_rules_value_not_empty CHECK (length(trim(value)) > 0),
  CONSTRAINT engagement_scope_rules_unique UNIQUE (engagement_id, rule_type, value, direction)
);
CREATE INDEX engagement_scope_rules_engagement_idx ON engagement_scope_rules(engagement_id);

-- Scan reports
CREATE TABLE scan_reports (
  id                 BIGINT              PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  engagement_id      BIGINT              NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  source_type        scan_source_type    NOT NULL,
  original_filename  TEXT                NOT NULL,
  storage_uri        TEXT                NOT NULL,
  sha256             TEXT                NOT NULL,
  scan_date          TIMESTAMPTZ,
  ingested_at        TIMESTAMPTZ         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  parser_version     TEXT                NOT NULL,
  parse_status       parse_status        NOT NULL DEFAULT 'pending',
  parse_error        TEXT,
  finding_count      INT                 NOT NULL DEFAULT 0,
  uploaded_by        BIGINT              NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

  CONSTRAINT scan_reports_unique_sha UNIQUE (engagement_id, sha256)
);
CREATE INDEX scan_reports_engagement_idx    ON scan_reports(engagement_id);
CREATE INDEX scan_reports_parse_status_idx  ON scan_reports(parse_status);
CREATE INDEX scan_reports_source_type_idx   ON scan_reports(source_type);

-- Findings
CREATE TABLE findings (
  id                   BIGINT               PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  engagement_id        BIGINT               NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  scan_report_id       BIGINT               NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
  finding_type         finding_type         NOT NULL,
  target_kind          target_kind          NOT NULL,
  target_ref           TEXT                 NOT NULL,
  title                TEXT                 NOT NULL,
  cve                  TEXT,
  cvss_score           NUMERIC(3,1),
  severity             severity_level       NOT NULL,
  confidence           finding_confidence   NOT NULL,
  source_id            TEXT,
  evidence             JSONB                NOT NULL,
  in_scope             BOOLEAN              NOT NULL,
  verification_status  verification_status  NOT NULL DEFAULT 'unverified',
  verified_by          BIGINT               REFERENCES users(id) ON DELETE SET NULL,
  verified_at          TIMESTAMPTZ,
  verification_notes   TEXT,
  graph_seeded_at      TIMESTAMPTZ,
  first_seen_at        TIMESTAMPTZ          NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at         TIMESTAMPTZ          NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at           TIMESTAMPTZ          NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at           TIMESTAMPTZ          NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT findings_cvss_range CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);
-- Dedup key: the plan normalizes target_ref + source_id|cve per engagement, enforced at the repo level
CREATE UNIQUE INDEX findings_dedup_idx
  ON findings (engagement_id, target_ref, COALESCE(cve, ''), COALESCE(source_id, ''));
CREATE INDEX findings_engagement_severity_idx ON findings(engagement_id, severity);
CREATE INDEX findings_engagement_inscope_idx  ON findings(engagement_id, in_scope);
CREATE INDEX findings_verification_idx        ON findings(engagement_id, verification_status);
CREATE INDEX findings_graph_unsynced_idx      ON findings(graph_seeded_at) WHERE graph_seeded_at IS NULL;

CREATE TRIGGER update_findings_modified
  BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

-- Finding sources (junction: same logical finding from multiple reports)
CREATE TABLE finding_sources (
  finding_id       BIGINT   NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  scan_report_id   BIGINT   NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
  source_evidence  JSONB    NOT NULL,
  PRIMARY KEY (finding_id, scan_report_id)
);
CREATE INDEX finding_sources_report_idx ON finding_sources(scan_report_id);

-- Retest structures
CREATE TABLE flow_retest_targets (
  flow_id     BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  finding_id  BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  PRIMARY KEY (flow_id, finding_id)
);

CREATE TABLE flow_retest_diff (
  flow_id      BIGINT      NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  finding_id   BIGINT      NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  diff_state   diff_state  NOT NULL,
  PRIMARY KEY (flow_id, finding_id)
);

-- Audit trail
CREATE TABLE scope_violations (
  id             BIGINT       PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  flow_id        BIGINT       NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  engagement_id  BIGINT       NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  tool_name      TEXT         NOT NULL,
  target         TEXT         NOT NULL,
  occurred_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX scope_violations_flow_idx        ON scope_violations(flow_id);
CREATE INDEX scope_violations_engagement_idx  ON scope_violations(engagement_id);

-- Flows: extend with engagement linkage
ALTER TABLE flows
  ADD COLUMN engagement_id    BIGINT     REFERENCES engagements(id) ON DELETE SET NULL,
  ADD COLUMN flow_type        flow_type  NOT NULL DEFAULT 'new_test',
  ADD COLUMN baseline_flow_id BIGINT     REFERENCES flows(id) ON DELETE SET NULL;

CREATE INDEX flows_engagement_idx ON flows(engagement_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE flows
  DROP COLUMN IF EXISTS baseline_flow_id,
  DROP COLUMN IF EXISTS flow_type,
  DROP COLUMN IF EXISTS engagement_id;

DROP TABLE IF EXISTS scope_violations;
DROP TABLE IF EXISTS flow_retest_diff;
DROP TABLE IF EXISTS flow_retest_targets;
DROP TABLE IF EXISTS finding_sources;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_reports;
DROP TABLE IF EXISTS engagement_scope_rules;
DROP TABLE IF EXISTS engagements;

DROP TYPE IF EXISTS diff_state;
DROP TYPE IF EXISTS flow_type;
DROP TYPE IF EXISTS verification_status;
DROP TYPE IF EXISTS finding_confidence;
DROP TYPE IF EXISTS severity_level;
DROP TYPE IF EXISTS target_kind;
DROP TYPE IF EXISTS finding_type;
DROP TYPE IF EXISTS parse_status;
DROP TYPE IF EXISTS scan_source_type;
DROP TYPE IF EXISTS scope_direction;
DROP TYPE IF EXISTS scope_rule_type;
DROP TYPE IF EXISTS engagement_status;
-- +goose StatementEnd
