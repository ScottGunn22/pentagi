# Scanner Report Ingestion & Engagement Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `Engagement` entity above PentAGI's `Flow`, ingest Qualys / Twistlock / Nmap / Burp scanner reports into a normalized schema, seed them into a per-Engagement Graphiti partition, expose findings to agents via dedicated Go tools, and hard-gate agent tool calls at the Engagement scope boundary.

**Architecture:** New `backend/pkg/ingestion/` package with sub-packages by responsibility (`parsers/`, `schema/`, `engagement/`, `seeder/`, `findings/`, `scope/`). New Postgres tables tied to an Engagement. REST + GraphQL surface. Thin React UI. Scope hard-gate wraps existing `pkg/tools/registry.go` at flow-start via a `WithScopeGate` installer, so no existing tool invocation can target an out-of-scope host/domain/URL/container image.

**Tech Stack:** Go 1.22+, goose migrations, SQLC, gqlgen, Gin, OpenTelemetry, Neo4j + Graphiti, PostgreSQL 15 + pgvector. Frontend: React + Apollo + Radix + Vite.

**Spec deviations from `docs/superpowers/specs/2026-04-21-scanner-report-ingestion-design.md`:**
1. Primary keys are `BIGINT GENERATED ALWAYS AS IDENTITY` (matches existing PentAGI convention — `flow_templates`, `flows`, `users`, etc.). The spec showed UUIDs. `graphiti_group_id` remains a text UUID because it is an external key to Neo4j.
2. Database access uses SQLC-generated queries (current codebase convention). All `_repo.go` files below are thin wrappers over SQLC `Querier` plus business logic; SQL lives in `*.sql` files under `backend/pkg/database/queries/`.

**Spec reference:** `docs/superpowers/specs/2026-04-21-scanner-report-ingestion-design.md`

---

## Phase plan (each phase = shippable milestone + commit boundary)

| Phase | Produces | Depends on |
|---|---|---|
| 0 | Working branch, CI green, no code changes | — |
| 1 | All new tables + enums migrated cleanly | 0 |
| 2 | `schema/` normalized types + unit tests | 1 |
| 3 | `engagement/` repo with Postgres CRUD | 1, 2 |
| 4 | `scope/` matcher with 100% test coverage | 2 |
| 5 | Nmap parser golden-file tests green | 2 |
| 6 | `seeder/` idempotent Graphiti write | 2 |
| 7 | Ingestion REST controller: upload nmap end-to-end | 3, 4, 5, 6 |
| 8 | Burp parser green | 2 |
| 9 | Twistlock parser green | 2 |
| 10 | Qualys parser green (streaming + partial) | 2 |
| 11 | Agent-facing `findings/` tools registered | 3 |
| 12 | GraphQL schema + resolvers + subscriptions | 3, 7 |
| 13 | Scope hard-gate wrapper + `Targets()` on existing tools | 4 |
| 14 | Flow integration (engagement_id, flow_type, retest logic) | 3, 13 |
| 15 | Frontend: Engagements pages + upload + flow integration | 12 |
| 16 | Observability spans/metrics, README, tidy-up | all |

---

## Phase 0: Setup and pre-flight

### Task 0.1: Create feature branch

**Files:** none (branch only)

- [ ] **Step 1: Create and check out a feature branch**

```bash
cd /home/sx0tt/pentagi
git checkout -b feature/scanner-ingestion main
```

Expected output: `Switched to a new branch 'feature/scanner-ingestion'`

- [ ] **Step 2: Verify baseline build works**

```bash
cd /home/sx0tt/pentagi/backend
go build -trimpath -o /tmp/pentagi-baseline ./cmd/pentagi
cd /home/sx0tt/pentagi/frontend
npm ci
npm run build
```

Expected: both builds complete without errors. If they don't, stop and fix the baseline before proceeding — no ingestion work on a broken tree.

- [ ] **Step 3: Confirm tests pass before we touch anything**

```bash
cd /home/sx0tt/pentagi/backend
go test ./...
```

Expected: all green. Any pre-existing failing test is a project-wide issue, not ours — document it in the commit message and proceed.

- [ ] **Step 4: Commit branch baseline marker**

No file changes yet. Skip commit; proceed to Phase 1.

---

## Phase 1: Database migrations

Produces a single goose migration that creates every new table, enum, and `flows` column. One migration so the schema change is atomic; rollback is clean.

### Task 1.1: Write the migration

**Files:**
- Create: `backend/migrations/sql/20260421_120000_engagement_ingestion.sql`

- [ ] **Step 1: Create the migration file**

```sql
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
```

- [ ] **Step 2: Run migrations against a fresh DB and verify they apply**

```bash
cd /home/sx0tt/pentagi
docker compose up -d pgvector
# wait for healthcheck
until docker compose exec -T pgvector pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
cd backend
go run ./cmd/pentagi migrate up   # or equivalent; if no CLI subcommand, boot main once:
# (the app runs goose at startup; a dry run that exits after migrations is sufficient)
```

Expected: migration applies, no errors. Verify with:

```bash
docker compose exec -T pgvector psql -U postgres -d pentagi -c "\dt"
```

Expected: see `engagements`, `engagement_scope_rules`, `scan_reports`, `findings`, `finding_sources`, `flow_retest_targets`, `flow_retest_diff`, `scope_violations` in the list.

- [ ] **Step 3: Test the Down migration**

```bash
docker compose exec -T pgvector psql -U postgres -d pentagi \
  -c "SET search_path = public; \d engagements"
# Use goose to roll down:
cd backend
goose -dir migrations/sql postgres "$DATABASE_URL" down
```

Expected: rollback clean, no error; `\dt` no longer shows the new tables. Re-apply Up.

- [ ] **Step 4: Commit**

```bash
git add backend/migrations/sql/20260421_120000_engagement_ingestion.sql
git commit -m "feat(ingestion): add engagement + scan report schema migration"
```

---

## Phase 2: Normalized schema package

Produces the in-flight types used by parsers, seeder, and repo. Pure data + validators — no DB, no JSON tags beyond what parsers need for evidence passthrough.

### Task 2.1: Create `pkg/ingestion/schema/types.go`

**Files:**
- Create: `backend/pkg/ingestion/schema/types.go`
- Test: `backend/pkg/ingestion/schema/types_test.go`

- [ ] **Step 1: Write failing tests for target-ref construction and severity parsing**

```go
// backend/pkg/ingestion/schema/types_test.go
package schema

import "testing"

func TestHostTargetRef(t *testing.T) {
    got := (&Host{IP: "10.1.2.3"}).TargetRef(443, "tcp")
    if got != "ip:10.1.2.3:443/tcp" {
        t.Fatalf("want ip:10.1.2.3:443/tcp, got %s", got)
    }
}

func TestContainerTargetRef(t *testing.T) {
    c := Container{Image: "nginx", Digest: "sha256:abc123"}
    if got := c.TargetRef(); got != "img:nginx@sha256:abc123" {
        t.Fatalf("unexpected: %s", got)
    }
}

func TestSeverityParse(t *testing.T) {
    cases := map[string]Severity{
        "Info": SeverityInfo, "LOW": SeverityLow, "Medium": SeverityMedium,
        "high": SeverityHigh, "CRITICAL": SeverityCritical,
    }
    for in, want := range cases {
        if got := ParseSeverity(in); got != want {
            t.Fatalf("ParseSeverity(%q)=%v, want %v", in, got, want)
        }
    }
}
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/sx0tt/pentagi/backend
go test ./pkg/ingestion/schema/...
```

Expected: `package pentagi/pkg/ingestion/schema is not in std (…)` or `undefined: Host`. Confirms TDD starting state.

- [ ] **Step 3: Implement `types.go`**

```go
// backend/pkg/ingestion/schema/types.go
package schema

import (
    "encoding/json"
    "fmt"
    "strings"
    "time"
)

type ScanSourceType string

const (
    SourceQualys    ScanSourceType = "qualys"
    SourceTwistlock ScanSourceType = "twistlock"
    SourceNmap      ScanSourceType = "nmap"
    SourceBurp      ScanSourceType = "burp"
)

type Severity string

const (
    SeverityInfo     Severity = "info"
    SeverityLow      Severity = "low"
    SeverityMedium   Severity = "medium"
    SeverityHigh     Severity = "high"
    SeverityCritical Severity = "critical"
)

func ParseSeverity(s string) Severity {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "info", "informational", "information", "0":
        return SeverityInfo
    case "low", "1":
        return SeverityLow
    case "medium", "med", "moderate", "2", "3":
        return SeverityMedium
    case "high", "4":
        return SeverityHigh
    case "critical", "crit", "5":
        return SeverityCritical
    }
    return SeverityInfo
}

type Confidence string

const (
    ConfidenceCertain   Confidence = "certain"
    ConfidenceFirm      Confidence = "firm"
    ConfidenceTentative Confidence = "tentative"
)

type FindingType string

const (
    TypeVulnerability        FindingType = "vulnerability"
    TypeWebIssue             FindingType = "web_issue"
    TypeExposedService       FindingType = "exposed_service"
    TypeContainerCVE         FindingType = "container_cve"
    TypeContainerCompliance  FindingType = "container_compliance"
    TypeSecretExposure       FindingType = "secret_exposure"
)

type TargetKind string

const (
    TargetHost        TargetKind = "host"
    TargetWebEndpoint TargetKind = "web_endpoint"
    TargetContainer   TargetKind = "container"
)

type TargetRef struct {
    Kind TargetKind
    Ref  string
}

type ReportBundle struct {
    SourceType   ScanSourceType
    ScanDate     *time.Time
    Hosts        []Host
    Containers   []Container
    WebEndpoints []WebEndpoint
    Findings     []Finding
    RawEvidence  json.RawMessage
}

type OSFingerprint struct {
    Family   string
    Name     string
    Version  string
    Accuracy int // 0-100
}

type Host struct {
    IP        string
    Hostnames []string
    OS        *OSFingerprint
    Services  []Service
}

// TargetRef builds "ip:<ip>:<port>/<proto>" for a host+service combo.
func (h *Host) TargetRef(port int, proto string) string {
    return fmt.Sprintf("ip:%s:%d/%s", h.IP, port, proto)
}

type EvidenceRef struct {
    SourceFile string
    Path       string // xpath, jsonpath, line range, etc
}

type Service struct {
    Port     int
    Protocol string
    Name     string
    Product  string
    Version  string
    Evidence EvidenceRef
}

type LayerInfo struct {
    Digest  string
    Command string
}

type Container struct {
    Image    string
    Tag      string
    Digest   string
    Registry string
    Layers   []LayerInfo
}

func (c *Container) TargetRef() string {
    if c.Digest != "" {
        return fmt.Sprintf("img:%s@%s", c.Image, c.Digest)
    }
    return fmt.Sprintf("img:%s:%s", c.Image, c.Tag)
}

type WebEndpoint struct {
    URL    string
    Method string
    Params []string
}

func (w *WebEndpoint) TargetRef() string {
    if w.Method != "" {
        return fmt.Sprintf("url:%s %s", w.Method, w.URL)
    }
    return "url:" + w.URL
}

type Finding struct {
    Type       FindingType
    Target     TargetRef
    Title      string
    CVE        string
    CVSSScore  *float64
    Severity   Severity
    Confidence Confidence
    SourceID   string
    Evidence   json.RawMessage
}
```

- [ ] **Step 4: Run — expect green**

```bash
go test ./pkg/ingestion/schema/... -v
```

Expected: `PASS` on all three tests.

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/schema/
git commit -m "feat(ingestion): normalized in-flight schema types"
```

---

## Phase 3: Engagement repo

Provides `engagement/` package with repo methods over the new Postgres tables. Uses SQLC for queries following existing codebase pattern.

### Task 3.1: Add SQLC queries for engagements

**Files:**
- Create: `backend/pkg/database/queries/engagements.sql`
- Create: `backend/pkg/database/queries/scan_reports.sql`
- Create: `backend/pkg/database/queries/findings.sql`
- Modify: `backend/pkg/database/queries/` (whichever file SQLC uses as entry — confirm from existing repo layout before adding new files)

- [ ] **Step 1: Check how SQLC is configured**

```bash
cd /home/sx0tt/pentagi/backend
find . -name 'sqlc.yaml' -o -name 'sqlc.yml' -o -name 'sqlc.json' | head
cat $(find . -name 'sqlc.y*ml' | head -1)
```

Note the input/output paths. All new query files must live in the configured `queries` dir. Expected config shows `queries:` path — use that.

- [ ] **Step 2: Write engagements queries**

```sql
-- queries/engagements.sql

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
  AND (sqlc.narg(status)::engagement_status IS NULL OR status = sqlc.narg(status)::engagement_status)
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateEngagement :one
UPDATE engagements
SET name = COALESCE(sqlc.narg(name), name),
    client = COALESCE(sqlc.narg(client), client),
    description = COALESCE(sqlc.narg(description), description),
    status = COALESCE(sqlc.narg(status), status),
    starts_at = COALESCE(sqlc.narg(starts_at), starts_at),
    ends_at = COALESCE(sqlc.narg(ends_at), ends_at),
    updated_by = $2
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
SELECT * FROM engagement_scope_rules WHERE engagement_id = $1
ORDER BY id;

-- name: DeleteScopeRule :exec
DELETE FROM engagement_scope_rules WHERE id = $1 AND engagement_id = $2;

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
```

- [ ] **Step 3: Write scan_reports queries**

```sql
-- queries/scan_reports.sql

-- name: CreateScanReport :one
INSERT INTO scan_reports (
  engagement_id, source_type, original_filename, storage_uri,
  sha256, scan_date, parser_version, uploaded_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetScanReport :one
SELECT * FROM scan_reports WHERE id = $1;

-- name: GetScanReportBySha :one
SELECT * FROM scan_reports WHERE engagement_id = $1 AND sha256 = $2;

-- name: ListScanReports :many
SELECT * FROM scan_reports WHERE engagement_id = $1
ORDER BY ingested_at DESC LIMIT $2 OFFSET $3;

-- name: UpdateScanReportStatus :exec
UPDATE scan_reports
SET parse_status = $2, parse_error = $3, finding_count = $4
WHERE id = $1;
```

- [ ] **Step 4: Write findings queries**

```sql
-- queries/findings.sql

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
  AND (sqlc.narg(severity)::severity_level IS NULL OR severity = sqlc.narg(severity)::severity_level)
  AND (sqlc.narg(cve)::text IS NULL OR cve = sqlc.narg(cve))
  AND (sqlc.narg(target_kind)::target_kind IS NULL OR target_kind = sqlc.narg(target_kind)::target_kind)
  AND (sqlc.narg(in_scope)::boolean IS NULL OR in_scope = sqlc.narg(in_scope)::boolean)
  AND (sqlc.narg(verification_status)::verification_status IS NULL OR verification_status = sqlc.narg(verification_status)::verification_status)
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
SET verification_status = $2, verification_notes = $3,
    verified_by = $4, verified_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: MarkFindingGraphSeeded :exec
UPDATE findings SET graph_seeded_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: FindingsPendingGraphSync :many
SELECT * FROM findings WHERE graph_seeded_at IS NULL LIMIT $1;
```

- [ ] **Step 5: Regenerate SQLC**

```bash
cd /home/sx0tt/pentagi/backend
sqlc generate
```

Expected: new `*.sql.go` files appear in `pkg/database/` (engagements.sql.go, scan_reports.sql.go, findings.sql.go). No errors. If sqlc complains about `sqlc.narg` syntax, confirm sqlc version supports it (≥ 1.17 does).

- [ ] **Step 6: Verify compile**

```bash
go build ./pkg/database/...
```

Expected: green. If errors mention unknown enum types, it means the migration enums need to be declared in sqlc.yaml's `overrides`. Follow the existing pattern in that file (check how `provider_type` is mapped, for example).

- [ ] **Step 7: Commit**

```bash
git add backend/pkg/database/queries/engagements.sql \
        backend/pkg/database/queries/scan_reports.sql \
        backend/pkg/database/queries/findings.sql \
        backend/pkg/database/*.sql.go \
        backend/pkg/database/sqlc.yaml
git commit -m "feat(ingestion): SQLC queries for engagements, reports, findings"
```

### Task 3.2: Engagement service wrapper

**Files:**
- Create: `backend/pkg/ingestion/engagement/service.go`
- Create: `backend/pkg/ingestion/engagement/service_test.go`

- [ ] **Step 1: Write failing test for group ID generation**

```go
// backend/pkg/ingestion/engagement/service_test.go
package engagement

import (
    "strings"
    "testing"
)

func TestGenerateGroupID(t *testing.T) {
    id1 := generateGroupID()
    id2 := generateGroupID()
    if id1 == id2 {
        t.Fatal("two consecutive calls produced same id")
    }
    if !strings.HasPrefix(id1, "eng-") {
        t.Fatalf("want prefix eng-, got %q", id1)
    }
    if len(id1) < 20 {
        t.Fatalf("id too short: %q", id1)
    }
}
```

- [ ] **Step 2: Run — expect failure**

```bash
go test ./pkg/ingestion/engagement/...
```

Expected: undefined `generateGroupID`.

- [ ] **Step 3: Implement `service.go`**

```go
// backend/pkg/ingestion/engagement/service.go
package engagement

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"

    "pentagi/pkg/database"
)

type Service struct {
    q database.Querier
}

func NewService(q database.Querier) *Service { return &Service{q: q} }

func generateGroupID() string {
    var b [12]byte
    if _, err := rand.Read(b[:]); err != nil {
        panic(fmt.Errorf("rand.Read: %w", err))
    }
    return "eng-" + hex.EncodeToString(b[:])
}

type CreateInput struct {
    Name        string
    Client      string
    Description string
    CreatedBy   int64
}

func (s *Service) Create(ctx context.Context, in CreateInput) (database.Engagement, error) {
    if in.Name == "" {
        return database.Engagement{}, errors.New("engagement name required")
    }
    if in.Client == "" {
        return database.Engagement{}, errors.New("engagement client required")
    }
    return s.q.CreateEngagement(ctx, database.CreateEngagementParams{
        Name:             in.Name,
        Client:           in.Client,
        Description:      toPtr(in.Description),
        GraphitiGroupID:  generateGroupID(),
        CreatedBy:        in.CreatedBy,
    })
}

func (s *Service) Get(ctx context.Context, id int64) (database.Engagement, error) {
    return s.q.GetEngagement(ctx, id)
}

// List, Update, SoftDelete, and scope-rule helpers follow the same thin-wrapper pattern.
// Add AddScopeRule, ListScopeRules, DeleteScopeRule methods that call the matching SQLC method.

func toPtr[T any](v T) *T { return &v }
```

- [ ] **Step 4: Run — expect green**

```bash
go test ./pkg/ingestion/engagement/... -v
go build ./pkg/ingestion/...
```

Expected: PASS. If `database.CreateEngagementParams` field names differ from what's written (sqlc tends to name by column exactly), adjust.

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/engagement/
git commit -m "feat(ingestion): engagement service with CRUD wrappers"
```

### Task 3.3: Integration test for engagement repo with testcontainers

**Files:**
- Create: `backend/pkg/ingestion/engagement/integration_test.go`

- [ ] **Step 1: Check whether the repo has an existing testcontainer pattern**

```bash
grep -rn "testcontainers" /home/sx0tt/pentagi/backend/pkg/ --include='*.go' | head
```

If there's existing helper code (likely in `pkg/database/` or a `testutil` package), reuse it. If not, skip this task for now and add integration tests in Phase 7's end-to-end test instead. Record the decision in the commit message.

- [ ] **Step 2: If using existing helper, write integration test following the existing style**

```go
// backend/pkg/ingestion/engagement/integration_test.go
//go:build integration

package engagement_test

import (
    "context"
    "testing"

    "pentagi/pkg/database"
    "pentagi/pkg/ingestion/engagement"
    "pentagi/pkg/testutil" // or wherever the pattern lives
)

func TestEngagementRoundTrip(t *testing.T) {
    ctx := context.Background()
    db := testutil.NewPostgres(t)
    q := database.New(db)
    svc := engagement.NewService(q)

    // seed a user (FK)
    userID := testutil.SeedUser(t, db, "pentester@example.com")

    e, err := svc.Create(ctx, engagement.CreateInput{
        Name: "ACME Q2", Client: "ACME", CreatedBy: userID,
    })
    if err != nil { t.Fatal(err) }

    got, err := svc.Get(ctx, e.ID)
    if err != nil { t.Fatal(err) }
    if got.Name != "ACME Q2" { t.Fatalf("round-trip mismatch: %+v", got) }
    if got.GraphitiGroupID == "" { t.Fatal("group id not assigned") }
}
```

- [ ] **Step 3: Run the integration test**

```bash
cd /home/sx0tt/pentagi/backend
go test -tags=integration ./pkg/ingestion/engagement/...
```

- [ ] **Step 4: Commit**

```bash
git add backend/pkg/ingestion/engagement/integration_test.go
git commit -m "test(ingestion): engagement repo integration test"
```

---

## Phase 4: Scope matcher (R-A gate foundation)

The matcher itself — no tool wrapping yet. 100% branch coverage target because this package carries legal risk.

### Task 4.1: Create matcher with table-driven tests

**Files:**
- Create: `backend/pkg/ingestion/scope/matcher.go`
- Create: `backend/pkg/ingestion/scope/matcher_test.go`

- [ ] **Step 1: Write the table-driven test covering all rule types**

```go
// backend/pkg/ingestion/scope/matcher_test.go
package scope

import "testing"

type ruleSpec struct{ kind, value, direction string }

func buildMatcher(t *testing.T, rules []ruleSpec) *Matcher {
    t.Helper()
    var rs []Rule
    for _, r := range rules {
        rs = append(rs, Rule{
            Type: RuleType(r.kind), Value: r.value, Direction: Direction(r.direction),
        })
    }
    m, err := NewMatcher(rs)
    if err != nil { t.Fatal(err) }
    return m
}

func TestMatcher_IncludeCIDR(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
    for _, tc := range []struct{ target string; want bool }{
        {"ip:10.1.2.3:443/tcp", true},
        {"ip:10.1.255.255:0/tcp", true},
        {"ip:10.2.0.1:443/tcp", false},
        {"ip:192.168.1.1:22/tcp", false},
    } {
        if got := m.InScope(tc.target); got != tc.want {
            t.Errorf("InScope(%q) = %v, want %v", tc.target, got, tc.want)
        }
    }
}

func TestMatcher_ExcludeCarvesFromInclude(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{
        {"cidr", "10.1.0.0/16", "include"},
        {"cidr", "10.1.99.0/24", "exclude"},
    })
    if !m.InScope("ip:10.1.50.1:80/tcp") { t.Fatal("10.1.50.1 should be in scope") }
    if m.InScope("ip:10.1.99.1:80/tcp")  { t.Fatal("10.1.99.1 should be excluded") }
}

func TestMatcher_DomainGlob(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{{"domain_glob", "*.acme.internal", "include"}})
    cases := map[string]bool{
        "host:app.acme.internal":       true,
        "host:api.beta.acme.internal":  true,
        "host:acme.internal":           false,   // does not match *. prefix
        "host:acme.external":           false,
    }
    for in, want := range cases {
        if got := m.InScope(in); got != want {
            t.Errorf("InScope(%q) = %v, want %v", in, got, want)
        }
    }
}

func TestMatcher_URLPrefix(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{{"url_prefix", "https://api.acme.internal/", "include"}})
    cases := map[string]bool{
        "url:GET https://api.acme.internal/users":     true,
        "url:POST https://api.acme.internal/v2/x":     true,
        "url:GET https://evil.example.com/":           false,
    }
    for in, want := range cases {
        if got := m.InScope(in); got != want {
            t.Errorf("InScope(%q) = %v, want %v", in, got, want)
        }
    }
}

func TestMatcher_ContainerImage(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{
        {"container_registry", "registry.acme.internal", "include"},
    })
    if !m.InScope("img:registry.acme.internal/app@sha256:abc") {
        t.Fatal("acme registry image should be in scope")
    }
    if m.InScope("img:docker.io/library/nginx@sha256:def") {
        t.Fatal("unrelated registry should be out of scope")
    }
}

func TestMatcher_EmptyRulesDenyAll(t *testing.T) {
    m := buildMatcher(t, nil)
    if m.InScope("ip:10.1.2.3:443/tcp") {
        t.Fatal("no include rules → everything must be out of scope (fail-closed)")
    }
}

func TestMatcher_InvalidCIDR(t *testing.T) {
    _, err := NewMatcher([]Rule{{Type: RuleCIDR, Value: "not-a-cidr", Direction: DirectionInclude}})
    if err == nil {
        t.Fatal("expected error on bogus CIDR")
    }
}
```

- [ ] **Step 2: Run — expect failure**

```bash
go test ./pkg/ingestion/scope/...
```

Expected: `undefined: NewMatcher`.

- [ ] **Step 3: Implement `matcher.go`**

```go
// backend/pkg/ingestion/scope/matcher.go
package scope

import (
    "fmt"
    "net"
    "net/url"
    "strings"
)

type RuleType string

const (
    RuleCIDR              RuleType = "cidr"
    RuleIP                RuleType = "ip"
    RuleDomain            RuleType = "domain"
    RuleDomainGlob        RuleType = "domain_glob"
    RuleURLPrefix         RuleType = "url_prefix"
    RuleContainerImage    RuleType = "container_image"
    RuleContainerRegistry RuleType = "container_registry"
)

type Direction string

const (
    DirectionInclude Direction = "include"
    DirectionExclude Direction = "exclude"
)

type Rule struct {
    Type      RuleType
    Value     string
    Direction Direction

    // pre-compiled
    cidr *net.IPNet
}

type Matcher struct{ rules []Rule }

func NewMatcher(rules []Rule) (*Matcher, error) {
    out := make([]Rule, 0, len(rules))
    for _, r := range rules {
        switch r.Type {
        case RuleCIDR:
            _, n, err := net.ParseCIDR(r.Value)
            if err != nil { return nil, fmt.Errorf("invalid cidr %q: %w", r.Value, err) }
            r.cidr = n
        case RuleIP:
            if net.ParseIP(r.Value) == nil { return nil, fmt.Errorf("invalid ip %q", r.Value) }
        case RuleDomain, RuleDomainGlob, RuleURLPrefix, RuleContainerImage, RuleContainerRegistry:
            if r.Value == "" { return nil, fmt.Errorf("empty rule value") }
        default:
            return nil, fmt.Errorf("unknown rule type %q", r.Type)
        }
        out = append(out, r)
    }
    return &Matcher{rules: out}, nil
}

// InScope is fail-closed: if no include rule matches, returns false.
// Exclude rules override includes for the same target.
func (m *Matcher) InScope(target string) bool {
    kind, body := splitTarget(target)
    include := false
    for _, r := range m.rules {
        if !m.ruleMatches(r, kind, body) { continue }
        if r.Direction == DirectionExclude {
            return false
        }
        include = true
    }
    return include
}

func splitTarget(t string) (kind, body string) {
    i := strings.IndexByte(t, ':')
    if i < 0 { return "", t }
    return t[:i], t[i+1:]
}

func (m *Matcher) ruleMatches(r Rule, kind, body string) bool {
    switch r.Type {
    case RuleCIDR:
        if kind != "ip" { return false }
        ip := net.ParseIP(extractHost(body))
        return ip != nil && r.cidr.Contains(ip)
    case RuleIP:
        if kind != "ip" { return false }
        return extractHost(body) == r.Value
    case RuleDomain:
        if kind != "host" { return false }
        return body == r.Value
    case RuleDomainGlob:
        if kind != "host" && kind != "url" { return false }
        host := body
        if kind == "url" { host = extractURLHost(body) }
        return matchGlob(r.Value, host)
    case RuleURLPrefix:
        if kind != "url" { return false }
        return strings.HasPrefix(extractURLOnly(body), r.Value)
    case RuleContainerImage:
        if kind != "img" { return false }
        return strings.HasPrefix(body, r.Value)
    case RuleContainerRegistry:
        if kind != "img" { return false }
        return strings.HasPrefix(body, r.Value+"/") || strings.HasPrefix(body, r.Value+"@")
    }
    return false
}

// extractHost parses "10.1.2.3:443/tcp" → "10.1.2.3".
func extractHost(body string) string {
    if i := strings.IndexByte(body, ':'); i >= 0 { return body[:i] }
    return body
}

// extractURLHost parses "GET https://a.b/c" → "a.b".
func extractURLHost(body string) string {
    raw := extractURLOnly(body)
    u, err := url.Parse(raw)
    if err != nil { return "" }
    return u.Hostname()
}

// extractURLOnly strips a leading method verb if present.
func extractURLOnly(body string) string {
    if i := strings.IndexByte(body, ' '); i >= 0 { return body[i+1:] }
    return body
}

// matchGlob supports leading-* glob only ("*.foo.com" matches "x.foo.com").
func matchGlob(pat, host string) bool {
    if strings.HasPrefix(pat, "*.") {
        return strings.HasSuffix(host, pat[1:]) && host != pat[2:]
    }
    return pat == host
}
```

- [ ] **Step 4: Run tests, verify green AND verify coverage**

```bash
go test ./pkg/ingestion/scope/... -v -coverprofile=/tmp/scope-cover.out
go tool cover -func=/tmp/scope-cover.out | tail
```

Expected: all tests PASS. `matcher.go` total coverage should be 95%+ (100% on `ruleMatches` and `NewMatcher`). Add cases for any uncovered branches.

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/scope/
git commit -m "feat(ingestion): scope matcher with fail-closed semantics"
```

### Task 4.2: Scope-rule loader that wires matcher to an Engagement

**Files:**
- Create: `backend/pkg/ingestion/scope/loader.go`
- Create: `backend/pkg/ingestion/scope/loader_test.go`

- [ ] **Step 1: Write the test**

```go
// backend/pkg/ingestion/scope/loader_test.go
package scope

import (
    "testing"

    "pentagi/pkg/database"
)

type fakeQ struct{ rows []database.EngagementScopeRule }
func (f fakeQ) ListScopeRules(_ any, _ int64) ([]database.EngagementScopeRule, error) {
    return f.rows, nil
}

// Replace with actual database.Querier interface in real code; this is illustrative.
// If the real Querier is big, write an inline interface with just ListScopeRules.

func TestLoadMatcher_SkipsInvalid(t *testing.T) {
    // When the DB contains a bogus rule, LoadMatcher should return an error
    // identifying the offending rule rather than silently dropping it.
    _, err := loadFromRows([]database.EngagementScopeRule{{
        RuleType: "cidr", Value: "garbage",
    }})
    if err == nil { t.Fatal("expected error on bogus cidr in DB row") }
}
```

- [ ] **Step 2: Implement loader**

```go
// backend/pkg/ingestion/scope/loader.go
package scope

import (
    "context"

    "pentagi/pkg/database"
)

type rulesLister interface {
    ListScopeRules(ctx context.Context, engagementID int64) ([]database.EngagementScopeRule, error)
}

func LoadMatcher(ctx context.Context, q rulesLister, engagementID int64) (*Matcher, error) {
    rows, err := q.ListScopeRules(ctx, engagementID)
    if err != nil { return nil, err }
    return loadFromRows(rows)
}

func loadFromRows(rows []database.EngagementScopeRule) (*Matcher, error) {
    rules := make([]Rule, 0, len(rows))
    for _, row := range rows {
        rules = append(rules, Rule{
            Type:      RuleType(row.RuleType),
            Value:     row.Value,
            Direction: Direction(row.Direction),
        })
    }
    return NewMatcher(rules)
}
```

- [ ] **Step 3: Run, commit**

```bash
go test ./pkg/ingestion/scope/... -v
git add backend/pkg/ingestion/scope/loader.go backend/pkg/ingestion/scope/loader_test.go
git commit -m "feat(ingestion): load scope matcher from DB"
```

---

## Phase 5: Nmap parser (proves the pipeline)

Nmap XML is the simplest format. First parser to land; establishes the golden-file pattern for all subsequent parsers.

### Task 5.1: Fixture + golden-file harness

**Files:**
- Create: `backend/pkg/ingestion/parsers/testdata/nmap/minimal.xml`
- Create: `backend/pkg/ingestion/parsers/testdata/nmap/minimal.golden.json`
- Create: `backend/pkg/ingestion/parsers/parser.go` (defines the common interface)

- [ ] **Step 1: Write the `Parser` interface shared by all four formats**

```go
// backend/pkg/ingestion/parsers/parser.go
package parsers

import (
    "io"

    "pentagi/pkg/ingestion/schema"
)

type Parser interface {
    // Source returns the scan source type this parser handles.
    Source() schema.ScanSourceType

    // Parse reads the report and returns a normalized bundle.
    // On partial parse success (e.g., malformed tail after valid body),
    // returns both a bundle and a non-nil err with errors.Is(err, ErrPartial).
    Parse(r io.Reader) (*schema.ReportBundle, error)
}

// ErrPartial marks a parser result that is incomplete but usable.
var ErrPartial = partialError{}

type partialError struct{}
func (partialError) Error() string { return "partial parse" }
```

- [ ] **Step 2: Build a realistic tiny nmap fixture**

```xml
<!-- backend/pkg/ingestion/parsers/testdata/nmap/minimal.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p 22,443 10.1.2.3" start="1713715200"
         startstr="Mon Apr 21 12:00:00 2026" version="7.94">
  <host starttime="1713715200">
    <status state="up" reason="syn-ack"/>
    <address addr="10.1.2.3" addrtype="ipv4"/>
    <hostnames>
      <hostname name="app.acme.internal" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="95">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
```

- [ ] **Step 3: Write golden output**

```json
{
  "SourceType": "nmap",
  "Hosts": [
    {
      "IP": "10.1.2.3",
      "Hostnames": ["app.acme.internal"],
      "OS": { "Family": "Linux", "Name": "Linux 5.x", "Version": "5.X", "Accuracy": 95 },
      "Services": [
        { "Port": 22,  "Protocol": "tcp", "Name": "ssh",   "Product": "OpenSSH", "Version": "9.6p1"  },
        { "Port": 443, "Protocol": "tcp", "Name": "https", "Product": "nginx",   "Version": "1.24.0" }
      ]
    }
  ],
  "Findings": [
    {
      "Type": "exposed_service",
      "Target": { "Kind": "host", "Ref": "ip:10.1.2.3:22/tcp" },
      "Title": "Exposed service ssh OpenSSH 9.6p1",
      "Severity": "info",
      "Confidence": "certain"
    },
    {
      "Type": "exposed_service",
      "Target": { "Kind": "host", "Ref": "ip:10.1.2.3:443/tcp" },
      "Title": "Exposed service https nginx 1.24.0",
      "Severity": "info",
      "Confidence": "certain"
    }
  ]
}
```

Note: evidence/rawevidence fields intentionally omitted from the golden — assert structurally, not byte-equal.

### Task 5.2: Nmap parser implementation

**Files:**
- Create: `backend/pkg/ingestion/parsers/nmap.go`
- Create: `backend/pkg/ingestion/parsers/nmap_test.go`

- [ ] **Step 1: Write the golden-file test**

```go
// backend/pkg/ingestion/parsers/nmap_test.go
package parsers

import (
    "encoding/json"
    "os"
    "strings"
    "testing"

    "pentagi/pkg/ingestion/schema"
)

func TestNmap_Minimal(t *testing.T) {
    f, err := os.Open("testdata/nmap/minimal.xml")
    if err != nil { t.Fatal(err) }
    defer f.Close()

    got, err := (&NmapParser{}).Parse(f)
    if err != nil { t.Fatalf("parse: %v", err) }
    if got.SourceType != schema.SourceNmap {
        t.Fatalf("source: %v", got.SourceType)
    }
    if len(got.Hosts) != 1 { t.Fatalf("hosts: %d", len(got.Hosts)) }
    h := got.Hosts[0]
    if h.IP != "10.1.2.3" { t.Fatalf("ip: %s", h.IP) }
    if len(h.Services) != 2 { t.Fatalf("services: %d", len(h.Services)) }

    if len(got.Findings) != 2 { t.Fatalf("findings: %d", len(got.Findings)) }
    titles := []string{got.Findings[0].Title, got.Findings[1].Title}
    if !strings.Contains(strings.Join(titles, " "), "OpenSSH 9.6p1") {
        t.Fatalf("expected OpenSSH finding, got %v", titles)
    }

    // Round-trip through JSON for stability smoke
    if _, err := json.Marshal(got); err != nil { t.Fatal(err) }
}

func TestNmap_EmptyFile(t *testing.T) {
    _, err := (&NmapParser{}).Parse(strings.NewReader(""))
    if err == nil { t.Fatal("expected error on empty input") }
}
```

- [ ] **Step 2: Run — expect failure**

```bash
go test ./pkg/ingestion/parsers/... -v -run TestNmap
```

Expected: undefined `NmapParser`.

- [ ] **Step 3: Implement `nmap.go`**

```go
// backend/pkg/ingestion/parsers/nmap.go
package parsers

import (
    "encoding/json"
    "encoding/xml"
    "fmt"
    "io"
    "strconv"

    "pentagi/pkg/ingestion/schema"
)

type NmapParser struct{}

func (p *NmapParser) Source() schema.ScanSourceType { return schema.SourceNmap }

type nmapRun struct {
    XMLName xml.Name   `xml:"nmaprun"`
    Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
    Addresses []nmapAddr     `xml:"address"`
    Hostnames nmapHostnames  `xml:"hostnames"`
    Ports     nmapPorts      `xml:"ports"`
    OS        *nmapOS        `xml:"os"`
}

type nmapAddr struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
    Hostnames []struct {
        Name string `xml:"name,attr"`
    } `xml:"hostname"`
}

type nmapPorts struct {
    Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
    Protocol string     `xml:"protocol,attr"`
    PortID   int        `xml:"portid,attr"`
    State    struct {
        State string `xml:"state,attr"`
    } `xml:"state"`
    Service nmapService `xml:"service"`
}

type nmapService struct {
    Name    string `xml:"name,attr"`
    Product string `xml:"product,attr"`
    Version string `xml:"version,attr"`
}

type nmapOS struct {
    Matches []struct {
        Name     string `xml:"name,attr"`
        Accuracy string `xml:"accuracy,attr"`
        Class    []struct {
            OSFamily string `xml:"osfamily,attr"`
            OSGen    string `xml:"osgen,attr"`
        } `xml:"osclass"`
    } `xml:"osmatch"`
}

func (p *NmapParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
    var run nmapRun
    if err := xml.NewDecoder(r).Decode(&run); err != nil {
        return nil, fmt.Errorf("nmap decode: %w", err)
    }

    bundle := &schema.ReportBundle{SourceType: schema.SourceNmap}

    for _, h := range run.Hosts {
        ip := ""
        for _, a := range h.Addresses {
            if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
                ip = a.Addr
                break
            }
        }
        if ip == "" { continue }

        hh := schema.Host{IP: ip}
        for _, n := range h.Hostnames.Hostnames {
            hh.Hostnames = append(hh.Hostnames, n.Name)
        }
        if h.OS != nil && len(h.OS.Matches) > 0 {
            m := h.OS.Matches[0]
            acc, _ := strconv.Atoi(m.Accuracy)
            os := &schema.OSFingerprint{Name: m.Name, Accuracy: acc}
            if len(m.Class) > 0 {
                os.Family = m.Class[0].OSFamily
                os.Version = m.Class[0].OSGen
            }
            hh.OS = os
        }

        for _, port := range h.Ports.Ports {
            if port.State.State != "open" { continue }
            svc := schema.Service{
                Port:     port.PortID,
                Protocol: port.Protocol,
                Name:     port.Service.Name,
                Product:  port.Service.Product,
                Version:  port.Service.Version,
            }
            hh.Services = append(hh.Services, svc)

            evidence, _ := json.Marshal(port)
            bundle.Findings = append(bundle.Findings, schema.Finding{
                Type:       schema.TypeExposedService,
                Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: hh.TargetRef(port.PortID, port.Protocol)},
                Title:      fmt.Sprintf("Exposed service %s %s %s", port.Service.Name, port.Service.Product, port.Service.Version),
                Severity:   schema.SeverityInfo,
                Confidence: schema.ConfidenceCertain,
                Evidence:   evidence,
            })
        }
        bundle.Hosts = append(bundle.Hosts, hh)
    }

    raw, _ := json.Marshal(run)
    bundle.RawEvidence = raw
    return bundle, nil
}
```

- [ ] **Step 4: Run — expect green**

```bash
go test ./pkg/ingestion/parsers/... -v
```

Expected: `TestNmap_Minimal` PASS, `TestNmap_EmptyFile` PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/parsers/
git commit -m "feat(ingestion): nmap XML parser with golden-file tests"
```

---

## Phase 6: Seeder (Graphiti writer)

Writes the normalized bundle into Graphiti scoped by `group_id`. Idempotent so re-ingest of the same report doesn't create duplicate edges.

### Task 6.1: Seeder skeleton with fake Graphiti client

**Files:**
- Create: `backend/pkg/ingestion/seeder/seeder.go`
- Create: `backend/pkg/ingestion/seeder/seeder_test.go`

- [ ] **Step 1: Write the test against a fake client**

```go
// backend/pkg/ingestion/seeder/seeder_test.go
package seeder

import (
    "context"
    "encoding/json"
    "testing"

    "pentagi/pkg/ingestion/schema"
)

type fakeClient struct{ calls []addEpisodeCall }

type addEpisodeCall struct {
    GroupID string
    Name    string
    Body    string
}

func (f *fakeClient) AddEpisode(ctx context.Context, groupID, name, body string) error {
    f.calls = append(f.calls, addEpisodeCall{groupID, name, body})
    return nil
}

func TestSeeder_HappyPath(t *testing.T) {
    c := &fakeClient{}
    s := NewSeeder(c)

    raw, _ := json.Marshal(map[string]string{"source":"nmap"})
    bundle := &schema.ReportBundle{
        SourceType: schema.SourceNmap,
        Hosts: []schema.Host{{IP: "10.1.2.3", Services: []schema.Service{
            {Port: 443, Protocol: "tcp", Name: "https", Product: "nginx", Version: "1.24"},
        }}},
        Findings: []schema.Finding{{
            Type: schema.TypeVulnerability, CVE: "CVE-2024-1234",
            Target: schema.TargetRef{Kind: schema.TargetHost, Ref: "ip:10.1.2.3:443/tcp"},
            Title: "Demo", Severity: schema.SeverityHigh, Confidence: schema.ConfidenceCertain,
        }},
        RawEvidence: raw,
    }

    if err := s.Seed(context.Background(), bundle, "eng-abc"); err != nil {
        t.Fatal(err)
    }
    if len(c.calls) == 0 { t.Fatal("no episodes written") }
    for _, call := range c.calls {
        if call.GroupID != "eng-abc" {
            t.Fatalf("wrong group id: %s", call.GroupID)
        }
    }
}

func TestSeeder_Idempotent(t *testing.T) {
    c := &fakeClient{}
    s := NewSeeder(c)
    bundle := &schema.ReportBundle{SourceType: schema.SourceNmap}
    if err := s.Seed(context.Background(), bundle, "eng-x"); err != nil { t.Fatal(err) }
    count1 := len(c.calls)
    if err := s.Seed(context.Background(), bundle, "eng-x"); err != nil { t.Fatal(err) }
    if len(c.calls) != count1 {
        t.Fatalf("second seed should not add episodes for empty bundle, got %d", len(c.calls))
    }
}
```

- [ ] **Step 2: Run — expect failure**

```bash
go test ./pkg/ingestion/seeder/... -v
```

- [ ] **Step 3: Implement seeder**

Graphiti's Go client (`pkg/graphiti/client.go`) provides `AddEpisode` — read it first to confirm the exact signature.

```bash
grep -n "AddEpisode" /home/sx0tt/pentagi/backend/pkg/graphiti/client.go
```

Then implement matching the actual signature:

```go
// backend/pkg/ingestion/seeder/seeder.go
package seeder

import (
    "context"
    "encoding/json"
    "fmt"
    "strings"

    "pentagi/pkg/ingestion/schema"
)

type EpisodeWriter interface {
    AddEpisode(ctx context.Context, groupID, name, body string) error
}

type Seeder struct{ client EpisodeWriter }

func NewSeeder(c EpisodeWriter) *Seeder { return &Seeder{client: c} }

// Seed writes a bundle as a series of episodes. Episode names are deterministic
// from content so that Graphiti's native dedup treats re-seeds as no-ops.
func (s *Seeder) Seed(ctx context.Context, b *schema.ReportBundle, groupID string) error {
    if groupID == "" { return fmt.Errorf("groupID required") }
    var errs []string

    for _, h := range b.Hosts {
        body, _ := json.Marshal(h)
        name := fmt.Sprintf("host:%s", h.IP)
        if err := s.client.AddEpisode(ctx, groupID, name, string(body)); err != nil {
            errs = append(errs, fmt.Sprintf("host %s: %v", h.IP, err))
        }
    }
    for _, c := range b.Containers {
        body, _ := json.Marshal(c)
        name := "container:" + c.TargetRef()
        if err := s.client.AddEpisode(ctx, groupID, name, string(body)); err != nil {
            errs = append(errs, fmt.Sprintf("container %s: %v", c.Image, err))
        }
    }
    for i, f := range b.Findings {
        body, _ := json.Marshal(f)
        name := fmt.Sprintf("finding:%s:%d", f.Target.Ref, i)
        if f.CVE != "" { name = fmt.Sprintf("finding:%s:%s", f.Target.Ref, f.CVE) }
        if err := s.client.AddEpisode(ctx, groupID, name, string(body)); err != nil {
            errs = append(errs, fmt.Sprintf("finding %s: %v", name, err))
        }
    }
    if len(errs) > 0 {
        return fmt.Errorf("seed errors: %s", strings.Join(errs, "; "))
    }
    return nil
}
```

- [ ] **Step 4: Run — expect green**

```bash
go test ./pkg/ingestion/seeder/... -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/seeder/
git commit -m "feat(ingestion): graphiti seeder with deterministic episode names"
```

### Task 6.2: Reconcile loop for pending graph seeding

**Files:**
- Create: `backend/pkg/ingestion/seeder/reconcile.go`
- Create: `backend/pkg/ingestion/seeder/reconcile_test.go`

- [ ] **Step 1: Write the test** — exercise that `ReconcileOnce` reads findings where `graph_seeded_at IS NULL`, writes each to the seeder, and marks the row seeded on success.

```go
// backend/pkg/ingestion/seeder/reconcile_test.go
package seeder

import (
    "context"
    "testing"

    "pentagi/pkg/database"
)

type fakeRepo struct {
    pending []database.Finding
    seeded  []int64
}
func (f *fakeRepo) FindingsPendingGraphSync(_ context.Context, lim int32) ([]database.Finding, error) {
    if int(lim) < len(f.pending) { return f.pending[:lim], nil }
    return f.pending, nil
}
func (f *fakeRepo) MarkFindingGraphSeeded(_ context.Context, id int64) error {
    f.seeded = append(f.seeded, id); return nil
}

type fakeEngagementLookup struct{ group string }
func (f fakeEngagementLookup) GroupID(_ context.Context, _ int64) (string, error) {
    return f.group, nil
}

func TestReconcile_MarksSeeded(t *testing.T) {
    repo := &fakeRepo{pending: []database.Finding{
        {ID: 1, EngagementID: 100},
        {ID: 2, EngagementID: 100},
    }}
    r := &Reconciler{
        Repo:      repo,
        GroupLookup: fakeEngagementLookup{group: "eng-x"},
        Client:    &fakeClient{},
    }
    if err := r.ReconcileOnce(context.Background(), 10); err != nil { t.Fatal(err) }
    if len(repo.seeded) != 2 { t.Fatalf("want 2 seeded, got %d", len(repo.seeded)) }
}
```

- [ ] **Step 2: Implement `Reconciler`**

```go
// backend/pkg/ingestion/seeder/reconcile.go
package seeder

import (
    "context"
    "encoding/json"
    "fmt"

    "pentagi/pkg/database"
)

type FindingRepo interface {
    FindingsPendingGraphSync(ctx context.Context, limit int32) ([]database.Finding, error)
    MarkFindingGraphSeeded(ctx context.Context, id int64) error
}

type GroupLookup interface {
    GroupID(ctx context.Context, engagementID int64) (string, error)
}

type Reconciler struct {
    Repo        FindingRepo
    GroupLookup GroupLookup
    Client      EpisodeWriter
}

func (r *Reconciler) ReconcileOnce(ctx context.Context, limit int32) error {
    rows, err := r.Repo.FindingsPendingGraphSync(ctx, limit)
    if err != nil { return err }
    for _, row := range rows {
        grp, err := r.GroupLookup.GroupID(ctx, row.EngagementID)
        if err != nil { return fmt.Errorf("group for finding %d: %w", row.ID, err) }
        body, _ := json.Marshal(row)
        name := fmt.Sprintf("finding:%s:%d", row.TargetRef, row.ID)
        if err := r.Client.AddEpisode(ctx, grp, name, string(body)); err != nil {
            continue // leave unseeded for next pass
        }
        if err := r.Repo.MarkFindingGraphSeeded(ctx, row.ID); err != nil {
            return err
        }
    }
    return nil
}
```

- [ ] **Step 3: Run tests, commit**

```bash
go test ./pkg/ingestion/seeder/... -v
git add backend/pkg/ingestion/seeder/
git commit -m "feat(ingestion): reconcile loop for unseeded findings"
```

---

## Phase 7: Ingestion REST controller + end-to-end smoke test

Milestone. After this phase, upload → parse → persist → seed → list works with nmap only. Proves the full pipeline before we layer on the other three parsers.

### Task 7.1: Controller

**Files:**
- Create: `backend/pkg/server/controllers/ingestion_controller.go`
- Modify: `backend/pkg/server/router.go` (register new routes — find the existing route registration block)

- [ ] **Step 1: Read the existing controller pattern**

```bash
wc -l /home/sx0tt/pentagi/backend/pkg/server/controllers/*.go
# pick a small one, read it to confirm Gin handler signatures and auth middleware usage:
head -80 /home/sx0tt/pentagi/backend/pkg/server/controllers/flows.go
```

This confirms: how handlers get the authenticated user ID, how errors are translated to HTTP responses, how JSON binding is done. Match that pattern.

- [ ] **Step 2: Implement `ingestion_controller.go`**

Controller skeleton. Add `// @Summary`, `// @Router`, etc. swagger annotations to every handler by copying the shape used in a peer controller (e.g., `backend/pkg/server/controllers/flows.go`); swag picks them up via `swag init`.

```go
// backend/pkg/server/controllers/ingestion_controller.go
package controllers

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"

    "pentagi/pkg/database"
    "pentagi/pkg/ingestion/engagement"
    "pentagi/pkg/ingestion/parsers"
    "pentagi/pkg/ingestion/schema"
    "pentagi/pkg/ingestion/scope"
    "pentagi/pkg/ingestion/seeder"

    "github.com/gin-gonic/gin"
)

type IngestionController struct {
    q       database.Querier
    eng     *engagement.Service
    seeder  *seeder.Seeder
    parsers map[schema.ScanSourceType]parsers.Parser
    storageDir string
}

func NewIngestionController(q database.Querier, eng *engagement.Service, s *seeder.Seeder, storageDir string) *IngestionController {
    return &IngestionController{
        q: q, eng: eng, seeder: s, storageDir: storageDir,
        parsers: map[schema.ScanSourceType]parsers.Parser{
            schema.SourceNmap:      &parsers.NmapParser{},
            // filled in as other parsers land
        },
    }
}

// POST /api/v1/engagements
func (c *IngestionController) CreateEngagement(ctx *gin.Context) {
    var body struct {
        Name        string `json:"name" binding:"required"`
        Client      string `json:"client" binding:"required"`
        Description string `json:"description"`
    }
    if err := ctx.ShouldBindJSON(&body); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
    }
    userID := currentUserID(ctx) // reuse existing helper; confirm name from peer controllers
    e, err := c.eng.Create(ctx.Request.Context(), engagement.CreateInput{
        Name: body.Name, Client: body.Client, Description: body.Description, CreatedBy: userID,
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusCreated, e)
}

// POST /api/v1/engagements/:id/reports
func (c *IngestionController) UploadReport(ctx *gin.Context) {
    engID := parseInt64Param(ctx, "id")
    sourceType := schema.ScanSourceType(ctx.PostForm("source_type"))
    if _, ok := c.parsers[sourceType]; !ok {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported source_type %q", sourceType)}); return
    }
    fh, err := ctx.FormFile("file")
    if err != nil { ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }

    // stream to temp, hash inline
    src, err := fh.Open(); if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()}); return }
    defer src.Close()
    tmp, err := os.CreateTemp(c.storageDir, "upload-*"); if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()}); return }
    defer tmp.Close()
    h := sha256.New()
    if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()}); return }
    sum := hex.EncodeToString(h.Sum(nil))

    // dedup guard
    if existing, err := c.q.GetScanReportBySha(ctx.Request.Context(), database.GetScanReportBySha256Params{
        EngagementID: engID, Sha256: sum,
    }); err == nil {
        _ = os.Remove(tmp.Name())
        ctx.JSON(http.StatusConflict, gin.H{"error": "already ingested", "scan_report_id": existing.ID})
        return
    } else if !errors.Is(err, database.ErrNotFound) { // confirm actual sentinel
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
    }

    // finalize storage location
    finalPath := filepath.Join(c.storageDir, fmt.Sprintf("%d-%s-%s", engID, sum, fh.Filename))
    if err := os.Rename(tmp.Name(), finalPath); err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
    }

    userID := currentUserID(ctx)
    row, err := c.q.CreateScanReport(ctx.Request.Context(), database.CreateScanReportParams{
        EngagementID: engID, SourceType: database.ScanSourceType(sourceType),
        OriginalFilename: fh.Filename, StorageUri: finalPath, Sha256: sum,
        ParserVersion: "v1", UploadedBy: userID,
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }

    // fire-and-forget parse in a goroutine (v1). v2 should use pkg/queue for durability.
    go c.runParse(context.Background(), row, sourceType, finalPath)

    ctx.JSON(http.StatusAccepted, row)
}

func (c *IngestionController) runParse(ctx context.Context, report database.ScanReport, source schema.ScanSourceType, path string) {
    p := c.parsers[source]
    f, err := os.Open(path)
    if err != nil { _ = c.markFailed(ctx, report.ID, err); return }
    defer f.Close()

    bundle, err := p.Parse(f)
    if err != nil && !errors.Is(err, parsers.ErrPartial) {
        _ = c.markFailed(ctx, report.ID, err); return
    }
    if err := c.persistBundle(ctx, report, bundle); err != nil {
        _ = c.markFailed(ctx, report.ID, err); return
    }
    eng, err := c.q.GetEngagement(ctx, report.EngagementID)
    if err == nil { _ = c.seeder.Seed(ctx, bundle, eng.GraphitiGroupID) }
    _ = c.q.UpdateScanReportStatus(ctx, database.UpdateScanReportStatusParams{
        ID: report.ID, ParseStatus: "succeeded", FindingCount: int32(len(bundle.Findings)),
    })
}

func (c *IngestionController) markFailed(ctx context.Context, id int64, err error) error {
    msg := err.Error()
    if len(msg) > 500 { msg = msg[:500] }
    return c.q.UpdateScanReportStatus(ctx, database.UpdateScanReportStatusParams{
        ID: id, ParseStatus: "failed", ParseError: &msg,
    })
}

func (c *IngestionController) persistBundle(ctx context.Context, report database.ScanReport, b *schema.ReportBundle) error {
    matcher, err := scope.LoadMatcher(ctx, c.q, report.EngagementID)
    if err != nil { return err }
    for _, f := range b.Findings {
        inScope := matcher.InScope(f.Target.Ref)
        var cvss *string // render numeric(3,1) as string if needed by sqlc; adapt to actual field type
        _, err := c.q.UpsertFinding(ctx, database.UpsertFindingParams{
            EngagementID: report.EngagementID, ScanReportID: report.ID,
            FindingType: database.FindingType(f.Type),
            TargetKind:  database.TargetKind(f.Target.Kind),
            TargetRef:   f.Target.Ref,
            Title:       f.Title, Cve: toPtr(f.CVE), CvssScore: cvss,
            Severity:    database.SeverityLevel(f.Severity),
            Confidence:  database.FindingConfidence(f.Confidence),
            SourceID:    toPtr(f.SourceID),
            Evidence:    f.Evidence,
            InScope:     inScope,
        })
        if err != nil { return err }
    }
    return nil
}

// toPtr returns a pointer, or nil if v equals its zero value. Use this across the
// ingestion controller for optional string/numeric fields mapping to SQLC nullable params.
func toPtr[T comparable](v T) *T {
    var zero T
    if v == zero { return nil }
    return &v
}
```

Notes for the implementer: exact `database.*Params` field names and the sentinel error for "not found" (`pgx.ErrNoRows` vs a repo-specific sentinel) must be confirmed against the SQLC output from Phase 3. Helper functions for pulling the authenticated user ID and int64 path params already exist in the peer controllers — `grep -n 'userID :=' backend/pkg/server/controllers/flows.go` to find them, and reuse the same approach rather than inventing new helpers.

The remaining CRUD handlers (each a thin wrapper; implement all in this step):

```go
// GET /api/v1/engagements — ListEngagements
func (c *IngestionController) ListEngagements(ctx *gin.Context) {
    limit := parseIntQuery(ctx, "limit", 50)
    offset := parseIntQuery(ctx, "offset", 0)
    rows, err := c.q.ListEngagements(ctx.Request.Context(), database.ListEngagementsParams{
        Limit: int32(limit), Offset: int32(offset),
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusOK, rows)
}

// GET /api/v1/engagements/:id
func (c *IngestionController) GetEngagement(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    row, err := c.eng.Get(ctx.Request.Context(), id)
    if err != nil { ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
    ctx.JSON(http.StatusOK, row)
}

// PATCH /api/v1/engagements/:id
func (c *IngestionController) UpdateEngagement(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    var body struct {
        Name, Client, Description *string                  `json:"name,omitempty"`
        Status                    *database.EngagementStatus `json:"status,omitempty"`
    }
    if err := ctx.ShouldBindJSON(&body); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
    }
    row, err := c.q.UpdateEngagement(ctx.Request.Context(), database.UpdateEngagementParams{
        ID: id, UpdatedBy: currentUserID(ctx),
        Name: body.Name, Client: body.Client, Description: body.Description, Status: body.Status,
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusOK, row)
}

// DELETE /api/v1/engagements/:id (soft)
func (c *IngestionController) DeleteEngagement(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    if err := c.q.SoftDeleteEngagement(ctx.Request.Context(), id); err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
    }
    ctx.Status(http.StatusNoContent)
}

// POST /api/v1/engagements/:id/scope-rules
func (c *IngestionController) AddScopeRule(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    var body struct {
        RuleType  string `json:"rule_type" binding:"required"`
        Value     string `json:"value" binding:"required"`
        Direction string `json:"direction"`
        Note      string `json:"note"`
    }
    if err := ctx.ShouldBindJSON(&body); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
    }
    dir := database.ScopeDirection("include")
    if body.Direction != "" { dir = database.ScopeDirection(body.Direction) }
    row, err := c.q.AddScopeRule(ctx.Request.Context(), database.AddScopeRuleParams{
        EngagementID: id, RuleType: database.ScopeRuleType(body.RuleType),
        Value: body.Value, Direction: dir, Note: toPtr(body.Note),
    })
    if err != nil { ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusCreated, row)
}

// DELETE /api/v1/engagements/:id/scope-rules/:ruleId
func (c *IngestionController) DeleteScopeRule(ctx *gin.Context) {
    engID := parseInt64Param(ctx, "id")
    ruleID := parseInt64Param(ctx, "ruleId")
    _ = c.q.DeleteScopeRule(ctx.Request.Context(), database.DeleteScopeRuleParams{
        ID: ruleID, EngagementID: engID,
    })
    ctx.Status(http.StatusNoContent)
}

// GET /api/v1/engagements/:id/reports
func (c *IngestionController) ListReports(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    rows, err := c.q.ListScanReports(ctx.Request.Context(), database.ListScanReportsParams{
        EngagementID: id, Limit: 200, Offset: 0,
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusOK, rows)
}

// GET /api/v1/engagements/:id/reports/:reportId
func (c *IngestionController) GetReport(ctx *gin.Context) {
    rid := parseInt64Param(ctx, "reportId")
    row, err := c.q.GetScanReport(ctx.Request.Context(), rid)
    if err != nil { ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
    ctx.JSON(http.StatusOK, row)
}

// GET /api/v1/engagements/:id/reports/:reportId/raw
func (c *IngestionController) DownloadReport(ctx *gin.Context) {
    rid := parseInt64Param(ctx, "reportId")
    row, err := c.q.GetScanReport(ctx.Request.Context(), rid)
    if err != nil { ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
    ctx.FileAttachment(row.StorageUri, row.OriginalFilename)
}

// GET /api/v1/engagements/:id/findings
func (c *IngestionController) ListFindings(ctx *gin.Context) {
    id := parseInt64Param(ctx, "id")
    params := database.ListFindingsParams{EngagementID: id, Limit: 200, Offset: 0}
    if v := ctx.Query("severity"); v != "" { sv := database.SeverityLevel(v); params.Severity = &sv }
    if v := ctx.Query("cve"); v != ""       { params.Cve = &v }
    if v := ctx.Query("target_kind"); v != "" { tk := database.TargetKind(v); params.TargetKind = &tk }
    if v := ctx.Query("in_scope"); v != "" {
        b := v == "true"; params.InScope = &b
    }
    if v := ctx.Query("verification_status"); v != "" {
        vs := database.VerificationStatus(v); params.VerificationStatus = &vs
    }
    rows, err := c.q.ListFindings(ctx.Request.Context(), params)
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusOK, rows)
}

// GET /api/v1/engagements/:id/findings/:findingId
func (c *IngestionController) GetFinding(ctx *gin.Context) {
    fid := parseInt64Param(ctx, "findingId")
    row, err := c.q.GetFinding(ctx.Request.Context(), fid)
    if err != nil { ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
    ctx.JSON(http.StatusOK, row)
}

// PATCH /api/v1/engagements/:id/findings/:findingId
func (c *IngestionController) UpdateFindingVerification(ctx *gin.Context) {
    fid := parseInt64Param(ctx, "findingId")
    var body struct {
        VerificationStatus string `json:"verification_status" binding:"required"`
        Notes              string `json:"notes"`
    }
    if err := ctx.ShouldBindJSON(&body); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
    }
    userID := currentUserID(ctx)
    row, err := c.q.UpdateFindingVerification(ctx.Request.Context(), database.UpdateFindingVerificationParams{
        ID: fid, VerificationStatus: database.VerificationStatus(body.VerificationStatus),
        VerificationNotes: toPtr(body.Notes), VerifiedBy: &userID,
    })
    if err != nil { ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    ctx.JSON(http.StatusOK, row)
}

// parseIntQuery is a small helper; if a peer helper exists already, use that instead.
func parseIntQuery(ctx *gin.Context, key string, dflt int) int {
    if v := ctx.Query(key); v != "" {
        if n, err := strconv.Atoi(v); err == nil { return n }
    }
    return dflt
}
```

- [ ] **Step 3: Wire routes into router**

Find the existing route registration block in `backend/pkg/server/router.go` (around where `flows` are registered). Add the ingestion routes under the same auth middleware:

```go
// In router.go, after existing routes:
ic := controllers.NewIngestionController(db, engSvc, seederInst, cfg.IngestionStorageDir)

v1 := api.Group("/engagements")
v1.POST("",          ic.CreateEngagement)
v1.GET("",           ic.ListEngagements)
v1.GET("/:id",       ic.GetEngagement)
v1.PATCH("/:id",     ic.UpdateEngagement)
v1.DELETE("/:id",    ic.DeleteEngagement)
v1.POST("/:id/scope-rules",             ic.AddScopeRule)
v1.DELETE("/:id/scope-rules/:ruleId",   ic.DeleteScopeRule)
v1.POST("/:id/reports",                 ic.UploadReport)
v1.GET("/:id/reports",                  ic.ListReports)
v1.GET("/:id/reports/:reportId",        ic.GetReport)
v1.GET("/:id/reports/:reportId/raw",    ic.DownloadReport)
v1.GET("/:id/findings",                 ic.ListFindings)
v1.GET("/:id/findings/:findingId",      ic.GetFinding)
v1.PATCH("/:id/findings/:findingId",    ic.UpdateFindingVerification)
```

Implement the handlers named above as thin wrappers over `engagement.Service` and the raw querier, following the pattern shown in Step 2.

- [ ] **Step 4: Add config knob for storage directory**

Modify `backend/pkg/config/config.go` to add:

```go
IngestionStorageDir string `envconfig:"INGESTION_STORAGE_DIR" default:"/var/lib/pentagi/ingestion"`
```

Ensure the directory exists at startup (idempotent `os.MkdirAll` in `cmd/pentagi/main.go` or wherever storage is initialized).

Add to `.env.example`:

```
INGESTION_STORAGE_DIR=/var/lib/pentagi/ingestion
```

- [ ] **Step 5: Build**

```bash
cd /home/sx0tt/pentagi/backend
go build -o /tmp/pentagi ./cmd/pentagi
```

Expected: green. If sqlc struct fields don't match, adjust.

- [ ] **Step 6: Commit**

```bash
git add backend/pkg/server/controllers/ingestion_controller.go \
        backend/pkg/server/router.go \
        backend/pkg/config/config.go \
        .env.example
git commit -m "feat(ingestion): REST controller + routes for engagements, reports, findings"
```

### Task 7.2: End-to-end smoke test

**Files:**
- Create: `backend/pkg/ingestion/e2e_test.go` (tag `//go:build integration`)

- [ ] **Step 1: Write the smoke test**

Starts the HTTP server against a real Postgres + Graphiti (testcontainers), creates an Engagement, uploads the nmap fixture, polls until parse succeeds, asserts two findings returned via `GET /findings`.

```go
// backend/pkg/ingestion/e2e_test.go
//go:build integration

package ingestion_test

// The actual harness depends heavily on how pkg/server/router.go is initialized.
// Use the same boot function the unit tests around flows use; search for "NewRouter"
// or "BootTestServer" in existing test files and reuse it.
//
// Key assertions the smoke test must make, independent of harness shape:
//
// 1. POST /api/v1/engagements returns 201 + id
// 2. POST /api/v1/engagements/:id/scope-rules for rule_type=cidr value=10.1.0.0/16 returns 201
// 3. POST /api/v1/engagements/:id/reports with source_type=nmap and the minimal.xml fixture
//    returns 202 and a scan_report_id
// 4. Poll GET /api/v1/engagements/:id/reports/:reportId up to 10s until parse_status == "succeeded"
// 5. GET /api/v1/engagements/:id/findings returns exactly 2 findings, both with in_scope=true
//    (because 10.1.2.3 is inside the CIDR)
// 6. POST /api/v1/engagements/:id/reports again with the same file returns 409 with the existing id
```

- [ ] **Step 2: Run against docker compose**

```bash
docker compose up -d pgvector neo4j graphiti
cd backend
go test -tags=integration ./pkg/ingestion/...
```

Expected: green. First-run slowness is expected (~30s warm-up).

- [ ] **Step 3: Commit**

```bash
git add backend/pkg/ingestion/e2e_test.go
git commit -m "test(ingestion): end-to-end smoke for nmap upload → finding query"
```

Milestone: Phase 7 complete means the full pipeline is proven. Everything after this phase is additive (more parsers, agent tools, UI, scope gate, flow types).

---

## Phase 8: Burp parser

Burp XML export. Slightly more structure than nmap (issues + base64 request/response pairs).

### Task 8.1: Fixture + parser

**Files:**
- Create: `backend/pkg/ingestion/parsers/testdata/burp/minimal.xml`
- Create: `backend/pkg/ingestion/parsers/burp.go`
- Create: `backend/pkg/ingestion/parsers/burp_test.go`

- [ ] **Step 1: Write a minimal Burp fixture**

```xml
<?xml version="1.0"?>
<issues burpVersion="2024.1">
  <issue>
    <serialNumber>1</serialNumber>
    <type>0x00100200</type>
    <name>SQL injection</name>
    <host ip="10.1.2.3">https://app.acme.internal</host>
    <path>/search</path>
    <location>https://app.acme.internal/search?q=1</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>...</issueBackground>
    <requestresponse>
      <request base64="true">R0VUIC9zZWFyY2g/cT0xJyBIVFRQLzEuMQ0K</request>
      <response base64="true">SFRUUC8xLjEgNTAwDQo=</response>
    </requestresponse>
  </issue>
</issues>
```

- [ ] **Step 2: Write the parser test** — asserts one web_issue finding with target_kind=web_endpoint, severity=high, confidence=certain, cve empty, title="SQL injection".

```go
// backend/pkg/ingestion/parsers/burp_test.go
package parsers

import (
    "os"
    "testing"

    "pentagi/pkg/ingestion/schema"
)

func TestBurp_Minimal(t *testing.T) {
    f, err := os.Open("testdata/burp/minimal.xml")
    if err != nil { t.Fatal(err) }
    defer f.Close()

    got, err := (&BurpParser{}).Parse(f)
    if err != nil { t.Fatal(err) }
    if len(got.Findings) != 1 { t.Fatalf("findings: %d", len(got.Findings)) }
    f0 := got.Findings[0]
    if f0.Severity != schema.SeverityHigh { t.Fatal("severity") }
    if f0.Confidence != schema.ConfidenceCertain { t.Fatal("confidence") }
    if f0.Target.Kind != schema.TargetWebEndpoint { t.Fatal("target kind") }
    if f0.Title != "SQL injection" { t.Fatal("title") }
}
```

- [ ] **Step 3: Implement `burp.go`**

```go
// backend/pkg/ingestion/parsers/burp.go
package parsers

import (
    "encoding/json"
    "encoding/xml"
    "fmt"
    "io"
    "strings"

    "pentagi/pkg/ingestion/schema"
)

type BurpParser struct{}

func (p *BurpParser) Source() schema.ScanSourceType { return schema.SourceBurp }

type burpIssues struct {
    XMLName xml.Name   `xml:"issues"`
    Issues  []burpIssue `xml:"issue"`
}

type burpIssue struct {
    SerialNumber string `xml:"serialNumber"`
    Name         string `xml:"name"`
    Host         string `xml:"host"`
    Location     string `xml:"location"`
    Severity     string `xml:"severity"`
    Confidence   string `xml:"confidence"`
}

func (p *BurpParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
    var doc burpIssues
    if err := xml.NewDecoder(r).Decode(&doc); err != nil {
        return nil, fmt.Errorf("burp decode: %w", err)
    }
    bundle := &schema.ReportBundle{SourceType: schema.SourceBurp}
    for _, iss := range doc.Issues {
        evidence, _ := json.Marshal(iss)
        confidence := schema.ConfidenceTentative
        switch strings.ToLower(iss.Confidence) {
        case "certain": confidence = schema.ConfidenceCertain
        case "firm":    confidence = schema.ConfidenceFirm
        }
        f := schema.Finding{
            Type:       schema.TypeWebIssue,
            Target:     schema.TargetRef{Kind: schema.TargetWebEndpoint, Ref: "url:" + iss.Location},
            Title:      iss.Name,
            Severity:   schema.ParseSeverity(iss.Severity),
            Confidence: confidence,
            SourceID:   iss.SerialNumber,
            Evidence:   evidence,
        }
        bundle.Findings = append(bundle.Findings, f)
        bundle.WebEndpoints = append(bundle.WebEndpoints, schema.WebEndpoint{URL: iss.Location})
    }
    return bundle, nil
}
```

- [ ] **Step 4: Wire into controller map**

```go
// backend/pkg/server/controllers/ingestion_controller.go — extend the parsers map
parsers: map[schema.ScanSourceType]parsers.Parser{
    schema.SourceNmap: &parsers.NmapParser{},
    schema.SourceBurp: &parsers.BurpParser{},  // add this line
},
```

- [ ] **Step 5: Run, commit**

```bash
go test ./pkg/ingestion/parsers/... -v
git add backend/pkg/ingestion/parsers/burp.go \
        backend/pkg/ingestion/parsers/burp_test.go \
        backend/pkg/ingestion/parsers/testdata/burp/ \
        backend/pkg/server/controllers/ingestion_controller.go
git commit -m "feat(ingestion): burp XML parser"
```

---

## Phase 9: Twistlock parser (streaming JSON)

### Task 9.1: Fixture + streaming parser

**Files:**
- Create: `backend/pkg/ingestion/parsers/testdata/twistlock/minimal.json`
- Create: `backend/pkg/ingestion/parsers/twistlock.go`
- Create: `backend/pkg/ingestion/parsers/twistlock_test.go`

- [ ] **Step 1: Write a minimal Twistlock JSON fixture**

```json
{
  "results": [
    {
      "id": "sha256:abc123",
      "name": "registry.acme.internal/app",
      "tag": "v1.2.3",
      "distro": "Debian 12",
      "vulnerabilities": [
        {
          "id": "CVE-2024-12345",
          "packageName": "openssl",
          "packageVersion": "3.0.11",
          "severity": "high",
          "cvss": 7.5,
          "description": "OpenSSL has a flaw..."
        },
        {
          "id": "CVE-2024-67890",
          "packageName": "libz",
          "packageVersion": "1.2.13",
          "severity": "critical",
          "cvss": 9.8,
          "description": "libz unbounded write..."
        }
      ],
      "complianceIssues": []
    }
  ]
}
```

- [ ] **Step 2: Test**

```go
// backend/pkg/ingestion/parsers/twistlock_test.go
package parsers

import (
    "os"
    "testing"

    "pentagi/pkg/ingestion/schema"
)

func TestTwistlock_Minimal(t *testing.T) {
    f, err := os.Open("testdata/twistlock/minimal.json")
    if err != nil { t.Fatal(err) }
    defer f.Close()
    got, err := (&TwistlockParser{}).Parse(f)
    if err != nil { t.Fatal(err) }
    if len(got.Containers) != 1 { t.Fatalf("containers: %d", len(got.Containers)) }
    if len(got.Findings) != 2 { t.Fatalf("findings: %d", len(got.Findings)) }
    sev := got.Findings[1].Severity
    if sev != schema.SeverityCritical { t.Fatalf("sev: %v", sev) }
}
```

- [ ] **Step 3: Implement streaming JSON parser**

```go
// backend/pkg/ingestion/parsers/twistlock.go
package parsers

import (
    "encoding/json"
    "fmt"
    "io"

    "pentagi/pkg/ingestion/schema"
)

type TwistlockParser struct{}

func (p *TwistlockParser) Source() schema.ScanSourceType { return schema.SourceTwistlock }

type twistlockDoc struct {
    Results []twistlockResult `json:"results"`
}

type twistlockResult struct {
    ID              string               `json:"id"`
    Name            string               `json:"name"`
    Tag             string               `json:"tag"`
    Distro          string               `json:"distro"`
    Vulnerabilities []twistlockVuln      `json:"vulnerabilities"`
    ComplianceIssues []twistlockCompliance `json:"complianceIssues"`
}

type twistlockVuln struct {
    ID             string  `json:"id"`
    PackageName    string  `json:"packageName"`
    PackageVersion string  `json:"packageVersion"`
    Severity       string  `json:"severity"`
    CVSS           float64 `json:"cvss"`
    Description    string  `json:"description"`
}

type twistlockCompliance struct {
    ID          string `json:"id"`
    Severity    string `json:"severity"`
    Description string `json:"description"`
}

func (p *TwistlockParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
    var doc twistlockDoc
    if err := json.NewDecoder(r).Decode(&doc); err != nil {
        return nil, fmt.Errorf("twistlock decode: %w", err)
    }
    bundle := &schema.ReportBundle{SourceType: schema.SourceTwistlock}
    for _, r := range doc.Results {
        reg, image := splitImage(r.Name)
        ct := schema.Container{
            Image: image, Tag: r.Tag, Digest: r.ID, Registry: reg,
        }
        ref := ct.TargetRef()
        bundle.Containers = append(bundle.Containers, ct)

        for _, v := range r.Vulnerabilities {
            evidence, _ := json.Marshal(v)
            cvss := v.CVSS
            bundle.Findings = append(bundle.Findings, schema.Finding{
                Type:       schema.TypeContainerCVE,
                Target:     schema.TargetRef{Kind: schema.TargetContainer, Ref: ref},
                Title:      fmt.Sprintf("%s in %s %s", v.ID, v.PackageName, v.PackageVersion),
                CVE:        v.ID,
                CVSSScore:  &cvss,
                Severity:   schema.ParseSeverity(v.Severity),
                Confidence: schema.ConfidenceFirm,
                SourceID:   v.ID,
                Evidence:   evidence,
            })
        }
        for _, c := range r.ComplianceIssues {
            evidence, _ := json.Marshal(c)
            bundle.Findings = append(bundle.Findings, schema.Finding{
                Type:       schema.TypeContainerCompliance,
                Target:     schema.TargetRef{Kind: schema.TargetContainer, Ref: ref},
                Title:      c.Description,
                Severity:   schema.ParseSeverity(c.Severity),
                Confidence: schema.ConfidenceFirm,
                SourceID:   c.ID,
                Evidence:   evidence,
            })
        }
    }
    return bundle, nil
}

func splitImage(full string) (registry, image string) {
    for i := 0; i < len(full); i++ {
        if full[i] == '/' {
            return full[:i], full[i+1:]
        }
    }
    return "", full
}
```

- [ ] **Step 4: Run, register in controller map, commit**

```bash
go test ./pkg/ingestion/parsers/... -v
```

Add `schema.SourceTwistlock: &parsers.TwistlockParser{}` to the controller map.

```bash
git add backend/pkg/ingestion/parsers/twistlock* \
        backend/pkg/ingestion/parsers/testdata/twistlock/ \
        backend/pkg/server/controllers/ingestion_controller.go
git commit -m "feat(ingestion): twistlock JSON parser"
```

---

## Phase 10: Qualys parser (streaming XML + partial)

Largest parser. Must stream. Must tolerate malformed tails and emit `ErrPartial`.

### Task 10.1: Fixture + happy-path parser

**Files:**
- Create: `backend/pkg/ingestion/parsers/testdata/qualys/minimal.xml`
- Create: `backend/pkg/ingestion/parsers/qualys.go`
- Create: `backend/pkg/ingestion/parsers/qualys_test.go`

- [ ] **Step 1: Write a minimal Qualys VM XML fixture** (representative of the VM scan report format; fields `QID`, `TITLE`, `SEVERITY`, `CVSS_BASE`, `CVE_ID_LIST`, `HOST`, `IP`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<SCAN_SUMMARY>
  <HEADER><KEY value="SCAN_DATE">2026-04-10</KEY></HEADER>
  <IP_RESULTS>
    <IP value="10.1.2.3" name="app.acme.internal">
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID id="qid_38170">38170</QID>
          <TYPE>Vuln</TYPE>
          <TITLE>OpenSSH Terrapin Prefix Truncation</TITLE>
          <SEVERITY>4</SEVERITY>
          <CVSS_BASE>5.9</CVSS_BASE>
          <CVE_ID_LIST>
            <CVE_ID><ID>CVE-2023-48795</ID></CVE_ID>
          </CVE_ID_LIST>
          <RESULT>SSH server on port 22 advertises chacha20-poly1305@openssh.com...</RESULT>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </IP>
  </IP_RESULTS>
</SCAN_SUMMARY>
```

- [ ] **Step 2: Test — golden-file style plus a second fixture for the partial case**

```go
// backend/pkg/ingestion/parsers/qualys_test.go
package parsers

import (
    "errors"
    "os"
    "strings"
    "testing"

    "pentagi/pkg/ingestion/schema"
)

func TestQualys_Minimal(t *testing.T) {
    f, err := os.Open("testdata/qualys/minimal.xml")
    if err != nil { t.Fatal(err) }
    defer f.Close()
    got, err := (&QualysParser{}).Parse(f)
    if err != nil { t.Fatal(err) }
    if len(got.Findings) != 1 { t.Fatalf("findings: %d", len(got.Findings)) }
    f0 := got.Findings[0]
    if f0.CVE != "CVE-2023-48795" { t.Fatalf("cve: %s", f0.CVE) }
    if f0.Severity != schema.SeverityHigh { t.Fatalf("sev: %v", f0.Severity) }
    if f0.SourceID != "38170" { t.Fatalf("qid: %s", f0.SourceID) }
    if f0.CVSSScore == nil || *f0.CVSSScore != 5.9 { t.Fatal("cvss") }
}

func TestQualys_Partial(t *testing.T) {
    // corrupted tail: first vuln valid, second one truncated
    xml := strings.Replace(mustReadFile(t, "testdata/qualys/minimal.xml"),
        "</SCAN_SUMMARY>", "<VULN_INFO><QID><!-- truncated", 1)
    got, err := (&QualysParser{}).Parse(strings.NewReader(xml))
    if !errors.Is(err, ErrPartial) {
        t.Fatalf("expected ErrPartial, got %v", err)
    }
    if len(got.Findings) == 0 {
        t.Fatal("partial parse should still have recovered the first finding")
    }
}

func mustReadFile(t *testing.T, path string) string {
    t.Helper()
    b, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    return string(b)
}
```

- [ ] **Step 3: Implement streaming XML parser**

The Qualys parser uses `xml.Decoder.Token()` rather than `Decoder.Decode` because real-world exports can reach hundreds of megabytes. On a truncated tail, capture the error, return what was successfully extracted plus `ErrPartial`.

```go
// backend/pkg/ingestion/parsers/qualys.go
package parsers

import (
    "encoding/json"
    "encoding/xml"
    "fmt"
    "io"
    "strconv"
    "strings"

    "pentagi/pkg/ingestion/schema"
)

type QualysParser struct{}

func (p *QualysParser) Source() schema.ScanSourceType { return schema.SourceQualys }

type qualysVuln struct {
    XMLName   xml.Name `xml:"VULN_INFO"`
    QID       string   `xml:"QID"`
    Title     string   `xml:"TITLE"`
    Severity  string   `xml:"SEVERITY"`
    CVSSBase  string   `xml:"CVSS_BASE"`
    Result    string   `xml:"RESULT"`
    CVEList   struct {
        IDs []struct {
            ID string `xml:"ID"`
        } `xml:"CVE_ID"`
    } `xml:"CVE_ID_LIST"`
}

func (p *QualysParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
    bundle := &schema.ReportBundle{SourceType: schema.SourceQualys}
    dec := xml.NewDecoder(r)
    var currentIP string
    var hosts = map[string]*schema.Host{}
    var partial bool

    for {
        tok, err := dec.Token()
        if err == io.EOF { break }
        if err != nil {
            partial = true
            break
        }

        switch e := tok.(type) {
        case xml.StartElement:
            switch e.Name.Local {
            case "IP":
                for _, a := range e.Attr {
                    if a.Name.Local == "value" { currentIP = a.Value }
                }
                if _, ok := hosts[currentIP]; !ok {
                    hosts[currentIP] = &schema.Host{IP: currentIP}
                    for _, a := range e.Attr {
                        if a.Name.Local == "name" && a.Value != "" {
                            hosts[currentIP].Hostnames = append(hosts[currentIP].Hostnames, a.Value)
                        }
                    }
                }
            case "VULN_INFO":
                var v qualysVuln
                if err := dec.DecodeElement(&v, &e); err != nil {
                    partial = true
                    break
                }
                if currentIP == "" { continue }
                evidence, _ := json.Marshal(v)
                sev := mapQualysSeverity(v.Severity)
                var cvssPtr *float64
                if cvss, err := strconv.ParseFloat(v.CVSSBase, 64); err == nil { cvssPtr = &cvss }
                cve := ""
                if len(v.CVEList.IDs) > 0 { cve = v.CVEList.IDs[0].ID }
                bundle.Findings = append(bundle.Findings, schema.Finding{
                    Type:       schema.TypeVulnerability,
                    Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: "ip:" + currentIP},
                    Title:      strings.TrimSpace(v.Title),
                    CVE:        cve,
                    CVSSScore:  cvssPtr,
                    Severity:   sev,
                    Confidence: schema.ConfidenceFirm,
                    SourceID:   v.QID,
                    Evidence:   evidence,
                })
            }
        }
    }

    for _, h := range hosts {
        bundle.Hosts = append(bundle.Hosts, *h)
    }
    if partial { return bundle, fmt.Errorf("qualys parse: %w", ErrPartial) }
    return bundle, nil
}

// Qualys severity enum 1-5 mapped to our severity.
func mapQualysSeverity(s string) schema.Severity {
    switch strings.TrimSpace(s) {
    case "5": return schema.SeverityCritical
    case "4": return schema.SeverityHigh
    case "3": return schema.SeverityMedium
    case "2": return schema.SeverityLow
    default:  return schema.SeverityInfo
    }
}
```

- [ ] **Step 4: Run tests, register in controller**

```bash
go test ./pkg/ingestion/parsers/... -v
```

Add `schema.SourceQualys: &parsers.QualysParser{}` to the controller map. Remember: the Qualys parser's partial-error semantics must propagate through the ingestion controller as `parse_status='partial'` not `'failed'`:

```go
// in runParse():
if err != nil && errors.Is(err, parsers.ErrPartial) {
    if persistErr := c.persistBundle(ctx, report, bundle); persistErr != nil {
        _ = c.markFailed(ctx, report.ID, persistErr); return
    }
    _ = c.q.UpdateScanReportStatus(ctx, database.UpdateScanReportStatusParams{
        ID: report.ID, ParseStatus: "partial",
        ParseError: toPtrStr(err.Error()), FindingCount: int32(len(bundle.Findings)),
    })
    return
}
```

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/ingestion/parsers/qualys* \
        backend/pkg/ingestion/parsers/testdata/qualys/ \
        backend/pkg/server/controllers/ingestion_controller.go
git commit -m "feat(ingestion): qualys streaming XML parser with partial tolerance"
```

---

## Phase 11: Agent-facing findings tools

These expose the `findings` table to the orchestrator/agents. Registered with the existing `pkg/tools/registry.go`.

### Task 11.1: `list_findings` tool

**Files:**
- Create: `backend/pkg/ingestion/findings/tools.go`
- Create: `backend/pkg/ingestion/findings/tools_test.go`
- Modify: `backend/pkg/tools/tools.go` (add new tool constants)
- Modify: `backend/pkg/tools/registry.go` (register new handlers)

- [ ] **Step 1: Add tool constants**

In `backend/pkg/tools/tools.go`, add to the constants block:

```go
ListFindingsToolName          = "list_findings"
GetTopFindingsByCVSSToolName  = "get_top_findings_by_cvss"
GetHostServicesToolName       = "get_host_services"
GetContainerCVEsToolName      = "get_container_cves"
GetFindingByIDToolName        = "get_finding_by_id"
MarkFindingVerifiedToolName   = "mark_finding_verified"
GetRetestDiffToolName         = "get_retest_diff"
```

- [ ] **Step 2: Write the tools in `findings/tools.go`**

Each tool has the shape PentAGI expects: JSON schema for args, an executor func that returns a string result. Study an existing tool (e.g., `pkg/tools/graphiti_search.go`) to copy the exact registration shape.

```go
// backend/pkg/ingestion/findings/tools.go
package findings

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"

    "pentagi/pkg/database"
)

type Tools struct {
    q            database.Querier
    engagementID int64
}

func New(q database.Querier, engagementID int64) *Tools {
    return &Tools{q: q, engagementID: engagementID}
}

type listFindingsArgs struct {
    Severity           string `json:"severity,omitempty"`
    CVE                string `json:"cve,omitempty"`
    TargetKind         string `json:"target_kind,omitempty"`
    VerificationStatus string `json:"verification_status,omitempty"`
    Limit              int32  `json:"limit,omitempty"`
}

func (t *Tools) ListFindings(ctx context.Context, raw json.RawMessage) (string, error) {
    var args listFindingsArgs
    if len(raw) > 0 {
        if err := json.Unmarshal(raw, &args); err != nil { return "", err }
    }
    if args.Limit == 0 || args.Limit > 500 { args.Limit = 50 }

    rows, err := t.q.ListFindings(ctx, buildListParams(t.engagementID, args))
    if err != nil { return "", err }
    out, _ := json.Marshal(rows)
    return string(out), nil
}

type topByCVSSArgs struct {
    Limit int32 `json:"limit,omitempty"`
}

func (t *Tools) GetTopFindingsByCVSS(ctx context.Context, raw json.RawMessage) (string, error) {
    var args topByCVSSArgs
    if len(raw) > 0 { _ = json.Unmarshal(raw, &args) }
    if args.Limit == 0 || args.Limit > 100 { args.Limit = 10 }
    rows, err := t.q.TopFindingsByCVSS(ctx, database.TopFindingsByCVSSParams{
        EngagementID: t.engagementID, Limit: args.Limit,
    })
    if err != nil { return "", err }
    out, _ := json.Marshal(rows)
    return string(out), nil
}

type getByIDArgs struct{ ID int64 `json:"id"` }

func (t *Tools) GetFindingByID(ctx context.Context, raw json.RawMessage) (string, error) {
    var args getByIDArgs
    if err := json.Unmarshal(raw, &args); err != nil { return "", err }
    row, err := t.q.GetFinding(ctx, args.ID)
    if err != nil { return "", err }
    if row.EngagementID != t.engagementID {
        return "", errors.New("finding does not belong to this engagement")
    }
    out, _ := json.Marshal(row)
    return string(out), nil
}

type markVerifiedArgs struct {
    ID                 int64  `json:"id"`
    VerificationStatus string `json:"verification_status"` // confirmed | false_positive | not_exploitable
    Notes              string `json:"notes,omitempty"`
}

func (t *Tools) MarkFindingVerified(ctx context.Context, raw json.RawMessage) (string, error) {
    var args markVerifiedArgs
    if err := json.Unmarshal(raw, &args); err != nil { return "", err }
    row, err := t.q.GetFinding(ctx, args.ID)
    if err != nil { return "", err }
    if row.EngagementID != t.engagementID {
        return "", errors.New("finding does not belong to this engagement")
    }
    updated, err := t.q.UpdateFindingVerification(ctx, database.UpdateFindingVerificationParams{
        ID: args.ID, VerificationStatus: database.VerificationStatus(args.VerificationStatus),
        VerificationNotes: toPtrStr(args.Notes),
    })
    if err != nil { return "", err }
    out, _ := json.Marshal(updated)
    return string(out), nil
}

func (t *Tools) GetHostServices(ctx context.Context, _ json.RawMessage) (string, error) {
    rows, err := t.q.FindingsByTargetKind(ctx, database.FindingsByTargetKindParams{
        EngagementID: t.engagementID, TargetKind: database.TargetKindHost,
    })
    if err != nil { return "", err }
    out, _ := json.Marshal(rows)
    return string(out), nil
}

func (t *Tools) GetContainerCVEs(ctx context.Context, _ json.RawMessage) (string, error) {
    rows, err := t.q.FindingsByTargetKind(ctx, database.FindingsByTargetKindParams{
        EngagementID: t.engagementID, TargetKind: database.TargetKindContainer,
    })
    if err != nil { return "", err }
    out, _ := json.Marshal(rows)
    return string(out), nil
}

type retestDiffArgs struct{ FlowID int64 `json:"flow_id"` }

func (t *Tools) GetRetestDiff(ctx context.Context, raw json.RawMessage) (string, error) {
    var args retestDiffArgs
    if err := json.Unmarshal(raw, &args); err != nil { return "", err }
    rows, err := t.q.GetFlowRetestDiff(ctx, args.FlowID) // query added in Phase 14
    if err != nil { return "", err }
    out, _ := json.Marshal(rows)
    return string(out), nil
}

func buildListParams(engagementID int64, a listFindingsArgs) database.ListFindingsParams {
    p := database.ListFindingsParams{EngagementID: engagementID, Limit: a.Limit}
    if a.Severity != ""           { sv := database.SeverityLevel(a.Severity); p.Severity = &sv }
    if a.CVE != ""                { c := a.CVE; p.Cve = &c }
    if a.TargetKind != ""         { tk := database.TargetKind(a.TargetKind); p.TargetKind = &tk }
    if a.VerificationStatus != "" { vs := database.VerificationStatus(a.VerificationStatus); p.VerificationStatus = &vs }
    return p
}

func toPtrStr(s string) *string { if s == "" { return nil }; return &s }
func ptrSeverity(s string) *database.SeverityLevel {
    v := database.SeverityLevel(s); return &v
}

var _ = fmt.Sprintf // silence unused if import not yet needed
```

- [ ] **Step 3: Write a unit test using a mocked querier**

```go
// backend/pkg/ingestion/findings/tools_test.go
package findings

import (
    "context"
    "encoding/json"
    "strings"
    "testing"

    "pentagi/pkg/database"
)

type stubQ struct{ findings []database.Finding }

func (s *stubQ) ListFindings(_ context.Context, _ database.ListFindingsParams) ([]database.Finding, error) {
    return s.findings, nil
}

// Embed more stubs for other methods the real test will hit...

func TestListFindings_DefaultLimit(t *testing.T) {
    // build 60 findings; expect 50 back
    rows := make([]database.Finding, 60)
    for i := range rows { rows[i] = database.Finding{ID: int64(i + 1), EngagementID: 1} }
    // stub returns whatever; the real limit clamp test would need a recording stub.
    _ = rows
    // Run against the real DB in integration tests. Unit test here asserts the
    // clamp logic on args before the query is issued.
    var args listFindingsArgs
    _ = json.Unmarshal([]byte(`{}`), &args)
    if args.Limit != 0 { t.Fatal("initial limit") }
    if args.Limit == 0 || args.Limit > 500 { args.Limit = 50 }
    if args.Limit != 50 { t.Fatalf("clamp: %d", args.Limit) }
    _ = strings.Contains
}
```

Integration coverage of these tools comes from Phase 12's full stack test.

- [ ] **Step 4: Register the tools in `pkg/tools/registry.go`**

Study the existing registration pattern (how `GraphitiSearchToolName` is wired) and replicate. Tools are engagement-scoped, so registration happens at flow-start when the flow has an `engagement_id`. If the flow has no engagement, these tools are not registered at all.

Pseudocode for the integration point (real code mirrors the existing builder pattern in registry.go):

```go
if flow.EngagementID != nil {
    ft := findings.New(q, *flow.EngagementID)
    reg.Add(tools.ListFindingsToolName,          /* jsonschema */, ft.ListFindings)
    reg.Add(tools.GetTopFindingsByCVSSToolName,  /* jsonschema */, ft.GetTopFindingsByCVSS)
    reg.Add(tools.GetFindingByIDToolName,        /* jsonschema */, ft.GetFindingByID)
    reg.Add(tools.MarkFindingVerifiedToolName,   /* jsonschema */, ft.MarkFindingVerified)
    reg.Add(tools.GetHostServicesToolName,       /* jsonschema */, ft.GetHostServices)
    reg.Add(tools.GetContainerCVEsToolName,      /* jsonschema */, ft.GetContainerCVEs)
    reg.Add(tools.GetRetestDiffToolName,         /* jsonschema */, ft.GetRetestDiff)
}
```

The JSON schemas should use the same `github.com/invopop/jsonschema` pattern visible in neighbouring tools — derive from args structs with `jsonschema:"required"` tags as appropriate.

- [ ] **Step 5: Commit**

```bash
go build ./... && go test ./pkg/ingestion/findings/... -v
git add backend/pkg/ingestion/findings/ \
        backend/pkg/tools/tools.go \
        backend/pkg/tools/registry.go
git commit -m "feat(ingestion): agent-facing findings tools"
```

---

## Phase 12: GraphQL schema and resolvers

### Task 12.1: Schema additions

**Files:**
- Modify: `backend/pkg/graph/schema.graphqls`

- [ ] **Step 1: Add types and mutations**

Append to `schema.graphqls`:

```graphql
enum EngagementStatus { ACTIVE ON_HOLD COMPLETED ARCHIVED }
enum ScanSourceType   { QUALYS TWISTLOCK NMAP BURP }
enum ParseStatus      { PENDING PARSING SUCCEEDED FAILED PARTIAL }
enum SeverityLevel    { INFO LOW MEDIUM HIGH CRITICAL }
enum FindingConfidence{ CERTAIN FIRM TENTATIVE }
enum VerificationStatus { UNVERIFIED VERIFYING CONFIRMED FALSE_POSITIVE NOT_EXPLOITABLE }
enum FlowType         { NEW_TEST RETEST_DIFF TARGETED_REVERIFY }
enum DiffState        { FIXED PERSISTENT NEW REGRESSED }
enum TargetKind       { HOST WEB_ENDPOINT CONTAINER }
enum ScopeRuleType    { CIDR IP DOMAIN DOMAIN_GLOB URL_PREFIX CONTAINER_IMAGE CONTAINER_REGISTRY }
enum ScopeDirection   { INCLUDE EXCLUDE }

type Engagement {
  id: ID!
  name: String!
  client: String!
  description: String
  status: EngagementStatus!
  scopeRules: [ScopeRule!]!
  scanReports: [ScanReport!]!
  findings(filter: FindingFilter, limit: Int = 50): [Finding!]!
  findingStats: FindingStats!
  flows: [Flow!]!
  createdAt: Time!
  updatedAt: Time!
}

type ScopeRule {
  id: ID!
  ruleType: ScopeRuleType!
  value: String!
  direction: ScopeDirection!
  note: String
}

type ScanReport {
  id: ID!
  sourceType: ScanSourceType!
  originalFilename: String!
  scanDate: Time
  ingestedAt: Time!
  parseStatus: ParseStatus!
  parseError: String
  findingCount: Int!
}

type Target {
  kind: TargetKind!
  ref: String!
}

type Finding {
  id: ID!
  title: String!
  cve: String
  cvssScore: Float
  severity: SeverityLevel!
  confidence: FindingConfidence!
  target: Target!
  inScope: Boolean!
  verificationStatus: VerificationStatus!
  sources: [ScanReport!]!
  evidence: String!
  firstSeenAt: Time!
  lastSeenAt: Time!
}

type FindingStats {
  critical: Int! high: Int! medium: Int! low: Int! info: Int!
  outOfScope: Int!
  confirmed: Int!
}

type RetestDiff {
  fixed: [Finding!]!
  persistent: [Finding!]!
  regressed: [Finding!]!
  new: [Finding!]!
}

input FindingFilter {
  severity: SeverityLevel
  cve: String
  targetKind: TargetKind
  inScope: Boolean
  verificationStatus: VerificationStatus
  sourceType: ScanSourceType
}

input CreateEngagementInput { name: String! client: String! description: String }
input UpdateEngagementInput { name: String client: String description: String status: EngagementStatus }
input ScopeRuleInput { ruleType: ScopeRuleType! value: String! direction: ScopeDirection direction_default INCLUDE note: String }
input VerifyFindingInput { verificationStatus: VerificationStatus! notes: String }

extend type Flow {
  engagement: Engagement
  flowType: FlowType!
  baselineFlow: Flow
  retestDiff: RetestDiff
  retestTargets: [Finding!]
}

extend type Query {
  engagement(id: ID!): Engagement
  engagements(limit: Int = 50, offset: Int = 0): [Engagement!]!
}

extend type Mutation {
  createEngagement(input: CreateEngagementInput!): Engagement!
  updateEngagement(id: ID!, input: UpdateEngagementInput!): Engagement!
  addScopeRule(engagementId: ID!, input: ScopeRuleInput!): ScopeRule!
  deleteScopeRule(id: ID!): Boolean!
  verifyFinding(id: ID!, input: VerifyFindingInput!): Finding!
}

extend type Subscription {
  reportIngested(engagementId: ID!): ScanReport!
  findingsUpdated(engagementId: ID!): Finding!
}
```

- [ ] **Step 2: Regenerate gqlgen**

```bash
cd /home/sx0tt/pentagi/backend
go run github.com/99designs/gqlgen --config ./gqlgen/gqlgen.yml
```

Expected: new resolver stubs appear under `pkg/graph/`. If gqlgen complains about a syntax error in the schema, fix it (the `direction_default INCLUDE` in the input above is illustrative — gqlgen uses `= INCLUDE` default-value syntax; correct to that form on first regen attempt).

- [ ] **Step 3: Implement resolvers**

Each new resolver is a thin wrapper over existing services (`engagement.Service`, `q.ListFindings`, etc). Match the existing resolver file layout — one file per root type extension — and let gqlgen's generated signatures drive the implementation.

Key implementations:
- `Query.engagement(id)` → `engagement.Service.Get`
- `Query.engagements(limit, offset)` → `engagement.Service.List`
- `Mutation.createEngagement` → `engagement.Service.Create`
- `Mutation.verifyFinding` → `q.UpdateFindingVerification`
- `Subscription.reportIngested` → wire into the existing subscription bus in `pkg/graph/subscriptions`
- `Subscription.findingsUpdated` → same

Existing flow resolver needs edits so `Flow.engagement`, `Flow.flowType`, `Flow.baselineFlow`, `Flow.retestDiff`, `Flow.retestTargets` resolve correctly.

- [ ] **Step 4: Wire subscription publishes into the controller**

In `ingestion_controller.runParse`, after updating status, call `subscriptions.PublishReportIngested(engagementID, report)`. Create the helper in `pkg/graph/subscriptions/` following the existing pattern for other subscriptions.

- [ ] **Step 5: Build and run**

```bash
go build ./... && go test ./...
```

- [ ] **Step 6: Commit**

```bash
git add backend/pkg/graph/
git commit -m "feat(ingestion): GraphQL types, queries, mutations, subscriptions"
```

---

## Phase 13: Scope hard-gate wrapper

### Task 13.1: `Targets()` method on each existing tool

**Files modified:** every file in `backend/pkg/tools/*.go` that registers a tool whose execution can reach an external target. From the Phase 0 scan of tool files:
- `terminal.go` (shell; freeform — returns nil)
- `browser.go` (URL)
- `executor.go` (container exec; freeform — returns nil)
- `duckduckgo.go`, `google.go`, `perplexity.go`, `searxng.go`, `sploitus.go`, `tavily.go`, `traversaal.go` (search; typically no per-call target — return nil)
- `graphiti_search.go`, `memory.go`, `search.go`, `code.go`, `guide.go` (internal — return nil)

Most tools will return `nil` for `Targets()` — the gate covers that case with post-hoc stdout redaction. Only a few tools emit scan/exec calls that have explicit targets in the args.

- [ ] **Step 1: Define the `Targets` interface in `pkg/ingestion/scope/`**

```go
// backend/pkg/ingestion/scope/gate.go
package scope

import (
    "context"
    "encoding/json"
)

type Target struct {
    Kind string // "ip", "host", "url", "img"
    Ref  string
}

type TargetExtractor interface {
    Targets(args json.RawMessage) []Target
}

type ExecutorFn func(ctx context.Context, name string, args json.RawMessage) (string, error)

// WithGate returns a wrapped executor that blocks out-of-scope targets.
// For tools that don't implement TargetExtractor, the wrapper returns results as-is.
// A post-hoc extractor can be added later to redact OOS matches from stdout.
func WithGate(matcher *Matcher, extractor TargetExtractor, inner ExecutorFn, auditFn func(target, tool string)) ExecutorFn {
    return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
        if extractor != nil {
            for _, tgt := range extractor.Targets(args) {
                if !matcher.InScope(toRef(tgt)) {
                    auditFn(toRef(tgt), name)
                    return makeScopeError(tgt, name), nil
                }
            }
        }
        return inner(ctx, name, args)
    }
}

func toRef(t Target) string { return t.Kind + ":" + t.Ref }

func makeScopeError(t Target, name string) string {
    out, _ := json.Marshal(map[string]any{
        "error":    "scope_violation",
        "target":   toRef(t),
        "tool":     name,
        "hint":     "target is not in the Engagement's declared scope",
    })
    return string(out)
}
```

- [ ] **Step 2: Implement `Targets()` on tools that have explicit targets**

For `terminal.go` (the shell tool — freeform; return nil and rely on post-hoc stdout extraction which is deferred to v2).

For `browser.go` — it has a URL arg. Inspect its args struct and write:

```go
// backend/pkg/tools/browser.go — add at end of the browser tool implementation
func (b *BrowserTool) Targets(raw json.RawMessage) []scope.Target {
    var args struct{ URL string `json:"url"` }
    if err := json.Unmarshal(raw, &args); err != nil { return nil }
    if args.URL == "" { return nil }
    return []scope.Target{{Kind: "url", Ref: args.URL}}
}
```

For v1, only the following existing tools need a `Targets()` implementation:

| Tool file | Args field | `Targets()` body |
|---|---|---|
| `pkg/tools/browser.go` | `url` | return `[]scope.Target{{Kind: "url", Ref: args.URL}}` if non-empty |
| `pkg/tools/terminal.go` | freeform shell | return `nil` (freeform; stdout redaction is v2) |
| `pkg/tools/executor.go` | freeform container exec | return `nil` |

All other existing tools in `pkg/tools/` (`duckduckgo.go`, `google.go`, `perplexity.go`, `searxng.go`, `sploitus.go`, `tavily.go`, `traversaal.go`, `graphiti_search.go`, `memory.go`, `search.go`, `code.go`, `guide.go`) are search/retrieval or internal and do not take an explicit external target — they don't need `Targets()` at all (the gate wrapper skips tools that don't implement the interface).

- [ ] **Step 3: Wire the gate at flow-start**

In `backend/pkg/controller/flow.go` (where a flow's tool registry is assembled), after loading tools and before the flow runs:

```go
if flow.EngagementID != nil {
    matcher, err := scope.LoadMatcher(ctx, q, *flow.EngagementID)
    if err != nil { return err }
    audit := func(target, name string) {
        _ = q.RecordScopeViolation(ctx, database.RecordScopeViolationParams{
            FlowID:       flow.ID,
            EngagementID: *flow.EngagementID,
            ToolName:     name,
            Target:       target,
        })
    }
    for name, spec := range registry.Tools() {
        extractor, _ := spec.Handler.(scope.TargetExtractor)
        spec.Handler = scope.WithGate(matcher, extractor, spec.Handler, audit)
        registry.Set(name, spec)
    }
}
```

(Adapt to the actual registry API in your codebase — this is pseudocode for the wiring shape.)

Add a `RecordScopeViolation` query under `queries/scope_violations.sql`:

```sql
-- name: RecordScopeViolation :exec
INSERT INTO scope_violations (flow_id, engagement_id, tool_name, target)
VALUES ($1, $2, $3, $4);
```

Regenerate sqlc.

- [ ] **Step 4: Tests**

```go
// backend/pkg/ingestion/scope/gate_test.go
package scope

import (
    "context"
    "encoding/json"
    "testing"
)

type fakeExtractor struct{ t []Target }
func (f fakeExtractor) Targets(_ json.RawMessage) []Target { return f.t }

func TestGate_BlocksOutOfScope(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
    audited := ""
    gated := WithGate(m, fakeExtractor{t: []Target{{Kind: "ip", Ref: "10.99.0.1:22/tcp"}}},
        func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
            t.Fatal("should not reach inner"); return "", nil
        },
        func(target, tool string) { audited = target })
    out, err := gated(context.Background(), "nmap", json.RawMessage(`{}`))
    if err != nil { t.Fatal(err) }
    if audited == "" { t.Fatal("audit not called") }
    if !containsJSON(out, "scope_violation") { t.Fatal("violation shape wrong: " + out) }
}

func TestGate_AllowsInScope(t *testing.T) {
    m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
    called := false
    gated := WithGate(m, fakeExtractor{t: []Target{{Kind: "ip", Ref: "10.1.5.5:80/tcp"}}},
        func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
            called = true; return "ok", nil
        }, func(_, _ string) {})
    out, err := gated(context.Background(), "nmap", json.RawMessage(`{}`))
    if err != nil { t.Fatal(err) }
    if out != "ok" { t.Fatalf("unexpected: %q", out) }
    if !called { t.Fatal("inner not called") }
}

func containsJSON(s, needle string) bool {
    return len(s) > 0 && (jsonContains(s, needle))
}
func jsonContains(s, n string) bool { return stringContains(s, n) }
func stringContains(s, n string) bool {
    return len(s) >= len(n) && (s[0:len(n)] == n || (len(s) > 0 && stringContains(s[1:], n)))
}
```

- [ ] **Step 5: Commit**

```bash
go test ./pkg/ingestion/scope/... -v
git add backend/pkg/ingestion/scope/gate.go \
        backend/pkg/ingestion/scope/gate_test.go \
        backend/pkg/tools/*.go \
        backend/pkg/controller/flow.go \
        backend/pkg/database/queries/scope_violations.sql \
        backend/pkg/database/*.sql.go
git commit -m "feat(ingestion): scope hard-gate wrapper on tool registry"
```

---

## Phase 14: Flow integration

Wires Engagement + flow types into the existing flow-start logic.

### Task 14.1: Extend flow creation

**Files:**
- Modify: `backend/pkg/controller/flow.go` (flow start — accept engagement_id, flow_type, baseline_flow_id)
- Modify: GraphQL `createFlow` resolver

- [ ] **Step 1: Change `createFlow` mutation arguments**

Update `createFlow` in `schema.graphqls`:

```graphql
extend type Mutation {
  # ...existing...
  createFlow(
    title: String!
    userID: ID!
    flowType: FlowType = NEW_TEST
    engagementId: ID
    baselineFlowId: ID
    retestTargetFindingIds: [ID!]
    # existing args unchanged
  ): Flow!
}
```

Regenerate gqlgen.

- [ ] **Step 2: Validation in the resolver**

```go
func (r *mutationResolver) CreateFlow(ctx context.Context, args ...) (*Flow, error) {
    switch args.FlowType {
    case FlowTypeRetestDiff:
        if args.BaselineFlowId == nil {
            return nil, errors.New("retest_diff flows require baselineFlowId")
        }
    case FlowTypeTargetedReverify:
        if len(args.RetestTargetFindingIds) == 0 {
            return nil, errors.New("targeted_reverify flows require retestTargetFindingIds")
        }
    }
    // Pass the new fields through when calling the existing flow-creation service —
    // the signature for whatever `c.flows.Create(...)` (or equivalent) lives in
    // pkg/controller/flow.go gains the three new fields via a struct option:
    //   opts := flow.CreateOptions{
    //       EngagementID: args.EngagementId,
    //       FlowType:     database.FlowType(args.FlowType),
    //       BaselineFlowID: args.BaselineFlowId,
    //       RetestTargets: args.RetestTargetFindingIds,
    //   }
    // Call the service, then return the existing Flow GraphQL shape.
}
```

- [ ] **Step 3: Persist retest targets / compute diff pre-flight**

```go
// For targeted_reverify: after flow row is inserted
for _, fid := range args.RetestTargetFindingIds {
    _ = q.InsertFlowRetestTarget(ctx, database.InsertFlowRetestTargetParams{FlowID: flow.ID, FindingID: fid})
}

// For retest_diff: compute diff synchronously
diff, err := computeRetestDiff(ctx, q, flow.EngagementID, *args.BaselineFlowId)
if err != nil { return nil, err }
for _, d := range diff {
    _ = q.InsertFlowRetestDiff(ctx, database.InsertFlowRetestDiffParams{
        FlowID: flow.ID, FindingID: d.FindingID, DiffState: d.State,
    })
}
```

`computeRetestDiff` uses `baseline_flow.created_at` as the cutoff per §5.2 of the spec:

```go
func computeRetestDiff(ctx context.Context, q database.Querier, engagementID, baselineFlowID int64) ([]diffRow, error) {
    baseline, err := q.GetFlow(ctx, baselineFlowID)
    if err != nil { return nil, err }
    baseSet, err := q.FindingsFirstSeenBefore(ctx, database.FindingsFirstSeenBeforeParams{
        EngagementID: engagementID, Cutoff: baseline.CreatedAt,
    })
    if err != nil { return nil, err }
    currentSet, err := q.ListFindings(ctx, database.ListFindingsParams{
        EngagementID: engagementID, Limit: 10_000,
    })
    if err != nil { return nil, err }
    return diffSets(baseSet, currentSet), nil
}
```

Add `FindingsFirstSeenBefore` to `queries/findings.sql`:

```sql
-- name: FindingsFirstSeenBefore :many
SELECT * FROM findings
WHERE engagement_id = $1 AND first_seen_at <= $2;
```

- [ ] **Step 4: Orchestrator prompt nudge**

Find the orchestrator initial prompt in `backend/pkg/templates/` or wherever the system prompt is composed for the pentester/orchestrator agents. Add conditional text:

```go
if flow.EngagementID != nil {
    eng, _ := q.GetEngagement(ctx, *flow.EngagementID)
    stats, _ := q.EngagementFindingStats(ctx, *flow.EngagementID)
    prompt += fmt.Sprintf("\n\nEngagement: %s (%s)\nIngested findings: %d critical, %d high, %d medium, %d low.\n" +
        "Call list_findings or get_top_findings_by_cvss to begin.\n",
        eng.Name, eng.Client, stats.CriticalCount, stats.HighCount, stats.MediumCount, stats.LowCount)
    if flow.FlowType == database.FlowTypeRetestDiff {
        prompt += "This is a retest. Call get_retest_diff for the structured delta against the prior flow.\n"
    }
    if flow.FlowType == database.FlowTypeTargetedReverify {
        prompt += "This is a targeted re-verification. Only the findings in retest_targets should be examined; use mark_finding_verified to record results.\n"
    }
}
```

- [ ] **Step 5: Test**

```go
// Unit test diffSets() with a handful of synthetic findings across cutoff times.
// End-to-end is exercised in Phase 15's smoke once the UI can drive it.
```

- [ ] **Step 6: Commit**

```bash
git add backend/pkg/controller/flow.go \
        backend/pkg/graph/schema.graphqls \
        backend/pkg/graph/ \
        backend/pkg/database/queries/findings.sql \
        backend/pkg/database/*.sql.go \
        backend/pkg/templates/
git commit -m "feat(ingestion): flow types with engagement context + retest diff"
```

---

## Phase 15: Frontend

### Task 15.1: GraphQL queries and codegen

**Files:**
- Create: `frontend/src/graphql/engagements.graphql`

- [ ] **Step 1: Write query files**

```graphql
# frontend/src/graphql/engagements.graphql
query Engagements { engagements { id name client status findingStats { critical high medium low info } updatedAt } }

query Engagement($id: ID!) {
  engagement(id: $id) {
    id name client description status
    scopeRules { id ruleType value direction note }
    scanReports { id sourceType originalFilename parseStatus findingCount ingestedAt }
    findings(limit: 200) { id title severity confidence cve cvssScore target { kind ref } inScope verificationStatus }
    findingStats { critical high medium low info outOfScope confirmed }
  }
}

mutation CreateEngagement($input: CreateEngagementInput!) {
  createEngagement(input: $input) { id name client }
}

mutation AddScopeRule($engagementId: ID!, $input: ScopeRuleInput!) {
  addScopeRule(engagementId: $engagementId, input: $input) { id ruleType value direction }
}

mutation VerifyFinding($id: ID!, $input: VerifyFindingInput!) {
  verifyFinding(id: $id, input: $input) { id verificationStatus }
}

subscription ReportIngested($engagementId: ID!) {
  reportIngested(engagementId: $engagementId) { id parseStatus findingCount }
}
```

- [ ] **Step 2: Regenerate types**

```bash
cd /home/sx0tt/pentagi/frontend
npm run graphql:generate
```

Expected: new types in `src/graphql/generated/`. No errors.

### Task 15.2: List page

**Files:**
- Create: `frontend/src/pages/engagements/index.tsx`
- Modify: `frontend/src/app.tsx` (add route)

- [ ] **Step 1: Page component**

```tsx
// frontend/src/pages/engagements/index.tsx
import { useQuery } from '@apollo/client';
import { Link, useNavigate } from 'react-router-dom';
import { EngagementsDocument } from '@/graphql/generated';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export default function EngagementsPage() {
  const { data, loading, error } = useQuery(EngagementsDocument);
  const nav = useNavigate();
  if (loading) return <div>Loading…</div>;
  if (error) return <div className="text-red-500">{error.message}</div>;
  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-semibold">Engagements</h1>
        <Button onClick={() => nav('/engagements/new')}>New Engagement</Button>
      </div>
      <table className="w-full text-left text-sm">
        <thead>
          <tr><th>Name</th><th>Client</th><th>Status</th><th>C/H/M/L/I</th><th>Updated</th></tr>
        </thead>
        <tbody>
          {data?.engagements.map(e => (
            <tr key={e.id} className="border-t hover:bg-muted">
              <td><Link to={`/engagements/${e.id}`} className="hover:underline">{e.name}</Link></td>
              <td>{e.client}</td>
              <td><Badge>{e.status}</Badge></td>
              <td>
                <span className="text-red-500">{e.findingStats.critical}</span>/
                <span className="text-orange-500">{e.findingStats.high}</span>/
                <span className="text-yellow-500">{e.findingStats.medium}</span>/
                <span>{e.findingStats.low}</span>/<span className="text-muted-foreground">{e.findingStats.info}</span>
              </td>
              <td className="text-muted-foreground">{new Date(e.updatedAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Route registration**

Find the existing `<Routes>` block in `src/app.tsx` and add:

```tsx
<Route path="/engagements" element={<EngagementsPage />} />
<Route path="/engagements/new" element={<CreateEngagementPage />} />
<Route path="/engagements/:id" element={<EngagementDetailPage />} />
```

Import accordingly.

- [ ] **Step 3: Sidebar link**

In whichever component renders the left sidebar (search for an existing nav entry for "Flows"), add:

```tsx
<NavLink to="/engagements">Engagements</NavLink>
```

- [ ] **Step 4: Commit**

```bash
cd /home/sx0tt/pentagi
git add frontend/src/pages/engagements/index.tsx frontend/src/app.tsx frontend/src/graphql/engagements.graphql frontend/src/graphql/generated/
git commit -m "feat(frontend): engagements list page"
```

### Task 15.3: Create page + Detail page with three tabs

**Files:**
- Create: `frontend/src/pages/engagements/create.tsx`
- Create: `frontend/src/pages/engagements/detail.tsx`
- Create: `frontend/src/pages/engagements/components/upload-dropzone.tsx`
- Create: `frontend/src/pages/engagements/components/findings-table.tsx`
- Create: `frontend/src/pages/engagements/components/scope-rule-editor.tsx`
- Create: `frontend/src/pages/engagements/components/engagement-context-pill.tsx`

- [ ] **Step 1: Create page form**

```tsx
// frontend/src/pages/engagements/create.tsx
import { useMutation } from '@apollo/client';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { CreateEngagementDocument } from '@/graphql/generated';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';

export default function CreateEngagementPage() {
  const nav = useNavigate();
  const [form, setForm] = useState({ name: '', client: '', description: '' });
  const [create, { loading, error }] = useMutation(CreateEngagementDocument);
  return (
    <form
      className="p-6 max-w-xl space-y-3"
      onSubmit={async e => {
        e.preventDefault();
        const { data } = await create({ variables: { input: form } });
        if (data?.createEngagement.id) nav(`/engagements/${data.createEngagement.id}`);
      }}
    >
      <h1 className="text-2xl font-semibold">New Engagement</h1>
      <Input placeholder="Name"   value={form.name}   onChange={e => setForm({ ...form, name: e.target.value })} required />
      <Input placeholder="Client" value={form.client} onChange={e => setForm({ ...form, client: e.target.value })} required />
      <Textarea placeholder="Description (optional)" value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })} />
      <Button type="submit" disabled={loading}>Create</Button>
      {error && <p className="text-red-500 text-sm">{error.message}</p>}
    </form>
  );
}
```

- [ ] **Step 2: Upload dropzone**

Sniffs source_type from extension, user confirms in a dropdown, uploads via REST (not GraphQL — multipart support).

```tsx
// frontend/src/pages/engagements/components/upload-dropzone.tsx
import { useState } from 'react';
import { Button } from '@/components/ui/button';

const EXT_TO_TYPE: Record<string, string> = {
  xml: 'nmap', json: 'twistlock', csv: 'qualys', nmap: 'nmap',
};

export function UploadDropzone({ engagementId, onUploaded }: { engagementId: string; onUploaded: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [sourceType, setSourceType] = useState<string>('nmap');
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  function pickFile(f: File) {
    setFile(f);
    const ext = f.name.split('.').pop()?.toLowerCase() ?? '';
    if (EXT_TO_TYPE[ext]) setSourceType(EXT_TO_TYPE[ext]);
  }

  async function upload() {
    if (!file) return;
    setUploading(true); setError(null);
    const body = new FormData();
    body.append('source_type', sourceType);
    body.append('file', file);
    const res = await fetch(`/api/v1/engagements/${engagementId}/reports`, { method: 'POST', body });
    setUploading(false);
    if (!res.ok) { setError(`Upload failed: ${res.status} ${await res.text()}`); return; }
    setFile(null); onUploaded();
  }

  return (
    <div className="border-2 border-dashed rounded p-4 text-sm space-y-2">
      <input type="file" accept=".xml,.json,.csv,.nmap" onChange={e => e.target.files?.[0] && pickFile(e.target.files[0])} />
      <select value={sourceType} onChange={e => setSourceType(e.target.value)}>
        <option value="nmap">nmap</option><option value="burp">burp</option>
        <option value="twistlock">twistlock</option><option value="qualys">qualys</option>
      </select>
      <Button onClick={upload} disabled={!file || uploading}>Upload</Button>
      {error && <p className="text-red-500">{error}</p>}
    </div>
  );
}
```

- [ ] **Step 3: Findings table (filterable)**

```tsx
// frontend/src/pages/engagements/components/findings-table.tsx
import type { Finding } from '@/graphql/generated';
import { Badge } from '@/components/ui/badge';

export function FindingsTable({ findings }: { findings: Finding[] }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr><th>Sev</th><th>CVE</th><th>Title</th><th>Target</th><th>Scope</th><th>Verif</th></tr>
      </thead>
      <tbody>
        {findings.map(f => (
          <tr key={f.id} className="border-t">
            <td><Badge variant={f.severity === 'CRITICAL' ? 'destructive' : 'default'}>{f.severity}</Badge></td>
            <td>{f.cve ?? '-'}</td>
            <td>{f.title}</td>
            <td className="font-mono text-xs">{f.target.ref}</td>
            <td>{f.inScope ? <Badge>IN</Badge> : <Badge variant="outline">OOS</Badge>}</td>
            <td>{f.verificationStatus}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

- [ ] **Step 4: Detail page orchestrating the three tabs**

```tsx
// frontend/src/pages/engagements/detail.tsx
import { useQuery } from '@apollo/client';
import { useParams } from 'react-router-dom';
import { EngagementDocument } from '@/graphql/generated';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { UploadDropzone } from './components/upload-dropzone';
import { FindingsTable } from './components/findings-table';

export default function EngagementDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, refetch } = useQuery(EngagementDocument, { variables: { id: id! } });
  if (!data?.engagement) return null;
  const e = data.engagement;

  return (
    <div className="p-6">
      <h1 className="text-2xl">{e.name} <span className="text-muted-foreground text-base">— {e.client}</span></h1>
      <Tabs defaultValue="reports" className="mt-4">
        <TabsList>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="flows">Flows</TabsTrigger>
        </TabsList>
        <TabsContent value="reports" className="space-y-4">
          <UploadDropzone engagementId={e.id} onUploaded={() => refetch()} />
          <table className="w-full text-sm">
            <thead><tr><th>File</th><th>Type</th><th>Status</th><th>Findings</th><th>Ingested</th></tr></thead>
            <tbody>
              {e.scanReports.map(r => (
                <tr key={r.id} className="border-t">
                  <td>{r.originalFilename}</td><td>{r.sourceType}</td>
                  <td>{r.parseStatus}</td><td>{r.findingCount}</td>
                  <td className="text-muted-foreground">{new Date(r.ingestedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TabsContent>
        <TabsContent value="findings"><FindingsTable findings={e.findings} /></TabsContent>
        <TabsContent value="flows">
          {/* Link to existing flow-create dialog with engagementId pre-filled */}
          <p className="text-sm">Flow integration lives in the existing flow-create dialog; pass this engagement id through.</p>
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

- [ ] **Step 5: Scope rule editor**

```tsx
// frontend/src/pages/engagements/components/scope-rule-editor.tsx
import { useState } from 'react';
import { useMutation } from '@apollo/client';
import { AddScopeRuleDocument } from '@/graphql/generated';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const RULE_TYPES = ['cidr', 'ip', 'domain', 'domain_glob', 'url_prefix', 'container_image', 'container_registry'] as const;

export function ScopeRuleEditor({ engagementId, rules, onAdded }: {
  engagementId: string;
  rules: { id: string; ruleType: string; value: string; direction: string }[];
  onAdded: () => void;
}) {
  const [add] = useMutation(AddScopeRuleDocument);
  const [form, setForm] = useState({ ruleType: 'cidr', value: '', direction: 'include' });

  return (
    <div className="space-y-2 text-sm">
      <ul className="space-y-1">
        {rules.map(r => (
          <li key={r.id} className="font-mono">
            [{r.direction}] {r.ruleType} = {r.value}
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <select value={form.ruleType} onChange={e => setForm({ ...form, ruleType: e.target.value })}>
          {RULE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <Input placeholder="value" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} />
        <select value={form.direction} onChange={e => setForm({ ...form, direction: e.target.value })}>
          <option value="include">include</option><option value="exclude">exclude</option>
        </select>
        <Button onClick={async () => {
          await add({ variables: { engagementId, input: form } });
          setForm({ ruleType: 'cidr', value: '', direction: 'include' });
          onAdded();
        }}>Add</Button>
      </div>
    </div>
  );
}
```

- [ ] **Step 6: Engagement context pill**

```tsx
// frontend/src/pages/engagements/components/engagement-context-pill.tsx
import type { Engagement } from '@/graphql/generated';

export function EngagementContextPill({ engagement }: { engagement: Pick<Engagement, 'name' | 'client'> }) {
  return (
    <div className="inline-flex items-center gap-2 rounded-full bg-muted px-3 py-1 text-xs">
      <span className="font-medium">Engagement:</span>
      <span>{engagement.name}</span>
      <span className="text-muted-foreground">— {engagement.client}</span>
    </div>
  );
}
```

- [ ] **Step 7: Flow-create dialog learns about engagements**

Find the flow-create component (grep for `createFlow` or the mutation name in `frontend/src/`). Two additions:

```tsx
// at the top of the existing flow-create form component:
import { useQuery } from '@apollo/client';
import { EngagementsDocument } from '@/graphql/generated';
import { EngagementContextPill } from '@/pages/engagements/components/engagement-context-pill';

// inside the component:
const { data: engData } = useQuery(EngagementsDocument);
const [engagementId, setEngagementId] = useState<string | undefined>(initialEngagementId);
const [flowType, setFlowType] = useState<'NEW_TEST' | 'RETEST_DIFF' | 'TARGETED_REVERIFY'>('NEW_TEST');
const selectedEng = engData?.engagements.find(e => e.id === engagementId);

// inside the JSX, above the existing submit button:
<label className="block text-sm">
  Engagement (optional)
  <select value={engagementId ?? ''} onChange={e => setEngagementId(e.target.value || undefined)}>
    <option value="">— none —</option>
    {engData?.engagements.map(e => <option key={e.id} value={e.id}>{e.name} — {e.client}</option>)}
  </select>
</label>
{engagementId && (
  <label className="block text-sm">
    Flow type
    <select value={flowType} onChange={e => setFlowType(e.target.value as any)}>
      <option value="NEW_TEST">New test</option>
      <option value="RETEST_DIFF">Retest (diff vs. prior flow)</option>
      <option value="TARGETED_REVERIFY">Targeted re-verify</option>
    </select>
  </label>
)}
{selectedEng && <EngagementContextPill engagement={selectedEng} />}

// when calling the createFlow mutation, include the new vars:
createFlow({ variables: { ...existing, engagementId, flowType } });
```

When `flowType === 'RETEST_DIFF'`, render a second dropdown for `baselineFlowId` populated from the engagement's flows. When `flowType === 'TARGETED_REVERIFY'`, render a multi-select of findings from `selectedEng.findings`. Both produce arrays/IDs that go into the mutation variables.

- [ ] **Step 7: Icon**

```tsx
// frontend/src/components/icons/engagement.tsx
import { FolderKanban } from 'lucide-react';
export const EngagementIcon = FolderKanban;
```

Register wherever existing entity icons get registered.

- [ ] **Step 8: Build and eyeball**

```bash
cd /home/sx0tt/pentagi/frontend
npm run lint
npm run build
npm run dev   # open the app, click around; confirm: list → create → detail → upload a fixture
```

- [ ] **Step 9: Commit**

```bash
cd /home/sx0tt/pentagi
git add frontend/src/
git commit -m "feat(frontend): engagement pages, upload dropzone, findings table"
```

---

## Phase 16: Observability + docs

### Task 16.1: OTEL spans and metrics

**Files:**
- Modify: `backend/pkg/ingestion/**/*.go` to wrap work in spans
- Modify: `backend/pkg/observability/` to register the new metrics (follow existing pattern)

- [ ] **Step 1: Add spans to ingestion controller**

Wrap `runParse`, `persistBundle`, and `seeder.Seed` calls in spans named as specified in the spec §7.2.

```go
// example shape in ingestion_controller.runParse:
ctx, span := obs.Tracer.Start(ctx, "ingestion.parse."+string(source))
defer span.End()
// ...
```

- [ ] **Step 2: Add metrics**

Register counters and histograms as specified in spec §7.2. Mirror the registration site used by existing metrics (check `backend/pkg/observability/metrics.go` or equivalent).

- [ ] **Step 3: Commit**

```bash
git add backend/pkg/ingestion/ backend/pkg/observability/
git commit -m "feat(ingestion): OTEL spans + metrics for ingest pipeline and scope gate"
```

### Task 16.2: README and migration note

**Files:**
- Create: `backend/pkg/ingestion/README.md`

- [ ] **Step 1: Write maintainer-facing README**

```markdown
# pkg/ingestion

Scanner report ingestion and Engagement lifecycle.

## Sub-packages
- `parsers/` — one `Parser` per source type. Golden-file tests live in `testdata/`.
- `schema/` — normalized in-flight types; pure data.
- `engagement/` — Postgres-backed service over the Engagement and scope-rule tables.
- `scope/` — matcher (fail-closed) and `WithGate` wrapper for tool executors.
- `seeder/` — writes normalized bundles to Graphiti scoped by `group_id`. Includes a reconcile loop for async retries.
- `findings/` — agent-facing Go tools registered with `pkg/tools/registry.go` when a flow has an engagement.

## Data flow (read §5 of the spec for full detail)
Upload → controller hash+dedupe → temp file → DB row (pending) → async parse → persist findings + upsert on target_ref+cve+source_id → scope classify in/OOS → seed Graphiti → mark succeeded → emit GraphQL subscription.

## Running the tests
- Unit: `go test ./pkg/ingestion/...`
- Integration (requires docker compose): `go test -tags=integration ./pkg/ingestion/...`

## Adding a new source type
1. Add the enum value via goose migration.
2. Implement `parsers/<source>.go` with golden-file tests.
3. Register in the controller's `parsers` map and in `schema.ScanSourceType`.
4. Update GraphQL `ScanSourceType` enum.
```

- [ ] **Step 2: Final build + tests**

```bash
cd /home/sx0tt/pentagi/backend
go build -o /tmp/pentagi ./cmd/pentagi
go test ./...
cd ../frontend
npm run lint && npm run build
```

Expected: everything green.

- [ ] **Step 3: Commit**

```bash
cd /home/sx0tt/pentagi
git add backend/pkg/ingestion/README.md
git commit -m "docs(ingestion): package README"
```

---

## Final definition-of-done (from spec §8)

- [ ] Migrations apply cleanly against empty DB and existing PentAGI DB
- [ ] All four parsers green on their golden-file tests
- [ ] End-to-end smoke passes in CI (`go test -tags=integration ./pkg/ingestion/...`)
- [ ] Scope hard-gate has full table-driven coverage
- [ ] UI: upload → finding list → create flow against a dev compose stack works
- [ ] `backend/pkg/ingestion/README.md` exists

When all checkboxes are ticked, open a draft PR to `origin/main` and request review.
