# Scanner Report Ingestion & Engagement Model — Design Spec

**Status:** Draft for review
**Date:** 2026-04-21
**Owner:** sx0tt
**Repo:** `ScottGunn22/pentagi` (fork of `vxcontrol/pentagi`)

## 1. Overview

PentAGI today starts each pentest flow from a cold context — the researcher agent discovers the target surface live. Real pentest engagements rarely work that way: the customer hands over Qualys exports, Twistlock/Aqua container scans, nmap sweeps, and Burp reports on day one, and the pentester works from that data.

This spec adds an ingestion layer that parses those four scanner outputs into a normalized schema, persists them, seeds them into a per-Engagement Graphiti knowledge-graph partition, exposes them to the agents through purpose-built Go tools, and hard-gates all agent tool calls at the declared engagement scope.

The feature also adds a new top-level entity — **Engagement** — that groups all scans, findings, and flows under a single SOW, enabling retests and targeted re-verification of prior findings.

## 2. Decisions captured

| Decision | Choice |
|---|---|
| Delivery model | Fork-and-extend of upstream PentAGI |
| Scanner formats in v1 | Qualys, Twistlock, Nmap, Burp (Aqua → v2) |
| Hardening priority | Qualys > Twistlock > Nmap > Burp |
| Implementation sequencing | Start nmap (simplest) to prove pipeline; Qualys last for hardening |
| Entry points | REST/GraphQL endpoint + thin React UI upload page |
| Top-level grouping | `Engagement` entity above `Flow` |
| UI label | "Engagement" (industry standard term) |
| Flow types | `new_test`, `retest_diff`, `targeted_reverify` |
| Findings → agents | Graph seeding + dedicated Go tools + small prompt nudge |
| Scope enforcement at ingest | I-B: soft-tag out-of-scope findings (`in_scope=false`) |
| Scope enforcement at runtime | R-A: hard-gate at tool layer (no OOS targets executed) |
| Verification workflow | Data model only in v1 (`verification_status` field + tool); orchestrator "verify first" workflow deferred to v2 |
| Access control | Solo semantics in v1; schema forward-compatible (`team_id`, `created_by`, `updated_by` stubs) |
| Package layout | New top-level `backend/pkg/ingestion/` with subpackages by responsibility |
| Raw file retention | Uploaded reports retained on storage backend for audit / re-parse |
| Finding deduplication | Junction `finding_sources` dedups same logical finding across multiple reports |

## 3. Architecture

```
┌──────────────┐   upload    ┌──────────────────────┐
│ User (UI/API)│────────────▶│ pkg/server/controllers│
└──────────────┘              │   /ingestion         │
                              └──────────┬───────────┘
                                         ▼
                    ┌─────────────────────────────────────┐
                    │      pkg/ingestion                  │
                    │  ┌───────────────────────────────┐  │
                    │  │ parsers/ (qualys/twistlock/   │  │
                    │  │           nmap/burp)          │  │
                    │  └──────────────┬────────────────┘  │
                    │  ┌──────────────▼────────────────┐  │
                    │  │ schema/  normalized Findings  │  │
                    │  └──────────────┬────────────────┘  │
                    │                 ▼                   │
                    │       ┌────────────────┐            │
                    │       │ engagement/    │──▶ Postgres│
                    │       │ (repo + model) │            │
                    │       └───────┬────────┘            │
                    │               ▼                     │
                    │       ┌────────────────┐            │
                    │       │ seeder/        │──▶ Graphiti│
                    │       │ (group_id-     │  (Neo4j)   │
                    │       │  scoped)       │            │
                    │       └────────────────┘            │
                    │       ┌────────────────┐            │
                    │       │ findings/      │──▶ agent   │
                    │       │ (Go tools for  │   tool     │
                    │       │  agents)       │   registry │
                    │       └────────────────┘            │
                    │       ┌────────────────┐            │
                    │       │ scope/         │──▶ hard-   │
                    │       │ (R-A matcher)  │   gate all │
                    │       │                │   existing │
                    │       │                │   tools    │
                    │       └────────────────┘            │
                    └─────────────────────────────────────┘
```

### 3.1 Package layout (`backend/pkg/ingestion/`)

| Subpackage | Responsibility | Key interface |
|---|---|---|
| `parsers/` | Per-format readers; each parser takes an `io.Reader` and returns a `schema.ReportBundle`. | `Parser.Parse(r io.Reader) (*schema.ReportBundle, error)` with one impl per format: `qualys.go`, `twistlock.go`, `nmap.go`, `burp.go`. |
| `schema/` | Normalized Go types: `ReportBundle`, `Host`, `Service`, `Finding`, `Container`, `WebEndpoint`, `EvidenceRef`. Pure data, no DB/JSON coupling. | Types + `Validate()` helpers. |
| `engagement/` | `Engagement` aggregate, Postgres repo, scope definition, Graphiti `group_id` assignment. | `Service.Create`, `Get`, `List`, `AttachReport`, `ListFindings`. |
| `seeder/` | Takes a `ReportBundle` + `group_id`, writes entities/edges to Graphiti idempotently. Reconcile loop for retries. | `Seeder.Seed(ctx, bundle, groupID) error`. |
| `findings/` | Agent-facing Go tools: `list_findings`, `get_top_findings_by_cvss`, `get_host_services`, `get_container_cves`, `get_finding_by_id`, `mark_finding_verified`, `get_retest_diff`. Registers with the existing `pkg/tools/registry.go`. | Each tool implements the existing `Tool` interface. |
| `scope/` | Matcher: "is this IP / domain / URL / container image in Engagement X's scope?" Backs the R-A hard-gate. Wraps existing tool registrations at flow start. | `Matcher.InScope(target, engagementID) bool`; `WithScopeGate(matcher)` wrapper. |

### 3.2 Touchpoints outside `pkg/ingestion/`

- **`backend/pkg/database/`** — new tables (§4.1), Engagement FK added to `flows` as nullable, new enums.
- **`backend/pkg/server/controllers/`** — new `ingestion_controller.go` for REST handlers.
- **`backend/pkg/graph/schema.graphqls`** — new types (`Engagement`, `ScanReport`, `Finding`, `ScopeRule`, `RetestDiff`), queries, mutations, subscriptions; existing `createFlow` mutation gains optional `engagementId`, `flowType`, `retestTargetFindingIds` args.
- **`backend/pkg/tools/registry.go`** — ingestion tools register here; scope matcher wraps executor tools via `WithScopeGate`.
- **`backend/migrations/sql/`** — new goose migration with table creations and enum definitions.
- **`frontend/src/pages/engagements/`** — new list, create, detail pages (Reports / Findings / Flows tabs).
- **`frontend/src/graphql/`** — new query/mutation files; run `npm run graphql:generate` afterwards.
- **`frontend/src/components/icons/`** — new Engagement icon.

## 4. Data model

### 4.1 Postgres tables

```sql
-- engagements: top-level SOW grouping
engagements
  id                  UUID PK
  name                TEXT NOT NULL
  client              TEXT NOT NULL
  description         TEXT
  status              engagement_status NOT NULL DEFAULT 'active'
  graphiti_group_id   TEXT UNIQUE NOT NULL
  starts_at           DATE
  ends_at             DATE
  created_by          BIGINT FK users(id) NOT NULL
  updated_by          BIGINT FK users(id) NOT NULL
  team_id             BIGINT NULL                    -- forward-compat stub
  created_at          TIMESTAMPTZ NOT NULL
  updated_at          TIMESTAMPTZ NOT NULL
  deleted_at          TIMESTAMPTZ NULL               -- soft delete

-- engagement_scope_rules: include/exclude rules defining the scope
engagement_scope_rules
  id                  UUID PK
  engagement_id       UUID FK engagements(id) ON DELETE CASCADE
  rule_type           scope_rule_type NOT NULL
  value               TEXT NOT NULL                  -- CIDR / hostname / URL prefix / image ref
  direction           scope_direction NOT NULL DEFAULT 'include'
  note                TEXT                           -- audit trail
  created_at          TIMESTAMPTZ NOT NULL

-- scan_reports: raw upload records
scan_reports
  id                  UUID PK
  engagement_id       UUID FK engagements(id) ON DELETE CASCADE
  source_type         scan_source_type NOT NULL
  original_filename   TEXT NOT NULL
  storage_uri         TEXT NOT NULL                  -- local FS or S3
  sha256              TEXT NOT NULL                  -- dedup
  scan_date           TIMESTAMPTZ                    -- from report if present
  ingested_at         TIMESTAMPTZ NOT NULL
  parser_version      TEXT NOT NULL
  parse_status        parse_status NOT NULL DEFAULT 'pending'
  parse_error         TEXT
  finding_count       INT NOT NULL DEFAULT 0
  uploaded_by         BIGINT FK users(id) NOT NULL
  UNIQUE (engagement_id, sha256)

-- findings: normalized finding records
findings
  id                  UUID PK
  engagement_id       UUID FK engagements(id) ON DELETE CASCADE
  scan_report_id      UUID FK scan_reports(id) ON DELETE CASCADE
  finding_type        finding_type NOT NULL
  target_kind         target_kind NOT NULL
  target_ref          TEXT NOT NULL                  -- "ip:10.1.2.3:443", "img:nginx@sha256:..."
  title               TEXT NOT NULL
  cve                 TEXT NULL
  cvss_score          NUMERIC(3,1) NULL
  severity            severity NOT NULL
  confidence          confidence NOT NULL
  source_id           TEXT NULL                      -- scanner-native id (QID, Burp issue_id)
  evidence            JSONB NOT NULL                 -- source-specific payload retained
  in_scope            BOOLEAN NOT NULL               -- I-B soft-tag computed at ingest
  verification_status verification_status NOT NULL DEFAULT 'unverified'
  verified_by         BIGINT FK users(id) NULL
  verified_at         TIMESTAMPTZ NULL
  verification_notes  TEXT
  graph_seeded_at     TIMESTAMPTZ NULL               -- reconcile trigger
  first_seen_at       TIMESTAMPTZ NOT NULL
  last_seen_at        TIMESTAMPTZ NOT NULL
  created_at          TIMESTAMPTZ NOT NULL
  updated_at          TIMESTAMPTZ NOT NULL

-- finding_sources: junction when same finding seen in multiple reports
finding_sources
  finding_id          UUID FK findings(id) ON DELETE CASCADE
  scan_report_id      UUID FK scan_reports(id) ON DELETE CASCADE
  source_evidence     JSONB NOT NULL
  PRIMARY KEY (finding_id, scan_report_id)

-- flow_retest_targets: for targeted_reverify flows only
flow_retest_targets
  flow_id             UUID FK flows(id) ON DELETE CASCADE
  finding_id          UUID FK findings(id) ON DELETE CASCADE
  PRIMARY KEY (flow_id, finding_id)

-- flow_retest_diff: for retest_diff flows; populated pre-flight
flow_retest_diff
  flow_id             UUID FK flows(id) ON DELETE CASCADE
  finding_id          UUID FK findings(id) ON DELETE CASCADE
  diff_state          diff_state NOT NULL            -- fixed | persistent | new | regressed
  PRIMARY KEY (flow_id, finding_id)

-- scope_violations: append-only audit log for R-A gate blocks
scope_violations
  id                  UUID PK
  flow_id             UUID FK flows(id) ON DELETE CASCADE
  engagement_id       UUID FK engagements(id) ON DELETE CASCADE
  tool_name           TEXT NOT NULL
  target              TEXT NOT NULL
  occurred_at         TIMESTAMPTZ NOT NULL

-- existing flows table gets two new columns
ALTER TABLE flows
  ADD COLUMN engagement_id UUID NULL REFERENCES engagements(id),
  ADD COLUMN flow_type flow_type NOT NULL DEFAULT 'new_test';
```

### 4.2 Enums

| Enum | Values |
|---|---|
| `engagement_status` | active, on_hold, completed, archived |
| `scope_rule_type` | cidr, ip, domain, domain_glob, url_prefix, container_image, container_registry |
| `scope_direction` | include, exclude |
| `scan_source_type` | qualys, twistlock, nmap, burp |
| `parse_status` | pending, parsing, succeeded, failed, partial |
| `finding_type` | vulnerability, web_issue, exposed_service, container_cve, container_compliance, secret_exposure |
| `target_kind` | host, web_endpoint, container |
| `severity` | info, low, medium, high, critical |
| `confidence` | certain, firm, tentative |
| `verification_status` | unverified, verifying, confirmed, false_positive, not_exploitable |
| `flow_type` | new_test, retest_diff, targeted_reverify |
| `diff_state` | fixed, persistent, new, regressed |

### 4.3 Normalized in-flight schema (`pkg/ingestion/schema/`)

Deliberately lossless — evidence blobs retained so we never have to re-parse.

```go
type ReportBundle struct {
    SourceType   ScanSourceType
    ScanDate     *time.Time
    Hosts        []Host
    Containers   []Container
    WebEndpoints []WebEndpoint
    Findings     []Finding        // flat list with target refs into the above
    RawEvidence  json.RawMessage  // scanner-specific full payload retained for audit
}

type Host struct {
    IP        string
    Hostnames []string
    OS        *OSFingerprint
    Services  []Service
}

type Service struct {
    Port     int
    Protocol string             // tcp | udp
    Name     string             // https, ssh
    Product  string             // nginx
    Version  string
    Evidence EvidenceRef
}

type Finding struct {
    Type       FindingType
    Target     TargetRef          // {Kind, Ref}, e.g. {Kind: "host", Ref: "ip:10.1.2.3:443"}
    Title      string
    CVE        string
    CVSSScore  *float64
    Severity   Severity
    Confidence Confidence
    SourceID   string
    Evidence   json.RawMessage    // native scanner payload, retained verbatim
}

type Container struct {
    Image    string
    Tag      string
    Digest   string
    Registry string
    Layers   []LayerInfo
}

type WebEndpoint struct {
    URL    string
    Method string
    Params []string
}
```

### 4.4 Graphiti entities and edges

Seeded per-Engagement via `group_id` so knowledge graphs are isolated between SOWs and retests inherit prior context automatically.

| Entity | Key attrs | Notes |
|---|---|---|
| `Host` | ip, hostnames, os | keyed by normalized IP |
| `Service` | port, protocol, product, version | |
| `Vulnerability` | cve, cvss_score, title, severity | CVE-less findings get a synthetic id `<source>:<source_id>` |
| `Container` | image, tag, digest, registry | digest is canonical key |
| `WebEndpoint` | url, method | |
| `Finding` | id, verification_status, in_scope | mirrors the Postgres row for graph-search convenience |

| Edge | Direction | Purpose |
|---|---|---|
| `HAS_SERVICE` | Host → Service | recon traversal |
| `EXPOSES_ENDPOINT` | Service → WebEndpoint | web surface enumeration |
| `AFFECTED_BY` | (Host \| Service \| Container) → Vulnerability | load-bearing edge for exploit selection |
| `RUNS_IN_CONTAINER` | Service → Container | container-runtime mapping |
| `EVIDENCED_BY` | Vulnerability → Finding | preserves source-trust chain across multiple scanners |

## 5. Data flow

### 5.1 Ingest path — `POST /api/v1/engagements/:id/reports`

```
1. Controller        validate engagement exists + active; validate content-type
                     stream body to temp file; compute sha256 inline
2. Dedup guard       UNIQUE (engagement_id, sha256) → 409 if already ingested
3. Persist raw       write to storage_uri; insert scan_reports row (status=pending)
4. Dispatch          enqueue a parse job via existing pkg/queue (async, returns 202)
                     response body returns the scan_report row with job id
5. Parse worker      open storage_uri; detect format (explicit source_type arg > sniff)
                     → parsers/<fmt>.Parse → schema.ReportBundle
                     on failure: parse_status='failed', parse_error set
6. Persist normalized in one transaction:
                     - upsert findings dedup'd by (engagement_id, target_ref, source_id|cve)
                     - bump last_seen_at on matches, create finding_sources row
                     - compute in_scope per finding via scope.Matcher
                     - update scan_reports.finding_count, parse_status='succeeded'
7. Seed graph        seeder.Seed(bundle, engagement.graphiti_group_id) — idempotent
                     entity keys deterministic; edges use upsert semantics
                     on success, set findings.graph_seeded_at
8. Emit event        GraphQL subscription publishes reportIngested to open clients
                     observability span closes with finding counts
```

**Failure isolation.** Steps 1-4 are synchronous so the user gets fast feedback on upload errors. Steps 5-8 are async; if graph seed (7) fails, findings are still persisted in Postgres — a separate reconcile job retries seeding. Postgres is authoritative; Graphiti is derived.

### 5.2 Flow creation — `createFlow(engagementId, flowType, ...)`

```
Common pre-flight for all three flow types:
  - resolve engagement, load graphiti_group_id
  - snapshot scope rules → scope.Matcher bound to this flow
  - hard-gate installer wraps every tool in pkg/tools/registry for this flow:
      InScope(target, engagementID) ? call tool : return ScopeError

new_test:
  - orchestrator prompt adds nudge: "Engagement {name} has {N} ingested findings
    across {M} hosts. Use list_findings / get_top_findings_by_cvss to start."
  - flow runs as today

retest_diff:
  - pre-flight computes diff between findings present at flow.previous_flow_ref
    time and now (status transitions: fixed | persistent | new | regressed)
  - diff persisted to flow_retest_diff table for deliverable output
  - orchestrator prompt gets structured summary of the diff
  - during the run, agents can call get_retest_diff tool to drill in

targeted_reverify:
  - caller supplies a list of finding_ids → written to flow_retest_targets
  - orchestrator prompt is narrow: "Verify these N findings only. Mark each
    confirmed/false_positive using mark_finding_verified."
  - list_findings / get_top_findings_by_cvss are hidden for this flow type;
    only get_finding_by_id is exposed, scoped to the target list
```

### 5.3 Scope hard-gate (R-A)

The existing `pkg/tools/registry.go` currently returns tool handlers keyed by name. We add a `registry.WithScopeGate(matcher)` wrapper applied at flow-start. Each tool declares a `Targets(args) []Target` method (most tools only need a one-line impl — nmap targets the `-target` arg, curl targets the URL). If any target is out of scope, the wrapper returns a structured tool error before invoking the tool body.

Error shape surfaced to the LLM:
```json
{ "error": "scope_violation", "target": "10.99.0.1",
  "engagement_id": "...", "hint": "target is not in the Engagement's declared scope" }
```

For tools with freeform args (e.g., the generic terminal executor running arbitrary shell), `Targets` returns `nil` → wrapper conservatively invokes a secondary IP/URL extractor on the stdout before returning results to the agent, and redacts any OOS matches. Imperfect but covers the 80% case (agent runs `curl http://10.99.0.1`; the response comes back redacted).

Every gate-block writes a row to `scope_violations`. Append-only audit trail.

## 6. HTTP / GraphQL surface

### 6.1 REST endpoints (new, under `pkg/server/controllers/ingestion_controller.go`)

```
POST   /api/v1/engagements                                 create engagement
GET    /api/v1/engagements                                 list (paginated)
GET    /api/v1/engagements/:id                             detail
PATCH  /api/v1/engagements/:id                             update name/status/dates
DELETE /api/v1/engagements/:id                             soft-delete

POST   /api/v1/engagements/:id/scope-rules                 add a scope rule
DELETE /api/v1/engagements/:id/scope-rules/:ruleId         remove

POST   /api/v1/engagements/:id/reports                     multipart upload
         form fields: source_type (required), file (required)
         → 202 + { scan_report_id, parse_status }
GET    /api/v1/engagements/:id/reports                     list ingested reports
GET    /api/v1/engagements/:id/reports/:reportId           single report metadata
GET    /api/v1/engagements/:id/reports/:reportId/raw       download original file

GET    /api/v1/engagements/:id/findings                    filterable listing
         query: severity, cve, target_kind, in_scope,
                verification_status, source_type, limit, cursor
GET    /api/v1/engagements/:id/findings/:findingId         detail with evidence
PATCH  /api/v1/engagements/:id/findings/:findingId         edit verification fields only
```

All endpoints require PentAGI's existing auth (session cookie or bearer token). Swagger annotations on every handler so `swag init` picks them up.

### 6.2 GraphQL additions (`pkg/graph/schema.graphqls`)

```graphql
type Engagement {
  id: ID!
  name: String!
  client: String!
  status: EngagementStatus!
  scopeRules: [ScopeRule!]!
  scanReports(first: Int, after: String): ScanReportConnection!
  findings(filter: FindingFilter, first: Int, after: String): FindingConnection!
  flows: [Flow!]!
  findingStats: FindingStats!
  createdAt: Time!
  updatedAt: Time!
}

type Finding {
  id: ID!
  title: String!
  cve: String
  cvssScore: Float
  severity: Severity!
  confidence: Confidence!
  target: Target!
  inScope: Boolean!
  verificationStatus: VerificationStatus!
  sources: [ScanReport!]!
  evidence: JSON!
  firstSeenAt: Time!
  lastSeenAt: Time!
}

extend type Flow {
  engagement: Engagement
  flowType: FlowType!
  retestDiff: RetestDiff
  retestTargets: [Finding!]
}

extend type Mutation {
  createEngagement(input: CreateEngagementInput!): Engagement!
  updateEngagement(id: ID!, input: UpdateEngagementInput!): Engagement!
  addScopeRule(engagementId: ID!, input: ScopeRuleInput!): ScopeRule!
  verifyFinding(id: ID!, input: VerifyFindingInput!): Finding!
  # Existing createFlow mutation gains optional:
  #   engagementId, flowType, retestTargetFindingIds
}

extend type Subscription {
  reportIngested(engagementId: ID!): ScanReport!
  findingsUpdated(engagementId: ID!): FindingUpdate!
}
```

### 6.3 Frontend (React + Apollo)

Under `frontend/src/pages/engagements/`:

- `index.tsx` — `/engagements` list page. Table with name, client, status, counts, last activity. "New Engagement" button.
- `create.tsx` — form: name, client, description, inline scope-rule editor, dates.
- `detail.tsx` — `/engagements/:id` with three tabs:
  1. **Reports** — upload dropzone accepting `.xml`, `.json`, `.csv`, `.nmap`; list of ingested reports with status badges; re-ingest button; raw file download. `source_type` is sniffed from extension and shown in a dropdown the user confirms before submit.
  2. **Findings** — filterable table backed by `findings` GraphQL query; click-through to evidence view; `verification_status` editable inline.
  3. **Flows** — list of flows for this engagement; "New flow" opens the existing flow-create dialog with `engagementId` pre-filled and a `flowType` selector.
- `components/engagement-context-pill.tsx` — indicator shown in the flow-create dialog ("Using context from Engagement: ACME Q2") so users always know a flow is scoped.

Existing flow pages get two non-breaking additions:
- If the flow has an engagement, surface a link to it in the flow header.
- For `retest_diff` flows, a "Retest findings" panel renders the structured diff.

One new icon registration in `frontend/src/components/icons/` for the Engagement entity.

## 7. Error handling, observability, testing

### 7.1 Error handling

**Ingest, synchronous portion (upload → 202).**
- Malformed / missing multipart → 400 with field-level message.
- Engagement not found or archived → 404 / 409.
- Duplicate sha256 for engagement → 409 with existing `scan_report_id` in the body (re-uploads idempotent and discoverable).
- Storage write failure → 500, no DB row created. Two-phase: write temp, fsync, insert DB row in tx, move to final path.

**Ingest, async parse.**
- Parser errors are captured, not propagated. `parse_status='failed'`, `parse_error` holds a truncated message + line/offset if the parser can give one. Subscription pushes the transition.
- `parse_status='partial'` when the parser extracts some findings but hits a recoverable error mid-file. Partial ingestion is preferable to all-or-nothing for this domain.
- Seeding failure (Graphiti down, schema drift): `scan_reports` stays `succeeded` (Postgres is authoritative). A `findings.graph_seeded_at IS NULL` condition drives a reconcile worker in `seeder/reconcile.go` that retries on a timer.

**Parser robustness (per-format).**
- Qualys: large XMLs must stream — `encoding/xml` `Decoder.Token()` loop, never `Unmarshal` whole document. Budget: 500MB input without OOM.
- Twistlock JSON: streaming JSON decoder for the same reason.
- Nmap XML: small, can load into memory safely.
- Burp XML: base64 request/response bodies decoded lazily, stored as evidence blob.

**Scope hard-gate.**
- Violations return a structured tool error to the agent (see §5.3). Agent reasons around it.
- Every gate-block is logged to `scope_violations` (append-only).

### 7.2 Observability

Reuses the existing `pkg/observability/` OpenTelemetry setup.

Spans:
- `ingestion.upload`
- `ingestion.parse.<source>`
- `ingestion.persist`
- `ingestion.seed`
- `ingestion.scope_gate` (low-cardinality, counters only)

Metrics:
- `ingestion_reports_total{source, status}` — counter
- `ingestion_findings_total{source, severity}` — counter, per ingest
- `ingestion_parse_duration_seconds{source}` — histogram
- `scope_violations_total{tool, flow_type}` — counter
- `graphiti_seed_failures_total` — counter (drives reconciler alert)

Structured logs on every parse: `{engagement_id, scan_report_id, source_type, finding_count, duration_ms, status}`.

### 7.3 Testing

**Unit tests — each component owns its own.**
- `parsers/` — golden-file tests against real-world sample reports (anonymized) in `testdata/`. Each parser asserts full normalized output against a checked-in fixture.
- `schema/` — validation helpers, IP normalization, target-ref construction.
- `scope/` — table-driven over CIDR matching, domain globs, URL prefixes, include/exclude precedence. **Coverage target 100%** on matcher logic — carries legal risk.
- `seeder/` — against a local Graphiti via testcontainers; asserts idempotency (seed twice, same graph state).
- `engagement/` — repo tested with testcontainers-postgres; verifies unique constraints, soft-delete, dedup upserts.

**Integration tests (`pkg/ingestion/integration_test.go`).**
- Upload → parse → persist → seed → GraphQL query returns expected findings.
- Upload same file twice → 409 on second.
- Create flow with `flowType=targeted_reverify` → agent sees only selected findings via `get_finding_by_id`.
- Scope gate: flow runs against in-scope target (allowed) and OOS target (refused with audit row).

**End-to-end smoke test (CI).**
- Tiny nmap XML fixture → full ingest → create `new_test` flow → assert orchestrator prompt contains the nudge string and `list_findings` returns the expected count. Runs via docker compose with mocked LLM.

**Explicitly not in v1.**
- Chaos / fuzzing on parser inputs — deferred to v2.
- Load testing Graphiti seeding at 10k+ findings — defer until seen.
- Multi-user concurrency on the same Engagement — solo semantics.

## 8. Definition of done for v1

1. All migrations apply cleanly against an empty DB and against an existing PentAGI DB.
2. All four parsers produce green golden-file tests.
3. End-to-end smoke test passes in CI.
4. Scope hard-gate has a passing table-driven matcher test suite.
5. UI pages render and the upload → finding flow works against a dev docker-compose stack.
6. `backend/pkg/ingestion/README.md` describes the pipeline for a future maintainer.

## 9. Out of scope for v1 (flagged for v2)

- Aqua parser (JSON shape near-identical to Twistlock; slot in v2).
- "Verify findings first" orchestrator workflow (data model in place; workflow later).
- Per-Engagement RBAC (solo semantics; schema forward-compat).
- PDF/HTML export of findings.
- Inline CVSS calculator / re-scoring UI.
- Bulk-verify UI (per-finding only in v1).
- Scope-rule CIDR overlap warning UI (backend rejects duplicates; UI not clever).
- Engagement search beyond the list page filter.
