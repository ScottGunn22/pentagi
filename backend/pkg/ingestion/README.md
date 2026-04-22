# pkg/ingestion

Scanner report ingestion + Engagement lifecycle for PentAGI.

## What it does

- Accepts uploaded reports (Qualys / Twistlock / Nmap / Burp) via REST or GraphQL.
- Parses them into a normalized in-memory schema.
- Persists findings to Postgres (deduped per `(engagement, target_ref, cve, source_id)`).
- Seeds them into a per-Engagement Graphiti partition so the LLM agents have prior context.
- Hard-gates every agent tool call so the agents physically cannot scan/exploit out-of-scope targets.
- Surfaces three flow types — new test, retest with diff, targeted re-verification — that share the same agent toolset but differ in pre-flight context and prompt nudge.

## Sub-packages

| Sub-package | Responsibility | Entry types |
|---|---|---|
| `parsers/` | One `Parser` per source format. Golden-file tested. | `Parser`, `NmapParser`, `BurpParser`, `TwistlockParser`, `QualysParser`, `ErrPartial` |
| `schema/` | Normalized in-flight types. Pure data, no DB coupling. | `ReportBundle`, `Host`, `Container`, `WebEndpoint`, `Finding`, `Severity`, `ParseSeverity` |
| `engagement/` | Postgres-backed CRUD over the engagement aggregate plus retest diff. | `Service`, `CreateInput`, `ComputeRetestDiff` |
| `scope/` | Fail-closed scope matcher + DB loader + `WithGate` wrapper. 100% branch coverage on rule matching. | `Matcher`, `LoadMatcher`, `WithGate`, `Target`, `TargetExtractor`, `AuditFn` |
| `seeder/` | Idempotent Graphiti episode writes + reconcile loop for retries. | `Seeder`, `SeedInput`, `Reconciler`, `EpisodeWriter` |
| `findings/` | Agent-facing tools (list/top/host/container/get/verify/diff). | `Tools`, `New(q, engagementID)` |

The controller layer lives outside this package, in `backend/pkg/server/services/ingestion.go` — it's the REST glue that ties the sub-packages together.

## Data flow

```
  HTTP POST /engagements/:id/reports (multipart)
           │
           ▼
  services.IngestionService.UploadReport
    • sha256 while streaming to $INGESTION_STORAGE_DIR
    • dedup on (engagement_id, sha256)
    • scan_reports row status = pending
           │
           ▼ go s.runParse(context.Background(), ...)
  runParse  [span: ingestion.parse.<source>]
    • parsers.<Source>Parser.Parse(file) -> *schema.ReportBundle
    • persistBundle                          [span: ingestion.persist]
        • scope.LoadMatcher + InScope tagging
        • UpsertFinding + AttachFindingSource
    • seeder.Seed                            [span: ingestion.seed]
        • group_id = engagement.graphiti_group_id
        • one episode per host / container / endpoint / finding
        • MarkFindingGraphSeeded on success
    • UpdateScanReportStatus (succeeded | partial | failed)

  At flow start (controller/flow.go):
    • flowToolsExecutor captures engagement_id
    • scope.LoadMatcher + ingestion/findings.New()
    • wrapWithScopeGate wraps every handler with scope.WithGate
    • AuditFn persists scope_violations + bumps scope_violations_total
```

## Adding a new scanner source

1. Add the enum value to a goose migration under `backend/migrations/sql/`:
   ```sql
   ALTER TYPE SCAN_SOURCE_TYPE ADD VALUE 'newscanner';
   ```
2. Add the corresponding constant to `pkg/ingestion/schema/types.go`:
   ```go
   const SourceNewscanner ScanSourceType = "newscanner"
   ```
3. Implement `pkg/ingestion/parsers/newscanner.go` with a `var _ Parser = (*NewscannerParser)(nil)` assertion + golden-file test fixture under `parsers/testdata/newscanner/`.
4. Register in the controller's parser map at `pkg/server/services/ingestion.go::NewIngestionService`:
   ```go
   schema.SourceNewscanner: &parsers.NewscannerParser{},
   ```
5. Update the GraphQL `ScanSourceType` enum in `pkg/graph/schema.graphqls` and rerun gqlgen.
6. Add the source to the frontend extension-sniffing map in `frontend/src/pages/engagements/components/upload-dropzone.tsx`.

## Observability

Spans (emitted via `obs.Observer.NewSpan`, `obs.SpanKindInternal` except upload which is server):
- `ingestion.upload` — REST handler body of `UploadReport`.
- `ingestion.parse.<source>` — full async parse pipeline, parented at the detached background ctx.
- `ingestion.persist` — `persistBundle` (scope load + finding upserts).
- `ingestion.seed` — the `seeder.Seed` call.

Metrics (see `pkg/ingestion/metrics.go`; lazily constructed, safe to call before `observability.InitObserver`):
- `ingestion_reports_total{source, status}` — terminal status one of `pending|succeeded|partial|failed`.
- `ingestion_findings_total{source, severity}` — incremented per-severity on successful parse.
- `ingestion_parse_duration_seconds{source}` — histogram, covers parse + persist + seed wall-clock.
- `scope_violations_total{tool, flow_id}` — one counter increment per blocked tool call. The spec called for `flow_type` as the second label; `flow_type` is a DB-level column on `flows` and is not threaded into `pkg/tools`, so we label by `flow_id` (same cardinality ceiling, joinable to `flows` in PromQL).
- `graphiti_seed_failures_total` — no labels; drives the reconciler alert.

Structured log fields on every parse (`runParse`, `persistBundle`): `engagement_id`, `scan_report_id`, `source_type`, `finding_count`, `duration_ms`, `status`, plus `finding_id` on finding-scoped warnings.

## Known v2 follow-ups

- Per-engagement RBAC (currently any authenticated user can access any engagement).
- Bulk `MarkFindingGraphSeeded` query (current loop is N+1).
- `persistBundle` wrapped in a transaction (rollback semantics vs. partial Graphiti seed need an audit first).
- Subscription publish wiring (declarations in place in the GraphQL schema; no events emitted yet).
- Stdout-IP redaction for the freeform terminal/executor tools.
- "Verify findings first" orchestrator workflow (data model in place; orchestration deferred).
- Populate `regressed` bucket in `ComputeRetestDiff` once verification history lands.

## Running tests

- Unit: `go test ./pkg/ingestion/...`
- Integration (requires docker compose pgvector + a dedicated test DB):
  ```
  PENTAGI_INGESTION_TEST_DSN='postgres://postgres:postgres@127.0.0.1:5432/pentagi_e2e?sslmode=disable' \
    go test -tags=integration ./pkg/ingestion/...
  ```

## Operational notes

- Storage dir: `INGESTION_STORAGE_DIR` (default `./data/ingestion` per `pkg/config/config.go`). Raw uploaded reports retained here, indexed by `<engagement_id>-<sha256>-<original_filename>`. `cmd/pentagi/main.go` calls `os.MkdirAll` at startup — ensure the process has write perms.
- Reconciler tick: not yet on a timer in v1; trigger via `seeder.Reconciler.ReconcileOnce(ctx, limit)` from a cron or supervisor when needed. v2 should run it on a 30s ticker and alert on `graphiti_seed_failures_total` rate.
- Dedup: `UploadReport` returns HTTP 409 with the existing `scan_report_id` when an identical `(engagement_id, sha256)` has already been uploaded; the raw file is not written twice.
- Failure semantics: a mid-`persistBundle` failure leaves earlier findings persisted and marks the `scan_reports` row `failed`. Safe for nmap-sized bundles; Phase 9/10 (Twistlock/Qualys, 1000s of findings) should wrap the loop in a transaction.
