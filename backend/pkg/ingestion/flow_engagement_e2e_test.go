//go:build integration

// Package ingestion — end-to-end check for the Phase 14 engagement-aware
// flow create path. Complements e2e_test.go (which drives the scanner-report
// ingestion REST surface) by exercising the flow-create plumbing that was
// wired in C1: the GraphQL mutation / REST handler accept the engagement
// args, they reach EngagementFlowOptions, and the eventual SQL writes land
// on the flows row plus flow_retest_targets / flow_retest_diff bridge tables.
//
// The full NewFlowWorker spin-up spawns docker containers and LLM providers
// which are not available in CI. Instead, the test drives the two SQL
// operations (CreateFlow + UpdateFlowEngagement + InsertFlowRetestTarget)
// directly to prove the engagement columns and bridge rows are persisted
// correctly. The REST/GraphQL argument-plumbing layer is covered by
// pkg/server/models and resolver-level tests; this file validates the
// persistence contract the plumbing targets.
package ingestion_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"

	"pentagi/migrations"
	"pentagi/pkg/database"
)

func TestEngagementAwareFlowCreate_SQL(t *testing.T) {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run this integration test", dsnEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	goose.SetBaseFS(migrations.EmbedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}
	if err := goose.UpContext(ctx, sqlDB, "sql"); err != nil {
		t.Fatalf("goose up: %v", err)
	}

	queries := database.New(sqlDB)

	// Seed a user so the created_by FK on engagements resolves. Same pattern
	// as the nmap e2e test — the OVERRIDING clause lets us own the PK so we
	// can also use it as the flow's user_id below.
	const uid int64 = 4242
	if _, err := sqlDB.ExecContext(ctx, `
		INSERT INTO users (id, hash, type, mail, name, status, role_id, password, password_change_required)
		OVERRIDING SYSTEM VALUE
		VALUES ($1, 'flow-eng-hash', 'local', 'flow-eng@example.com', 'flow-eng', 'active', 2, 'x', false)
		ON CONFLICT (id) DO NOTHING`, uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// --- step 1: create engagement --------------------------------------------
	eng, err := queries.CreateEngagement(ctx, database.CreateEngagementParams{
		Name:            "FlowCreateE2E",
		Client:          "Acme",
		Description:     sql.NullString{},
		GraphitiGroupID: "test-group-flow-e2e",
		CreatedBy:       uid,
	})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	engID := eng.ID

	// --- step 2: create a finding we can target in a targeted_reverify flow ---
	// Need a scan_report first so the finding's FK resolves.
	report, err := queries.CreateScanReport(ctx, database.CreateScanReportParams{
		EngagementID:     engID,
		SourceType:       database.ScanSourceTypeNmap,
		OriginalFilename: "placeholder.xml",
		StorageUri:       "local://placeholder.xml",
		Sha256:           "deadbeef-flow-e2e",
		ScanDate:         sql.NullTime{},
		ParserVersion:    "test",
		UploadedBy:       uid,
	})
	if err != nil {
		t.Fatalf("create scan report: %v", err)
	}

	finding, err := queries.UpsertFinding(ctx, database.UpsertFindingParams{
		EngagementID: engID,
		ScanReportID: report.ID,
		FindingType:  database.FindingTypeVulnerability,
		TargetKind:   database.TargetKindHost,
		TargetRef:    "ip:10.1.2.3:443/tcp",
		Title:        "e2e-target-finding",
		Severity:     database.SeverityLevelMedium,
		Confidence:   database.FindingConfidenceFirm,
		SourceID:     sql.NullString{String: "e2e-finding-sid", Valid: true},
		Evidence:     json.RawMessage(`{}`),
		InScope:      true,
	})
	if err != nil {
		t.Fatalf("upsert finding: %v", err)
	}

	// --- step 3a: create a NEW_TEST flow with engagement context -------------
	// Mirrors the path the resolver + REST handler take after building the
	// EngagementFlowOptions value: CreateFlow → UpdateFlowEngagement.
	newFlow, err := queries.CreateFlow(ctx, database.CreateFlowParams{
		Title:              "e2e-new-test",
		Status:             database.FlowStatusCreated,
		Model:              "gpt-4",
		ModelProviderName:  "openai",
		ModelProviderType:  database.ProviderTypeOpenai,
		Language:           "en",
		ToolCallIDTemplate: "call_{id}",
		Functions:          json.RawMessage(`{}`),
		UserID:             uid,
	})
	if err != nil {
		t.Fatalf("create flow (new_test): %v", err)
	}
	if err := queries.UpdateFlowEngagement(ctx, database.UpdateFlowEngagementParams{
		ID:           newFlow.ID,
		EngagementID: sql.NullInt64{Int64: engID, Valid: true},
		FlowType:     database.FlowTypeNewTest,
	}); err != nil {
		t.Fatalf("update flow engagement (new_test): %v", err)
	}

	got, err := queries.GetFlow(ctx, newFlow.ID)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if !got.EngagementID.Valid || got.EngagementID.Int64 != engID {
		t.Fatalf("new_test flow: engagement_id=%+v want %d", got.EngagementID, engID)
	}
	if got.FlowType != database.FlowTypeNewTest {
		t.Fatalf("new_test flow: flow_type=%q want %q", got.FlowType, database.FlowTypeNewTest)
	}
	if got.BaselineFlowID.Valid {
		t.Fatalf("new_test flow: baseline_flow_id should be NULL, got %+v", got.BaselineFlowID)
	}

	// --- step 3b: targeted_reverify flow with one target ---------------------
	tr, err := queries.CreateFlow(ctx, database.CreateFlowParams{
		Title:              "e2e-targeted",
		Status:             database.FlowStatusCreated,
		Model:              "gpt-4",
		ModelProviderName:  "openai",
		ModelProviderType:  database.ProviderTypeOpenai,
		Language:           "en",
		ToolCallIDTemplate: "call_{id}",
		Functions:          json.RawMessage(`{}`),
		UserID:             uid,
	})
	if err != nil {
		t.Fatalf("create flow (targeted_reverify): %v", err)
	}
	if err := queries.UpdateFlowEngagement(ctx, database.UpdateFlowEngagementParams{
		ID:           tr.ID,
		EngagementID: sql.NullInt64{Int64: engID, Valid: true},
		FlowType:     database.FlowTypeTargetedReverify,
	}); err != nil {
		t.Fatalf("update flow engagement (targeted): %v", err)
	}
	if err := queries.InsertFlowRetestTarget(ctx, database.InsertFlowRetestTargetParams{
		FlowID:    tr.ID,
		FindingID: finding.ID,
	}); err != nil {
		t.Fatalf("insert flow retest target: %v", err)
	}

	targets, err := queries.ListFlowRetestTargets(ctx, tr.ID)
	if err != nil {
		t.Fatalf("list flow retest targets: %v", err)
	}
	if len(targets) != 1 || targets[0] != finding.ID {
		t.Fatalf("targeted_reverify flow: targets=%+v want [%d]", targets, finding.ID)
	}

	// --- step 3c: retest_diff flow pointing at the earlier NEW_TEST as baseline
	rd, err := queries.CreateFlow(ctx, database.CreateFlowParams{
		Title:              "e2e-retest-diff",
		Status:             database.FlowStatusCreated,
		Model:              "gpt-4",
		ModelProviderName:  "openai",
		ModelProviderType:  database.ProviderTypeOpenai,
		Language:           "en",
		ToolCallIDTemplate: "call_{id}",
		Functions:          json.RawMessage(`{}`),
		UserID:             uid,
	})
	if err != nil {
		t.Fatalf("create flow (retest_diff): %v", err)
	}
	if err := queries.UpdateFlowEngagement(ctx, database.UpdateFlowEngagementParams{
		ID:             rd.ID,
		EngagementID:   sql.NullInt64{Int64: engID, Valid: true},
		FlowType:       database.FlowTypeRetestDiff,
		BaselineFlowID: sql.NullInt64{Int64: newFlow.ID, Valid: true},
	}); err != nil {
		t.Fatalf("update flow engagement (retest_diff): %v", err)
	}

	rdRow, err := queries.GetFlow(ctx, rd.ID)
	if err != nil {
		t.Fatalf("get flow (retest_diff): %v", err)
	}
	if rdRow.FlowType != database.FlowTypeRetestDiff {
		t.Fatalf("retest_diff flow: flow_type=%q want %q", rdRow.FlowType, database.FlowTypeRetestDiff)
	}
	if !rdRow.BaselineFlowID.Valid || rdRow.BaselineFlowID.Int64 != newFlow.ID {
		t.Fatalf("retest_diff flow: baseline_flow_id=%+v want %d", rdRow.BaselineFlowID, newFlow.ID)
	}
}
