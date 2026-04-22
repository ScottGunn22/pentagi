//go:build integration

// Package ingestion — end-to-end smoke test for the scanner-report ingestion
// pipeline. Drives the full REST surface (upload -> async parse -> persist ->
// query findings) against a live Postgres database.
//
// This test is gated on the "integration" build tag so the default `go test
// ./...` invocation never tries to stand up a real database. Run it via:
//
//	export PENTAGI_INGESTION_TEST_DSN='postgres://user:pass@localhost:5432/pentagi_ingestion_e2e?sslmode=disable'
//	go test -tags=integration ./pkg/ingestion/...
//
// Prerequisites (the test does NOT manage these itself):
//  1. A dedicated Postgres database reachable at DSN above. The test assumes
//     it has full DDL privileges — it will run the project's goose migrations
//     at startup.
//  2. The database must be empty or previously migrated by this suite; any
//     unrelated schema may collide with goose.
//
// Graphiti is stubbed with a no-op seeder to keep the test hermetic. Graphiti
// coverage lives in pkg/ingestion/seeder/* unit tests.
package ingestion_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"

	"pentagi/migrations"
	"pentagi/pkg/database"
	"pentagi/pkg/graphiti"
	"pentagi/pkg/ingestion/engagement"
	"pentagi/pkg/ingestion/seeder"
	"pentagi/pkg/server/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	testUID uint64 = 1
	// dsnEnv is the env var the caller uses to point the test at a live
	// Postgres. Unset => the whole test suite skips.
	dsnEnv = "PENTAGI_INGESTION_TEST_DSN"
)

func TestIngestionE2E_NmapUploadToFindings(t *testing.T) {
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
	tmpStorage := t.TempDir()

	// A disabled graphiti client — AddMessages is a no-op, so the seeder
	// exercises its internal flow without hitting any network.
	gc, err := graphiti.NewClient("", 5*time.Second, false)
	if err != nil {
		t.Fatalf("graphiti client: %v", err)
	}
	sd := seeder.NewSeeder(gc)

	svc := services.NewIngestionService(
		queries,
		engagement.NewService(queries),
		sd,
		tmpStorage,
		logrus.NewEntry(logrus.StandardLogger()),
	)

	// Minimal router: wrap the handlers in a gin engine with a fake "uid"
	// injected on every request so the services layer behaves as if an
	// authenticated user is making the call.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("test-salt"))
	r.Use(sessions.Sessions("auth", store))
	r.Use(func(c *gin.Context) {
		c.Set("uid", testUID)
		c.Set("prm", []string{})
		c.Next()
	})
	g := r.Group("/api/v1/engagements")
	{
		g.POST("", svc.CreateEngagement)
		g.GET("", svc.ListEngagements)
		g.GET("/:id", svc.GetEngagement)
		g.POST("/:id/scope-rules", svc.AddScopeRule)
		g.POST("/:id/reports", svc.UploadReport)
		g.GET("/:id/reports", svc.ListReports)
		g.GET("/:id/reports/:reportId", svc.GetReport)
		g.GET("/:id/findings", svc.ListFindings)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Seed a local user so the created_by FK in engagements resolves.
	// users.id is BIGINT GENERATED ALWAYS AS IDENTITY → use OVERRIDING SYSTEM VALUE
	// so the test owns the ID it later passes via the fake auth middleware.
	if _, err := sqlDB.ExecContext(ctx, `
		INSERT INTO users (id, hash, type, mail, name, status, role_id, password, password_change_required)
		OVERRIDING SYSTEM VALUE
		VALUES ($1, 'e2e-hash', 'local', 'e2e@example.com', 'e2e', 'active', 2, 'x', false)
		ON CONFLICT (id) DO NOTHING`, testUID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// --- step 1: create engagement -------------------------------------------
	// doJSON already extracts the {"data":...} envelope, so the out type is the
	// inner shape directly — no second wrapper struct needed.
	createBody := map[string]string{"name": "Acme Q1", "client": "Acme"}
	var eng database.Engagement
	doJSON(t, srv.URL+"/api/v1/engagements", http.MethodPost, createBody, http.StatusCreated, &eng)
	engID := eng.ID
	if engID == 0 {
		t.Fatalf("expected engagement id, got 0 (resp=%+v)", eng)
	}
	t.Logf("engagement id: %d, group: %s", engID, eng.GraphitiGroupID)

	// --- step 2: add an in-scope CIDR rule so minimal.xml targets count ------
	scopeBody := map[string]string{"rule_type": "cidr", "value": "10.1.0.0/16", "direction": "include"}
	doJSON(t,
		fmt.Sprintf("%s/api/v1/engagements/%d/scope-rules", srv.URL, engID),
		http.MethodPost, scopeBody, http.StatusCreated, nil)

	// --- step 3: upload minimal.xml ------------------------------------------
	xmlPath := filepath.Join("parsers", "testdata", "nmap", "minimal.xml")
	body1, ct1 := buildUpload(t, xmlPath, "nmap")
	var report database.ScanReport
	doMultipart(t,
		fmt.Sprintf("%s/api/v1/engagements/%d/reports", srv.URL, engID),
		ct1, body1, http.StatusAccepted, &report)
	reportID := report.ID
	if reportID == 0 {
		t.Fatal("expected scan_report id")
	}

	// --- step 4: poll until parse_status is succeeded ------------------------
	deadline := time.Now().Add(10 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		var poll database.ScanReport
		doJSON(t,
			fmt.Sprintf("%s/api/v1/engagements/%d/reports/%d", srv.URL, engID, reportID),
			http.MethodGet, nil, http.StatusOK, &poll)
		status = string(poll.ParseStatus)
		if status == "succeeded" || status == "partial" {
			break
		}
		if status == "failed" {
			t.Fatalf("parse failed: %s", poll.ParseError.String)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status != "succeeded" && status != "partial" {
		t.Fatalf("timeout waiting for parse to complete; last status=%q", status)
	}

	// --- step 5: findings list ----------------------------------------------
	var findings []database.Finding
	doJSON(t,
		fmt.Sprintf("%s/api/v1/engagements/%d/findings", srv.URL, engID),
		http.MethodGet, nil, http.StatusOK, &findings)
	if got := len(findings); got != 2 {
		t.Fatalf("expected 2 findings, got %d", got)
	}
	for _, f := range findings {
		if !f.InScope {
			t.Errorf("finding %d (%s) should be in scope", f.ID, f.TargetRef)
		}
	}

	// --- step 6: same upload again -> 409 -----------------------------------
	body2, ct2 := buildUpload(t, xmlPath, "nmap")
	var errResp map[string]any
	doMultipart(t,
		fmt.Sprintf("%s/api/v1/engagements/%d/reports", srv.URL, engID),
		ct2, body2, http.StatusConflict, &errResp)
	if code, _ := errResp["code"].(string); !strings.HasPrefix(code, "Ingestion.ScanReportDuplicate") {
		t.Errorf("expected ScanReportDuplicate code, got %+v", errResp)
	}
}

// -- http helpers -------------------------------------------------------------

// doJSON sends a JSON request, asserts status, and decodes the body envelope
// ({"status":"success","data":<out>}) into `out` when non-nil.
func doJSON(t *testing.T, url, method string, payload any, wantStatus int, out any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status=%d want=%d body=%s", method, url, resp.StatusCode, wantStatus, string(raw))
	}
	if out == nil {
		return
	}
	// Errors use a flat envelope; success uses {status,data}.
	if m, ok := out.(*map[string]any); ok {
		if err := json.Unmarshal(raw, m); err != nil {
			t.Fatalf("decode error envelope: %v (body=%s)", err, string(raw))
		}
		return
	}
	env := struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, string(raw))
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		t.Fatalf("decode data: %v (body=%s)", err, string(raw))
	}
}

func doMultipart(t *testing.T, url, ct string, body *bytes.Buffer, wantStatus int, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", ct)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s: status=%d want=%d body=%s", url, resp.StatusCode, wantStatus, string(raw))
	}
	if out == nil {
		return
	}
	if m, ok := out.(*map[string]any); ok {
		if err := json.Unmarshal(raw, m); err != nil {
			t.Fatalf("decode error: %v (body=%s)", err, string(raw))
		}
		return
	}
	env := struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, string(raw))
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		t.Fatalf("decode data: %v (body=%s)", err, string(raw))
	}
}

func buildUpload(t *testing.T, path, sourceType string) (*bytes.Buffer, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	_ = mw.WriteField("source_type", sourceType)
	fw, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write form: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close mw: %v", err)
	}
	return buf, mw.FormDataContentType()
}

