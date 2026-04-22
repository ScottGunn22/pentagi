package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pentagi/pkg/database"
)

// stubRepo is a narrow, hand-rolled fake satisfying the Repo interface
// above. We only need Repo (not the full database.Querier), so this
// stays under 40 lines; expand it per-test with the single method the
// tool being tested exercises.
type stubRepo struct {
	// ListFindings
	listCalled bool
	listParams database.ListFindingsParams
	listResult []database.Finding
	listErr    error

	// TopFindingsByCVSS
	topCalled bool
	topParams database.TopFindingsByCVSSParams
	topResult []database.Finding

	// FindingsByTargetKind
	byKindParams database.FindingsByTargetKindParams
	byKindResult []database.Finding

	// GetFinding / UpdateFindingVerification
	finding    database.Finding
	findingErr error

	updateCalled bool
	updateParams database.UpdateFindingVerificationParams
	updateResult database.Finding
	updateErr    error

	// ListFlowRetestDiff
	diffCalled bool
	diffFlowID int64
	diffResult []database.FlowRetestDiff
	diffErr    error

	// record_finding plumbing
	scanReport        database.GetOrCreateAgentScanReportRow
	scanReportParams  database.GetOrCreateAgentScanReportParams
	scanReportErr     error
	upsertCalled      bool
	upsertParams      database.UpsertFindingParams
	upsertResult      database.UpsertFindingRow
	upsertErr         error
	attachCalled      bool
	attachParams      database.AttachFindingSourceParams
	attachErr         error
	scopeRules        []database.EngagementScopeRule
	scopeRulesErr     error
	scopeRulesEngID   int64
}

func (s *stubRepo) GetOrCreateAgentScanReport(_ context.Context, p database.GetOrCreateAgentScanReportParams) (database.GetOrCreateAgentScanReportRow, error) {
	s.scanReportParams = p
	if s.scanReportErr != nil {
		return database.GetOrCreateAgentScanReportRow{}, s.scanReportErr
	}
	// Default: echo the inputs into a plausible row so callers that don't
	// pre-populate scanReport still get non-zero IDs.
	if s.scanReport.ID == 0 {
		return database.GetOrCreateAgentScanReportRow{
			ID:               777,
			EngagementID:     p.EngagementID,
			SourceType:       database.ScanSourceTypeAgent,
			OriginalFilename: p.OriginalFilename,
			StorageUri:       p.StorageUri,
			Sha256:           p.Sha256,
			ParserVersion:    "agent-v1",
			ParseStatus:      database.ParseStatusSucceeded,
			UploadedBy:       p.UploadedBy,
		}, nil
	}
	return s.scanReport, nil
}

func (s *stubRepo) UpsertFinding(_ context.Context, p database.UpsertFindingParams) (database.UpsertFindingRow, error) {
	s.upsertCalled = true
	s.upsertParams = p
	if s.upsertErr != nil {
		return database.UpsertFindingRow{}, s.upsertErr
	}
	if s.upsertResult.ID == 0 {
		// Echo a plausible row so json.Marshal in RecordFinding doesn't
		// produce an empty-looking result in happy-path tests.
		return database.UpsertFindingRow{
			ID:           999,
			EngagementID: p.EngagementID,
			ScanReportID: p.ScanReportID,
			FindingType:  p.FindingType,
			TargetKind:   p.TargetKind,
			TargetRef:    p.TargetRef,
			Title:        p.Title,
			Severity:     p.Severity,
			Confidence:   p.Confidence,
			Evidence:     p.Evidence,
			InScope:      p.InScope,
			IsNew:        true,
		}, nil
	}
	return s.upsertResult, nil
}

func (s *stubRepo) AttachFindingSource(_ context.Context, p database.AttachFindingSourceParams) error {
	s.attachCalled = true
	s.attachParams = p
	return s.attachErr
}

func (s *stubRepo) ListScopeRules(_ context.Context, engagementID int64) ([]database.EngagementScopeRule, error) {
	s.scopeRulesEngID = engagementID
	return s.scopeRules, s.scopeRulesErr
}

func (s *stubRepo) ListFindings(_ context.Context, p database.ListFindingsParams) ([]database.Finding, error) {
	s.listCalled = true
	s.listParams = p
	return s.listResult, s.listErr
}

func (s *stubRepo) TopFindingsByCVSS(_ context.Context, p database.TopFindingsByCVSSParams) ([]database.Finding, error) {
	s.topCalled = true
	s.topParams = p
	return s.topResult, nil
}

func (s *stubRepo) FindingsByTargetKind(_ context.Context, p database.FindingsByTargetKindParams) ([]database.Finding, error) {
	s.byKindParams = p
	return s.byKindResult, nil
}

func (s *stubRepo) GetFinding(_ context.Context, id int64) (database.Finding, error) {
	if s.findingErr != nil {
		return database.Finding{}, s.findingErr
	}
	if s.finding.ID == 0 {
		return database.Finding{}, errors.New("not found")
	}
	if id != s.finding.ID {
		return database.Finding{}, errors.New("not found")
	}
	return s.finding, nil
}

func (s *stubRepo) UpdateFindingVerification(_ context.Context, p database.UpdateFindingVerificationParams) (database.Finding, error) {
	s.updateCalled = true
	s.updateParams = p
	return s.updateResult, s.updateErr
}

func (s *stubRepo) ListFlowRetestDiff(_ context.Context, flowID int64) ([]database.FlowRetestDiff, error) {
	s.diffCalled = true
	s.diffFlowID = flowID
	return s.diffResult, s.diffErr
}

// --- constructor ---

func TestNew_RejectsZeroEngagement(t *testing.T) {
	if _, err := New(&stubRepo{}, 0, 0, 0); err == nil {
		t.Fatal("expected error for engagementID=0")
	}
	if _, err := New(&stubRepo{}, -1, 0, 0); err == nil {
		t.Fatal("expected error for negative engagementID")
	}
	if _, err := New(nil, 5, 0, 0); err == nil {
		t.Fatal("expected error for nil repo")
	}
}

// --- list_findings ---

func TestListFindings_LimitClampAndDefaults(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int32
	}{
		{"empty args", ``, 50},
		{"empty object", `{}`, 50},
		{"under cap", `{"limit": 25}`, 25},
		{"at cap", `{"limit": 500}`, 500},
		{"over cap", `{"limit": 9999}`, 50},
		{"negative", `{"limit": -5}`, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stubRepo{}
			tl, err := New(s, 42, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tl.ListFindings(context.Background(), "list_findings", json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !s.listCalled {
				t.Fatal("repo.ListFindings was not called")
			}
			if s.listParams.Limit != int64(tc.want) {
				t.Errorf("limit = %d, want %d", s.listParams.Limit, tc.want)
			}
			if s.listParams.EngagementID != 42 {
				t.Errorf("engagement_id = %d, want 42", s.listParams.EngagementID)
			}
		})
	}
}

func TestListFindings_FilterPassthrough(t *testing.T) {
	s := &stubRepo{}
	tl, err := New(s, 7, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"severity":"high","cve":"CVE-2024-1234","target_kind":"host","verification_status":"confirmed","limit":100,"offset":50}`
	if _, err := tl.ListFindings(context.Background(), "list_findings", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	if s.listParams.Severity.SeverityLevel != database.SeverityLevelHigh || !s.listParams.Severity.Valid {
		t.Errorf("severity filter not forwarded: %+v", s.listParams.Severity)
	}
	if s.listParams.Cve.String != "CVE-2024-1234" || !s.listParams.Cve.Valid {
		t.Errorf("cve filter not forwarded: %+v", s.listParams.Cve)
	}
	if s.listParams.TargetKind.TargetKind != database.TargetKindHost || !s.listParams.TargetKind.Valid {
		t.Errorf("target_kind filter not forwarded: %+v", s.listParams.TargetKind)
	}
	if s.listParams.VerificationStatus.VerificationStatus != database.VerificationStatusConfirmed {
		t.Errorf("verification_status filter not forwarded: %+v", s.listParams.VerificationStatus)
	}
	if s.listParams.Offset != 50 {
		t.Errorf("offset = %d, want 50", s.listParams.Offset)
	}
}

func TestListFindings_InvalidJSON(t *testing.T) {
	tl, err := New(&stubRepo{}, 1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tl.ListFindings(context.Background(), "list_findings", json.RawMessage(`{not json`))
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

// --- get_top_findings_by_cvss ---

func TestGetTopFindingsByCVSS_ClampAndEngagement(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int32
	}{
		{"empty", ``, 10},
		{"under cap", `{"limit": 5}`, 5},
		{"over cap", `{"limit": 9999}`, 10},
		{"negative", `{"limit": -1}`, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stubRepo{}
			tl, err := New(s, 11, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tl.GetTopFindingsByCVSS(context.Background(), "get_top_findings_by_cvss", json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if !s.topCalled {
				t.Fatal("repo.TopFindingsByCVSS not called")
			}
			if s.topParams.Limit != int64(tc.want) {
				t.Errorf("limit = %d, want %d", s.topParams.Limit, tc.want)
			}
			if s.topParams.EngagementID != 11 {
				t.Errorf("engagement_id = %d, want 11", s.topParams.EngagementID)
			}
		})
	}
}

// --- get_host_services / get_container_cves ---

func TestGetHostServices_UsesHostKind(t *testing.T) {
	s := &stubRepo{}
	tl, _ := New(s, 3, 0, 0)
	if _, err := tl.GetHostServices(context.Background(), "get_host_services", nil); err != nil {
		t.Fatal(err)
	}
	if s.byKindParams.TargetKind != database.TargetKindHost {
		t.Errorf("got %q, want %q", s.byKindParams.TargetKind, database.TargetKindHost)
	}
	if s.byKindParams.EngagementID != 3 {
		t.Errorf("engagement_id = %d, want 3", s.byKindParams.EngagementID)
	}
}

func TestGetContainerCVEs_UsesContainerKind(t *testing.T) {
	s := &stubRepo{}
	tl, _ := New(s, 4, 0, 0)
	if _, err := tl.GetContainerCVEs(context.Background(), "get_container_cves", nil); err != nil {
		t.Fatal(err)
	}
	if s.byKindParams.TargetKind != database.TargetKindContainer {
		t.Errorf("got %q, want %q", s.byKindParams.TargetKind, database.TargetKindContainer)
	}
	if s.byKindParams.EngagementID != 4 {
		t.Errorf("engagement_id = %d, want 4", s.byKindParams.EngagementID)
	}
}

// --- get_finding_by_id ---

func TestGetFindingByID_RejectsCrossEngagement(t *testing.T) {
	// Finding belongs to engagement 7; Tools is bound to engagement 1.
	s := &stubRepo{finding: database.Finding{ID: 42, EngagementID: 7}}
	tl, _ := New(s, 1, 0, 0)

	_, err := tl.GetFindingByID(context.Background(), "get_finding_by_id", json.RawMessage(`{"id":42}`))
	if err == nil {
		t.Fatal("expected cross-engagement rejection")
	}
	if !strings.Contains(err.Error(), "engagement") {
		t.Fatalf("error should mention engagement, got: %v", err)
	}
}

func TestGetFindingByID_AcceptsSameEngagement(t *testing.T) {
	s := &stubRepo{finding: database.Finding{ID: 42, EngagementID: 1, Title: "demo"}}
	tl, _ := New(s, 1, 0, 0)

	out, err := tl.GetFindingByID(context.Background(), "get_finding_by_id", json.RawMessage(`{"id":42}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"id":42`) {
		t.Errorf("expected finding in output, got: %s", out)
	}
}

func TestGetFindingByID_RejectsBadInput(t *testing.T) {
	tl, _ := New(&stubRepo{}, 1, 0, 0)
	_, err := tl.GetFindingByID(context.Background(), "get_finding_by_id", json.RawMessage(`{"id":0}`))
	if err == nil {
		t.Fatal("expected error for id=0")
	}
	_, err = tl.GetFindingByID(context.Background(), "get_finding_by_id", json.RawMessage(`{"id":-5}`))
	if err == nil {
		t.Fatal("expected error for negative id")
	}
}

// --- mark_finding_verified ---

func TestMarkFindingVerified_RejectsCrossEngagement(t *testing.T) {
	s := &stubRepo{finding: database.Finding{ID: 99, EngagementID: 2}}
	tl, _ := New(s, 1, 0, 0)

	_, err := tl.MarkFindingVerified(context.Background(), "mark_finding_verified",
		json.RawMessage(`{"id":99,"verification_status":"confirmed","notes":"exploited"}`))
	if err == nil {
		t.Fatal("expected cross-engagement rejection")
	}
	if !strings.Contains(err.Error(), "engagement") {
		t.Fatalf("error should mention engagement, got: %v", err)
	}
	if s.updateCalled {
		t.Fatal("update must not be called after isolation check fails")
	}
}

func TestMarkFindingVerified_RejectsInvalidStatus(t *testing.T) {
	s := &stubRepo{finding: database.Finding{ID: 10, EngagementID: 1}}
	tl, _ := New(s, 1, 0, 0)

	for _, bad := range []string{"", "unverified", "verifying", "maybe", "yes"} {
		raw := `{"id":10,"verification_status":"` + bad + `"}`
		_, err := tl.MarkFindingVerified(context.Background(), "mark_finding_verified", json.RawMessage(raw))
		if err == nil {
			t.Errorf("expected rejection for status %q", bad)
		}
	}
}

func TestMarkFindingVerified_HappyPath(t *testing.T) {
	updated := database.Finding{
		ID:                 10,
		EngagementID:       1,
		VerificationStatus: database.VerificationStatusConfirmed,
		VerificationNotes:  sql.NullString{String: "RCE confirmed via payload X", Valid: true},
	}
	s := &stubRepo{
		finding:      database.Finding{ID: 10, EngagementID: 1},
		updateResult: updated,
	}
	tl, _ := New(s, 1, 0, 0)

	out, err := tl.MarkFindingVerified(context.Background(), "mark_finding_verified",
		json.RawMessage(`{"id":10,"verification_status":"confirmed","notes":"RCE confirmed via payload X"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.updateCalled {
		t.Fatal("update was not called")
	}
	if s.updateParams.ID != 10 {
		t.Errorf("update.ID = %d, want 10", s.updateParams.ID)
	}
	if s.updateParams.VerificationStatus != database.VerificationStatusConfirmed {
		t.Errorf("update.VerificationStatus = %q, want confirmed", s.updateParams.VerificationStatus)
	}
	if s.updateParams.VerificationNotes.String != "RCE confirmed via payload X" || !s.updateParams.VerificationNotes.Valid {
		t.Errorf("notes not forwarded: %+v", s.updateParams.VerificationNotes)
	}
	if s.updateParams.VerifiedBy.Valid {
		t.Error("verified_by must be NULL until Phase 14 wires user context")
	}
	if !strings.Contains(out, `"id":10`) {
		t.Errorf("expected updated finding in output, got: %s", out)
	}
}

func TestMarkFindingVerified_EmptyNotesStaysNull(t *testing.T) {
	s := &stubRepo{
		finding:      database.Finding{ID: 10, EngagementID: 1},
		updateResult: database.Finding{ID: 10, EngagementID: 1},
	}
	tl, _ := New(s, 1, 0, 0)
	if _, err := tl.MarkFindingVerified(context.Background(), "mark_finding_verified",
		json.RawMessage(`{"id":10,"verification_status":"false_positive"}`)); err != nil {
		t.Fatal(err)
	}
	if s.updateParams.VerificationNotes.Valid {
		t.Errorf("expected NULL notes when omitted, got %+v", s.updateParams.VerificationNotes)
	}
}

// --- compile-time: real *database.Queries satisfies Repo ---
// This catches interface drift if anybody changes the sqlc-generated
// signatures without updating Repo.

var _ Repo = (*database.Queries)(nil)

// --- get_retest_diff ---

func TestGetRetestDiff_HappyPath(t *testing.T) {
	want := []database.FlowRetestDiff{
		{FlowID: 42, FindingID: 1, DiffState: database.DiffStateFixed},
		{FlowID: 42, FindingID: 2, DiffState: database.DiffStatePersistent},
	}
	s := &stubRepo{diffResult: want}
	tl, _ := New(s, 1, 0, 0)
	got, err := tl.GetRetestDiff(context.Background(), "get_retest_diff", json.RawMessage(`{"flow_id":42}`))
	if err != nil {
		t.Fatalf("GetRetestDiff: %v", err)
	}
	if !s.diffCalled || s.diffFlowID != 42 {
		t.Errorf("expected ListFlowRetestDiff(42), got called=%v flowID=%d", s.diffCalled, s.diffFlowID)
	}
	if !strings.Contains(got, `"diff_state":"fixed"`) {
		t.Errorf("expected 'fixed' in output, got %s", got)
	}
}

func TestGetRetestDiff_RejectsInvalidFlowID(t *testing.T) {
	s := &stubRepo{}
	tl, _ := New(s, 1, 0, 0)
	if _, err := tl.GetRetestDiff(context.Background(), "get_retest_diff", json.RawMessage(`{"flow_id":0}`)); err == nil {
		t.Fatal("expected error for flow_id=0")
	}
	if _, err := tl.GetRetestDiff(context.Background(), "get_retest_diff", json.RawMessage(`{"flow_id":-1}`)); err == nil {
		t.Fatal("expected error for negative flow_id")
	}
	if s.diffCalled {
		t.Error("ListFlowRetestDiff must not be invoked for invalid args")
	}
}

func TestGetRetestDiff_MalformedJSON(t *testing.T) {
	s := &stubRepo{}
	tl, _ := New(s, 1, 0, 0)
	if _, err := tl.GetRetestDiff(context.Background(), "get_retest_diff", json.RawMessage(`{bad json}`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// --- record_finding ---

// scopeInclude builds a scope.ListScopeRules result that includes the given
// rule values, so the loaded matcher classifies the target as in-scope. We
// use the SCIDR include form because it exercises the most of the matcher
// code path; any include direction would do.
func includeScopeRules(values ...string) []database.EngagementScopeRule {
	rows := make([]database.EngagementScopeRule, 0, len(values))
	for i, v := range values {
		rows = append(rows, database.EngagementScopeRule{
			ID:           int64(i + 1),
			EngagementID: 1,
			RuleType:     database.ScopeRuleTypeCidr,
			Value:        v,
			Direction:    database.ScopeDirectionInclude,
		})
	}
	return rows
}

func TestRecordFinding_HappyPath(t *testing.T) {
	s := &stubRepo{scopeRules: includeScopeRules("10.1.2.0/24")}
	// flowID=42, userID=7 -> synthetic scan_reports row should carry those.
	tl, err := New(s, 1, 42, 7)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{
		"title": "SSRF via image-fetch endpoint",
		"target_kind": "host",
		"target_ref": "ip:10.1.2.3:443/tcp",
		"severity": "high",
		"cve": "CVE-2024-0001",
		"cvss_score": 8.2,
		"confidence": "firm",
		"source_id": "agent-ssrf-1",
		"evidence": {"req": "GET /image?u=http://169.254.169.254"}
	}`
	out, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.upsertCalled {
		t.Fatal("repo.UpsertFinding was not called")
	}
	if s.upsertParams.EngagementID != 1 {
		t.Errorf("engagement_id = %d, want 1", s.upsertParams.EngagementID)
	}
	if s.upsertParams.ScanReportID == 0 {
		t.Error("scan_report_id must be non-zero (synthetic scan_reports row)")
	}
	if s.upsertParams.Severity != database.SeverityLevelHigh {
		t.Errorf("severity = %q, want %q", s.upsertParams.Severity, database.SeverityLevelHigh)
	}
	if s.upsertParams.TargetKind != database.TargetKindHost {
		t.Errorf("target_kind = %q, want %q", s.upsertParams.TargetKind, database.TargetKindHost)
	}
	if s.upsertParams.Title != "SSRF via image-fetch endpoint" {
		t.Errorf("title = %q", s.upsertParams.Title)
	}
	if s.upsertParams.TargetRef != "ip:10.1.2.3:443/tcp" {
		t.Errorf("target_ref = %q", s.upsertParams.TargetRef)
	}
	if !s.upsertParams.InScope {
		t.Error("target should be in-scope given the 10.1.2.0/24 include rule")
	}
	if s.upsertParams.Cve.String != "CVE-2024-0001" || !s.upsertParams.Cve.Valid {
		t.Errorf("cve not forwarded: %+v", s.upsertParams.Cve)
	}
	if s.upsertParams.CvssScore.String != "8.2" || !s.upsertParams.CvssScore.Valid {
		t.Errorf("cvss_score not forwarded: %+v", s.upsertParams.CvssScore)
	}
	if s.upsertParams.SourceID.String != "agent-ssrf-1" || !s.upsertParams.SourceID.Valid {
		t.Errorf("source_id not forwarded: %+v", s.upsertParams.SourceID)
	}
	if s.upsertParams.Confidence != database.FindingConfidenceFirm {
		t.Errorf("confidence = %q", s.upsertParams.Confidence)
	}
	if s.upsertParams.FindingType != database.FindingTypeVulnerability {
		t.Errorf("finding_type default = %q", s.upsertParams.FindingType)
	}
	// Synthetic scan_reports row should be per-flow.
	if s.scanReportParams.EngagementID != 1 {
		t.Errorf("scan_report engagement_id = %d", s.scanReportParams.EngagementID)
	}
	if s.scanReportParams.UploadedBy != 7 {
		t.Errorf("scan_report uploaded_by = %d, want 7", s.scanReportParams.UploadedBy)
	}
	if !strings.Contains(s.scanReportParams.OriginalFilename, "flow-42") {
		t.Errorf("scan_report filename = %q, want to mention flow-42", s.scanReportParams.OriginalFilename)
	}
	if !s.attachCalled {
		t.Error("AttachFindingSource should have been invoked")
	}
	if !strings.Contains(out, `"id":999`) {
		t.Errorf("output should include the upserted row id; got %s", out)
	}
}

func TestRecordFinding_RejectsBadArgs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty title", `{"target_kind":"host","target_ref":"ip:10.1.2.3","severity":"high"}`},
		{"empty target_ref", `{"title":"x","target_kind":"host","target_ref":"","severity":"high"}`},
		{"missing target_kind", `{"title":"x","target_ref":"ip:10.1.2.3","severity":"high"}`},
		{"bogus severity", `{"title":"x","target_kind":"host","target_ref":"ip:10.1.2.3","severity":"hugely"}`},
		{"invalid json", `{not json`},
		{"cvss too high", `{"title":"x","target_kind":"host","target_ref":"ip:1.2.3.4","severity":"high","cvss_score":11}`},
		{"bad confidence", `{"title":"x","target_kind":"host","target_ref":"ip:1.2.3.4","severity":"high","confidence":"guessing"}`},
		{"bad finding_type", `{"title":"x","target_kind":"host","target_ref":"ip:1.2.3.4","severity":"high","finding_type":"made_up"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stubRepo{scopeRules: includeScopeRules("10.1.2.0/24")}
			tl, _ := New(s, 1, 42, 7)
			if _, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(tc.raw)); err == nil {
				t.Fatalf("expected error")
			}
			if s.upsertCalled {
				t.Fatal("UpsertFinding must not be called when validation fails")
			}
		})
	}
}

func TestRecordFinding_OutOfScopeStillStored(t *testing.T) {
	// Scope only includes 10.0.0.0/8; the agent target lives in 192.168/16.
	s := &stubRepo{scopeRules: includeScopeRules("10.0.0.0/8")}
	tl, _ := New(s, 1, 42, 7)
	raw := `{
		"title": "Exposed admin panel outside declared scope",
		"target_kind": "web_endpoint",
		"target_ref": "url:http://192.168.50.1/admin",
		"severity": "medium"
	}`
	if _, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.upsertCalled {
		t.Fatal("UpsertFinding should have been called — out-of-scope findings are stored, not rejected")
	}
	if s.upsertParams.InScope {
		t.Error("in_scope should be false for 192.168.50.1 when scope is 10.0.0.0/8")
	}
}

func TestRecordFinding_RequiresFlowAndUser(t *testing.T) {
	s := &stubRepo{scopeRules: includeScopeRules("10.0.0.0/8")}
	// flowID=0 — record_finding has nothing to key the synthetic report on.
	tl, _ := New(s, 1, 0, 7)
	raw := `{"title":"x","target_kind":"host","target_ref":"ip:10.1.1.1","severity":"low"}`
	if _, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw)); err == nil {
		t.Fatal("expected error when flowID is zero")
	}
	// userID=0 — scan_reports.uploaded_by is NOT NULL.
	tl2, _ := New(s, 1, 42, 0)
	if _, err := tl2.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw)); err == nil {
		t.Fatal("expected error when userID is zero")
	}
}

func TestRecordFinding_DeterministicScanReportSha(t *testing.T) {
	// Two record_finding calls from the same flow must hit
	// GetOrCreateAgentScanReport with identical sha256 values, so repeat
	// agent writes share the same scan_reports parent row.
	s := &stubRepo{scopeRules: includeScopeRules("10.0.0.0/8")}
	tl, _ := New(s, 1, 42, 7)
	raw1 := `{"title":"one","target_kind":"host","target_ref":"ip:10.1.1.1","severity":"low"}`
	raw2 := `{"title":"two","target_kind":"host","target_ref":"ip:10.1.1.2","severity":"high"}`
	if _, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw1)); err != nil {
		t.Fatal(err)
	}
	first := s.scanReportParams.Sha256
	if _, err := tl.RecordFinding(context.Background(), "record_finding", json.RawMessage(raw2)); err != nil {
		t.Fatal(err)
	}
	second := s.scanReportParams.Sha256
	if first == "" || first != second {
		t.Errorf("sha must be deterministic per-flow; got %q then %q", first, second)
	}
}
