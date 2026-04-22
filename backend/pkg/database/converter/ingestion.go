package converter

import (
	"strconv"
	"strings"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/graph/model"
)

// ConvertEngagement maps a sqlc-generated database.Engagement to the
// GraphQL model.Engagement. Nested collections (scope rules, scan reports,
// findings, stats) are caller-supplied so the converter stays pure; pass nil
// slices when a surface doesn't need them and let the GraphQL layer emit
// empty arrays.
func ConvertEngagement(
	eng database.Engagement,
	rules []database.EngagementScopeRule,
	reports []database.ScanReport,
	findings []database.Finding,
	findingsReportsByID map[int64]database.ScanReport,
	stats *database.EngagementFindingStatsRow,
) *model.Engagement {
	// Engagement status strings are lower_snake in the database and
	// UPPER_SNAKE in the GraphQL enum; the database form is what gqlgen
	// expects when we upper-case it.
	status := model.EngagementStatus(strings.ToUpper(string(eng.Status)))

	var description *string
	if eng.Description.Valid {
		d := eng.Description.String
		description = &d
	}

	return &model.Engagement{
		ID:           eng.ID,
		Name:         eng.Name,
		Client:       eng.Client,
		Description:  description,
		Status:       status,
		ScopeRules:   ConvertScopeRules(rules),
		ScanReports:  ConvertScanReports(reports),
		Findings:     ConvertFindings(findings, findingsReportsByID),
		FindingStats: ConvertFindingStats(stats),
		CreatedAt:    eng.CreatedAt,
		UpdatedAt:    eng.UpdatedAt,
	}
}

// ConvertScopeRules bulk-maps scope rules, returning a non-nil slice so the
// GraphQL schema's non-null array contract is honoured even when empty.
func ConvertScopeRules(rules []database.EngagementScopeRule) []*model.ScopeRule {
	out := make([]*model.ScopeRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ConvertScopeRule(r))
	}
	return out
}

func ConvertScopeRule(r database.EngagementScopeRule) *model.ScopeRule {
	var note *string
	if r.Note.Valid {
		n := r.Note.String
		note = &n
	}
	return &model.ScopeRule{
		ID:        r.ID,
		RuleType:  model.ScopeRuleType(strings.ToUpper(string(r.RuleType))),
		Value:     r.Value,
		Direction: model.ScopeDirection(strings.ToUpper(string(r.Direction))),
		Note:      note,
	}
}

// ConvertScanReports bulk-maps scan reports.
func ConvertScanReports(reports []database.ScanReport) []*model.ScanReport {
	out := make([]*model.ScanReport, 0, len(reports))
	for _, r := range reports {
		out = append(out, ConvertScanReport(r))
	}
	return out
}

func ConvertScanReport(r database.ScanReport) *model.ScanReport {
	var scanDate *time.Time
	if r.ScanDate.Valid {
		d := r.ScanDate.Time
		scanDate = &d
	}
	var parseError *string
	if r.ParseError.Valid {
		e := r.ParseError.String
		parseError = &e
	}
	return &model.ScanReport{
		ID:               r.ID,
		SourceType:       model.ScanSourceType(strings.ToUpper(string(r.SourceType))),
		OriginalFilename: r.OriginalFilename,
		ScanDate:         scanDate,
		IngestedAt:       r.IngestedAt,
		ParseStatus:      model.ParseStatus(strings.ToUpper(string(r.ParseStatus))),
		ParseError:       parseError,
		FindingCount:     int(r.FindingCount),
	}
}

// ConvertFindings bulk-maps findings. reportsByID (nullable) lets the
// converter resolve the finding's source report into a model.ScanReport
// without an extra database trip; pass nil to fall back to an empty
// sources slice.
func ConvertFindings(
	findings []database.Finding,
	reportsByID map[int64]database.ScanReport,
) []*model.Finding {
	out := make([]*model.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, ConvertFinding(f, reportsByID))
	}
	return out
}

// ConvertFinding maps a single finding. The sources slice currently includes
// only the owning scan_report; the finding_sources join table is not yet
// surfaced on the GraphQL API (Phase 14 may expand this).
func ConvertFinding(
	f database.Finding,
	reportsByID map[int64]database.ScanReport,
) *model.Finding {
	var cve *string
	if f.Cve.Valid {
		v := f.Cve.String
		cve = &v
	}
	var cvss *float64
	if f.CvssScore.Valid {
		// cvss_score is stored as NUMERIC → sql.NullString; parse float.
		if v, err := strconv.ParseFloat(f.CvssScore.String, 64); err == nil {
			cvss = &v
		}
	}

	sources := make([]*model.ScanReport, 0, 1)
	if reportsByID != nil {
		if rep, ok := reportsByID[f.ScanReportID]; ok {
			sources = append(sources, ConvertScanReport(rep))
		}
	}

	evidence := ""
	if len(f.Evidence) > 0 {
		evidence = string(f.Evidence)
	}

	return &model.Finding{
		ID:    f.ID,
		Title: f.Title,
		Cve:   cve,
		CvssScore: cvss,
		Severity:   model.SeverityLevel(strings.ToUpper(string(f.Severity))),
		Confidence: model.FindingConfidence(strings.ToUpper(string(f.Confidence))),
		Target: &model.Target{
			Kind: model.TargetKind(strings.ToUpper(string(f.TargetKind))),
			Ref:  f.TargetRef,
		},
		InScope:            f.InScope,
		VerificationStatus: model.VerificationStatus(strings.ToUpper(string(f.VerificationStatus))),
		Sources:            sources,
		Evidence:           evidence,
		FirstSeenAt:        f.FirstSeenAt,
		LastSeenAt:         f.LastSeenAt,
	}
}

// ConvertFindingStats collapses the stats row into the GraphQL shape.
// A nil input yields a zero-valued stats pointer so the GraphQL non-null
// contract is honoured on an empty engagement.
func ConvertFindingStats(s *database.EngagementFindingStatsRow) *model.FindingStats {
	if s == nil {
		return &model.FindingStats{}
	}
	return &model.FindingStats{
		Critical:   int(s.CriticalCount),
		High:       int(s.HighCount),
		Medium:     int(s.MediumCount),
		Low:        int(s.LowCount),
		Info:       int(s.InfoCount),
		OutOfScope: int(s.OosCount),
		Confirmed:  int(s.ConfirmedCount),
	}
}
