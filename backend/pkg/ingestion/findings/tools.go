// Package findings exposes engagement findings to the LLM agents as a
// small set of JSON-in/JSON-out tools.
//
// Each Tools instance is engagement-scoped: the engagement ID is captured
// in the constructor and every query is filtered or re-checked against
// it, so an agent in engagement 1 cannot read findings from engagement 7
// even if it guesses an ID.
//
// Phase 11 ships the tool handlers and their JSON schemas. Wiring them
// into the per-flow executor registry (backend/pkg/tools/tools.go,
// GetPrimaryExecutor / GetPentesterExecutor / etc.) is deferred to
// Phase 14, which also plumbs engagement_id from the Flow row through
// NewFlowToolsExecutor. Until Phase 14 lands, agents will not see these
// tools; that is intentional — legacy flows have no engagement context.
package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"pentagi/pkg/database"
)

// ---------------------------------------------------------------------
// Agent-facing arg structs.
//
// The JSON schemas for these structs are reflected by pkg/tools/registry.go
// (which imports this package — not the other way around, to avoid an
// import cycle). Keep field names, tags, and jsonschema annotations in sync
// with tools/args.go's pre-Phase-14 definitions; changing them here affects
// what the LLM sees.
// ---------------------------------------------------------------------

// ListFindingsAction controls list_findings.
type ListFindingsAction struct {
	Severity           string `json:"severity,omitempty" jsonschema:"enum=info,enum=low,enum=medium,enum=high,enum=critical" jsonschema_description:"Filter by severity level"`
	CVE                string `json:"cve,omitempty" jsonschema_description:"Exact CVE identifier to filter on, e.g. CVE-2024-1234"`
	TargetKind         string `json:"target_kind,omitempty" jsonschema:"enum=host,enum=web_endpoint,enum=container" jsonschema_description:"Filter by target kind"`
	VerificationStatus string `json:"verification_status,omitempty" jsonschema:"enum=unverified,enum=verifying,enum=confirmed,enum=false_positive,enum=not_exploitable" jsonschema_description:"Filter by verification status"`
	Limit              int32  `json:"limit,omitempty" jsonschema:"type=integer" jsonschema_description:"Maximum rows to return (default 50, capped at 500)"`
	Offset             int32  `json:"offset,omitempty" jsonschema:"type=integer" jsonschema_description:"Pagination offset (default 0)"`
}

// TopFindingsByCVSSAction controls get_top_findings_by_cvss.
type TopFindingsByCVSSAction struct {
	Limit int32 `json:"limit,omitempty" jsonschema:"type=integer" jsonschema_description:"Top-N findings to return, ordered by CVSS score desc (default 10, capped at 100)"`
}

// FindingsByKindAction is the (empty) args struct shared by
// get_host_services and get_container_cves. The engagement is captured at
// construction time and the target kind is bound into each tool's identity,
// so no runtime arguments are needed.
type FindingsByKindAction struct{}

// GetFindingByIDAction controls get_finding_by_id.
type GetFindingByIDAction struct {
	ID int64 `json:"id" jsonschema:"required,type=integer" jsonschema_description:"Database id of the finding to fetch. Must belong to the current engagement."`
}

// MarkFindingVerifiedAction controls mark_finding_verified.
type MarkFindingVerifiedAction struct {
	ID                 int64  `json:"id" jsonschema:"required,type=integer" jsonschema_description:"Database id of the finding to update"`
	VerificationStatus string `json:"verification_status" jsonschema:"required,enum=confirmed,enum=false_positive,enum=not_exploitable" jsonschema_description:"Terminal classification the agent is assigning. 'confirmed' means the vulnerability was reproduced; 'false_positive' means the scanner was wrong; 'not_exploitable' means real but not reachable / not useful."`
	Notes              string `json:"notes,omitempty" jsonschema_description:"Free-text reasoning for the classification. Include evidence the agent gathered (commands run, payloads tried, responses seen)."`
}

// GetRetestDiffAction controls get_retest_diff.
type GetRetestDiffAction struct {
	FlowID int64 `json:"flow_id" jsonschema:"required,type=integer" jsonschema_description:"Flow id whose retest diff should be returned. Typically the current flow."`
}

// Repo is the narrow slice of database.Querier this package needs.
// Using an interface rather than *database.Queries keeps tests light
// (see tools_test.go) — the real *database.Queries satisfies it via
// structural typing.
type Repo interface {
	ListFindings(ctx context.Context, arg database.ListFindingsParams) ([]database.Finding, error)
	TopFindingsByCVSS(ctx context.Context, arg database.TopFindingsByCVSSParams) ([]database.Finding, error)
	FindingsByTargetKind(ctx context.Context, arg database.FindingsByTargetKindParams) ([]database.Finding, error)
	GetFinding(ctx context.Context, id int64) (database.Finding, error)
	UpdateFindingVerification(ctx context.Context, arg database.UpdateFindingVerificationParams) (database.Finding, error)
}

// Tools bundles the six agent-facing finding handlers. Construct one per
// flow at flow-start when the flow has a non-null engagement_id.
type Tools struct {
	repo         Repo
	engagementID int64
}

// New returns a Tools bound to engagementID. engagementID must be > 0; a
// zero value is refused because it would silently match any legacy row
// whose engagement_id was defaulted to 0.
func New(repo Repo, engagementID int64) (*Tools, error) {
	if repo == nil {
		return nil, errors.New("findings.New: repo is required")
	}
	if engagementID <= 0 {
		return nil, fmt.Errorf("findings.New: engagementID must be positive, got %d", engagementID)
	}
	return &Tools{repo: repo, engagementID: engagementID}, nil
}

// ---- list_findings ----

const (
	defaultListLimit = 50
	maxListLimit     = 500
	defaultTopLimit  = 10
	maxTopLimit      = 100
)

// ListFindings implements list_findings: paginated, filterable listing
// of findings scoped to this Tools' engagement. The argument schema is
// ListFindingsAction (defined alongside the registry reflector so
// the LLM-facing schema never diverges from the handler's parser).
func (t *Tools) ListFindings(ctx context.Context, _ string, raw json.RawMessage) (string, error) {
	var args ListFindingsAction
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", fmt.Errorf("list_findings: invalid arguments: %w", err)
		}
	}
	args.Limit = clampListLimit(args.Limit)
	if args.Offset < 0 {
		args.Offset = 0
	}

	params := t.buildListParams(args)
	rows, err := t.repo.ListFindings(ctx, params)
	if err != nil {
		return "", fmt.Errorf("list_findings: query failed: %w", err)
	}
	out, err := json.Marshal(rows)
	if err != nil {
		return "", fmt.Errorf("list_findings: marshal failed: %w", err)
	}
	return string(out), nil
}

func clampListLimit(in int32) int32 {
	if in <= 0 || in > maxListLimit {
		return defaultListLimit
	}
	return in
}

func clampTopLimit(in int32) int32 {
	if in <= 0 || in > maxTopLimit {
		return defaultTopLimit
	}
	return in
}

func (t *Tools) buildListParams(a ListFindingsAction) database.ListFindingsParams {
	p := database.ListFindingsParams{
		EngagementID: t.engagementID,
		Limit:        int64(a.Limit),
		Offset:       int64(a.Offset),
	}
	if a.Severity != "" {
		p.Severity = database.NullSeverityLevel{
			SeverityLevel: database.SeverityLevel(a.Severity),
			Valid:         true,
		}
	}
	if a.CVE != "" {
		p.Cve = sql.NullString{String: a.CVE, Valid: true}
	}
	if a.TargetKind != "" {
		p.TargetKind = database.NullTargetKind{
			TargetKind: database.TargetKind(a.TargetKind),
			Valid:      true,
		}
	}
	if a.VerificationStatus != "" {
		p.VerificationStatus = database.NullVerificationStatus{
			VerificationStatus: database.VerificationStatus(a.VerificationStatus),
			Valid:              true,
		}
	}
	return p
}

// ---- get_top_findings_by_cvss ----

// GetTopFindingsByCVSS returns the highest-CVSS findings for the
// engagement. Use it at engagement kickoff to prioritise attack surface.
func (t *Tools) GetTopFindingsByCVSS(ctx context.Context, _ string, raw json.RawMessage) (string, error) {
	var args TopFindingsByCVSSAction
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", fmt.Errorf("get_top_findings_by_cvss: invalid arguments: %w", err)
		}
	}
	args.Limit = clampTopLimit(args.Limit)

	rows, err := t.repo.TopFindingsByCVSS(ctx, database.TopFindingsByCVSSParams{
		EngagementID: t.engagementID,
		Limit:        int64(args.Limit),
	})
	if err != nil {
		return "", fmt.Errorf("get_top_findings_by_cvss: query failed: %w", err)
	}
	out, err := json.Marshal(rows)
	if err != nil {
		return "", fmt.Errorf("get_top_findings_by_cvss: marshal failed: %w", err)
	}
	return string(out), nil
}

// ---- get_host_services / get_container_cves ----

// GetHostServices returns findings whose target is a host (services &
// host-level findings).
func (t *Tools) GetHostServices(ctx context.Context, _ string, _ json.RawMessage) (string, error) {
	return t.findingsByKind(ctx, database.TargetKindHost, "get_host_services")
}

// GetContainerCVEs returns findings whose target is a container (CVEs
// from image scanners like Twistlock).
func (t *Tools) GetContainerCVEs(ctx context.Context, _ string, _ json.RawMessage) (string, error) {
	return t.findingsByKind(ctx, database.TargetKindContainer, "get_container_cves")
}

func (t *Tools) findingsByKind(ctx context.Context, kind database.TargetKind, toolName string) (string, error) {
	rows, err := t.repo.FindingsByTargetKind(ctx, database.FindingsByTargetKindParams{
		EngagementID: t.engagementID,
		TargetKind:   kind,
	})
	if err != nil {
		return "", fmt.Errorf("%s: query failed: %w", toolName, err)
	}
	out, err := json.Marshal(rows)
	if err != nil {
		return "", fmt.Errorf("%s: marshal failed: %w", toolName, err)
	}
	return string(out), nil
}

// ---- get_finding_by_id ----

// GetFindingByID returns a single finding. Enforces engagement isolation:
// a finding from another engagement is rejected with an error rather
// than leaked.
func (t *Tools) GetFindingByID(ctx context.Context, _ string, raw json.RawMessage) (string, error) {
	var args GetFindingByIDAction
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("get_finding_by_id: invalid arguments: %w", err)
	}
	if args.ID <= 0 {
		return "", errors.New("get_finding_by_id: id must be positive")
	}

	row, err := t.repo.GetFinding(ctx, args.ID)
	if err != nil {
		return "", fmt.Errorf("get_finding_by_id: query failed: %w", err)
	}
	if row.EngagementID != t.engagementID {
		return "", fmt.Errorf("get_finding_by_id: finding %d does not belong to engagement %d", args.ID, t.engagementID)
	}
	out, err := json.Marshal(row)
	if err != nil {
		return "", fmt.Errorf("get_finding_by_id: marshal failed: %w", err)
	}
	return string(out), nil
}

// ---- mark_finding_verified ----

// allowedAgentVerificationStatuses is the set of statuses an LLM agent
// can assign. 'unverified' and 'verifying' are excluded because setting
// them via this tool would be meaningless (the first is the default, the
// second is controller-managed). 'confirmed', 'false_positive',
// 'not_exploitable' are terminal classifications the agent can make.
var allowedAgentVerificationStatuses = map[string]struct{}{
	string(database.VerificationStatusConfirmed):      {},
	string(database.VerificationStatusFalsePositive):  {},
	string(database.VerificationStatusNotExploitable): {},
}

// MarkFindingVerified updates verification_status + verification_notes.
// Enforces engagement isolation via a GetFinding pre-read (parallel to
// GetFindingByID).
func (t *Tools) MarkFindingVerified(ctx context.Context, _ string, raw json.RawMessage) (string, error) {
	var args MarkFindingVerifiedAction
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("mark_finding_verified: invalid arguments: %w", err)
	}
	if args.ID <= 0 {
		return "", errors.New("mark_finding_verified: id must be positive")
	}
	if _, ok := allowedAgentVerificationStatuses[args.VerificationStatus]; !ok {
		return "", fmt.Errorf("mark_finding_verified: verification_status must be one of confirmed|false_positive|not_exploitable, got %q", args.VerificationStatus)
	}

	existing, err := t.repo.GetFinding(ctx, args.ID)
	if err != nil {
		return "", fmt.Errorf("mark_finding_verified: lookup failed: %w", err)
	}
	if existing.EngagementID != t.engagementID {
		return "", fmt.Errorf("mark_finding_verified: finding %d does not belong to engagement %d", args.ID, t.engagementID)
	}

	updated, err := t.repo.UpdateFindingVerification(ctx, database.UpdateFindingVerificationParams{
		ID:                 args.ID,
		VerificationStatus: database.VerificationStatus(args.VerificationStatus),
		VerificationNotes:  sql.NullString{String: args.Notes, Valid: args.Notes != ""},
		// VerifiedBy stays NULL — agents don't carry a user id. Phase 14
		// will populate it if/when the tool is invoked from a flow that
		// has a user context.
	})
	if err != nil {
		return "", fmt.Errorf("mark_finding_verified: update failed: %w", err)
	}
	out, err := json.Marshal(updated)
	if err != nil {
		return "", fmt.Errorf("mark_finding_verified: marshal failed: %w", err)
	}
	return string(out), nil
}
