// Package services — IngestionService exposes the REST layer for scanner-report
// ingestion: engagements, scope rules, raw scan reports, and findings. It glues
// the pkg/ingestion subpackages (engagement.Service, parsers.Parser, scope.Matcher,
// seeder.Seeder) together, persists the parsed bundle via the SQLC Querier, and
// fires off a best-effort Graphiti seed for each finding.
//
// The handlers follow the surrounding codebase conventions: response.Success /
// response.Error for JSON envelopes, logger.FromContext(c) for structured logs,
// and c.GetUint64("uid") to pull the authenticated user id out of the gin
// context (populated by auth_middleware.AuthTokenRequired).
package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"pentagi/pkg/database"
	"pentagi/pkg/ingestion/engagement"
	"pentagi/pkg/ingestion/parsers"
	"pentagi/pkg/ingestion/schema"
	"pentagi/pkg/ingestion/scope"
	"pentagi/pkg/ingestion/seeder"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// IngestionService is the REST-layer service for the scanner-ingestion feature.
// It owns its own Querier (for direct SQLC access) plus a small set of
// collaborators created up-front in NewIngestionService.
type IngestionService struct {
	q          database.Querier
	eng        *engagement.Service
	seeder     *seeder.Seeder
	storageDir string
	parsers    map[schema.ScanSourceType]parsers.Parser
	log        *logrus.Entry
}

// NewIngestionService constructs the service. The caller is responsible for
// ensuring storageDir exists (see cmd/pentagi/main.go).
func NewIngestionService(
	q database.Querier,
	eng *engagement.Service,
	sd *seeder.Seeder,
	storageDir string,
	log *logrus.Entry,
) *IngestionService {
	return &IngestionService{
		q:          q,
		eng:        eng,
		seeder:     sd,
		storageDir: storageDir,
		log:        log,
		parsers: map[schema.ScanSourceType]parsers.Parser{
			schema.SourceNmap:      &parsers.NmapParser{},
			schema.SourceBurp:      &parsers.BurpParser{},
			schema.SourceTwistlock: &parsers.TwistlockParser{},
			schema.SourceQualys:    &parsers.QualysParser{},
		},
	}
}

// -- request payloads ---------------------------------------------------------

type createEngagementRequest struct {
	Name        string `json:"name" binding:"required"`
	Client      string `json:"client" binding:"required"`
	Description string `json:"description"`
}

type updateEngagementRequest struct {
	Name        *string `json:"name"`
	Client      *string `json:"client"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
}

type addScopeRuleRequest struct {
	RuleType  string `json:"rule_type" binding:"required"`
	Value     string `json:"value" binding:"required"`
	Direction string `json:"direction"` // optional — defaults to "include"
	Note      string `json:"note"`
}

type updateFindingVerificationRequest struct {
	VerificationStatus string `json:"verification_status" binding:"required"`
	Notes              string `json:"notes"`
}

// -- engagement handlers ------------------------------------------------------

// CreateEngagement
// @Summary Create a new engagement
// @Tags Ingestion
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param json body createEngagementRequest true "engagement details"
// @Success 201 {object} response.successResp{data=database.Engagement}
// @Router /engagements/ [post]
func (s *IngestionService) CreateEngagement(c *gin.Context) {
	var req createEngagementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Error("engagement create: bind")
		response.Error(c, response.ErrIngestionInvalidRequest, err)
		return
	}

	uid := c.GetUint64("uid")
	row, err := s.eng.Create(c.Request.Context(), engagement.CreateInput{
		Name:        req.Name,
		Client:      req.Client,
		Description: req.Description,
		CreatedBy:   int64(uid),
	})
	if err != nil {
		logger.FromContext(c).WithError(err).Error("engagement create: persist")
		response.Error(c, response.ErrIngestionInvalidData, err)
		return
	}
	response.Success(c, http.StatusCreated, row)
}

// ListEngagements
// @Summary List engagements
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param limit query int false "page size (default 50)"
// @Param offset query int false "offset (default 0)"
// @Success 200 {object} response.successResp{data=[]database.Engagement}
// @Router /engagements/ [get]
func (s *IngestionService) ListEngagements(c *gin.Context) {
	limit := parseInt64Query(c, "limit", 50)
	offset := parseInt64Query(c, "offset", 0)
	rows, err := s.q.ListEngagements(c.Request.Context(), database.ListEngagementsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		logger.FromContext(c).WithError(err).Error("engagement list")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, rows)
}

// GetEngagement
// @Summary Get an engagement by id
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Success 200 {object} response.successResp{data=database.Engagement}
// @Router /engagements/{id} [get]
func (s *IngestionService) GetEngagement(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	row, err := s.q.GetEngagement(c.Request.Context(), engID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrEngagementNotFound, err)
			return
		}
		logger.FromContext(c).WithError(err).Error("engagement get")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, row)
}

// UpdateEngagement
// @Summary Update engagement fields
// @Tags Ingestion
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param json body updateEngagementRequest true "fields to patch"
// @Success 200 {object} response.successResp{data=database.Engagement}
// @Router /engagements/{id} [patch]
func (s *IngestionService) UpdateEngagement(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	var req updateEngagementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Error("engagement update: bind")
		response.Error(c, response.ErrIngestionInvalidRequest, err)
		return
	}

	params := database.UpdateEngagementParams{
		ID:        engID,
		UpdatedBy: int64(c.GetUint64("uid")),
	}
	if req.Name != nil {
		params.Name = sql.NullString{String: *req.Name, Valid: true}
	}
	if req.Client != nil {
		params.Client = sql.NullString{String: *req.Client, Valid: true}
	}
	if req.Description != nil {
		params.Description = sql.NullString{String: *req.Description, Valid: true}
	}
	if req.Status != nil {
		params.Status = database.NullEngagementStatus{
			EngagementStatus: database.EngagementStatus(*req.Status),
			Valid:            true,
		}
	}

	row, err := s.q.UpdateEngagement(c.Request.Context(), params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrEngagementNotFound, err)
			return
		}
		logger.FromContext(c).WithError(err).Error("engagement update")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, row)
}

// DeleteEngagement
// @Summary Soft-delete an engagement
// @Tags Ingestion
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Success 204 "engagement deleted"
// @Router /engagements/{id} [delete]
func (s *IngestionService) DeleteEngagement(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := s.q.SoftDeleteEngagement(c.Request.Context(), engID); err != nil {
		logger.FromContext(c).WithError(err).Error("engagement delete")
		response.Error(c, response.ErrInternal, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// -- scope rules --------------------------------------------------------------

// AddScopeRule
// @Summary Attach a scope rule to an engagement
// @Tags Ingestion
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param json body addScopeRuleRequest true "scope rule"
// @Success 201 {object} response.successResp{data=database.EngagementScopeRule}
// @Router /engagements/{id}/scope-rules [post]
func (s *IngestionService) AddScopeRule(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	var req addScopeRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, response.ErrIngestionInvalidRequest, err)
		return
	}
	direction := req.Direction
	if direction == "" {
		direction = "include"
	}
	row, err := s.q.AddScopeRule(c.Request.Context(), database.AddScopeRuleParams{
		EngagementID: engID,
		RuleType:     database.ScopeRuleType(req.RuleType),
		Value:        req.Value,
		Direction:    database.ScopeDirection(direction),
		Note:         nullStringFromStr(req.Note),
	})
	if err != nil {
		logger.FromContext(c).WithError(err).Error("scope rule add")
		response.Error(c, response.ErrIngestionInvalidData, err)
		return
	}
	response.Success(c, http.StatusCreated, row)
}

// DeleteScopeRule
// @Summary Delete a scope rule
// @Tags Ingestion
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param ruleId path int true "scope rule id"
// @Success 204 "scope rule deleted"
// @Router /engagements/{id}/scope-rules/{ruleId} [delete]
func (s *IngestionService) DeleteScopeRule(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	ruleID, ok := parseInt64Param(c, "ruleId")
	if !ok {
		return
	}
	if err := s.q.DeleteScopeRule(c.Request.Context(), database.DeleteScopeRuleParams{
		ID:           ruleID,
		EngagementID: engID,
	}); err != nil {
		logger.FromContext(c).WithError(err).Error("scope rule delete")
		response.Error(c, response.ErrInternal, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// -- scan reports -------------------------------------------------------------

// UploadReport accepts a multipart file upload (field "file") + form field
// "source_type". It hashes the file while streaming to disk, dedups against
// GetScanReportBySha, persists the scan_reports row in status "pending", and
// kicks off the async parse.
//
// @Summary Upload a scanner report
// @Tags Ingestion
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param source_type formData string true "scanner source (nmap|burp|qualys|twistlock)"
// @Param file formData file true "report file"
// @Success 202 {object} response.successResp{data=database.ScanReport}
// @Failure 409 {object} response.errorResp "already ingested"
// @Router /engagements/{id}/reports [post]
func (s *IngestionService) UploadReport(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}

	sourceType := schema.ScanSourceType(c.PostForm("source_type"))
	if _, ok := s.parsers[sourceType]; !ok {
		response.Error(c, response.ErrUnsupportedSourceType,
			fmt.Errorf("unsupported source_type %q", sourceType))
		return
	}

	fh, err := c.FormFile("file")
	if err != nil {
		response.Error(c, response.ErrIngestionInvalidRequest, err)
		return
	}

	src, err := fh.Open()
	if err != nil {
		response.Error(c, response.ErrInternal, err)
		return
	}
	defer src.Close()

	if err := os.MkdirAll(s.storageDir, 0o755); err != nil {
		response.Error(c, response.ErrInternal, err)
		return
	}

	tmp, err := os.CreateTemp(s.storageDir, "upload-*")
	if err != nil {
		response.Error(c, response.ErrInternal, err)
		return
	}
	// Close handle in every exit path. Rename succeeds without the handle
	// being closed on some filesystems (not Windows) but explicit is clearer.
	tmpPath := tmp.Name()
	cleanupTmp := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil {
		cleanupTmp()
		response.Error(c, response.ErrInternal, err)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		response.Error(c, response.ErrInternal, err)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))

	// Dedup guard: if an identical upload already exists for this engagement,
	// surface the existing row with 409 Conflict so the caller can reconcile.
	existing, err := s.q.GetScanReportBySha(c.Request.Context(), database.GetScanReportByShaParams{
		EngagementID: engID,
		Sha256:       sum,
	})
	if err == nil {
		_ = os.Remove(tmpPath)
		response.Error(c, response.ErrScanReportDuplicate,
			fmt.Errorf("existing scan_report_id=%d", existing.ID))
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		_ = os.Remove(tmpPath)
		logger.FromContext(c).WithError(err).Error("scan report dedup lookup")
		response.Error(c, response.ErrInternal, err)
		return
	}

	finalPath := filepath.Join(s.storageDir, fmt.Sprintf("%d-%s-%s", engID, sum, filepath.Base(fh.Filename)))
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		response.Error(c, response.ErrInternal, err)
		return
	}

	uid := c.GetUint64("uid")
	row, err := s.q.CreateScanReport(c.Request.Context(), database.CreateScanReportParams{
		EngagementID:     engID,
		SourceType:       database.ScanSourceType(sourceType),
		OriginalFilename: fh.Filename,
		StorageUri:       finalPath,
		Sha256:           sum,
		ScanDate:         sql.NullTime{}, // not extracted from XML in v1
		ParserVersion:    "v1",
		UploadedBy:       int64(uid),
	})
	if err != nil {
		_ = os.Remove(finalPath)
		logger.FromContext(c).WithError(err).Error("scan report create")
		response.Error(c, response.ErrInternal, err)
		return
	}

	// Fire-and-forget async parse. Use a detached background context so the
	// parse is not cancelled when the HTTP handler returns. Failures are
	// recorded on the row itself via UpdateScanReportStatus.
	go s.runParse(context.Background(), row, sourceType, finalPath)

	response.Success(c, http.StatusAccepted, row)
}

// ListReports
// @Summary List scan reports for an engagement
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Success 200 {object} response.successResp{data=[]database.ScanReport}
// @Router /engagements/{id}/reports [get]
func (s *IngestionService) ListReports(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	limit := parseInt64Query(c, "limit", 50)
	offset := parseInt64Query(c, "offset", 0)
	rows, err := s.q.ListScanReports(c.Request.Context(), database.ListScanReportsParams{
		EngagementID: engID,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		logger.FromContext(c).WithError(err).Error("scan report list")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, rows)
}

// GetReport
// @Summary Get a scan report
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param reportId path int true "scan report id"
// @Success 200 {object} response.successResp{data=database.ScanReport}
// @Router /engagements/{id}/reports/{reportId} [get]
func (s *IngestionService) GetReport(c *gin.Context) {
	reportID, ok := parseInt64Param(c, "reportId")
	if !ok {
		return
	}
	row, err := s.q.GetScanReport(c.Request.Context(), reportID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrScanReportNotFound, err)
			return
		}
		logger.FromContext(c).WithError(err).Error("scan report get")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, row)
}

// DownloadReport serves the raw uploaded file bytes.
//
// @Summary Download the original scan report file
// @Tags Ingestion
// @Produce octet-stream
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param reportId path int true "scan report id"
// @Success 200 "report file"
// @Router /engagements/{id}/reports/{reportId}/raw [get]
func (s *IngestionService) DownloadReport(c *gin.Context) {
	reportID, ok := parseInt64Param(c, "reportId")
	if !ok {
		return
	}
	row, err := s.q.GetScanReport(c.Request.Context(), reportID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrScanReportNotFound, err)
			return
		}
		response.Error(c, response.ErrInternal, err)
		return
	}
	c.FileAttachment(row.StorageUri, row.OriginalFilename)
}

// -- findings -----------------------------------------------------------------

// ListFindings
// @Summary List findings for an engagement
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param severity query string false "filter: info|low|medium|high|critical"
// @Param cve query string false "filter: exact CVE id"
// @Param target_kind query string false "filter: host|web_endpoint|container"
// @Param in_scope query bool false "filter: true|false"
// @Param verification_status query string false "filter verification status"
// @Param limit query int false "page size (default 100)"
// @Param offset query int false "offset (default 0)"
// @Success 200 {object} response.successResp{data=[]database.Finding}
// @Router /engagements/{id}/findings [get]
func (s *IngestionService) ListFindings(c *gin.Context) {
	engID, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	params := database.ListFindingsParams{
		EngagementID: engID,
		Limit:        parseInt64Query(c, "limit", 100),
		Offset:       parseInt64Query(c, "offset", 0),
	}
	if v := c.Query("severity"); v != "" {
		params.Severity = database.NullSeverityLevel{
			SeverityLevel: database.SeverityLevel(v), Valid: true,
		}
	}
	if v := c.Query("cve"); v != "" {
		params.Cve = sql.NullString{String: v, Valid: true}
	}
	if v := c.Query("target_kind"); v != "" {
		params.TargetKind = database.NullTargetKind{
			TargetKind: database.TargetKind(v), Valid: true,
		}
	}
	if v := c.Query("in_scope"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(c, response.ErrIngestionInvalidRequest, err)
			return
		}
		params.InScope = sql.NullBool{Bool: b, Valid: true}
	}
	if v := c.Query("verification_status"); v != "" {
		params.VerificationStatus = database.NullVerificationStatus{
			VerificationStatus: database.VerificationStatus(v), Valid: true,
		}
	}

	rows, err := s.q.ListFindings(c.Request.Context(), params)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("finding list")
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, rows)
}

// GetFinding
// @Summary Get a single finding
// @Tags Ingestion
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param findingId path int true "finding id"
// @Success 200 {object} response.successResp{data=database.Finding}
// @Router /engagements/{id}/findings/{findingId} [get]
func (s *IngestionService) GetFinding(c *gin.Context) {
	findingID, ok := parseInt64Param(c, "findingId")
	if !ok {
		return
	}
	row, err := s.q.GetFinding(c.Request.Context(), findingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrFindingNotFound, err)
			return
		}
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, row)
}

// UpdateFindingVerification
// @Summary Patch a finding's verification status
// @Tags Ingestion
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "engagement id"
// @Param findingId path int true "finding id"
// @Param json body updateFindingVerificationRequest true "verification payload"
// @Success 200 {object} response.successResp{data=database.Finding}
// @Router /engagements/{id}/findings/{findingId} [patch]
func (s *IngestionService) UpdateFindingVerification(c *gin.Context) {
	findingID, ok := parseInt64Param(c, "findingId")
	if !ok {
		return
	}
	var req updateFindingVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, response.ErrIngestionInvalidRequest, err)
		return
	}
	uid := c.GetUint64("uid")
	row, err := s.q.UpdateFindingVerification(c.Request.Context(), database.UpdateFindingVerificationParams{
		ID:                 findingID,
		VerificationStatus: database.VerificationStatus(req.VerificationStatus),
		VerificationNotes:  nullStringFromStr(req.Notes),
		VerifiedBy:         sql.NullInt64{Int64: int64(uid), Valid: uid != 0},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrFindingNotFound, err)
			return
		}
		response.Error(c, response.ErrInternal, err)
		return
	}
	response.Success(c, http.StatusOK, row)
}

// -- async parse pipeline -----------------------------------------------------

// runParse is the background routine spawned from UploadReport. It owns the
// full "parse -> persist -> seed -> mark status" pipeline and records any
// failure on the scan_reports row itself so callers can poll GetReport.
func (s *IngestionService) runParse(
	ctx context.Context,
	report database.ScanReport,
	source schema.ScanSourceType,
	path string,
) {
	// Bind the parse log entry to the report+engagement once so every
	// downstream warn/error inside this goroutine is correlatable. The
	// caller passes context.Background() (request cancellation must not
	// kill an in-flight parse), so we cannot rely on logger.FromContext.
	log := s.log.WithFields(logrus.Fields{
		"scan_report_id": report.ID,
		"engagement_id":  report.EngagementID,
		"source_type":    string(source),
	})

	p, ok := s.parsers[source]
	if !ok {
		_ = s.markFailed(ctx, report.ID, fmt.Errorf("no parser registered for %q", source))
		return
	}

	f, err := os.Open(path)
	if err != nil {
		_ = s.markFailed(ctx, report.ID, err)
		return
	}
	defer f.Close()

	bundle, parseErr := p.Parse(f)
	if parseErr != nil && !errors.Is(parseErr, parsers.ErrPartial) {
		_ = s.markFailed(ctx, report.ID, parseErr)
		return
	}
	if bundle == nil {
		_ = s.markFailed(ctx, report.ID, errors.New("parser returned nil bundle"))
		return
	}

	persisted, err := s.persistBundle(ctx, report, bundle)
	if err != nil {
		_ = s.markFailed(ctx, report.ID, err)
		return
	}

	// Best-effort Graphiti seed. Failures leave findings with graph_seeded_at=NULL
	// so the reconciler (Phase 6) retries them on its next tick.
	eng, err := s.q.GetEngagement(ctx, report.EngagementID)
	if err != nil {
		log.WithError(err).
			Warn("seed: get engagement failed; reconciler will retry")
	} else if s.seeder != nil {
		seedErr := s.seeder.Seed(ctx, seeder.SeedInput{
			SourceType:   source,
			Hosts:        bundle.Hosts,
			Containers:   bundle.Containers,
			WebEndpoints: bundle.WebEndpoints,
			Findings:     persisted,
		}, eng.GraphitiGroupID)
		if seedErr != nil {
			log.WithError(seedErr).
				Warn("graphiti seed had errors; reconciler will retry unmarked findings")
		} else {
			// TODO(phase-9+): replace this N+1 loop with MarkFindingGraphSeededBulk
			// once larger parsers (Burp/Twistlock/Qualys) start producing 100s of
			// findings per report.
			for _, row := range persisted {
				if err := s.q.MarkFindingGraphSeeded(ctx, row.ID); err != nil {
					log.WithError(err).WithField("finding_id", row.ID).
						Warn("mark graph_seeded_at failed")
				}
			}
		}
	}

	status := database.ParseStatusSucceeded
	var perr sql.NullString
	if parseErr != nil {
		// Must be ErrPartial at this point — it was the only non-nil branch
		// we allowed to reach here.
		status = database.ParseStatusPartial
		perr = sql.NullString{String: parseErr.Error(), Valid: true}
	}
	if err := s.q.UpdateScanReportStatus(ctx, database.UpdateScanReportStatusParams{
		ID:           report.ID,
		ParseStatus:  status,
		ParseError:   perr,
		FindingCount: int32(len(persisted)),
	}); err != nil {
		log.WithError(err).
			Warn("update scan report status failed")
	}
}

// persistBundle upserts every finding in the bundle, attaches a finding_sources
// row per report, and returns the persisted DB rows (needed for the seeder,
// whose episode names key off the DB primary key).
//
// Not transactional: each upsert is its own round-trip. A mid-bundle failure
// leaves earlier findings persisted; the controller marks the scan_report as
// failed but the orphaned findings remain in the DB. Acceptable for nmap-sized
// bundles (tens of findings) but Phase 9/10 (Twistlock/Qualys, 1000s of
// findings per report) should wrap this loop in a single transaction via
// `Queries.WithTx` once we audit the rollback semantics for graphiti seeding.
func (s *IngestionService) persistBundle(
	ctx context.Context,
	report database.ScanReport,
	b *schema.ReportBundle,
) ([]database.Finding, error) {
	matcher, err := scope.LoadMatcher(ctx, s.q, report.EngagementID)
	if err != nil {
		return nil, fmt.Errorf("load scope matcher: %w", err)
	}

	out := make([]database.Finding, 0, len(b.Findings))
	for _, f := range b.Findings {
		inScope := matcher.InScope(f.Target.Ref)
		row, err := s.q.UpsertFinding(ctx, database.UpsertFindingParams{
			EngagementID: report.EngagementID,
			ScanReportID: report.ID,
			FindingType:  database.FindingType(f.Type),
			TargetKind:   database.TargetKind(f.Target.Kind),
			TargetRef:    f.Target.Ref,
			Title:        f.Title,
			Cve:          nullStringFromStr(f.CVE),
			CvssScore:    cvssToNullString(f.CVSSScore),
			Severity:     database.SeverityLevel(f.Severity),
			Confidence:   database.FindingConfidence(f.Confidence),
			SourceID:     nullStringFromStr(f.SourceID),
			Evidence:     evidenceOrEmpty(f.Evidence),
			InScope:      inScope,
		})
		if err != nil {
			return nil, fmt.Errorf("upsert finding %q: %w", f.Target.Ref, err)
		}
		// Attach junction row so multi-source findings are traceable.
		if err := s.q.AttachFindingSource(ctx, database.AttachFindingSourceParams{
			FindingID:      row.ID,
			ScanReportID:   report.ID,
			SourceEvidence: evidenceOrEmpty(f.Evidence),
		}); err != nil {
			return nil, fmt.Errorf("attach finding_source %d: %w", row.ID, err)
		}

		out = append(out, database.Finding{
			ID:                 row.ID,
			EngagementID:       row.EngagementID,
			ScanReportID:       row.ScanReportID,
			FindingType:        row.FindingType,
			TargetKind:         row.TargetKind,
			TargetRef:          row.TargetRef,
			Title:              row.Title,
			Cve:                row.Cve,
			CvssScore:          row.CvssScore,
			Severity:           row.Severity,
			Confidence:         row.Confidence,
			SourceID:           row.SourceID,
			Evidence:           row.Evidence,
			InScope:            row.InScope,
			VerificationStatus: row.VerificationStatus,
			VerifiedBy:         row.VerifiedBy,
			VerifiedAt:         row.VerifiedAt,
			VerificationNotes:  row.VerificationNotes,
			GraphSeededAt:      row.GraphSeededAt,
			FirstSeenAt:        row.FirstSeenAt,
			LastSeenAt:         row.LastSeenAt,
			CreatedAt:          row.CreatedAt,
			UpdatedAt:          row.UpdatedAt,
		})
	}
	return out, nil
}

func (s *IngestionService) markFailed(ctx context.Context, id int64, cause error) error {
	msg := cause.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return s.q.UpdateScanReportStatus(ctx, database.UpdateScanReportStatusParams{
		ID:           id,
		ParseStatus:  database.ParseStatusFailed,
		ParseError:   sql.NullString{String: msg, Valid: true},
		FindingCount: 0,
	})
}

// -- helpers ------------------------------------------------------------------

// parseInt64Param reads a path param and writes a 400 on failure.
func parseInt64Param(c *gin.Context, key string) (int64, bool) {
	v, err := strconv.ParseInt(c.Param(key), 10, 64)
	if err != nil {
		response.Error(c, response.ErrIngestionInvalidRequest,
			fmt.Errorf("invalid %s: %w", key, err))
		return 0, false
	}
	return v, true
}

// parseInt64Query reads an optional query param, returning fallback on miss.
func parseInt64Query(c *gin.Context, key string, fallback int64) int64 {
	raw := c.Query(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

func nullStringFromStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// cvssToNullString stores CVSS as a formatted string in NUMERIC column.
// Database column is NUMERIC, SQLC maps to sql.NullString because pgx drivers
// return NUMERIC as text. Callers should use "%.1f" precision to match
// how analytics / rollups compare scores.
func cvssToNullString(f *float64) sql.NullString {
	if f == nil {
		return sql.NullString{}
	}
	return sql.NullString{
		String: strconv.FormatFloat(*f, 'f', 1, 64),
		Valid:  true,
	}
}

// evidenceOrEmpty ensures the evidence JSON column is never NULL. The DB
// column is declared NOT NULL with default '{}'; passing a nil slice causes a
// "null value in column evidence violates not-null constraint". Using an
// empty JSON object keeps downstream JSON consumers happy.
func evidenceOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}
