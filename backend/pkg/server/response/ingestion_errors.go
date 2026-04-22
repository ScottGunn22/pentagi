package response

// Ingestion (engagements / scan reports / findings) error sentinels.
// Kept in a dedicated file so the module feature can evolve independently
// of the legacy error catalogue in errors.go.

var ErrIngestionInvalidRequest = NewHttpError(400, "Ingestion.InvalidRequest", "invalid ingestion request data")
var ErrIngestionInvalidData = NewHttpError(500, "Ingestion.InvalidData", "invalid ingestion data")
var ErrEngagementNotFound = NewHttpError(404, "Ingestion.EngagementNotFound", "engagement not found")
var ErrScopeRuleNotFound = NewHttpError(404, "Ingestion.ScopeRuleNotFound", "scope rule not found")
var ErrScanReportNotFound = NewHttpError(404, "Ingestion.ScanReportNotFound", "scan report not found")
var ErrFindingNotFound = NewHttpError(404, "Ingestion.FindingNotFound", "finding not found")
var ErrScanReportDuplicate = NewHttpError(409, "Ingestion.ScanReportDuplicate", "scan report already ingested")
var ErrUnsupportedSourceType = NewHttpError(400, "Ingestion.UnsupportedSourceType", "unsupported scanner source type")
