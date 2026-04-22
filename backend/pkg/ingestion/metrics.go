// Package ingestion exposes the feature-level OpenTelemetry metrics for the
// scanner-report ingestion pipeline. The metrics here are deliberately
// lightweight — counters + a single histogram — and are lazily initialized via
// sync.Once on first access so importers need not care about ordering vs.
// observability.InitObserver.
//
// Call sites in pkg/server/services/ingestion.go, pkg/ingestion/seeder, and
// pkg/tools (via scope.WithGate's AuditFn) resolve the metrics through the
// accessor functions below and call Add/Record directly on the returned
// instruments. Every accessor is safe to call even before the Observer has
// been configured — in that case the underlying meter is a noop and the
// Add/Record calls degrade to no-ops.
package ingestion

import (
	"sync"

	obs "pentagi/pkg/observability"

	"go.opentelemetry.io/otel/metric"
)

var (
	metricsOnce sync.Once

	reportsCounter     metric.Int64Counter
	findingsCounter    metric.Int64Counter
	parseDurationHist  metric.Float64Histogram
	scopeViolCounter   metric.Int64Counter
	seedFailureCounter metric.Int64Counter
)

func initMetrics() {
	metricsOnce.Do(func() {
		if obs.Observer == nil {
			return
		}
		reportsCounter, _ = obs.Observer.NewInt64Counter(
			"ingestion_reports_total",
			metric.WithDescription("Scanner reports seen by the ingestion pipeline, labelled by source and terminal parse status."),
		)
		findingsCounter, _ = obs.Observer.NewInt64Counter(
			"ingestion_findings_total",
			metric.WithDescription("Findings persisted by the ingestion pipeline, labelled by source and severity."),
		)
		parseDurationHist, _ = obs.Observer.NewFloat64Histogram(
			"ingestion_parse_duration_seconds",
			metric.WithDescription("Wall-clock time spent in parser.Parse + persistBundle per scan report."),
			metric.WithUnit("s"),
		)
		scopeViolCounter, _ = obs.Observer.NewInt64Counter(
			"scope_violations_total",
			metric.WithDescription("Agent tool calls blocked by the scope gate."),
		)
		seedFailureCounter, _ = obs.Observer.NewInt64Counter(
			"graphiti_seed_failures_total",
			metric.WithDescription("Graphiti episode-write failures seen by the seeder (drives the reconciler alert)."),
		)
	})
}

// ReportsCounter returns the ingestion_reports_total counter. Labels used at
// call sites: source (nmap|burp|qualys|twistlock), status (pending|succeeded|
// partial|failed).
func ReportsCounter() metric.Int64Counter {
	initMetrics()
	return reportsCounter
}

// FindingsCounter returns ingestion_findings_total. Labels: source, severity.
func FindingsCounter() metric.Int64Counter {
	initMetrics()
	return findingsCounter
}

// ParseDurationHistogram returns ingestion_parse_duration_seconds. Labels:
// source.
func ParseDurationHistogram() metric.Float64Histogram {
	initMetrics()
	return parseDurationHist
}

// ScopeViolationsCounter returns scope_violations_total. Labels: tool, flow_id
// (stringified). The spec originally proposed flow_type but flow_type is not
// threaded into pkg/tools today; flow_id preserves the same cardinality
// ceiling and can be joined against the flows table to recover flow_type.
func ScopeViolationsCounter() metric.Int64Counter {
	initMetrics()
	return scopeViolCounter
}

// SeedFailuresCounter returns graphiti_seed_failures_total. No labels; the
// counter exists purely to drive the reconciler alert (reconciler ticks at a
// low rate so even a few failures per hour matter).
func SeedFailuresCounter() metric.Int64Counter {
	initMetrics()
	return seedFailureCounter
}
