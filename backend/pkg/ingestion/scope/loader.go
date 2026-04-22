package scope

import (
	"context"

	"pentagi/pkg/database"
)

// rulesLister is the narrow slice of database.Querier that the loader
// actually needs. Taking an interface (rather than *database.Queries)
// lets tests inject a fake without spinning up a real DB.
type rulesLister interface {
	ListScopeRules(ctx context.Context, engagementID int64) ([]database.EngagementScopeRule, error)
}

// LoadMatcher fetches every scope rule for the given engagement and
// returns a validated Matcher. Any DB error, or any malformed rule
// rejected by NewMatcher, is surfaced to the caller — an engagement
// with invalid scope rules must not silently allow unrestricted access.
func LoadMatcher(ctx context.Context, q rulesLister, engagementID int64) (*Matcher, error) {
	rows, err := q.ListScopeRules(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return loadFromRows(rows)
}

// loadFromRows converts SQLC rows into Rule values and delegates to
// NewMatcher for validation. Split out for direct unit-testing without
// a lister.
func loadFromRows(rows []database.EngagementScopeRule) (*Matcher, error) {
	rules := make([]Rule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, Rule{
			Type:      RuleType(row.RuleType),
			Value:     row.Value,
			Direction: Direction(row.Direction),
		})
	}
	return NewMatcher(rules)
}
