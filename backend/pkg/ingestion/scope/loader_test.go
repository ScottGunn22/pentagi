package scope

import (
	"context"
	"errors"
	"testing"

	"pentagi/pkg/database"
)

// fakeLister is a minimal rulesLister for unit-testing LoadMatcher
// without a real database.
type fakeLister struct {
	rules []database.EngagementScopeRule
	err   error
	got   int64
}

func (f *fakeLister) ListScopeRules(_ context.Context, engagementID int64) ([]database.EngagementScopeRule, error) {
	f.got = engagementID
	return f.rules, f.err
}

func TestLoadFromRows_RejectsInvalid(t *testing.T) {
	_, err := loadFromRows([]database.EngagementScopeRule{{
		RuleType:  database.ScopeRuleTypeCidr,
		Value:     "garbage",
		Direction: database.ScopeDirectionInclude,
	}})
	if err == nil {
		t.Fatal("expected error on bogus cidr in DB row")
	}
}

func TestLoadFromRows_Empty(t *testing.T) {
	m, err := loadFromRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.InScope("ip:10.1.2.3:443/tcp") {
		t.Fatal("empty rules must be fail-closed")
	}
}

func TestLoadFromRows_HappyPath(t *testing.T) {
	rows := []database.EngagementScopeRule{
		{RuleType: database.ScopeRuleTypeCidr, Value: "10.1.0.0/16", Direction: database.ScopeDirectionInclude},
		{RuleType: database.ScopeRuleTypeCidr, Value: "10.1.99.0/24", Direction: database.ScopeDirectionExclude},
		{RuleType: database.ScopeRuleTypeDomain, Value: "app.acme.internal", Direction: database.ScopeDirectionInclude},
	}
	m, err := loadFromRows(rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.InScope("ip:10.1.2.3:443/tcp") {
		t.Fatal("10.1.2.3 should be in scope")
	}
	if m.InScope("ip:10.1.99.5:443/tcp") {
		t.Fatal("10.1.99.5 should be excluded")
	}
	if !m.InScope("host:app.acme.internal") {
		t.Fatal("domain rule should match")
	}
}

func TestLoadMatcher_PassesEngagementIDAndBuildsMatcher(t *testing.T) {
	lister := &fakeLister{
		rules: []database.EngagementScopeRule{
			{RuleType: database.ScopeRuleTypeIp, Value: "10.1.2.3", Direction: database.ScopeDirectionInclude},
		},
	}
	m, err := LoadMatcher(context.Background(), lister, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lister.got != 42 {
		t.Fatalf("expected engagementID 42, got %d", lister.got)
	}
	if !m.InScope("ip:10.1.2.3:0/tcp") {
		t.Fatal("expected matcher built from DB rows to match its rule")
	}
}

func TestLoadMatcher_SurfacesListerError(t *testing.T) {
	boom := errors.New("db unavailable")
	lister := &fakeLister{err: boom}
	_, err := LoadMatcher(context.Background(), lister, 1)
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestLoadMatcher_SurfacesRuleValidationError(t *testing.T) {
	lister := &fakeLister{
		rules: []database.EngagementScopeRule{
			{RuleType: database.ScopeRuleTypeCidr, Value: "not-a-cidr", Direction: database.ScopeDirectionInclude},
		},
	}
	_, err := LoadMatcher(context.Background(), lister, 1)
	if err == nil {
		t.Fatal("expected validation error to bubble up from NewMatcher")
	}
}
