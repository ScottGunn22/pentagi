package scope

import "testing"

type ruleSpec struct{ kind, value, direction string }

func buildMatcher(t *testing.T, rules []ruleSpec) *Matcher {
	t.Helper()
	var rs []Rule
	for _, r := range rules {
		rs = append(rs, Rule{
			Type:      RuleType(r.kind),
			Value:     r.value,
			Direction: Direction(r.direction),
		})
	}
	m, err := NewMatcher(rs)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMatcher_IncludeCIDR(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{"ip:10.1.2.3:443/tcp", true},
		{"ip:10.1.255.255:0/tcp", true},
		{"ip:10.2.0.1:443/tcp", false},
		{"ip:192.168.1.1:22/tcp", false},
	} {
		if got := m.InScope(tc.target); got != tc.want {
			t.Errorf("InScope(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestMatcher_ExcludeCarvesFromInclude(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{
		{"cidr", "10.1.0.0/16", "include"},
		{"cidr", "10.1.99.0/24", "exclude"},
	})
	if !m.InScope("ip:10.1.50.1:80/tcp") {
		t.Fatal("10.1.50.1 should be in scope")
	}
	if m.InScope("ip:10.1.99.1:80/tcp") {
		t.Fatal("10.1.99.1 should be excluded")
	}
}

func TestMatcher_IPLiteral(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"ip", "10.1.2.3", "include"}})
	if !m.InScope("ip:10.1.2.3:0/tcp") {
		t.Fatal("expected match")
	}
	if m.InScope("ip:10.1.2.4:0/tcp") {
		t.Fatal("expected no match")
	}
}

func TestMatcher_DomainExact(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"domain", "app.acme.internal", "include"}})
	if !m.InScope("host:app.acme.internal") {
		t.Fatal("expected match")
	}
	if m.InScope("host:other.acme.internal") {
		t.Fatal("expected no match")
	}
}

func TestMatcher_DomainGlob(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"domain_glob", "*.acme.internal", "include"}})
	cases := map[string]bool{
		"host:app.acme.internal":      true,
		"host:api.beta.acme.internal": true,
		"host:acme.internal":          false, // glob requires "x." prefix
		"host:acme.external":          false,
	}
	for in, want := range cases {
		if got := m.InScope(in); got != want {
			t.Errorf("InScope(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMatcher_DomainGlobAcrossURL(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"domain_glob", "*.acme.internal", "include"}})
	if !m.InScope("url:GET https://api.acme.internal/users") {
		t.Fatal("URL whose host matches the glob should be in scope")
	}
	if m.InScope("url:GET https://evil.example.com/") {
		t.Fatal("URL whose host does not match should be out of scope")
	}
}

func TestMatcher_URLPrefix(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"url_prefix", "https://api.acme.internal/", "include"}})
	cases := map[string]bool{
		"url:GET https://api.acme.internal/users": true,
		"url:POST https://api.acme.internal/v2/x": true,
		"url:GET https://evil.example.com/":       false,
		"url:https://api.acme.internal/no-method": true, // method optional
	}
	for in, want := range cases {
		if got := m.InScope(in); got != want {
			t.Errorf("InScope(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMatcher_ContainerImage(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"container_image", "registry.acme.internal/app", "include"}})
	if !m.InScope("img:registry.acme.internal/app@sha256:abc") {
		t.Fatal("specific image should be in scope")
	}
	if m.InScope("img:registry.acme.internal/other@sha256:def") {
		t.Fatal("different image in same registry should be out of scope")
	}
}

func TestMatcher_ContainerRegistry(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"container_registry", "registry.acme.internal", "include"}})
	if !m.InScope("img:registry.acme.internal/app@sha256:abc") {
		t.Fatal("acme registry image should be in scope")
	}
	if m.InScope("img:docker.io/library/nginx@sha256:def") {
		t.Fatal("unrelated registry should be out of scope")
	}
}

func TestMatcher_EmptyRulesDenyAll(t *testing.T) {
	m := buildMatcher(t, nil)
	if m.InScope("ip:10.1.2.3:443/tcp") {
		t.Fatal("no include rules → everything must be out of scope (fail-closed)")
	}
}

func TestMatcher_InvalidCIDR(t *testing.T) {
	_, err := NewMatcher([]Rule{{Type: RuleCIDR, Value: "not-a-cidr", Direction: DirectionInclude}})
	if err == nil {
		t.Fatal("expected error on bogus CIDR")
	}
}

func TestMatcher_InvalidIP(t *testing.T) {
	_, err := NewMatcher([]Rule{{Type: RuleIP, Value: "not-an-ip", Direction: DirectionInclude}})
	if err == nil {
		t.Fatal("expected error on bogus IP")
	}
}

func TestMatcher_UnknownRuleType(t *testing.T) {
	_, err := NewMatcher([]Rule{{Type: RuleType("bogus"), Value: "x", Direction: DirectionInclude}})
	if err == nil {
		t.Fatal("expected error on unknown rule type")
	}
}

func TestMatcher_EmptyValueRejected(t *testing.T) {
	_, err := NewMatcher([]Rule{{Type: RuleDomain, Value: "", Direction: DirectionInclude}})
	if err == nil {
		t.Fatal("expected error on empty domain")
	}
}

// TestMatcher_RuleMatchesUnknownTypeIsFalse covers the defensive default
// branch in ruleMatches that NewMatcher's validation prevents from ever
// being reached in normal use. Constructing the Matcher literal bypasses
// NewMatcher so we can exercise the otherwise-dead line and prove the
// behaviour is fail-safe (returns false) if a future RuleType is added
// to the type set without a matching switch case.
func TestMatcher_RuleMatchesUnknownTypeIsFalse(t *testing.T) {
	m := &Matcher{rules: []Rule{{Type: RuleType("future_unknown"), Value: "x", Direction: DirectionInclude}}}
	if m.InScope("ip:10.1.2.3:443/tcp") {
		t.Fatal("unknown rule type must default-deny, not silently match")
	}
}

// TestMatcher_KindMismatch covers the "wrong kind" early-return branch
// for every rule type: a CIDR rule should never match a host: target,
// an IP rule should never match a url: target, etc. This drives the
// kind-guard branch coverage in ruleMatches to 100%.
func TestMatcher_KindMismatch(t *testing.T) {
	cases := []struct {
		name   string
		rule   ruleSpec
		target string
	}{
		{"cidr vs host", ruleSpec{"cidr", "10.0.0.0/8", "include"}, "host:app.acme.internal"},
		{"ip vs host", ruleSpec{"ip", "10.1.2.3", "include"}, "host:app.acme.internal"},
		{"domain vs ip", ruleSpec{"domain", "app.acme.internal", "include"}, "ip:10.1.2.3:0/tcp"},
		{"domain_glob vs ip", ruleSpec{"domain_glob", "*.acme.internal", "include"}, "ip:10.1.2.3:0/tcp"},
		{"url_prefix vs host", ruleSpec{"url_prefix", "https://a/", "include"}, "host:app.acme.internal"},
		{"container_image vs host", ruleSpec{"container_image", "registry/app", "include"}, "host:app.acme.internal"},
		{"container_registry vs host", ruleSpec{"container_registry", "registry", "include"}, "host:app.acme.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := buildMatcher(t, []ruleSpec{tc.rule})
			if m.InScope(tc.target) {
				t.Fatalf("InScope(%q) with %+v should be false (kind mismatch)", tc.target, tc.rule)
			}
		})
	}
}

// TestMatcher_CIDRNonIPBody covers the ip == nil branch inside the
// RuleCIDR case, reached when a target is tagged as ip: but the body
// is not a parseable address.
func TestMatcher_CIDRNonIPBody(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.0.0.0/8", "include"}})
	if m.InScope("ip:not-an-ip:0/tcp") {
		t.Fatal("non-parseable IP body must not match CIDR rule")
	}
}

// TestMatcher_DomainExactMatch covers the non-glob (exact) branch of
// matchGlob by routing a plain domain value through the domain_glob
// rule type. matchGlob is shared between domain and domain_glob rules.
func TestMatcher_DomainGlobExactFallback(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"domain_glob", "app.acme.internal", "include"}})
	if !m.InScope("host:app.acme.internal") {
		t.Fatal("non-wildcard glob pattern should fall through to exact match")
	}
	if m.InScope("host:other.acme.internal") {
		t.Fatal("non-wildcard glob pattern should not match unrelated host")
	}
}

// TestMatcher_URLUnparseableHost exercises extractURLHost's parse-error
// branch. url.Parse is very permissive but rejects inputs containing
// raw control characters, which gives us a deterministic error path.
func TestMatcher_URLUnparseableHost(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"domain_glob", "*.acme.internal", "include"}})
	// Embedded \x7f (DEL) makes url.Parse return an error.
	if m.InScope("url:GET https://api.acme.internal\x7f/x") {
		t.Fatal("URL that fails url.Parse must not be in scope")
	}
}

// TestMatcher_TargetWithoutKindPrefix covers splitTarget's no-colon
// path. A bare token cannot match any rule type, so it must be out of
// scope.
func TestMatcher_TargetWithoutKindPrefix(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{
		{"cidr", "10.0.0.0/8", "include"},
		{"domain", "app.acme.internal", "include"},
	})
	if m.InScope("10.1.2.3") {
		t.Fatal("target without kind prefix must be out of scope")
	}
}

// TestMatcher_IPLiteralBareBody exercises extractHost's no-colon
// branch: a target body like "10.1.2.3" (no :port/proto suffix) should
// still match an IP rule for the same address.
func TestMatcher_IPLiteralBareBody(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"ip", "10.1.2.3", "include"}})
	if !m.InScope("ip:10.1.2.3") {
		t.Fatal("bare ip body (no port/proto) should still match an IP rule")
	}
}
