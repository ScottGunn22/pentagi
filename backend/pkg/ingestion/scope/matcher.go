// Package scope implements engagement scope matching with fail-closed
// semantics. A target is in scope only when at least one include rule
// matches AND no exclude rule matches; an empty rule set denies every
// target. The matcher is the foundation for the runtime hard-gate that
// prevents agent tools from reaching out-of-scope hosts, URLs, or
// container images.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RuleType enumerates the kinds of scope rules recognised by the
// matcher. The values mirror the database enum.
type RuleType string

const (
	RuleCIDR              RuleType = "cidr"
	RuleIP                RuleType = "ip"
	RuleDomain            RuleType = "domain"
	RuleDomainGlob        RuleType = "domain_glob"
	RuleURLPrefix         RuleType = "url_prefix"
	RuleContainerImage    RuleType = "container_image"
	RuleContainerRegistry RuleType = "container_registry"
)

// Direction describes whether a rule grants or revokes scope.
type Direction string

const (
	DirectionInclude Direction = "include"
	DirectionExclude Direction = "exclude"
)

// Rule is a single parsed scope rule. Callers build Rules from either
// the DB loader or directly in tests.
type Rule struct {
	Type      RuleType
	Value     string
	Direction Direction

	// pre-compiled fields populated by NewMatcher
	cidr *net.IPNet
}

// Matcher evaluates targets against a pre-validated rule set.
type Matcher struct{ rules []Rule }

// NewMatcher validates every rule up-front and returns a ready-to-use
// Matcher. It returns an error if any rule has an unknown type, an
// empty value, or a malformed CIDR / IP literal.
func NewMatcher(rules []Rule) (*Matcher, error) {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		switch r.Type {
		case RuleCIDR:
			_, n, err := net.ParseCIDR(r.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr %q: %w", r.Value, err)
			}
			r.cidr = n
		case RuleIP:
			if net.ParseIP(r.Value) == nil {
				return nil, fmt.Errorf("invalid ip %q", r.Value)
			}
		case RuleDomain, RuleDomainGlob, RuleURLPrefix, RuleContainerImage, RuleContainerRegistry:
			if r.Value == "" {
				return nil, fmt.Errorf("empty rule value for type %q", r.Type)
			}
		default:
			return nil, fmt.Errorf("unknown rule type %q", r.Type)
		}
		out = append(out, r)
	}
	return &Matcher{rules: out}, nil
}

// InScope is fail-closed: if no include rule matches, returns false.
// Any matching exclude rule short-circuits to false regardless of
// includes.
//
// Target strings use a short kind-prefix grammar understood by the
// ingestion pipeline:
//
//	ip:<addr>[:<port>/<proto>]  — IPv4/IPv6 host
//	host:<fqdn>                 — hostname
//	url:[<METHOD> ]<url>        — HTTP(S) URL, optional leading verb
//	img:<ref>                   — OCI image reference
func (m *Matcher) InScope(target string) bool {
	kind, body := splitTarget(target)
	include := false
	for _, r := range m.rules {
		if !m.ruleMatches(r, kind, body) {
			continue
		}
		if r.Direction == DirectionExclude {
			return false
		}
		include = true
	}
	return include
}

// splitTarget separates the kind prefix from the body on the first
// colon. A target with no colon is treated as having an empty kind,
// which no rule will match.
func splitTarget(t string) (kind, body string) {
	i := strings.IndexByte(t, ':')
	if i < 0 {
		return "", t
	}
	return t[:i], t[i+1:]
}

// ruleMatches reports whether a single rule matches a pre-split target.
// It is the dispatch point for every RuleType.
func (m *Matcher) ruleMatches(r Rule, kind, body string) bool {
	switch r.Type {
	case RuleCIDR:
		if kind != "ip" {
			return false
		}
		ip := net.ParseIP(extractHost(body))
		return ip != nil && r.cidr.Contains(ip)
	case RuleIP:
		if kind != "ip" {
			return false
		}
		return extractHost(body) == r.Value
	case RuleDomain:
		if kind != "host" {
			return false
		}
		return body == r.Value
	case RuleDomainGlob:
		if kind != "host" && kind != "url" {
			return false
		}
		host := body
		if kind == "url" {
			host = extractURLHost(body)
		}
		return matchGlob(r.Value, host)
	case RuleURLPrefix:
		if kind != "url" {
			return false
		}
		return strings.HasPrefix(extractURLOnly(body), r.Value)
	case RuleContainerImage:
		if kind != "img" {
			return false
		}
		return strings.HasPrefix(body, r.Value)
	case RuleContainerRegistry:
		if kind != "img" {
			return false
		}
		return strings.HasPrefix(body, r.Value+"/") || strings.HasPrefix(body, r.Value+"@")
	}
	// Unreachable: NewMatcher rejects unknown rule types, so a Matcher
	// can never hold one. Kept defensive for future RuleType additions.
	return false
}

// extractHost parses "10.1.2.3:443/tcp" → "10.1.2.3". For bodies with
// no colon (e.g. a bare IP) the whole body is returned.
func extractHost(body string) string {
	if i := strings.IndexByte(body, ':'); i >= 0 {
		return body[:i]
	}
	return body
}

// extractURLHost parses "GET https://a.b/c" → "a.b". Returns "" when
// url.Parse rejects the input — the caller treats that as "no match".
func extractURLHost(body string) string {
	raw := extractURLOnly(body)
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// extractURLOnly strips a leading method verb if present (so "GET http…"
// becomes just "http…"). Plain URLs pass through unchanged.
func extractURLOnly(body string) string {
	if i := strings.IndexByte(body, ' '); i >= 0 {
		return body[i+1:]
	}
	return body
}

// matchGlob supports leading-"*." globs ("*.foo.com" matches
// "x.foo.com" but not "foo.com") and exact matches for anything else.
func matchGlob(pat, host string) bool {
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(host, pat[1:]) && host != pat[2:]
	}
	return pat == host
}
