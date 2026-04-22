package scope

import (
	"context"
	"encoding/json"
)

// Target is what a tool's args resolve to in scope-check terms.
// Kind matches the matcher's target-string prefix (ip, host, url, img).
type Target struct {
	Kind string
	Ref  string
}

// TargetExtractor is implemented by tools whose args reference an external
// target. Tools that don't (search, internal-only ops) need not implement it
// and the gate wrapper passes their calls through unchanged.
type TargetExtractor interface {
	Targets(args json.RawMessage) []Target
}

// ExecutorFn matches PentAGI's pkg/tools.ExecutorHandler signature.
type ExecutorFn func(ctx context.Context, name string, args json.RawMessage) (string, error)

// AuditFn is invoked for every gate-blocked call so the controller can persist
// to scope_violations. The function is intentionally NOT inlined into the
// gate — keeps the gate package free of pkg/database imports and lets Phase 14
// wire whatever audit sink is appropriate.
type AuditFn func(target, tool string)

// WithGate returns a wrapped ExecutorFn that blocks any call whose extracted
// targets are out of scope. If extractor is nil, the gate passes calls through
// unchanged (the tool has no targetable args). Otherwise, every Target the
// extractor returns must satisfy matcher.InScope; the first OOS target
// short-circuits with a structured "scope_violation" tool result and an
// AuditFn invocation.
//
// The wrapper returns the violation as a successful (nil error) tool result
// so the LLM observes the error in-context and can route around it. Returning
// an error here would surface as a tool-call failure that the agent might
// retry blindly.
func WithGate(matcher *Matcher, extractor TargetExtractor, inner ExecutorFn, audit AuditFn) ExecutorFn {
	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		if extractor == nil {
			return inner(ctx, name, args)
		}
		for _, t := range extractor.Targets(args) {
			if !matcher.InScope(toRef(t)) {
				if audit != nil {
					audit(toRef(t), name)
				}
				return makeScopeError(t, name), nil
			}
		}
		return inner(ctx, name, args)
	}
}

func toRef(t Target) string { return t.Kind + ":" + t.Ref }

func makeScopeError(t Target, name string) string {
	out, _ := json.Marshal(map[string]any{
		"error":           "scope_violation",
		"target":          toRef(t),
		"tool":            name,
		"engagement_hint": "target is not in the Engagement's declared scope; choose another target or request a scope expansion",
	})
	return string(out)
}
