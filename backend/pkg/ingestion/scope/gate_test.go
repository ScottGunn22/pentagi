package scope

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fakeExtractor struct{ out []Target }

func (f fakeExtractor) Targets(_ json.RawMessage) []Target { return f.out }

func TestGate_BlocksOutOfScope(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
	audited := ""
	gated := WithGate(m,
		fakeExtractor{out: []Target{{Kind: "ip", Ref: "10.99.0.1:22/tcp"}}},
		func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
			t.Fatal("inner should not have been invoked")
			return "", nil
		},
		func(target, tool string) { audited = target },
	)
	out, err := gated(context.Background(), "nmap", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if audited == "" {
		t.Fatal("audit not invoked")
	}
	if !strings.Contains(out, "scope_violation") {
		t.Fatalf("unexpected response: %s", out)
	}
}

func TestGate_AllowsInScope(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
	called := false
	gated := WithGate(m,
		fakeExtractor{out: []Target{{Kind: "ip", Ref: "10.1.5.5:80/tcp"}}},
		func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
			called = true
			return "ok", nil
		},
		func(_, _ string) {},
	)
	out, err := gated(context.Background(), "nmap", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok" || !called {
		t.Fatalf("expected inner to be called and return ok; got out=%q called=%v", out, called)
	}
}

func TestGate_NoExtractorPassesThrough(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
	called := false
	gated := WithGate(m, nil,
		func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
			called = true
			return "passthrough", nil
		},
		func(_, _ string) { t.Fatal("audit should not be called when no extractor") },
	)
	out, err := gated(context.Background(), "search", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !called || out != "passthrough" {
		t.Fatalf("passthrough failed; got=%q called=%v", out, called)
	}
}

func TestGate_NilAuditDoesntPanic(t *testing.T) {
	m := buildMatcher(t, []ruleSpec{{"cidr", "10.1.0.0/16", "include"}})
	gated := WithGate(m,
		fakeExtractor{out: []Target{{Kind: "ip", Ref: "10.99.0.1:80/tcp"}}},
		func(_ context.Context, _ string, _ json.RawMessage) (string, error) {
			t.Fatal("should not invoke")
			return "", nil
		},
		nil, // no audit sink
	)
	out, err := gated(context.Background(), "nmap", json.RawMessage(`{}`))
	if err != nil || !strings.Contains(out, "scope_violation") {
		t.Fatalf("nil audit should still produce scope_violation; got out=%q err=%v", out, err)
	}
}
