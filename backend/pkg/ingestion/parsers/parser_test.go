package parsers

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// Locks the contract that wrapping ErrPartial via fmt.Errorf("...: %w", ErrPartial)
// is recoverable via errors.Is. Phase 10's Qualys parser depends on this and
// would otherwise discover the contract by failing at runtime.
func TestErrPartial_IsMatchesWrapped(t *testing.T) {
	wrapped := fmt.Errorf("qualys parse: %w", ErrPartial)
	if !errors.Is(wrapped, ErrPartial) {
		t.Fatal("errors.Is must match a wrapped ErrPartial; the partial-parse contract is broken")
	}
	plain := errors.New("not partial")
	if errors.Is(plain, ErrPartial) {
		t.Fatal("errors.Is must NOT match unrelated errors")
	}
}

func TestMustJSON_PrimitivesRoundTrip(t *testing.T) {
	type sample struct {
		A string
		B int
	}
	raw := mustJSON(sample{A: "x", B: 7})
	var back sample
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.A != "x" || back.B != 7 {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestMustJSON_PanicsOnUnmarshalable(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on unmarshalable type")
		}
	}()
	// channels have no JSON encoding; this MUST panic
	_ = mustJSON(make(chan int))
}
