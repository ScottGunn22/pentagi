package parsers

import (
	"encoding/json"
	"fmt"
	"io"

	"pentagi/pkg/ingestion/schema"
)

// Parser is the contract every scanner-source reader implements.
// On partial parse success (a malformed tail after a valid body)
// the parser MUST return both a bundle (with what was successfully
// extracted) and an error wrapping ErrPartial via fmt.Errorf("...: %w", ErrPartial).
type Parser interface {
	Source() schema.ScanSourceType
	Parse(r io.Reader) (*schema.ReportBundle, error)
}

// ErrPartial marks a parse result that is incomplete but usable.
// Callers detect via errors.Is(err, ErrPartial).
var ErrPartial = partialError{}

type partialError struct{}

func (partialError) Error() string { return "partial parse" }

// mustJSON marshals plain-struct evidence into a json.RawMessage. Parsers
// pass scanner-shape structs whose fields are all primitives or other
// plain structs, so json.Marshal cannot fail at runtime; if it ever
// does, that is a programmer error (a non-marshalable field added to a
// scanner struct), not user data — panic so the bug is loud.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Errorf("parsers: unmarshalable evidence: %w", err))
	}
	return b
}
