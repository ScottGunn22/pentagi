package parsers

import (
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
