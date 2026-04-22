// Package engagement exposes business-logic helpers on top of the SQLC
// Querier for the engagements table. It owns derived concerns such as
// graphiti group-id generation that don't belong on the raw data layer.
package engagement

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"pentagi/pkg/database"
)

// Service wraps a database.Querier with engagement-specific helpers.
type Service struct {
	q database.Querier
}

// NewService constructs a Service backed by the given Querier.
func NewService(q database.Querier) *Service { return &Service{q: q} }

// generateGroupID produces an opaque identifier used as the
// graphiti_group_id. The "eng-" prefix lets downstream consumers tell
// at a glance which graph namespace an entity belongs to.
func generateGroupID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("rand.Read: %w", err))
	}
	return "eng-" + hex.EncodeToString(b[:])
}

// CreateInput captures the caller-supplied fields for a new engagement.
// Optional fields (Description) may be left zero; validation of the
// required fields happens in Create.
type CreateInput struct {
	Name        string
	Client      string
	Description string
	CreatedBy   int64
}

// Create inserts a new engagement. It validates required fields, derives
// a fresh graphiti group id, and delegates to the generated querier.
// The created_by user is also used as updated_by for the initial row.
func (s *Service) Create(ctx context.Context, in CreateInput) (database.Engagement, error) {
	if in.Name == "" {
		return database.Engagement{}, errors.New("engagement name required")
	}
	if in.Client == "" {
		return database.Engagement{}, errors.New("engagement client required")
	}
	return s.q.CreateEngagement(ctx, database.CreateEngagementParams{
		Name:            in.Name,
		Client:          in.Client,
		Description:     sql.NullString{String: in.Description, Valid: in.Description != ""},
		GraphitiGroupID: generateGroupID(),
		CreatedBy:       in.CreatedBy,
	})
}

// Get returns an active (non-soft-deleted) engagement by id.
func (s *Service) Get(ctx context.Context, id int64) (database.Engagement, error) {
	return s.q.GetEngagement(ctx, id)
}
