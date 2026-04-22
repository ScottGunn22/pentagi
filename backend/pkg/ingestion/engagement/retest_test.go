package engagement

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"pentagi/pkg/database"
)

// fakeRetestRepo is a hand-rolled stub. It covers only the three Querier
// methods ComputeRetestDiff needs; any other call panics so we catch drift.
type fakeRetestRepo struct {
	flow     database.Flow
	flowErr  error
	baseline []database.Finding
	baselErr error
	current  []database.Finding
	curErr   error

	// last-seen args for assertions
	lastBaselineArg database.FindingsFirstSeenBeforeParams
}

func (f *fakeRetestRepo) GetFlow(_ context.Context, id int64) (database.Flow, error) {
	if f.flowErr != nil {
		return database.Flow{}, f.flowErr
	}
	if f.flow.ID != id {
		return database.Flow{}, errors.New("unexpected flow id")
	}
	return f.flow, nil
}

func (f *fakeRetestRepo) FindingsFirstSeenBefore(
	_ context.Context, arg database.FindingsFirstSeenBeforeParams,
) ([]database.Finding, error) {
	f.lastBaselineArg = arg
	return f.baseline, f.baselErr
}

func (f *fakeRetestRepo) FindingsByEngagement(
	_ context.Context, _ int64,
) ([]database.Finding, error) {
	return f.current, f.curErr
}

func finding(id int64) database.Finding {
	return database.Finding{ID: id, EngagementID: 1}
}

// bucketize groups a []InsertFlowRetestDiffParams by DiffState for easier
// assertions: map[state]set-of-finding-ids.
func bucketize(t *testing.T, rows []database.InsertFlowRetestDiffParams) map[database.DiffState]map[int64]struct{} {
	t.Helper()
	out := map[database.DiffState]map[int64]struct{}{}
	for _, r := range rows {
		if out[r.DiffState] == nil {
			out[r.DiffState] = map[int64]struct{}{}
		}
		out[r.DiffState][r.FindingID] = struct{}{}
	}
	return out
}

func TestComputeRetestDiff_AllThreeBuckets(t *testing.T) {
	// baseline: {1, 2, 3}; current: {2, 3, 4}
	// => fixed={1}, persistent={2,3}, new={4}
	repo := &fakeRetestRepo{
		flow: database.Flow{
			ID:        42,
			CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
		},
		baseline: []database.Finding{finding(1), finding(2), finding(3)},
		current:  []database.Finding{finding(2), finding(3), finding(4)},
	}
	got, err := ComputeRetestDiff(context.Background(), repo, 1, 42)
	if err != nil {
		t.Fatalf("ComputeRetestDiff: %v", err)
	}
	buckets := bucketize(t, got)

	if _, ok := buckets[database.DiffStateFixed][1]; !ok {
		t.Errorf("expected finding 1 in fixed bucket, got %+v", buckets)
	}
	if len(buckets[database.DiffStateFixed]) != 1 {
		t.Errorf("fixed bucket should have exactly one entry, got %+v", buckets[database.DiffStateFixed])
	}
	if _, ok := buckets[database.DiffStatePersistent][2]; !ok {
		t.Errorf("expected finding 2 persistent, got %+v", buckets)
	}
	if _, ok := buckets[database.DiffStatePersistent][3]; !ok {
		t.Errorf("expected finding 3 persistent, got %+v", buckets)
	}
	if _, ok := buckets[database.DiffStateNew][4]; !ok {
		t.Errorf("expected finding 4 new, got %+v", buckets)
	}
	if _, ok := buckets[database.DiffStateRegressed]; ok {
		t.Errorf("regressed bucket should stay empty in v1, got %+v", buckets[database.DiffStateRegressed])
	}
}

func TestComputeRetestDiff_EmptyCurrent_AllFixed(t *testing.T) {
	repo := &fakeRetestRepo{
		flow: database.Flow{
			ID:        7,
			CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
		},
		baseline: []database.Finding{finding(10), finding(11)},
		current:  nil,
	}
	got, err := ComputeRetestDiff(context.Background(), repo, 1, 7)
	if err != nil {
		t.Fatalf("ComputeRetestDiff: %v", err)
	}
	buckets := bucketize(t, got)
	if len(buckets[database.DiffStateFixed]) != 2 {
		t.Errorf("expected both findings fixed, got %+v", buckets)
	}
}

func TestComputeRetestDiff_EmptyBaseline_AllNew(t *testing.T) {
	repo := &fakeRetestRepo{
		flow: database.Flow{
			ID:        9,
			CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
		},
		baseline: nil,
		current:  []database.Finding{finding(100), finding(200)},
	}
	got, err := ComputeRetestDiff(context.Background(), repo, 1, 9)
	if err != nil {
		t.Fatalf("ComputeRetestDiff: %v", err)
	}
	buckets := bucketize(t, got)
	if len(buckets[database.DiffStateNew]) != 2 {
		t.Errorf("expected both findings new, got %+v", buckets)
	}
}

func TestComputeRetestDiff_InvalidBaseline_Errors(t *testing.T) {
	repo := &fakeRetestRepo{flowErr: errors.New("boom")}
	if _, err := ComputeRetestDiff(context.Background(), repo, 1, 99); err == nil {
		t.Fatal("expected error from fake GetFlow")
	}

	// baseline flow with no created_at is invalid — diff cannot anchor.
	repo = &fakeRetestRepo{
		flow: database.Flow{ID: 5, CreatedAt: sql.NullTime{Valid: false}},
	}
	if _, err := ComputeRetestDiff(context.Background(), repo, 1, 5); err == nil {
		t.Fatal("expected error on flow with null created_at")
	}
}

func TestComputeRetestDiff_UsesBaselineCreatedAt(t *testing.T) {
	anchor := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	repo := &fakeRetestRepo{
		flow: database.Flow{
			ID:        13,
			CreatedAt: sql.NullTime{Time: anchor, Valid: true},
		},
	}
	if _, err := ComputeRetestDiff(context.Background(), repo, 77, 13); err != nil {
		t.Fatalf("ComputeRetestDiff: %v", err)
	}
	if repo.lastBaselineArg.EngagementID != 77 {
		t.Errorf("engagement id mismatch, got %d", repo.lastBaselineArg.EngagementID)
	}
	if !repo.lastBaselineArg.FirstSeenAt.Equal(anchor) {
		t.Errorf("baseline cutoff mismatch: got %v want %v", repo.lastBaselineArg.FirstSeenAt, anchor)
	}
}
