package seeder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/graphiti"
)

type fakeRepo struct {
	pending []database.Finding
	seeded  []int64
}

func (f *fakeRepo) FindingsPendingGraphSync(_ context.Context, lim int64) ([]database.Finding, error) {
	if int(lim) < len(f.pending) {
		return f.pending[:lim], nil
	}
	return f.pending, nil
}

func (f *fakeRepo) MarkFindingGraphSeeded(_ context.Context, id int64) error {
	f.seeded = append(f.seeded, id)
	return nil
}

type fakeEngagementLookup struct {
	group string
	err   error
}

func (f fakeEngagementLookup) GroupID(_ context.Context, _ int64) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.group, nil
}

// flakyClient fails whenever any message name contains the trailing segment
// ":<failOnID>" — which matches the deterministic finding:<ref>:<id> form
// emitted by both the seeder and the reconciler.
type flakyClient struct {
	failOnID int64
	calls    []string
}

func (f *flakyClient) AddMessages(_ context.Context, req graphiti.AddMessagesRequest) error {
	for _, m := range req.Messages {
		f.calls = append(f.calls, m.Name)
	}
	if f.failOnID != 0 {
		suffix := fmt.Sprintf(":%d", f.failOnID)
		for _, m := range req.Messages {
			if strings.HasSuffix(m.Name, suffix) {
				return errors.New("synthetic write failure")
			}
		}
	}
	return nil
}

func TestReconcile_MarksSeeded(t *testing.T) {
	repo := &fakeRepo{pending: []database.Finding{
		{ID: 1, EngagementID: 100, TargetRef: "ip:10.0.0.1:80/tcp"},
		{ID: 2, EngagementID: 100, TargetRef: "ip:10.0.0.2:80/tcp"},
	}}
	r := &Reconciler{
		Repo:        repo,
		GroupLookup: fakeEngagementLookup{group: "eng-x"},
		Client:      &fakeClient{},
		// Logger intentionally nil — nil-safety path exercised here.
	}
	if err := r.ReconcileOnce(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if len(repo.seeded) != 2 {
		t.Fatalf("want 2 seeded, got %d", len(repo.seeded))
	}
}

func TestReconcile_SkipsOnWriteFailure(t *testing.T) {
	repo := &fakeRepo{pending: []database.Finding{
		{ID: 1, EngagementID: 100, TargetRef: "ip:a:80/tcp"},
		{ID: 2, EngagementID: 100, TargetRef: "ip:b:80/tcp"},
	}}
	r := &Reconciler{
		Repo:        repo,
		GroupLookup: fakeEngagementLookup{group: "eng-x"},
		Client:      &flakyClient{failOnID: 2},
	}
	if err := r.ReconcileOnce(context.Background(), 10); err != nil {
		t.Fatalf("per-finding write failure must not surface as error: %v", err)
	}
	if len(repo.seeded) != 1 || repo.seeded[0] != 1 {
		t.Fatalf("want only id=1 marked seeded, got %v", repo.seeded)
	}
}

func TestReconcile_PropagatesGroupLookupError(t *testing.T) {
	repo := &fakeRepo{pending: []database.Finding{{ID: 1, EngagementID: 100}}}
	r := &Reconciler{
		Repo:        repo,
		GroupLookup: fakeEngagementLookup{err: errors.New("db down")},
		Client:      &fakeClient{},
	}
	if err := r.ReconcileOnce(context.Background(), 10); err == nil {
		t.Fatal("expected error when group lookup fails")
	}
}

// TestReconcile_EpisodeNameMatchesSeederHelper locks the cross-producer
// naming agreement: the reconciler must use the exact same episode name
// that the seeder would build for the same (target_ref, id). If this
// assertion drifts, Graphiti will see two different episodes for one
// logical finding and produce duplicate edges on every retry.
func TestReconcile_EpisodeNameMatchesSeederHelper(t *testing.T) {
	row := database.Finding{ID: 99, EngagementID: 7, TargetRef: "ip:10.0.0.9:22/tcp"}
	client := &fakeClient{}
	r := &Reconciler{
		Repo:        &fakeRepo{pending: []database.Finding{row}},
		GroupLookup: fakeEngagementLookup{group: "eng-x"},
		Client:      client,
	}
	if err := r.ReconcileOnce(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if len(client.calls) != 1 {
		t.Fatalf("want 1 graphiti call, got %d", len(client.calls))
	}
	got := client.calls[0].Messages[0].Name
	want := findingEpisodeName(row.TargetRef, row.ID)
	if got != want {
		t.Fatalf("reconciler emitted episode name %q; seeder helper wants %q", got, want)
	}
}
