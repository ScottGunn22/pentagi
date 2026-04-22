package seeder

import "fmt"

// findingEpisodeName returns the deterministic Graphiti episode name for a
// finding. Both the synchronous seed path (Phase 7 controller) and the
// reconcile loop call this so that a retry of the same logical finding
// resolves to the same episode key — Graphiti's name+group_id dedup then
// makes the second write a no-op rather than a duplicate edge.
//
// The DB ID is the only key both producers can guarantee at write time.
// CVE is not a primary key (multiple findings can share a CVE on different
// targets), and bundle-position changes if the parser is re-run.
func findingEpisodeName(targetRef string, dbID int64) string {
	return fmt.Sprintf("finding:%s:%d", targetRef, dbID)
}
