package engagement

import (
	"strings"
	"testing"
)

func TestGenerateGroupID(t *testing.T) {
	id1 := generateGroupID()
	id2 := generateGroupID()
	if id1 == id2 {
		t.Fatal("two consecutive calls produced same id")
	}
	if !strings.HasPrefix(id1, "eng-") {
		t.Fatalf("want prefix eng-, got %q", id1)
	}
	if len(id1) < 20 {
		t.Fatalf("id too short: %q", id1)
	}
}
