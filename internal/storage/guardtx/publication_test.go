package guardtx

import (
	"database/sql"
	"testing"
)

func TestGuardPublicationOwnershipDetachedAndForgotten(t *testing.T) {
	runner := &sql.DB{}
	other := &sql.DB{}
	scopes.Store(runner, &scope{})
	defer Forget(runner)
	NotePublicationTables(other, "config")
	if len(PublicationTables(other)) != 0 || Bound(other) {
		t.Fatal("disabled runner acquired publication")
	}
	if len(PublicationTables(runner)) != 0 {
		t.Fatal("unrelated native/no-op acquired dirty tables")
	}
	NotePublicationTables(runner, "config", "bd_guard_operations", "config")
	copy := PublicationTables(runner)
	if len(copy) != 2 || !copy["config"] || !copy["bd_guard_operations"] {
		t.Fatal("actual ownership omitted/doubled")
	}
	delete(copy, "config")
	copy["unrelated"] = true
	if len(PublicationTables(runner)) != 2 || !PublicationTables(runner)["config"] {
		t.Fatal("caller mutated scope")
	}
	Forget(runner)
	if Bound(runner) || len(PublicationTables(runner)) != 0 {
		t.Fatal("committed/rolled back runner retained ownership")
	}
	scopes.Store(runner, &scope{})
	if len(PublicationTables(runner)) != 0 {
		t.Fatal("rebound original runner inherited prior ownership")
	}
}
