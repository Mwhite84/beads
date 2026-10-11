package guardtx

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestReservedPublicationTokenProtectsWritesAndPreservesLaterPrepare(t *testing.T) {
	ctx := context.Background()
	f := &guardFake{enabled: true, image: guardImage{root: "initial", token: "original", generation: "generation"}}
	db := sql.OpenDB(guardConnector{fake: f})
	defer db.Close()
	tx, err := BeginTx(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Rollback(tx)
	if _, err := tx.ExecContext(ctx, "UPDATE guard_fixture SET value = ?", "companion+primary"); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	if err := PrepareWithReservedToken(ctx, tx, token); err != nil {
		t.Fatal(err)
	}
	if f.stampCalls != 1 || f.stampArgs[0][0].Value != token {
		t.Fatal("reserved token not actual protected CAS")
	}
	if err := Prepare(ctx, tx); err != nil || f.stampCalls != 1 {
		t.Fatal("later ordinary Prepare restamped unchanged root", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE guard_fixture SET value = ?", "new-after-reserved"); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(ctx, tx); err != nil || f.stampCalls != 2 || f.stampArgs[1][0].Value == token {
		t.Fatal("later real writes bypassed normal stamp", err)
	}
	if err := Commit(ctx, tx); err != nil || f.stampCalls != 2 {
		t.Fatal("final native commit changed prepared root", err)
	}
}
func TestReservedPublicationTokenRefusesInvalidUnboundAndConflict(t *testing.T) {
	ctx := context.Background()
	if !errors.Is(PrepareWithReservedToken(ctx, &sql.DB{}, strings.Repeat("a", 64)), ErrUnsupported) {
		t.Fatal("unbound reserved scope admitted")
	}
	for _, token := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		f := &guardFake{enabled: true, image: guardImage{root: "initial", token: "original", generation: "generation"}}
		db := sql.OpenDB(guardConnector{fake: f})
		tx, err := BeginTx(ctx, db, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(PrepareWithReservedToken(ctx, tx, token), ErrUnsupported) || f.stampCalls != 0 {
			t.Fatal("invalid native token stamped")
		}
		_ = Rollback(tx)
		_ = db.Close()
	}
	f := &guardFake{enabled: true, affectedZero: true, image: guardImage{root: "initial", token: "original", generation: "generation"}}
	db := sql.OpenDB(guardConnector{fake: f})
	defer db.Close()
	tx, err := BeginTx(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Rollback(tx)
	if _, err := tx.ExecContext(ctx, "UPDATE guard_fixture SET value = ?", "primary"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(PrepareWithReservedToken(ctx, tx, strings.Repeat("a", 64)), ErrConflict) {
		t.Fatal("reserved stamp swallowed competing writer")
	}
	if !errors.Is(Prepare(ctx, tx), ErrConflict) {
		t.Fatal("failed reserved stamp lost poisoned scope")
	}
}
