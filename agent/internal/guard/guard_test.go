// SPDX-License-Identifier: AGPL-3.0-or-later

package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"siem/internal/contract"
)

func TestJournalRecentAndPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	if _, err := Append(dir, contract.TamperRecord{Kind: contract.TamperStop, At: now.Add(-8 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4*MaxEvents+5; i++ {
		if _, err := Append(dir, contract.TamperRecord{Kind: contract.TamperBadToken, Detail: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Recent(dir, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxEvents || got[len(got)-1].Detail != fmt.Sprint(4*MaxEvents+4) || got[0].ID == "" {
		t.Fatalf("got %d, last %+v", len(got), got[len(got)-1])
	}
	// Dziennik przycięty do ostatnich wpisów.
	again, _ := Recent(dir, now.Add(time.Second))
	data, _ := os.ReadFile(filepath.Join(dir, journalFile))
	if len(again) != MaxEvents || len(data) > 200*MaxEvents {
		t.Fatalf("po przycięciu: %d wpisów, %d B", len(again), len(data))
	}
}

func TestVerify(t *testing.T) {
	now := time.Now().UTC()
	tok, err := contract.NewUninstallToken()
	if err != nil {
		t.Fatal(err)
	}
	h := contract.UninstallHash("agt-pc01", tok)
	tokens := []contract.UninstallToken{{ID: contract.UninstallTokenID(h), Hash: h, ExpiresAt: now.Add(time.Hour)}}
	// Wielkość liter i myślniki bez znaczenia.
	lower := []byte(tok)
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + 32
		}
	}
	if _, err := Verify("agt-pc01", string(lower), tokens, nil, now); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		agent, token string
		tokens       []contract.UninstallToken
		used         map[string]bool
		at           time.Time
		want         error
	}{
		{"agt-pc02", tok, tokens, nil, now, ErrBadToken}, // token innego agenta
		{"agt-pc01", "ABCDE-ABCDE-ABCDE-ABCDE", tokens, nil, now, ErrBadToken},
		{"agt-pc01", "", tokens, nil, now, ErrNoTokenArg},
		{"agt-pc01", tok, nil, nil, now, ErrNoTokens},
		{"agt-pc01", tok, tokens, map[string]bool{tokens[0].ID: true}, now, ErrUsedToken},
		{"agt-pc01", tok, tokens, nil, now.Add(2 * time.Hour), ErrExpToken},
	}
	for i, c := range cases {
		if _, err := Verify(c.agent, c.token, c.tokens, c.used, c.at); !errors.Is(err, c.want) {
			t.Errorf("%d: %v, chcę %v", i, err, c.want)
		}
	}
}

func TestMarkersAndUsed(t *testing.T) {
	dir := t.TempDir()
	boot := time.Now().Add(-time.Hour).UTC()
	if prev, err := MarkRunning(dir, boot); err != nil || prev != nil {
		t.Fatal(prev, err)
	}
	// Ten sam start systemu – poprzedni proces nie usunął znacznika (zabity).
	if prev, _ := MarkRunning(dir, boot.Add(time.Second)); prev == nil || prev.PID != os.Getpid() {
		t.Fatalf("brak wykrycia zabicia: %+v", prev)
	}
	// Inny start systemu (utrata zasilania) – bez zgłoszenia.
	if prev, _ := MarkRunning(dir, boot.Add(time.Hour)); prev != nil {
		t.Fatalf("restart systemu zgłoszony jako zabicie: %+v", prev)
	}
	ClearRunning(dir)
	if prev, _ := MarkRunning(dir, boot.Add(time.Hour)); prev != nil {
		t.Fatal("znacznik po czystym zatrzymaniu")
	}

	if u, err := ReadUnlock(dir); u != nil || err != nil {
		t.Fatal(u, err)
	}
	if err := WriteUnlock(dir, Unlock{Action: "stop", Token: "X"}); err != nil {
		t.Fatal(err)
	}
	u, _ := ReadUnlock(dir)
	if !u.Fresh(time.Now()) || u.Fresh(time.Now().Add(UnlockFresh+time.Second)) {
		t.Fatalf("świeżość znacznika: %+v", u)
	}
	var none *Unlock
	if none.Fresh(time.Now()) {
		t.Fatal("brak znacznika jako świeży")
	}
	RemoveUnlock(dir)

	if RecordedState(dir) != "" {
		t.Fatal("stan bez zapisu")
	}
	_ = RecordState(dir, "protected")
	if RecordedState(dir) != "protected" {
		t.Fatal("stan")
	}
	_ = MarkUsed(dir, "a")
	_ = MarkUsed(dir, "b")
	if u := Used(dir); !u["a"] || !u["b"] || len(u) != 2 {
		t.Fatal(u)
	}
}
