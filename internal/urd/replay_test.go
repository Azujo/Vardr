package urd

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestReplayReadsArchivedBatches(t *testing.T) {
	a, _, _ := fill(t)
	ctx := context.Background()
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour)

	var got []RecordMeta
	var progressCalls int
	st, err := a.Replay(ctx, from, to, nil, func(m RecordMeta, payload []byte) error {
		if SumHex(payload) != m.SHA256 {
			t.Fatalf("paczka %s niezgodna", m.Batch)
		}
		got = append(got, m)
		return nil
	}, func(ReplayStats) { progressCalls++ })
	if err != nil || st.Batches != 12 || len(got) != 12 || progressCalls != 4 {
		t.Fatalf("odtworzenie: %+v %v (wywołania postępu %d)", st, err, progressCalls)
	}
	if got[0].Batch != "b000" || got[0].Agent != "agt-1" || got[0].ReceivedAt.IsZero() {
		t.Fatalf("metadane pierwszej paczki: %+v", got[0])
	}

	// Filtr agentów.
	st, err = a.Replay(ctx, from, to, []string{"agt-inny"}, func(RecordMeta, []byte) error {
		t.Fatal("paczka innego agenta nie powinna zostać odtworzona")
		return nil
	}, nil)
	if err != nil || st.Batches != 0 || st.Skipped != 12 {
		t.Fatalf("filtr agentów: %+v %v", st, err)
	}

	// Uszkodzony segment przerywa odtwarzanie.
	rewrite(t, segFiles(t, a)[0], func(b []byte) []byte { b[len(b)-2] ^= 1; return b })
	if _, err := a.Replay(ctx, from, to, nil, func(RecordMeta, []byte) error { return nil }, nil); err == nil ||
		!strings.Contains(err.Error(), "weryfikację") {
		t.Fatalf("uszkodzone archiwum: %v", err)
	}
}
