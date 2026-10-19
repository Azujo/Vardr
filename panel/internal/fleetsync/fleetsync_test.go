package fleetsync

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

type fakeStore struct{ used map[string]bool }

func (f *fakeStore) UpsertAgents(context.Context, []store.Agent) error { return nil }

// Jak w bazie: token istnieje (wydany w panelu) i jest nieużyty – tylko wtedy „oznaczony teraz”.
func (f *fakeStore) MarkUninstallTokensUsed(_ context.Context, uses []store.TokenUse) ([]store.TokenUse, error) {
	var out []store.TokenUse
	for _, u := range uses {
		key := u.AgentID + "/" + u.TokenID
		if used, issued := f.used[key]; issued && !used {
			f.used[key] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// Deinstalacja tokenem z panelu wycofuje agenta raz; zatrzymanie tokenem,
// token spoza panelu i kolejne heartbeaty z tym samym zdarzeniem – nie.
func TestApplyTokenUsesRetires(t *testing.T) {
	st := &fakeStore{used: map[string]bool{"agt-1/aaa": false, "agt-1/bbb": false}}
	var retired []string
	retire := func(_ context.Context, u store.TokenUse) error {
		retired = append(retired, u.AgentID+"/"+u.TokenID)
		return nil
	}
	status := func(kind, token string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"protection": contract.ProtectionStatus{Enabled: true,
			Events: []contract.TamperRecord{{ID: "1", At: time.Now(), Kind: kind, TokenID: token}}}})
		return b
	}
	log := slog.New(slog.DiscardHandler)
	ctx := context.Background()
	ApplyTokenUses(ctx, log, st, retire, TokenUses("agt-1", status(contract.TamperStopToken, "bbb")))    // tylko zatrzymanie
	ApplyTokenUses(ctx, log, st, retire, TokenUses("agt-1", status(contract.TamperUninstallTok, "zzz"))) // token spoza panelu
	ApplyTokenUses(ctx, log, st, retire, TokenUses("agt-1", status(contract.TamperUninstallTok, "aaa")))
	ApplyTokenUses(ctx, log, st, retire, TokenUses("agt-1", status(contract.TamperUninstallTok, "aaa"))) // kolejny heartbeat
	if !slices.Equal(retired, []string{"agt-1/aaa"}) {
		t.Fatalf("wycofani: %v", retired)
	}
}
