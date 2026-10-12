package api

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"siem/internal/identity"
	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

type memIdentities struct {
	domains []string
	aliases map[string]store.IdentityAlias
}

func (m *memIdentities) IdentityDomains(context.Context) ([]string, error) { return m.domains, nil }
func (m *memIdentities) SetIdentityDomains(_ context.Context, d []string, _ string) error {
	m.domains = d
	return nil
}
func (m *memIdentities) IdentityAliases(context.Context) ([]store.IdentityAlias, error) {
	var out []store.IdentityAlias
	for _, a := range m.aliases {
		out = append(out, a)
	}
	return out, nil
}
func (m *memIdentities) SetIdentityAlias(_ context.Context, a store.IdentityAlias) error {
	m.aliases[a.Alias] = a
	return nil
}
func (m *memIdentities) DeleteIdentityAlias(_ context.Context, alias string) (store.IdentityAlias, error) {
	a, ok := m.aliases[alias]
	if !ok {
		return a, store.ErrNotFound
	}
	delete(m.aliases, alias)
	return a, nil
}

type fakePeople []events.Person

func (f fakePeople) People(context.Context, time.Time, string, int) ([]events.Person, error) {
	return f, nil
}
func (f fakePeople) DomainsSeen(context.Context, time.Time) ([]events.DomainSeen, error) {
	return []events.DomainSeen{{Domain: "azujo", Events: 90}, {Domain: "azujo.pl", Events: 10}}, nil
}

func TestIdentitiesAPI(t *testing.T) {
	e := newEnv(t)
	mi := &memIdentities{aliases: map[string]store.IdentityAlias{}}
	var published []identity.Config
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Identities: &Identities{Store: mi,
		Publish: func(_ context.Context, c identity.Config) error { published = append(published, c); return nil },
		People:  fakePeople{{Identity: "jkowalski"}, {Identity: "j.kowalski"}, {Identity: `azujo\j_kowalski`}, {Identity: "ewa"}}}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	if code, _, _ := analyst.do("PUT", "/api/v1/identities/domains", map[string]any{"domains": []string{"azujo"}}); code != 403 {
		t.Fatalf("domeny przez analityka: %d", code)
	}
	if code, out, _ := admin.do("PUT", "/api/v1/identities/domains", map[string]any{"domains": []string{"Azujo", "azujo.pl", "AZUJO", "zła domena"}}); code != 400 {
		t.Fatalf("zła domena: %d %v", code, out)
	}
	if code, _, _ := admin.do("PUT", "/api/v1/identities/domains", map[string]any{"domains": []string{"Azujo", "azujo.pl", "AZUJO"}}); code != 200 ||
		!slices.Equal(mi.domains, []string{"azujo", "azujo.pl"}) {
		t.Fatalf("domeny: %d %v", code, mi.domains)
	}
	if code, _, _ := admin.do("POST", "/api/v1/identities/aliases", map[string]any{"alias": "J.Kowalski", "identity": "jkowalski", "note": "login VPN"}); code != 200 {
		t.Fatalf("alias: %d", code)
	}
	// Łańcuch aliasów odrzucony.
	if code, out, _ := admin.do("POST", "/api/v1/identities/aliases", map[string]any{"alias": "jk", "identity": "j.kowalski"}); code != 400 || out["error"] != "alias_chain" {
		t.Fatalf("łańcuch: %d %v", code, out)
	}
	last := published[len(published)-1]
	if last.Aliases["j.kowalski"] != "jkowalski" || len(last.Domains) != 2 {
		t.Fatalf("publikacja: %+v", last)
	}
	// Domena NetBIOS spoza listy – podpowiedź.
	if _, out, _ := analyst.do("GET", "/api/v1/identities/domains-seen", nil); out["domains"].([]any)[0].(map[string]any)["covered"] != true ||
		out["domains"].([]any)[1].(map[string]any)["covered"] != true {
		t.Fatalf("domeny w zdarzeniach (azujo i azujo.pl na liście): %v", out)
	}
	code, out, _ := analyst.do("GET", "/api/v1/identities/resolve?user=J.Kowalski", nil)
	if code != 200 || out["identity"] != "jkowalski" {
		t.Fatalf("podgląd: %v", out)
	}
	if _, out, _ := analyst.do("GET", "/api/v1/identities/resolve?user=admin&domain=PC01", nil); out["identity"] != `pc01\admin` {
		t.Fatalf("konto lokalne: %v", out)
	}
	code, out, _ = analyst.do("GET", "/api/v1/identities/people", nil)
	sugg, _ := out["suggestions"].([]any)
	if code != 200 || len(sugg) != 1 || len(sugg[0].(map[string]any)["identities"].([]any)) != 3 {
		t.Fatalf("podpowiedzi: %v", out)
	}
	if code, _, _ := admin.do("POST", "/api/v1/identities/aliases/delete", map[string]any{"alias": "j.kowalski"}); code != 200 || len(mi.aliases) != 0 {
		t.Fatalf("usunięcie aliasu: %d", code)
	}
	for _, a := range []string{"identity_domains_changed", "identity_alias_set", "identity_alias_deleted"} {
		if !slices.Contains(e.st.actions(), a) {
			t.Fatalf("brak audytu %s", a)
		}
	}
}
