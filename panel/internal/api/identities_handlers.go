// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/identity"
	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

// Tożsamości osób (etap 7a): domeny organizacji i aliasy kont w Sadze,
// dostarczane normalizatorom przez NATS KV; widok osób ze zdarzeń.

// IdentityStore to domeny i aliasy (implementuje store.PG).
type IdentityStore interface {
	IdentityDomains(ctx context.Context) ([]string, error)
	SetIdentityDomains(ctx context.Context, domains []string, by string) error
	IdentitySharedAccounts(ctx context.Context) ([]string, error)
	SetIdentitySharedAccounts(ctx context.Context, accounts []string, by string) error
	IdentityAliases(ctx context.Context) ([]store.IdentityAlias, error)
	SetIdentityAlias(ctx context.Context, a store.IdentityAlias) error
	DeleteIdentityAlias(ctx context.Context, alias string) (store.IdentityAlias, error)
}

// PeopleSource to osoby ze zdarzeń (implementuje events.Searcher).
type PeopleSource interface {
	People(ctx context.Context, from time.Time, q string, limit int) ([]events.Person, error)
	DomainsSeen(ctx context.Context, from time.Time) ([]events.DomainSeen, error)
}

// Identities to moduł tożsamości panelu (opcjonalny).
type Identities struct {
	Store IdentityStore
	// Publish dostarcza konfigurację normalizatorom; nil – bez NATS.
	Publish func(ctx context.Context, c identity.Config) error
	// People (opcjonalne) – osoby ze zdarzeń w ClickHouse.
	People PeopleSource
}

// Config zwraca konfigurację z bazy.
func (m *Identities) Config(ctx context.Context) (identity.Config, error) {
	var c identity.Config
	ds, err := m.Store.IdentityDomains(ctx)
	if err != nil {
		return c, err
	}
	as, err := m.Store.IdentityAliases(ctx)
	if err != nil {
		return c, err
	}
	c.Domains = ds
	if c.Shared, err = m.Store.IdentitySharedAccounts(ctx); err != nil {
		return c, err
	}
	if len(as) > 0 {
		c.Aliases = map[string]string{}
		for _, a := range as {
			c.Aliases[a.Alias] = a.Identity
		}
	}
	return c, nil
}

func (s *Server) identitiesEnabled(w http.ResponseWriter) bool {
	if s.Identities == nil {
		writeError(w, http.StatusServiceUnavailable, "identities_disabled", "tożsamości wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) getIdentities(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	ds, err := s.Identities.Store.IdentityDomains(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	as, err := s.Identities.Store.IdentityAliases(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sh, err := s.Identities.Store.IdentitySharedAccounts(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": nonNilSlice(ds), "aliases": nonNilSlice(as), "shared": nonNilSlice(sh),
		"delivery": s.Identities.Publish != nil, "people": s.Identities.People != nil})
}

// publishIdentities wysyła bieżącą konfigurację normalizatorom i zwraca
// odpowiedź dla panelu: kod dostarczenia (delivery: ok, no_nats, failed) i opis.
func (s *Server) publishIdentities(r *http.Request) map[string]any {
	res := func(code, msg string) map[string]any { return map[string]any{"delivery": code, "message": msg} }
	if s.Identities.Publish == nil {
		return res("no_nats", "zapisano; brak połączenia z NATS – normalizatory dostaną zmianę po jego przywróceniu")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	c, err := s.Identities.Config(ctx)
	if err == nil {
		err = s.Identities.Publish(ctx, c)
	}
	if err != nil {
		s.Log.Warn("delivering identities to NATS failed – the periodic sync will retry", "err", err)
		return res("failed", "zapisano; dostarczenie do normalizatorów nieudane – panel ponowi je w ciągu 5 minut")
	}
	return res("ok", "zapisano; nowe zdarzenia dostają tożsamość według zmiany w ciągu kilku sekund (zapisane – bez zmian)")
}

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func (s *Server) setIdentityDomains(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Domains []string `json:"domains"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	seen := map[string]bool{}
	domains := []string{}
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		if len(d) > 255 || !domainRe.MatchString(d) {
			writeError(w, http.StatusBadRequest, "bad_domain", "niepoprawna domena: "+d+" (np. azujo, azujo.centrala, azujo.pl)")
			return
		}
		seen[d] = true
		domains = append(domains, d)
	}
	if len(domains) > 100 {
		writeError(w, http.StatusBadRequest, "too_many", "najwyżej 100 domen")
		return
	}
	before, err := s.Identities.Store.IdentityDomains(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Identities.Store.SetIdentityDomains(r.Context(), domains, a.user.Username); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "identity_domains_changed", "", map[string]any{"before": before, "after": domains})
	out := s.publishIdentities(r)
	out["domains"] = domains
	writeJSON(w, http.StatusOK, out)
}

// sharedRe: nazwa konta wspólnego (bez domeny i spacji).
var sharedRe = regexp.MustCompile(`^[^\s"'<>\\@\x00-\x1f]{1,64}$`)

func (s *Server) setIdentityShared(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Accounts []string `json:"accounts"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	seen := map[string]bool{}
	accounts := []string{}
	for _, x := range req.Accounts {
		x = identity.Normalize(x)
		if x == "" || seen[x] {
			continue
		}
		if !sharedRe.MatchString(x) {
			writeError(w, http.StatusBadRequest, "bad_account", "niepoprawne konto: "+x+" (sama nazwa, np. admin, root)")
			return
		}
		seen[x] = true
		accounts = append(accounts, x)
	}
	if len(accounts) > 100 {
		writeError(w, http.StatusBadRequest, "too_many", "najwyżej 100 kont")
		return
	}
	before, err := s.Identities.Store.IdentitySharedAccounts(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Identities.Store.SetIdentitySharedAccounts(r.Context(), accounts, a.user.Username); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "identity_shared_changed", "", map[string]any{"before": before, "after": accounts})
	out := s.publishIdentities(r)
	out["accounts"] = accounts
	writeJSON(w, http.StatusOK, out)
}

// accountRe: nazwa konta albo tożsamość (także DOMENA\konto i UPN).
var accountRe = regexp.MustCompile(`^[^\s"'<>\x00-\x1f][^"'<>\x00-\x1f]{0,319}$`)

func (s *Server) setIdentityAlias(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Alias    string `json:"alias"`
		Identity string `json:"identity"`
		Note     string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	al, id, note := identity.Normalize(req.Alias), identity.Normalize(req.Identity), strings.TrimSpace(req.Note)
	if !accountRe.MatchString(al) || !accountRe.MatchString(id) || len(note) > 500 {
		writeError(w, http.StatusBadRequest, "bad_alias", "podaj nazwę konta (np. j.kowalski, AZUJO\\jan, jan@firma.pl) i osobę (np. jkowalski)")
		return
	}
	if al == id {
		writeError(w, http.StatusBadRequest, "bad_alias", "alias i osoba są takie same")
		return
	}
	// Bez łańcuchów: osoba nie może być aliasem, alias nie może być osobą innego aliasu.
	as, err := s.Identities.Store.IdentityAliases(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, x := range as {
		if x.Alias == id {
			writeError(w, http.StatusBadRequest, "alias_chain", "„"+id+"” jest już aliasem osoby „"+x.Identity+"” – wskaż tę osobę")
			return
		}
		if x.Identity == al {
			writeError(w, http.StatusBadRequest, "alias_chain", "„"+al+"” to osoba z aliasami – najpierw przenieś jej aliasy")
			return
		}
	}
	if err := s.Identities.Store.SetIdentityAlias(r.Context(), store.IdentityAlias{Alias: al, Identity: id, Note: note,
		CreatedBy: a.user.Username}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "identity_alias_set", al, map[string]any{"identity": id, "note": note})
	writeJSON(w, http.StatusOK, s.publishIdentities(r))
}

func (s *Server) deleteIdentityAlias(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Alias string `json:"alias"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	old, err := s.Identities.Store.DeleteIdentityAlias(r.Context(), identity.Normalize(req.Alias))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego aliasu")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "identity_alias_deleted", old.Alias, map[string]any{"identity": old.Identity})
	writeJSON(w, http.StatusOK, s.publishIdentities(r))
}

// resolveIdentity pokazuje, jaką tożsamość dostanie konto przy bieżących
// ustawieniach (z bazy – także przed dostarczeniem do normalizatorów).
func (s *Server) resolveIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	c, err := s.Identities.Config(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, map[string]any{"identity": identity.New(c).ResolveOn(q.Get("user"), q.Get("domain"), q.Get("host"))})
}

// Suggestion to podpowiedź połączenia: tożsamości różniące się tylko
// kropkami, podkreśleniami albo myślnikami (np. j.kowalski i jkowalski).
type Suggestion struct {
	Identities []string `json:"identities"`
}

func squash(id string) string {
	if i := strings.LastIndexAny(id, `\`); i >= 0 {
		id = id[i+1:]
	}
	if i := strings.IndexByte(id, '@'); i > 0 {
		id = id[:i]
	}
	return strings.NewReplacer(".", "", "_", "", "-", "").Replace(id)
}

func (s *Server) listPeople(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	if s.Identities.People == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – widok osób niedostępny")
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 24*90 {
		hours = 168
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		writeError(w, http.StatusBadRequest, "bad_query", "za długi tekst")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	people, err := s.Identities.People.People(ctx, s.now().Add(-time.Duration(hours)*time.Hour), q, 500)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "events_failed", err)
		return
	}
	groups := map[string][]string{}
	for _, p := range people {
		k := squash(p.Identity)
		groups[k] = append(groups[k], p.Identity)
	}
	sugg := []Suggestion{}
	for _, ids := range groups {
		if len(ids) > 1 {
			sort.Strings(ids)
			sugg = append(sugg, Suggestion{Identities: ids})
		}
	}
	sort.Slice(sugg, func(i, j int) bool { return sugg[i].Identities[0] < sugg[j].Identities[0] })
	writeJSON(w, http.StatusOK, map[string]any{"people": people, "suggestions": sugg})
}

type domainSeenView struct {
	events.DomainSeen
	Covered bool `json:"covered"` // należy do organizacji (na liście albo lista pusta)
}

// domainsSeen: domeny kont w zdarzeniach z ostatnich 7 dni i czy są na
// liście domen organizacji – literówka albo brak domeny NetBIOS (np. AZUJO
// obok azujo.centrala) rozdziela tożsamości tej samej osoby.
func (s *Server) domainsSeen(w http.ResponseWriter, r *http.Request) {
	if !s.identitiesEnabled(w) {
		return
	}
	if s.Identities.People == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – podpowiedź domen niedostępna")
		return
	}
	ds, err := s.Identities.Store.IdentityDomains(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	conf := map[string]bool{}
	for _, d := range ds {
		conf[d] = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	seen, err := s.Identities.People.DomainsSeen(ctx, s.now().Add(-7*24*time.Hour))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "events_failed", err)
		return
	}
	out := make([]domainSeenView, 0, len(seen))
	for _, d := range seen {
		if identity.TechnicalDomain(d.Domain) {
			continue // konta wbudowane (np. ze zdarzeń sprzed poprawki) – nie do listy organizacji
		}
		out = append(out, domainSeenView{DomainSeen: d, Covered: len(conf) == 0 || conf[d.Domain]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}
