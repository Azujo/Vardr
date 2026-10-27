// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

// ---- atrapa bazy: grupy ----

func (m *memStore) ensureDefault() {
	if m.groups == nil {
		m.groups = map[int64]store.AgentGroup{1: {ID: 1, Name: "Domyślna", Profile: "workstation", IsDefault: true}}
		m.assign = map[string]int64{}
		m.nextGroup = 1
	}
}
func (m *memStore) ListGroups(context.Context) ([]store.AgentGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	var out []store.AgentGroup
	for _, g := range m.groups {
		for _, gid := range m.assign {
			if gid == g.ID {
				g.Agents++
			}
		}
		out = append(out, g)
	}
	return out, nil
}
func (m *memStore) GroupByID(_ context.Context, id int64) (store.AgentGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	g, ok := m.groups[id]
	if !ok {
		return g, store.ErrNotFound
	}
	return g, nil
}
func (m *memStore) CreateGroup(_ context.Context, g store.AgentGroup) (store.AgentGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	for _, x := range m.groups {
		if strings.EqualFold(x.Name, g.Name) {
			return g, store.ErrConflict
		}
	}
	m.nextGroup++
	g.ID = m.nextGroup
	m.groups[g.ID] = g
	return g, nil
}
func (m *memStore) UpdateGroup(_ context.Context, g store.AgentGroup) (store.AgentGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	old, ok := m.groups[g.ID]
	if !ok {
		return g, store.ErrNotFound
	}
	g.IsDefault = old.IsDefault
	m.groups[g.ID] = g
	return g, nil
}
func (m *memStore) DeleteGroup(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	g, ok := m.groups[id]
	if !ok {
		return store.ErrNotFound
	}
	if g.IsDefault {
		return store.ErrInUse
	}
	for _, gid := range m.assign {
		if gid == id {
			return store.ErrInUse
		}
	}
	delete(m.groups, id)
	return nil
}
func (m *memStore) AssignAgent(_ context.Context, agentID string, groupID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	m.assign[agentID] = groupID
	return nil
}
func (m *memStore) GroupForAgent(_ context.Context, agentID string) (store.AgentGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	if id, ok := m.assign[agentID]; ok {
		return m.groups[id], nil
	}
	return m.groups[1], nil
}
func (m *memStore) AgentGroupIDs(context.Context) (map[string]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureDefault()
	out := map[string]int64{}
	for k, v := range m.assign {
		out[k] = v
	}
	return out, nil
}

// configRequest to pobranie konfiguracji przez agenta (mTLS).
func configRequest(e *env, agentID, etag string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://panel/enroll/v1/config", nil)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: agentID}, SerialNumber: big.NewInt(77)}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	if etag != "" {
		r.Header.Set("If-None-Match", etag)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestGroupsAndAgentConfig(t *testing.T) {
	e, _ := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")

	// Walidacja limitów (te same reguły co w agencie).
	if code, out, _ := admin.do("POST", "/api/v1/groups", map[string]any{"name": "Zła", "profile": "server",
		"limits": map[string]any{"cpu_max_percent": 150}}); code != 400 || !strings.Contains(out["message"].(string), "CPU") {
		t.Fatalf("walidacja: %d %v", code, out)
	}
	code, out, _ := admin.do("POST", "/api/v1/groups", map[string]any{"name": "Serwery IIS", "profile": "server",
		"limits": map[string]any{"cpu_max_percent": 5, "max_eps": 2000, "priority": "below_normal"}})
	if code != 201 {
		t.Fatalf("grupa: %d %v", code, out)
	}
	gid := int64(out["group"].(map[string]any)["id"].(float64))

	// Agent bez przypisania dostaje grupę domyślną.
	w := configRequest(e, "agt-pc1", "")
	var def map[string]any
	json.Unmarshal(w.Body.Bytes(), &def)
	if w.Code != 200 || def["profile"] != "workstation" || def["group"] != "Domyślna" || w.Header().Get("ETag") == "" {
		t.Fatalf("konfiguracja domyślna: %d %v", w.Code, def)
	}
	if w2 := configRequest(e, "agt-pc1", w.Header().Get("ETag")); w2.Code != 304 {
		t.Fatalf("niezmieniona konfiguracja powinna dać 304: %d", w2.Code)
	}

	// Przypisanie do grupy zmienia konfigurację (i wersję).
	if code, _, _ := admin.do("PUT", "/api/v1/agents/agt-pc1/group", map[string]any{"group_id": gid}); code != 200 {
		t.Fatalf("przypisanie: %d", code)
	}
	w3 := configRequest(e, "agt-pc1", w.Header().Get("ETag"))
	var cfg map[string]any
	json.Unmarshal(w3.Body.Bytes(), &cfg)
	if w3.Code != 200 || cfg["profile"] != "server" || cfg["limits"].(map[string]any)["max_eps"] != 2000.0 || cfg["version"] == def["version"] {
		t.Fatalf("konfiguracja grupy: %d %v", w3.Code, cfg)
	}

	// Grupy z agentami ani domyślnej nie można usunąć.
	if code, out, _ := admin.do("DELETE", "/api/v1/groups/"+itoa(gid), nil); code != 409 || out["error"] != "in_use" {
		t.Fatalf("usunięcie używanej: %d %v", code, out)
	}
	if code, _, _ := admin.do("DELETE", "/api/v1/groups/1", nil); code != 409 {
		t.Fatalf("usunięcie domyślnej: %d", code)
	}

	// Lista agentów: stan konfiguracji z heartbeatu.
	now := e.clock
	e.st.agents = map[string]store.Agent{
		"agt-pc1": {ID: "agt-pc1", LastSeen: now, Status: json.RawMessage(`{"config":{"version":"` + cfg["version"].(string) + `"}}`)},
		"agt-pc2": {ID: "agt-pc2", LastSeen: now, Status: json.RawMessage(`{"config":{"version":"stara"}}`)},
		"agt-pc3": {ID: "agt-pc3", LastSeen: now, Status: json.RawMessage(`{}`)},
	}
	_, list, _ := admin.do("GET", "/api/v1/agents", nil)
	states := map[string]string{}
	for _, a := range list["agents"].([]any) {
		m := a.(map[string]any)
		states[m["id"].(string)] = m["group"].(string) + "/" + m["config_state"].(string)
	}
	want := map[string]string{"agt-pc1": "Serwery IIS/applied", "agt-pc2": "Domyślna/pending", "agt-pc3": "Domyślna/unknown"}
	for id, s := range want {
		if states[id] != s {
			t.Errorf("%s: %q, chcę %q", id, states[id], s)
		}
	}

	// Token z grupą: profil z grupy, rejestracja przypisuje agenta.
	_, tok, _ := admin.do("POST", "/api/v1/enroll-tokens", map[string]any{"name": "IIS", "profile": "workstation", "valid_hours": 1, "group_id": gid})
	if tok["token"].(map[string]any)["profile"] != "server" {
		t.Fatalf("profil tokenu z grupy: %v", tok)
	}
	code, reg := agentPost(e, "/enroll/v1/register", map[string]any{"token": tok["secret"], "csr": newCSR(t), "hostname": "IIS02"}, nil)
	if code != 200 || reg["profile"] != "server" {
		t.Fatalf("rejestracja z grupą: %d %v", code, reg)
	}
	if g, _ := e.st.GroupForAgent(context.Background(), "agt-iis02"); g.ID != gid {
		t.Fatalf("agent nie trafił do grupy: %+v", g)
	}
	_ = time.Now
}

func TestAgentAutoUpdate(t *testing.T) {
	e, _ := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")
	dir := e.agentDir
	msi := []byte("instalator MSI agenta")
	if err := os.WriteFile(filepath.Join(dir, "vardr-agent.msi"), msi, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AGENT_VERSION"), []byte("0.10.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	download := func(agentID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://panel"+contract.AgentMSIPath, nil)
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: agentID}, SerialNumber: big.NewInt(77)}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w
	}

	// Bez automatycznych aktualizacji: konfiguracja bez instalatora, pobranie zabronione.
	w := configRequest(e, "agt-pc1", "")
	if strings.Contains(w.Body.String(), `"update"`) {
		t.Fatalf("aktualizacja w grupie bez auto_update: %s", w.Body)
	}
	if d := download("agt-pc1"); d.Code != 403 {
		t.Fatalf("pobranie bez auto_update: %d", d.Code)
	}

	// Włączenie wymaga hasła.
	group := map[string]any{"name": "Stacje", "profile": "workstation", "limits": map[string]any{"auto_update": true}}
	if code, out, _ := admin.do("POST", "/api/v1/groups", group); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("auto_update bez hasła: %d %v", code, out)
	}
	group["password"] = "haslo-admina-123"
	code, out, _ := admin.do("POST", "/api/v1/groups", group)
	if code != 201 {
		t.Fatalf("grupa: %d %v", code, out)
	}
	gid := int64(out["group"].(map[string]any)["id"].(float64))
	if code, _, _ := admin.do("PUT", "/api/v1/agents/agt-pc1/group", map[string]any{"group_id": gid}); code != 200 {
		t.Fatalf("przypisanie: %d", code)
	}
	_, list, _ := admin.do("GET", "/api/v1/groups", nil)
	if list["agent_version"] != "0.10.0" {
		t.Fatalf("wersja instalatora na serwerze: %v", list["agent_version"])
	}

	w = configRequest(e, "agt-pc1", "")
	var cfg contract.AgentConfig
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.Update == nil {
		t.Fatalf("konfiguracja z aktualizacją: %s %v", w.Body, err)
	}
	sum := sha256.Sum256(msi)
	if cfg.Update.Version != "0.10.0" || cfg.Update.SHA256 != hex.EncodeToString(sum[:]) || cfg.Update.Size != int64(len(msi)) || cfg.Validate() != nil {
		t.Fatalf("aktualizacja: %+v", cfg.Update)
	}
	if d := download("agt-pc1"); d.Code != 200 || !bytes.Equal(d.Body.Bytes(), msi) {
		t.Fatalf("pobranie: %d %q", d.Code, d.Body)
	}

	// Nowy instalator zmienia wersję konfiguracji (agent nie dostanie 304).
	etag := w.Header().Get("ETag")
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "vardr-agent.msi"), []byte("nowszy instalator"), 0o600)
	os.WriteFile(filepath.Join(dir, "AGENT_VERSION"), []byte("0.10.1"), 0o600)
	if w2 := configRequest(e, "agt-pc1", etag); w2.Code != 200 || !strings.Contains(w2.Body.String(), `"0.10.1"`) {
		t.Fatalf("nowy instalator: %d %s", w2.Code, w2.Body)
	}

	// Edycja grupy z już włączonymi aktualizacjami nie wymaga hasła.
	if code, out, _ := admin.do("PATCH", "/api/v1/groups/"+itoa(gid), map[string]any{"name": "Stacje biurowe", "profile": "workstation",
		"limits": map[string]any{"auto_update": true, "max_eps": 100}}); code != 200 {
		t.Fatalf("edycja: %d %v", code, out)
	}
}
