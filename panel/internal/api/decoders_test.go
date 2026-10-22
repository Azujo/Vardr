// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/internal/decode"
	"siem/panel/internal/api/store"
)

type memDecoders struct {
	rows map[string]store.SyslogDecoder
	vers []store.DecoderVersion
}

func (m *memDecoders) ListDecoders(context.Context) ([]store.SyslogDecoder, error) {
	var out []store.SyslogDecoder
	for _, d := range m.rows {
		out = append(out, d)
	}
	return out, nil
}
func (m *memDecoders) SaveDecoder(_ context.Context, d store.SyslogDecoder, action, note string) (store.SyslogDecoder, error) {
	d.Revision = len(m.vers) + 1
	m.rows[d.ID] = d
	m.vers = append(m.vers, store.DecoderVersion{DecoderID: d.ID, Revision: d.Revision, Action: action, Source: d.Source,
		Enabled: d.Enabled, Note: note, ChangedBy: d.UpdatedBy})
	return d, nil
}
func (m *memDecoders) DeleteDecoder(_ context.Context, id, note, by string) (store.SyslogDecoder, error) {
	d, ok := m.rows[id]
	if !ok {
		return d, store.ErrNotFound
	}
	delete(m.rows, id)
	m.vers = append(m.vers, store.DecoderVersion{DecoderID: id, Action: "reverted", Note: note, ChangedBy: by})
	return d, nil
}
func (m *memDecoders) DecoderVersions(_ context.Context, id string, _ int) ([]store.DecoderVersion, error) {
	var out []store.DecoderVersion
	for _, v := range m.vers {
		if v.DecoderID == id {
			out = append(out, v)
		}
	}
	return out, nil
}

const nasDecoder = `id: synology
title: Synology DSM
dataset: synology.dsm
priority: 60
match:
  app: [WinFileService, Connection]
parser:
  type: regex
  patterns:
    - regex: 'User \[(?P<user>[^\]]+)\] from \[(?P<src_ip>[0-9a-fA-F.:]+)\] failed to log in'
      set: {event.action: login, event.outcome: failure}
fields:
  user.name: user
  source.ip: src_ip
samples:
  - '<12>Oct  9 13:00:00 nas01 Connection: User [admin] from [192.168.88.20] failed to log in via [DSM] due to authorization failure.'
`

func TestDecodersAPI(t *testing.T) {
	e := newEnv(t)
	md := &memDecoders{rows: map[string]store.SyslogDecoder{}}
	published := map[string]*decode.Custom{}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Decoders: &Decoders{Store: md, Loc: time.UTC,
		Publish: func(_ context.Context, id string, c *decode.Custom) error { published[id] = c; return nil }}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	code, out, _ := analyst.do("GET", "/api/v1/decoders", nil)
	list, _ := out["decoders"].([]any)
	if code != 200 || len(list) < 2 {
		t.Fatalf("lista dekoderów: %d %v", code, out)
	}

	// Test: definicja z edytora na próbce – i na wiadomości, której nie rozpoznaje.
	code, out, _ = analyst.do("POST", "/api/v1/decoders/test", map[string]any{"source": nasDecoder, "samples": []string{
		"<12>Oct  9 13:00:00 nas01 Connection: User [jan] from [10.1.1.5] failed to log in via [SMB] due to authorization failure.",
		"<13>Oct  9 13:00:00 nas01 smbd[1]: share opened"}})
	res, _ := out["results"].([]any)
	if code != 200 || len(res) != 2 {
		t.Fatalf("test dekodera: %d %v", code, out)
	}
	r0 := res[0].(map[string]any)
	ev := r0["event"].(map[string]any)
	if r0["decoder"] != "synology" || r0["candidate"] != true || ev["user.name"] != "jan" || ev["source.ip"] != "10.1.1.5" ||
		ev["event.outcome"] != "failure" {
		t.Fatalf("wynik dekodowania: %v", r0)
	}
	if r1 := res[1].(map[string]any); r1["dataset"] != "syslog.generic" || r1["candidate"] != false {
		t.Fatalf("wiadomość nierozpoznana: %v", r1)
	}
	if code, out, _ := analyst.do("POST", "/api/v1/decoders/test", map[string]any{"source": "id: x\n"}); code != 200 || out["ok"] != false {
		t.Fatalf("błędna definicja: %d %v", code, out)
	}

	// Zapis: tylko administrator; id ze ścieżki; próbki muszą się dekodować.
	if code, _, _ := analyst.do("PUT", "/api/v1/decoders/synology", map[string]any{"source": nasDecoder}); code != 403 {
		t.Fatalf("zapis przez analityka: %d", code)
	}
	if code, out, _ := admin.do("PUT", "/api/v1/decoders/inny", map[string]any{"source": nasDecoder}); code != 400 || out["error"] != "bad_id" {
		t.Fatalf("inne id: %d %v", code, out)
	}
	bad := strings.Replace(nasDecoder, "failed to log in via [DSM]", "logged in via [DSM]", 1)
	if code, out, _ := admin.do("PUT", "/api/v1/decoders/synology", map[string]any{"source": strings.Replace(bad, "app: [WinFileService, Connection]", "regex: 'failed'", 1)}); code != 400 || out["error"] != "sample_failed" {
		t.Fatalf("próbka niepasująca: %d %v", code, out)
	}
	if code, out, _ := admin.do("PUT", "/api/v1/decoders/synology", map[string]any{"source": nasDecoder, "note": "NAS w biurze"}); code != 200 {
		t.Fatalf("zapis: %d %v", code, out)
	}
	if c := published["synology"]; c == nil || !c.Enabled || c.Source != nasDecoder {
		t.Fatalf("publikacja: %+v", c)
	}

	// Wyłączenie wbudowanego: powód i hasło; włączenie z powrotem usuwa wpis.
	if code, out, _ := admin.do("POST", "/api/v1/decoders/mikrotik/enabled", map[string]any{"enabled": false, "reason": "test"}); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("wyłączenie bez hasła: %d %v", code, out)
	}
	if code, _, _ := admin.do("POST", "/api/v1/decoders/mikrotik/enabled", map[string]any{"enabled": false, "reason": "test", "password": "haslo-adama-123"}); code != 200 {
		t.Fatalf("wyłączenie: %d", code)
	}
	if c := published["mikrotik"]; c == nil || c.Enabled {
		t.Fatalf("publikacja wyłączenia: %+v", c)
	}
	code, out, _ = analyst.do("POST", "/api/v1/decoders/test", map[string]any{"samples": []string{
		"<131>Oct  9 20:54:15 MikroTik login failure for user admin from 192.168.88.10 via winbox"}})
	if r := out["results"].([]any)[0].(map[string]any); r["dataset"] != "syslog.generic" {
		t.Fatalf("wyłączony dekoder nadal działa: %v", r)
	}
	if code, _, _ := admin.do("POST", "/api/v1/decoders/mikrotik/enabled", map[string]any{"enabled": true}); code != 200 {
		t.Fatalf("włączenie: %d", code)
	}
	if _, ok := md.rows["mikrotik"]; ok || published["mikrotik"] != nil {
		t.Fatalf("włączony wbudowany nie powinien mieć wpisu: %v %v", md.rows, published["mikrotik"])
	}

	// Usunięcie własnego: powód i hasło.
	if code, _, _ := admin.do("POST", "/api/v1/decoders/synology/revert", map[string]any{"reason": "niepotrzebny"}); code != 403 {
		t.Fatalf("usunięcie bez hasła: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/decoders/synology/revert", map[string]any{"reason": "niepotrzebny", "password": "haslo-adama-123"}); code != 200 {
		t.Fatalf("usunięcie: %d", code)
	}
	if _, ok := published["synology"]; !ok || published["synology"] != nil {
		t.Fatal("usunięcie nie trafiło do normalizatorów")
	}
	acts := e.st.actions()
	for _, a := range []string{"decoder_saved", "decoder_enabled_changed", "decoder_deleted"} {
		if !slices.Contains(acts, a) {
			t.Fatalf("brak wpisu audytu %s: %v", a, acts)
		}
	}
}
