// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/panel/internal/api/store"
	"siem/panel/internal/notify"
)

type memNotify struct {
	chans []store.Channel
	log   []store.NotifyLogEntry
}

func (m *memNotify) ListChannels(context.Context) ([]store.Channel, error) { return m.chans, nil }
func (m *memNotify) ChannelByID(_ context.Context, id int64) (store.Channel, error) {
	for _, c := range m.chans {
		if c.ID == id {
			return c, nil
		}
	}
	return store.Channel{}, store.ErrNotFound
}
func (m *memNotify) CreateChannel(_ context.Context, c store.Channel) (store.Channel, error) {
	c.ID = int64(len(m.chans) + 1)
	c.Signed = c.SigningSecret != ""
	m.chans = append(m.chans, c)
	return c, nil
}
func (m *memNotify) UpdateChannel(_ context.Context, c store.Channel) (store.Channel, error) {
	for i, x := range m.chans {
		if x.ID == c.ID {
			if c.URL == "" {
				c.URL = x.URL
			}
			c.Kind, c.SigningSecret, c.Signed = x.Kind, x.SigningSecret, x.Signed
			m.chans[i] = c
			return c, nil
		}
	}
	return c, store.ErrNotFound
}
func (m *memNotify) SetChannelSecret(_ context.Context, id int64, secret string) (store.Channel, error) {
	for i, x := range m.chans {
		if x.ID == id {
			m.chans[i].SigningSecret, m.chans[i].Signed = secret, secret != ""
			return m.chans[i], nil
		}
	}
	return store.Channel{}, store.ErrNotFound
}
func (m *memNotify) DeleteChannel(_ context.Context, id int64) error {
	m.chans = slices.DeleteFunc(m.chans, func(c store.Channel) bool { return c.ID == id })
	return nil
}
func (m *memNotify) NotifyLog(context.Context, int) ([]store.NotifyLogEntry, error) {
	return m.log, nil
}
func (m *memNotify) RecordDelivery(_ context.Context, e store.NotifyLogEntry) error {
	m.log = append(m.log, e)
	return nil
}

func TestNotifyChannelsAPI(t *testing.T) {
	e := newEnv(t)
	mn := &memNotify{}
	svc := &notify.Service{Store: mn, Log: slog.New(slog.DiscardHandler), Client: nil}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Notify: &Notifications{Store: mn, Svc: svc}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	secret := "https://discord.com/api/webhooks/1557/SEKRET-TOKEN-wxyz"
	body := map[string]any{"name": "Discord SOC", "kind": "discord", "url": secret, "events": []string{"health", "anchor"}}
	if code, _, _ := analyst.do("POST", "/api/v1/notify/channels", body); code != 403 {
		t.Fatalf("kanały tylko dla administratora: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/notify/channels", map[string]any{"name": "x", "kind": "discord",
		"url": "https://evil.example/api/webhooks/1/a", "events": []string{"health"}}); code != 400 {
		t.Fatalf("adres spoza Discorda: %d", code)
	}
	code, out, _ := admin.do("POST", "/api/v1/notify/channels", body)
	if code != 201 {
		t.Fatalf("dodanie kanału: %d %v", code, out)
	}
	code, out, _ = admin.do("GET", "/api/v1/notify/channels", nil)
	b, _ := json.Marshal(out)
	raw := string(b)
	if code != 200 || strings.Contains(raw, "SEKRET") || !strings.Contains(raw, "discord.com…wxyz") {
		t.Fatalf("lista kanałów nie może zawierać adresu: %s", raw)
	}

	// Zmiana nazwy – bez hasła; wyłączenie, rezygnacja z kotwicy, zmiana adresu i usunięcie – z hasłem.
	if code, _, _ := admin.do("PATCH", "/api/v1/notify/channels/1", map[string]any{"name": "Discord", "events": []string{"health", "anchor"}}); code != 200 {
		t.Fatalf("zmiana nazwy: %d", code)
	}
	for _, b := range []map[string]any{
		{"name": "Discord", "events": []string{"health", "anchor"}, "enabled": false},
		{"name": "Discord", "events": []string{"health"}},
		{"name": "Discord", "events": []string{"health", "anchor"}, "url": "https://discord.com/api/webhooks/9/inny"},
	} {
		if code, out, _ := admin.do("PATCH", "/api/v1/notify/channels/1", b); code != 403 || out["error"] != "reauth_required" {
			t.Fatalf("osłabienie bez hasła: %v → %d %v", b, code, out)
		}
	}
	if code, _, _ := admin.do("POST", "/api/v1/notify/channels/1/delete", map[string]any{"password": "zle"}); code != 403 {
		t.Fatalf("usunięcie ze złym hasłem: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/notify/channels/1/delete", map[string]any{"password": "haslo-adama-123"}); code != 204 || len(mn.chans) != 0 {
		t.Fatalf("usunięcie: %d %v", code, mn.chans)
	}
	acts := e.st.actions()
	for _, a := range []string{"notify_channel_created", "notify_channel_changed", "notify_channel_deleted", "reauth_failed"} {
		if !slices.Contains(acts, a) {
			t.Fatalf("brak wpisu audytu %s: %v", a, acts)
		}
	}
}

// Kanał Power Automate / Teams z podpisem: sekret tylko w odpowiedzi na
// utworzenie (i na nowy sekret), lista go nie zawiera; wyłączenie podpisu
// i nowy sekret – z hasłem; Discord bez podpisu.
func TestNotifyTeamsSigned(t *testing.T) {
	e := newEnv(t)
	mn := &memNotify{}
	svc := &notify.Service{Store: mn, Log: slog.New(slog.DiscardHandler)}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Notify: &Notifications{Store: mn, Svc: svc}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	admin := e.client("10.0.0.2")
	admin.login("adam", "haslo-adama-123")

	flow := "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SEKRET"
	if code, out, _ := admin.do("POST", "/api/v1/notify/channels", map[string]any{"name": "d", "kind": "discord",
		"url": "https://discord.com/api/webhooks/1/a", "events": []string{"health"}, "sign": true}); code != 400 || out["error"] != "not_signable" {
		t.Fatalf("podpis na Discordzie: %d %v", code, out)
	}
	if code, _, _ := admin.do("POST", "/api/v1/notify/channels", map[string]any{"name": "t", "kind": "teams",
		"url": "https://n8n.lan/hook", "events": []string{"alert"}}); code != 400 {
		t.Fatalf("adres spoza Power Automate: %d", code)
	}
	code, out, _ := admin.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Teams SOC", "kind": "teams",
		"url": flow, "events": []string{"alert", "incident"}, "sign": true})
	first, _ := out["signing_secret"].(string)
	if code != 201 || !strings.HasPrefix(first, "vardrsig_") || mn.chans[0].SigningSecret != first {
		t.Fatalf("kanał Teams z podpisem: %d %v", code, out)
	}
	code, out, _ = admin.do("GET", "/api/v1/notify/channels", nil)
	b, _ := json.Marshal(out)
	if code != 200 || strings.Contains(string(b), first) || strings.Contains(string(b), "SEKRET") || !strings.Contains(string(b), `"signed":true`) {
		t.Fatalf("lista kanałów: %s", b)
	}
	keep := map[string]any{"name": "Teams SOC", "events": []string{"alert", "incident"}}
	for _, extra := range []map[string]any{{"sign": false}, {"new_secret": true}} {
		req := maps.Clone(keep)
		maps.Copy(req, extra)
		if code, out, _ := admin.do("PATCH", "/api/v1/notify/channels/1", req); code != 403 || out["error"] != "reauth_required" {
			t.Fatalf("%v bez hasła: %d %v", extra, code, out)
		}
	}
	req := maps.Clone(keep)
	req["new_secret"], req["password"] = true, "haslo-adama-123"
	code, out, _ = admin.do("PATCH", "/api/v1/notify/channels/1", req)
	if second, _ := out["signing_secret"].(string); code != 200 || second == "" || second == first || mn.chans[0].SigningSecret != second {
		t.Fatalf("nowy sekret: %d %v", code, out)
	}
	req = maps.Clone(keep)
	req["sign"], req["password"] = false, "haslo-adama-123"
	if code, out, _ := admin.do("PATCH", "/api/v1/notify/channels/1", req); code != 200 || mn.chans[0].Signed || out["signing_secret"] != nil {
		t.Fatalf("wyłączenie podpisu: %d %v", code, out)
	}
}
