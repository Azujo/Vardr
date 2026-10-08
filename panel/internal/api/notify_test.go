package api

import (
	"context"
	"encoding/json"
	"log/slog"
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
	m.chans = append(m.chans, c)
	return c, nil
}
func (m *memNotify) UpdateChannel(_ context.Context, c store.Channel) (store.Channel, error) {
	for i, x := range m.chans {
		if x.ID == c.ID {
			if c.URL == "" {
				c.URL = x.URL
			}
			c.Kind = x.Kind
			m.chans[i] = c
			return c, nil
		}
	}
	return c, store.ErrNotFound
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
