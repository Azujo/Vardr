package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"siem/internal/urd"
	"siem/panel/internal/api/store"
)

type memStore struct {
	mu    sync.Mutex
	chans []store.Channel
	log   []store.NotifyLogEntry
}

func (m *memStore) ListChannels(context.Context) ([]store.Channel, error) { return m.chans, nil }
func (m *memStore) RecordDelivery(_ context.Context, e store.NotifyLogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, e)
	return nil
}

// receiver udaje Discorda / webhook i zapamiętuje treści.
func receiver(t *testing.T, status int) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var got []map[string]any
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestSendRoutesByEventAndRecords(t *testing.T) {
	disc, discGot := receiver(t, http.StatusNoContent)
	hook, hookGot := receiver(t, http.StatusOK)
	st := &memStore{chans: []store.Channel{
		{ID: 1, Name: "discord", Kind: KindDiscord, URL: disc.URL + "/api/webhooks/1/sekret", Events: []string{EventHealth, EventAnchor}, Enabled: true},
		{ID: 2, Name: "webhook", Kind: KindWebhook, URL: hook.URL + "/hook", Events: []string{EventAnchor}, Enabled: true},
		{ID: 3, Name: "wyłączony", Kind: KindWebhook, URL: hook.URL + "/off", Events: []string{EventHealth}, Enabled: false},
	}}
	s := &Service{Store: st, Log: slog.New(slog.DiscardHandler), Client: disc.Client()}
	n, err := s.Send(context.Background(), Message{Event: EventHealth, Severity: SevCritical, Title: "Archiwizator nie działa",
		Fields: []Field{{Name: "Waga", Value: "critical"}}})
	if err != nil || n != 1 || len(*discGot) != 1 || len(*hookGot) != 0 {
		t.Fatalf("alert zdrowia: n=%d err=%v discord=%d webhook=%d", n, err, len(*discGot), len(*hookGot))
	}
	embed := (*discGot)[0]["embeds"].([]any)[0].(map[string]any)
	if embed["title"] != "Archiwizator nie działa" || embed["color"] != float64(0xE03131) {
		t.Fatalf("treść dla Discorda: %v", (*discGot)[0])
	}
	if len(st.log) != 1 || !st.log[0].OK || st.log[0].Channel != "discord" {
		t.Fatalf("dziennik: %+v", st.log)
	}
	seq := int64(5)
	s.Client = hook.Client()
	if n, err := s.Send(context.Background(), Message{Event: EventAnchor, Title: "Kotwica", AnchorSeq: &seq, AnchorSHA256: "ab"}); err != nil || n != 2 ||
		len(*hookGot) != 1 || (*hookGot)[0]["event"] != EventAnchor || st.log[2].AnchorSHA256 != "ab" {
		t.Fatalf("kotwica: %d %v", n, err)
	}
}

func TestSendErrorHidesURL(t *testing.T) {
	st := &memStore{chans: []store.Channel{{ID: 1, Name: "zły", Kind: KindWebhook, URL: "https://127.0.0.1:1/tajny-token-123",
		Events: []string{EventHealth}, Enabled: true}}}
	s := &Service{Store: st, Log: slog.New(slog.DiscardHandler), Client: &http.Client{Timeout: time.Second}}
	_, err := s.Send(context.Background(), Message{Event: EventHealth, Title: "x"})
	if err == nil || strings.Contains(err.Error(), "tajny-token") || strings.Contains(st.log[0].Error, "tajny-token") {
		t.Fatalf("błąd nie może zawierać adresu: %v / %q", err, st.log[0].Error)
	}
}

func TestValidateURLAndHint(t *testing.T) {
	for _, c := range []struct {
		kind, url string
		ok        bool
	}{
		{KindDiscord, "https://discord.com/api/webhooks/1/abc", true},
		{KindDiscord, "https://evil.example/api/webhooks/1/abc", false},
		{KindDiscord, "http://discord.com/api/webhooks/1/abc", false},
		{KindWebhook, "https://n8n.lan/hook", true},
		{KindWebhook, "https://user:pass@n8n.lan/hook", false},
		{KindWebhook, "ftp://x", false},
	} {
		if err := ValidateURL(c.kind, c.url); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.kind, c.url, err)
		}
	}
	if h := Hint("https://discord.com/api/webhooks/123/SEKRET-abcd"); h != "discord.com…abcd" || strings.Contains(h, "SEKRET") {
		t.Fatalf("podpowiedź adresu: %s", h)
	}
}

func TestGrafanaRelay(t *testing.T) {
	disc, got := receiver(t, http.StatusNoContent)
	st := &memStore{chans: []store.Channel{{ID: 1, Name: "d", Kind: KindDiscord, URL: disc.URL + "/x", Events: []string{EventHealth}, Enabled: true}}}
	s := &Service{Store: st, Log: slog.New(slog.DiscardHandler), Client: disc.Client()}
	h := s.GrafanaHandler("tok")
	body := `{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"a","severity":"critical"},
		"annotations":{"summary":"Archiwizator nie działa","description":"brak sygnału"},"startsAt":"2026-10-08T07:00:00Z"},
		{"status":"resolved","labels":{"alertname":"b"},"annotations":{"summary":"Mało miejsca"}}]}`
	for _, c := range []struct {
		auth string
		want int
	}{{"", 401}, {"Bearer zly", 401}, {"Bearer tok", 204}} {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Fatalf("%q: %d, oczekiwano %d", c.auth, rec.Code, c.want)
		}
	}
	if len(*got) != 2 {
		t.Fatalf("wiadomości: %d", len(*got))
	}
	second := (*got)[1]["embeds"].([]any)[0].(map[string]any)
	if second["title"] != "Rozwiązane: Mało miejsca" || second["color"] != float64(0x2F9E44) {
		t.Fatalf("rozwiązany alert: %v", second)
	}
}

type fakeArchive struct{}

func (fakeArchive) Overview(context.Context) (urd.Overview, error) {
	return urd.Overview{Summary: urd.Summary{ManifestsTotal: 40, Manifests: 30},
		LastVerification: &urd.Verification{OK: true, FinishedAt: time.Date(2026, 10, 8, 5, 0, 0, 0, time.UTC)}}, nil
}
func (fakeArchive) RecentManifests(context.Context, int) ([]urd.ManifestRecord, error) {
	return []urd.ManifestRecord{{Seq: 40, SHA256: strings.Repeat("a", 64), Hour: time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)}}, nil
}

type anchorStore struct{ last *time.Time }

func (a anchorStore) LastAnchorAt(context.Context) (*time.Time, error) { return a.last, nil }

func TestAnchorScheduleAndMessage(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	a := &Anchor{Hour: 7, Loc: loc, Archive: fakeArchive{}}
	at := func(h, m int) time.Time { return time.Date(2026, 10, 8, h, m, 0, 0, loc) }
	yesterday := at(7, 2).Add(-24 * time.Hour)
	today := at(7, 2)
	for _, c := range []struct {
		now  time.Time
		last *time.Time
		want bool
	}{
		{at(6, 59), &yesterday, false},
		{at(7, 0), &yesterday, true},
		{at(7, 0), nil, true},
		{at(12, 0), &today, false},
	} {
		if got := a.due(c.now, c.last); got != c.want {
			t.Errorf("%v (ostatnia %v): %v", c.now, c.last, got)
		}
	}
	m, err := a.Message(context.Background(), at(7, 0))
	if err != nil || *m.AnchorSeq != 40 || m.AnchorSHA256 != strings.Repeat("a", 64) || m.Event != EventAnchor ||
		!strings.Contains(m.Fields[3].Value, strings.Repeat("a", 64)) || !strings.Contains(m.Fields[2].Value, "zgodne") {
		t.Fatalf("kotwica: %+v %v", m, err)
	}
}
