// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"siem/internal/alerts"
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
		{KindTeams, "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=x", true},
		{KindTeams, "https://default1234.56.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?sig=x", true},
		{KindTeams, "https://logic.azure.com.evil.example/workflows/abc", false},
		{KindTeams, "https://n8n.lan/hook", false},
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

// Wartości ze zdarzeń (polecenie procesu, konto) mogą pochodzić od
// atakującego: w Discordzie nie mogą stać się linkiem ani formatowaniem.
// Wiadomość musi się zmieścić w limicie embedu (6000 znaków).
func TestDiscordAlertPayloadIsSafe(t *testing.T) {
	a := &AlertSender{PanelURL: "https://siem:8444"}
	al := alerts.Alert{ID: 7, RuleTitle: "PowerShell", Level: "high", HostName: "pc1",
		Summary:      "polecenie: powershell [Otwórz alert w panelu](https://zly.example/x) **pilne**",
		UserName:     "jan_kowalski",
		GroupFields:  map[string]string{"CommandLine": strings.Repeat("A", 3000)},
		Instructions: strings.Repeat("Sprawdź ", 400)}
	p := discordPayload(a.Message(al))
	embed := p["embeds"].([]any)[0].(map[string]any)
	desc := embed["description"].(string)
	if strings.Contains(desc, "](https") || strings.Contains(desc, "**") || !strings.Contains(desc, `\[Otwórz`) {
		t.Fatalf("Markdown nie został zneutralizowany: %q", desc)
	}
	total := len([]rune(embed["title"].(string))) + len([]rune(desc))
	var panel, user string
	for _, f := range embed["fields"].([]map[string]any) {
		total += len([]rune(f["name"].(string))) + len([]rune(f["value"].(string)))
		switch f["name"] {
		case "Panel":
			panel = f["value"].(string)
		case "Konto":
			user = f["value"].(string)
		}
	}
	if total > 6000 {
		t.Fatalf("embed ma %d znaków (limit Discorda 6000)", total)
	}
	if panel != "https://siem:8444/alerts/7" || user != `jan\_kowalski` {
		t.Fatalf("link do panelu %q (ma zostać bez zmian), konto %q", panel, user)
	}
}

func TestAlertFilter(t *testing.T) {
	alert := func(level, rule string) Message { return Message{Event: EventAlert, Level: level, RuleID: rule} }
	cases := []struct {
		f    store.AlertFilter
		m    Message
		want bool
	}{
		{store.AlertFilter{}, alert("low", "r1"), true},
		{store.AlertFilter{MinLevel: "high"}, alert("medium", "r1"), false},
		{store.AlertFilter{MinLevel: "high"}, alert("critical", "r1"), true},
		{store.AlertFilter{RulesMode: "only", Rules: []string{"r2"}}, alert("high", "r1"), false},
		{store.AlertFilter{RulesMode: "only", Rules: []string{"r2"}}, alert("high", "r2"), true},
		{store.AlertFilter{RulesMode: "except", Rules: []string{"r2"}}, alert("high", "r2"), false},
		// Filtr dotyczy tylko alertów detekcji.
		{store.AlertFilter{MinLevel: "critical"}, Message{Event: EventHealth}, true},
	}
	for i, c := range cases {
		if got := Accepts(c.f, c.m); got != c.want {
			t.Errorf("przypadek %d: %v, oczekiwano %v", i, got, c.want)
		}
	}
	closed := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	m := (&AlertSender{Svc: &Service{}, PanelURL: "https://siem"}).Resolved(alerts.Alert{ID: 3, RuleID: "hb", Level: "high",
		RuleTitle: "Utrata łączności z agentem", HostName: "dc01", FirstSeen: closed.Add(-75 * time.Minute), ClosedAt: &closed,
		CloseReason: "Agent znów wysyła heartbeat"})
	if m.Severity != SevOK || m.RuleID != "hb" || !strings.HasPrefix(m.Title, "[ROZWIĄZANY]") || m.Fields[0].Value != "1 h 15 min" {
		t.Fatalf("wiadomość o rozwiązaniu: %+v", m)
	}
}

func TestAttackLine(t *testing.T) {
	got := attackLine([]string{"attack.credential_access", "attack.t1110.001", "attack.t1098"})
	if got != "T1110.001 Password Guessing (Credential Access)\nT1098 Account Manipulation (Persistence, Privilege Escalation)" {
		t.Fatalf("%q", got)
	}
	if attackLine(nil) != "" {
		t.Fatal("bez tagów – pusto")
	}
}

// Reguła z SigmaHQ: autor i źródło w wiadomości (DRL 1.1); reguła Vardra – bez.
func TestAlertMessageAttribution(t *testing.T) {
	rules := map[string]alerts.RuleInfo{
		"sig": {ID: "sig", File: "sigmahq/windows/process_creation/x.yml", Source: "author: Jan Kowalski\n",
			Tags: []string{"attack.t1059.001"}},
		"own": {ID: "own", File: "windows/x.yml", Source: "author: Vardr\n"},
	}
	s := &AlertSender{Rule: func(id string) (alerts.RuleInfo, bool) { r, ok := rules[id]; return r, ok }}
	field := func(m Message, name string) string {
		for _, f := range m.Fields {
			if f.Name == name {
				return f.Value
			}
		}
		return ""
	}
	m := s.Message(alerts.Alert{RuleID: "sig", Level: "high", RuleTitle: "X"})
	if v := field(m, "Autor reguły"); !strings.Contains(v, "Jan Kowalski") || !strings.Contains(v, "DRL") || field(m, "MITRE ATT&CK") == "" {
		t.Fatalf("SigmaHQ: %+v", m.Fields)
	}
	if v := field(s.Message(alerts.Alert{RuleID: "own", Level: "high"}), "Autor reguły"); v != "" {
		t.Fatalf("reguła Vardra z autorem: %q", v)
	}
}

func TestAlertMessageEnglish(t *testing.T) {
	s := &AlertSender{Svc: &Service{Lang: func(context.Context) string { return "en" }}}
	m := s.Message(alerts.Alert{RuleID: "r", Level: "high", RuleTitle: "Wyczyszczenie dziennika", Summary: "komputer dc01",
		Instructions: "Sprawdź.", HostName: "dc01",
		I18n: map[string]alerts.AlertText{"en": {Title: "Log cleared", Summary: "computer dc01"}}})
	if m.Title != "[HIGH] Log cleared" || m.Text != "computer dc01" {
		t.Fatalf("wiadomość: %q / %q", m.Title, m.Text)
	}
	var names []string
	for _, f := range m.Fields {
		names = append(names, f.Name+"="+f.Value)
	}
	got := strings.Join(names, "; ")
	// Instrukcja bez tłumaczenia – oryginalna.
	if !strings.Contains(got, "Computer=dc01") || !strings.Contains(got, "What to do=Sprawdź.") {
		t.Fatalf("pola: %s", got)
	}
}

// Karta Teams: tytuł z kolorem ważności, pola jako FactSet, link do panelu
// jako przycisk; dane ze zdarzeń bez działających linków Markdownu; dane
// strukturalne w polu „vardr” dla własnych przepływów.
func TestTeamsAlertCard(t *testing.T) {
	a := &AlertSender{PanelURL: "https://siem:8444"}
	al := alerts.Alert{ID: 7, RuleTitle: "PowerShell", Level: "critical", HostName: "pc1",
		Summary:  "polecenie: powershell [Otwórz alert w panelu](https://zly.example/x)",
		UserName: "jan_kowalski", GroupFields: map[string]string{"CommandLine": "[klik](https://zly.example/y) " + strings.Repeat("A", 3000)}}
	m := a.Message(al)
	p := teamsPayload(m)
	att := p["attachments"].([]any)[0].(map[string]any)
	card := att["content"].(map[string]any)
	// Karta (renderowana przez Teams) bez linków; dane w „vardr” – surowe,
	// to dane dla przepływu, nie tekst do wyświetlenia.
	if raw, _ := json.Marshal(card); strings.Contains(string(raw), "](https://zly") {
		t.Fatalf("link Markdownu z danych zdarzenia w karcie: %s", raw)
	}
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" || card["type"] != "AdaptiveCard" || p["type"] != "message" {
		t.Fatalf("kształt wiadomości: %v", p)
	}
	body := card["body"].([]any)
	title := body[0].(map[string]any)
	if title["color"] != "Attention" || !strings.Contains(title["text"].(string), "PowerShell") {
		t.Fatalf("tytuł: %v", title)
	}
	actions := card["actions"].([]any)
	if act := actions[0].(map[string]any); act["url"] != "https://siem:8444/alerts/7" || act["type"] != "Action.OpenUrl" {
		t.Fatalf("przycisk panelu: %v", actions)
	}
	for _, b := range body {
		if fs, ok := b.(map[string]any)["facts"].([]any); ok {
			for _, f := range fs {
				if v := f.(map[string]any)["value"].(string); len([]rune(v)) > teamsMaxValue || strings.HasPrefix(v, "https://siem") {
					t.Fatalf("pole: %q", v)
				}
			}
		}
	}
	if v := p["vardr"].(map[string]any); v["event"] != EventAlert || v["severity"] != m.Severity {
		t.Fatalf("dane dla przepływów: %v", v)
	}
}

// Podpis HMAC: kanał z sekretem wysyła znacznik czasu i podpis treści,
// który odbiorca odtwarza; bez sekretu – bez nagłówków.
func TestSignedDelivery(t *testing.T) {
	var mu sync.Mutex
	var heads []http.Header
	var bodies [][]byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		heads, bodies = append(heads, r.Header.Clone()), append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	st := &memStore{chans: []store.Channel{
		{ID: 1, Name: "teams", Kind: KindTeams, URL: srv.URL + "/t", Events: []string{EventHealth}, Enabled: true, SigningSecret: "tajny-sekret"},
		{ID: 2, Name: "hook", Kind: KindWebhook, URL: srv.URL + "/h", Events: []string{EventHealth}, Enabled: true},
	}}
	s := &Service{Store: st, Log: slog.New(slog.DiscardHandler), Client: srv.Client(), Now: func() time.Time { return now }}
	if n, err := s.Send(context.Background(), Message{Event: EventHealth, Severity: SevWarning, Title: "Dysk"}); err != nil || n != 2 {
		t.Fatalf("wysyłka: %d %v", n, err)
	}
	var signed, plain int
	for i, h := range heads {
		if sig := h.Get(HeaderSignature); sig != "" {
			signed++
			ts := h.Get(HeaderTimestamp)
			if ts != "1793016000" || sig != Sign("tajny-sekret", ts, bodies[i]) || Sign("inny", ts, bodies[i]) == sig {
				t.Fatalf("podpis: %s %s", ts, sig)
			}
		} else {
			plain++
		}
	}
	if signed != 1 || plain != 1 {
		t.Fatalf("podpisane %d, bez podpisu %d", signed, plain)
	}
}
