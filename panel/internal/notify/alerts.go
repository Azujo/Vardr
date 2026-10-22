// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/attack"
)

// EventAlert: alerty detekcji (Gjallarhorn).
const EventAlert = "alert"

// OutboxStore to outbox alertów (implementuje alerts.PG).
type OutboxStore interface {
	ClaimOutbox(ctx context.Context, now time.Time, limit int) ([]alerts.Pending, error)
	MarkSent(ctx context.Context, id int64, now time.Time) error
	MarkFailed(ctx context.Context, id int64, errMsg string, next time.Time) error
	SentPerRule(ctx context.Context, since time.Time) (map[string]int, error)
	Hold(ctx context.Context, outboxID int64, now time.Time) error
	DueDigests(ctx context.Context, olderThan time.Time) ([]alerts.Digest, error)
	MarkDigested(ctx context.Context, rule string, upto, now time.Time) error
}

// AlertSender wysyła nowe alerty z outboxa na kanały subskrybujące alerty.
// Outbox jest zapisywany przez detektor w tej samej transakcji co alert,
// więc żaden alert nie zostaje bez powiadomienia (najwyżej przyjdzie dwa razy).
type AlertSender struct {
	Store    OutboxStore
	Svc      *Service
	Log      *slog.Logger
	PanelURL string // np. https://192.168.88.98:8444 – link w wiadomości
	Every    time.Duration
	// Burza alertów: najwyżej PerRule osobnych powiadomień o nowych alertach
	// jednej reguły w oknie Window (domyślnie 5 w 10 min); nadwyżka trafia do
	// jednej wiadomości zbiorczej po Window. Alerty krytyczne i wiadomości
	// o rozwiązaniu zawsze osobno. PerRule < 0 wyłącza limit.
	PerRule int
	Window  time.Duration
	// Rule (opcjonalne): reguła alertu – techniki MITRE ATT&CK i, dla reguł
	// z SigmaHQ, autor i źródło (licencja DRL 1.1) w wiadomości.
	Rule func(ruleID string) (alerts.RuleInfo, bool)

	digestRetry time.Time // po nieudanej wiadomości zbiorczej – nie częściej niż co minutę
}

func (a *AlertSender) limits() (int, time.Duration) {
	n, w := a.PerRule, a.Window
	if n == 0 {
		n = 5
	}
	if w <= 0 {
		w = 10 * time.Minute
	}
	return n, w
}

// Run przegląda outbox co Every (domyślnie 5 s).
func (a *AlertSender) Run(ctx context.Context) {
	if a.Every <= 0 {
		a.Every = 5 * time.Second
	}
	t := time.NewTicker(a.Every)
	defer t.Stop()
	failing := false
	for {
		if err := a.tick(ctx); err != nil && ctx.Err() == nil {
			if !failing {
				a.Log.Warn("obsługa outboxa alertów nieudana", "err", err)
			}
			failing = true
		} else {
			failing = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *AlertSender) tick(ctx context.Context) error {
	now := a.Svc.now()
	pending, err := a.Store.ClaimOutbox(ctx, now, 20)
	if err != nil {
		return err
	}
	perRule, window := a.limits()
	var sent map[string]int
	if len(pending) > 0 && perRule > 0 {
		if sent, err = a.Store.SentPerRule(ctx, now.Add(-window)); err != nil {
			return err
		}
	}
	for _, p := range pending {
		limited := perRule > 0 && p.Kind != "resolved" && p.Alert.Level != "critical"
		if limited && sent[p.Alert.RuleID] >= perRule {
			// Ponad limit – do wiadomości zbiorczej.
			if err := a.Store.Hold(ctx, p.OutboxID, now); err != nil {
				return err
			}
			continue
		}
		m := a.Message(p.Alert)
		if p.Kind == "resolved" {
			m = a.Resolved(p.Alert)
		}
		_, err := a.Svc.Send(ctx, m)
		if err == nil {
			// Brak kanałów subskrybujących alerty też kończy wpis (nie ma dokąd wysłać).
			if err := a.Store.MarkSent(ctx, p.OutboxID, now); err != nil {
				return err
			}
			if limited {
				sent[p.Alert.RuleID]++
			}
			continue
		}
		next := now.Add(backoff(p.Attempts))
		if p.Attempts+1 >= maxAttempts {
			// Odbiorca trwale odrzuca (np. usunięty webhook) – bez końca nie ponawiamy;
			// alert jest w panelu, a błąd zostaje w outboxie.
			next = now.AddDate(100, 0, 0)
			a.Log.Error("powiadomienie o alercie porzucone po wielu próbach", "alert", p.Alert.ID, "attempts", p.Attempts+1, "err", err)
		} else {
			a.Log.Warn("powiadomienie o alercie nieudane – ponowię", "alert", p.Alert.ID, "attempt", p.Attempts+1, "next", next, "err", err)
		}
		if err := a.Store.MarkFailed(ctx, p.OutboxID, err.Error(), next); err != nil {
			return err
		}
	}
	return a.digests(ctx, now)
}

// digests wysyła wiadomości zbiorcze dla reguł, których wstrzymane alerty
// czekają co najmniej okno limitu.
func (a *AlertSender) digests(ctx context.Context, now time.Time) error {
	if now.Before(a.digestRetry) {
		return nil
	}
	_, window := a.limits()
	due, err := a.Store.DueDigests(ctx, now.Add(-window))
	if err != nil {
		return err
	}
	for _, d := range due {
		if _, err := a.Svc.Send(ctx, a.DigestMessage(d)); err != nil {
			a.digestRetry = now.Add(time.Minute)
			a.Log.Warn("wiadomość zbiorcza o alertach nieudana – ponowię", "rule", d.RuleID, "alerts", d.Count, "err", err)
			return nil
		}
		if err := a.Store.MarkDigested(ctx, d.RuleID, d.Upto, now); err != nil {
			return err
		}
	}
	return nil
}

// DigestMessage buduje wiadomość zbiorczą dla reguły.
func (a *AlertSender) DigestMessage(d alerts.Digest) Message {
	top := ""
	for _, l := range Levels {
		if slices.Contains(d.Levels, l) {
			top = l
		}
	}
	perRule, window := a.limits()
	m := Message{
		Event: EventAlert, Level: top, RuleID: d.RuleID, Severity: levelSeverity[top], At: a.Svc.now(), Untrusted: true,
		Title: fmt.Sprintf("[ZBIORCZO] %s – %d %s", d.RuleTitle, d.Count, plural(d.Count, "alert", "alerty", "alertów")),
		Text: fmt.Sprintf("Reguła przekroczyła limit %d osobnych powiadomień w %s – kolejne alerty zebrane w tej wiadomości "+
			"(pierwszy wstrzymany %s). Wszystkie są w panelu.", perRule, humanDuration(window), d.First.Local().Format("15:04")),
	}
	if m.Severity == "" {
		m.Severity = SevWarning
	}
	if len(d.Hosts) > 0 {
		hosts := strings.Join(d.Hosts, ", ")
		if d.HostCount > len(d.Hosts) {
			hosts += fmt.Sprintf(" … (łącznie %d)", d.HostCount)
		}
		m.Fields = append(m.Fields, Field{Name: "Komputery", Value: hosts})
	}
	if a.PanelURL != "" {
		m.Fields = append(m.Fields, Field{Name: "Panel", Trusted: true,
			Value: a.PanelURL + "/alerts?status=all&rule=" + url.QueryEscape(d.RuleID)})
	}
	return m
}

func plural(n int, one, few, many string) string {
	switch {
	case n == 1:
		return one
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20):
		return few
	}
	return many
}

// maxAttempts: po tylu nieudanych próbach (ok. doby) powiadomienie jest porzucane.
const maxAttempts = 30

// backoff: 30 s, 1, 2, 4… min, najwyżej godzina.
func backoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 0; i < attempts && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

var levelSeverity = map[string]string{"critical": SevCritical, "high": SevCritical, "medium": SevWarning, "low": SevInfo, "informational": SevInfo}

var levelLabel = map[string]string{"critical": "KRYTYCZNY", "high": "WYSOKI", "medium": "ŚREDNI", "low": "NISKI", "informational": "INFO"}

// Resolved buduje wiadomość o rozwiązaniu alertu (np. agent znów
// w kontakcie). Filtr kanału jak dla samego alertu (poziom, reguła).
func (a *AlertSender) Resolved(al alerts.Alert) Message {
	m := Message{
		Event: EventAlert, Severity: SevOK, Level: al.Level, RuleID: al.RuleID,
		Title: "[ROZWIĄZANY] " + al.RuleTitle, Text: al.CloseReason, At: a.Svc.now(), Untrusted: true,
	}
	if al.ClosedAt != nil {
		m.At = *al.ClosedAt
		m.Fields = append(m.Fields, Field{Name: "Przerwa", Trusted: true, Inline: true,
			Value: humanDuration(al.ClosedAt.Sub(al.FirstSeen))})
	}
	if al.HostName != "" {
		m.Fields = append(m.Fields, Field{Name: "Komputer", Value: al.HostName, Inline: true})
	}
	if a.PanelURL != "" {
		m.Fields = append(m.Fields, Field{Name: "Panel", Trusted: true, Value: a.PanelURL + "/alerts/" + strconv.FormatInt(al.ID, 10)})
	}
	return m
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}

// Message buduje wiadomość o alercie.
func (a *AlertSender) Message(al alerts.Alert) Message {
	m := Message{
		Event:    EventAlert,
		Severity: levelSeverity[al.Level],
		Title:    fmt.Sprintf("[%s] %s", levelLabel[al.Level], al.RuleTitle),
		Text:     al.Summary,
		At:       al.CreatedAt,
		Level:    al.Level,
		RuleID:   al.RuleID,
		// Opis, konto, klucz i instrukcja zawierają wartości ze zdarzeń.
		Untrusted: true,
	}
	if m.Severity == "" {
		m.Severity = SevWarning
	}
	add := func(name, val string, inline bool) {
		if val != "" {
			m.Fields = append(m.Fields, Field{Name: name, Value: val, Inline: inline})
		}
	}
	trusted := func(name, val string, inline bool) {
		m.Fields = append(m.Fields, Field{Name: name, Value: val, Inline: inline, Trusted: true})
	}
	add("Komputer", al.HostName, true)
	add("Konto", al.UserName, true)
	add("Adres źródłowy", al.SourceIP, true)
	if len(al.GroupFields) > 0 {
		keys := make([]string, 0, len(al.GroupFields))
		for k := range al.GroupFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+" = "+al.GroupFields[k])
		}
		add("Klucz alertu", strings.Join(parts, "\n"), false)
	}
	trusted("Czas zdarzenia", al.FirstSeen.Local().Format("2006-01-02 15:04:05"), true)
	if a.Rule != nil {
		if r, ok := a.Rule(al.RuleID); ok {
			if s := attackLine(r.Tags); s != "" {
				trusted("MITRE ATT&CK", s, false)
			}
			// Autor z pliku reguły (treść spoza Vardra – jak pola zdarzenia).
			if at := r.SigmaHQAttribution(); at != nil {
				add("Autor reguły", at.Line(), false)
			}
		}
	}
	add("Co zrobić", strings.TrimSpace(al.Instructions), false)
	if a.PanelURL != "" {
		trusted("Panel", a.PanelURL+"/alerts/"+strconv.FormatInt(al.ID, 10), false)
	}
	return m
}

// attackLine opisuje techniki ATT&CK reguły jednym tekstem
// („T1110.001 Password Guessing (Credential Access)”, kolejne w nowej linii).
func attackLine(tags []string) string {
	d := attack.Enterprise()
	m := d.Map(tags)
	var lines []string
	for _, t := range m.Techniques {
		var tactics []string
		for _, s := range t.Tactics {
			if ta, ok := d.Tactic(s); ok {
				tactics = append(tactics, ta.Name)
			}
		}
		l := t.ID + " " + t.Name
		if len(tactics) > 0 {
			l += " (" + strings.Join(tactics, ", ") + ")"
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}
