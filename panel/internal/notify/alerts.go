package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
)

// EventAlert: alerty detekcji (Gjallarhorn).
const EventAlert = "alert"

// OutboxStore to outbox alertów (implementuje alerts.PG).
type OutboxStore interface {
	ClaimOutbox(ctx context.Context, now time.Time, limit int) ([]alerts.Pending, error)
	MarkSent(ctx context.Context, id int64, now time.Time) error
	MarkFailed(ctx context.Context, id int64, errMsg string, next time.Time) error
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
	for _, p := range pending {
		m := a.Message(p.Alert)
		_, err := a.Svc.Send(ctx, m)
		if err == nil {
			// Brak kanałów subskrybujących alerty też kończy wpis (nie ma dokąd wysłać).
			if err := a.Store.MarkSent(ctx, p.OutboxID, now); err != nil {
				return err
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
	return nil
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

// Message buduje wiadomość o alercie.
func (a *AlertSender) Message(al alerts.Alert) Message {
	m := Message{
		Event:    EventAlert,
		Severity: levelSeverity[al.Level],
		Title:    fmt.Sprintf("[%s] %s", levelLabel[al.Level], al.RuleTitle),
		Text:     al.Summary,
		At:       al.CreatedAt,
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
	add("Co zrobić", strings.TrimSpace(al.Instructions), false)
	if a.PanelURL != "" {
		trusted("Panel", a.PanelURL+"/alerts/"+strconv.FormatInt(al.ID, 10), false)
	}
	return m
}
