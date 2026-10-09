// Package notify wysyła wiadomości Heimdalla poza system – na kanały
// ustawione w panelu (Discord, webhook): alerty zdrowia z Grafany, codzienną
// kotwicę archiwum Urd, a później alerty detekcji (Gjallarhorn).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"siem/panel/internal/api/store"
)

// Zdarzenia, które kanał może subskrybować.
const (
	EventHealth = "health" // alerty zdrowia systemu (Grafana)
	EventAnchor = "anchor" // codzienna kotwica archiwum Urd
	EventTest   = "test"   // wiadomość testowa z panelu (tylko wskazany kanał)
)

// Events to zdarzenia do wyboru w panelu.
var Events = []string{EventAlert, EventHealth, EventAnchor}

// Rodzaje kanałów.
const (
	KindDiscord = "discord"
	KindWebhook = "webhook"
)

// Ważność wiadomości (kolor na Discordzie).
const (
	SevCritical = "critical"
	SevWarning  = "warning"
	SevInfo     = "info"
	SevOK       = "ok"
)

// Field to para nazwa–wartość w wiadomości.
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// Message to wiadomość niezależna od kanału.
type Message struct {
	Event    string
	Severity string
	Title    string
	Text     string
	Fields   []Field
	At       time.Time
	// Kotwica archiwum (dla dziennika wysyłek).
	AnchorSeq    *int64
	AnchorSHA256 string
}

// Store to kanały i dziennik wysyłek (implementuje store.PG).
type Store interface {
	ListChannels(ctx context.Context) ([]store.Channel, error)
	RecordDelivery(ctx context.Context, e store.NotifyLogEntry) error
}

// Service wysyła wiadomości na kanały.
type Service struct {
	Store  Store
	Log    *slog.Logger
	Client *http.Client
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Send wysyła wiadomość na wszystkie włączone kanały, które subskrybują jej
// zdarzenie. Zwraca liczbę udanych wysyłek; błąd, gdy żadna się nie udała.
func (s *Service) Send(ctx context.Context, m Message) (int, error) {
	chans, err := s.Store.ListChannels(ctx)
	if err != nil {
		return 0, err
	}
	ok, tried := 0, 0
	var errs []error
	for _, c := range chans {
		if !c.Enabled || !slices.Contains(c.Events, m.Event) {
			continue
		}
		tried++
		if err := s.SendTo(ctx, c, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		} else {
			ok++
		}
	}
	if tried > 0 && ok == 0 {
		return 0, errors.Join(errs...)
	}
	return ok, nil
}

// HasSubscribers mówi, czy jakiś włączony kanał subskrybuje zdarzenie.
func (s *Service) HasSubscribers(ctx context.Context, event string) (bool, error) {
	chans, err := s.Store.ListChannels(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(chans, func(c store.Channel) bool { return c.Enabled && slices.Contains(c.Events, event) }), nil
}

// SendTo wysyła wiadomość na jeden kanał i zapisuje wynik w dzienniku.
func (s *Service) SendTo(ctx context.Context, c store.Channel, m Message) error {
	if m.At.IsZero() {
		m.At = s.now()
	}
	err := s.deliver(ctx, c, m)
	id := c.ID
	e := store.NotifyLogEntry{At: s.now(), ChannelID: &id, Channel: c.Name, Event: m.Event, Title: m.Title, OK: err == nil,
		AnchorSeq: m.AnchorSeq, AnchorSHA256: m.AnchorSHA256}
	if err != nil {
		e.Error = err.Error()
		s.Log.Warn("wysyłka powiadomienia nieudana", "channel", c.Name, "event", m.Event, "err", err)
	}
	if rerr := s.Store.RecordDelivery(context.WithoutCancel(ctx), e); rerr != nil {
		s.Log.Warn("zapis w dzienniku wysyłek nieudany", "err", rerr)
	}
	return err
}

func (s *Service) deliver(ctx context.Context, c store.Channel, m Message) error {
	var body []byte
	var err error
	switch c.Kind {
	case KindDiscord:
		body, err = json.Marshal(discordPayload(m))
	case KindWebhook:
		body, err = json.Marshal(webhookPayload(m))
	default:
		return fmt.Errorf("nieznany rodzaj kanału %q", c.Kind)
	}
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
		if err != nil {
			return errors.New("niepoprawny adres kanału")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Heimdall-SIEM")
		resp, err := s.client().Do(req)
		if err != nil {
			return safeErr(err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		// Discord: limit wiadomości – jedna ponowna próba po wskazanym czasie.
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fmt.Errorf("odbiorca odpowiedział HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}

func retryAfter(v string) time.Duration {
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 30 {
		return time.Duration(f * float64(time.Second))
	}
	return 2 * time.Second
}

// safeErr usuwa adres z błędu sieci – adres webhooka zawiera sekret.
func safeErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return errors.New("przekroczony czas połączenia z odbiorcą")
		}
		return fmt.Errorf("połączenie z odbiorcą nieudane: %v", ue.Err)
	}
	return err
}

var sevColor = map[string]int{SevCritical: 0xE03131, SevWarning: 0xF08C00, SevInfo: 0x1C7ED6, SevOK: 0x2F9E44}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func discordPayload(m Message) map[string]any {
	embed := map[string]any{
		"title":       clip(m.Title, 256),
		"description": clip(m.Text, 4000),
		"color":       sevColor[m.Severity],
		"timestamp":   m.At.UTC().Format(time.RFC3339),
		"footer":      map[string]any{"text": "Heimdall SIEM"},
	}
	var fields []map[string]any
	for i, f := range m.Fields {
		if i == 25 {
			break
		}
		fields = append(fields, map[string]any{"name": clip(f.Name, 256), "value": clip(f.Value, 1024), "inline": f.Inline})
	}
	if fields != nil {
		embed["fields"] = fields
	}
	return map[string]any{"username": "Heimdall", "embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}}
}

func webhookPayload(m Message) map[string]any {
	fields := map[string]string{}
	for _, f := range m.Fields {
		fields[f.Name] = f.Value
	}
	return map[string]any{"source": "heimdall", "event": m.Event, "severity": m.Severity, "title": m.Title,
		"text": m.Text, "fields": fields, "at": m.At.UTC().Format(time.RFC3339)}
}

// ValidateURL sprawdza adres kanału: tylko HTTPS, dla Discorda – adres
// webhooka Discorda (panel nie wyśle danych w dowolne miejsce sieci
// wewnętrznej pod pozorem „Discorda”).
func ValidateURL(kind, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("adres musi zaczynać się od https:// i nie może zawierać loginu ani hasła")
	}
	if len(raw) > 2000 {
		return errors.New("adres jest za długi")
	}
	if kind == KindDiscord {
		host := strings.ToLower(u.Hostname())
		if host != "discord.com" && host != "discordapp.com" && host != "ptb.discord.com" && host != "canary.discord.com" {
			return errors.New("adres webhooka Discorda ma postać https://discord.com/api/webhooks/…")
		}
		if !strings.HasPrefix(u.Path, "/api/webhooks/") {
			return errors.New("adres webhooka Discorda ma postać https://discord.com/api/webhooks/…")
		}
	}
	return nil
}

// Hint to bezpieczny opis adresu do pokazania w panelu (bez sekretu).
func Hint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	tail := ""
	if p := strings.TrimRight(u.Path, "/"); len(p) > 4 {
		tail = "…" + p[len(p)-4:]
	}
	return u.Host + tail
}
