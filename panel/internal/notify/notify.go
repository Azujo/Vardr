// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notify wysyła wiadomości Vardra poza system – na kanały
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

	"siem/internal/lang"
	"siem/panel/internal/api/store"
)

// Zdarzenia, które kanał może subskrybować.
const (
	EventHealth = "health" // alerty zdrowia systemu (Grafana)
	EventAnchor = "anchor" // codzienna kotwica archiwum Urd
	// EventIncident: incydenty – nowy incydent poważny (NIS2) i terminy zgłoszeń.
	EventIncident = "incident"
	EventTest     = "test" // wiadomość testowa z panelu (tylko wskazany kanał)
)

// Events to zdarzenia do wyboru w panelu.
var Events = []string{EventAlert, EventIncident, EventHealth, EventAnchor}

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
	// Trusted: wartość tworzy Vardr (link do panelu, czas) – nie jest
	// escapowana nawet w wiadomości z danymi ze zdarzeń (Untrusted).
	Trusted bool `json:"-"`
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
	// Level i RuleID: alert detekcji – do filtru kanału (AlertFilter).
	Level  string
	RuleID string
	// Untrusted: treść i pola (poza Trusted) pochodzą ze zdarzeń, czyli
	// potencjalnie od atakującego – w Discordzie Markdown jest escapowany
	// (np. ukryty link „[panel](https://zly.adres)” w poleceniu procesu).
	Untrusted bool
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
	// Lang: język systemu – w nim powstają wiadomości (nil – polski).
	Lang func(ctx context.Context) string
}

// Language: język wiadomości (pl, en).
func (s *Service) Language(ctx context.Context) string {
	if s == nil || s.Lang == nil {
		return "pl"
	}
	return s.Lang(ctx)
}

// pick: tekst polski albo angielski (dla „en”).
func pick(lang, pl, en string) string {
	if lang == "en" {
		return en
	}
	return pl
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
		if !c.Enabled || !slices.Contains(c.Events, m.Event) || !Accepts(c.AlertFilter, m) {
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

// Levels: poziomy alertów od najniższego.
var Levels = []string{"informational", "low", "medium", "high", "critical"}

// Accepts mówi, czy filtr kanału przepuszcza wiadomość (dotyczy tylko
// alertów detekcji; inne rodzaje wiadomości przechodzą zawsze).
func Accepts(f store.AlertFilter, m Message) bool {
	if m.Event != EventAlert {
		return true
	}
	if f.MinLevel != "" && slices.Index(Levels, m.Level) < slices.Index(Levels, f.MinLevel) {
		return false
	}
	switch f.RulesMode {
	case "only":
		return slices.Contains(f.Rules, m.RuleID)
	case "except":
		return !slices.Contains(f.Rules, m.RuleID)
	}
	return true
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
		if s.Language(ctx) == "en" {
			e.Error = lang.English(err)
		}
		s.Log.Warn("sending the notification failed", "channel", c.Name, "event", m.Event, "err", err)
	}
	if rerr := s.Store.RecordDelivery(context.WithoutCancel(ctx), e); rerr != nil {
		s.Log.Warn("writing to the notification log failed", "err", rerr)
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
		return fmt.Errorf("unknown channel kind %q", c.Kind)
	}
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
		if err != nil {
			return lang.Errorf("niepoprawny adres kanału", "invalid channel address")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Vardr-SIEM")
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
		return lang.Errorf("odbiorca odpowiedział HTTP %d: %s", "the recipient responded with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
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
			return lang.Errorf("przekroczony czas połączenia z odbiorcą", "connection to the recipient timed out")
		}
		return lang.Errorf("połączenie z odbiorcą nieudane: %v", "connection to the recipient failed: %v", ue.Err)
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

// mdEscaper: znaki Markdownu Discorda poprzedzone ukośnikiem wstecznym.
var mdEscaper = strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`,
	"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "<", `\<`, ">", `\>`, "#", `\#`)

// discordLimit: łączna długość tekstów embedu dopuszczana przez Discorda
// (6000) z zapasem – dłuższa wiadomość jest odrzucana (HTTP 400).
const discordLimit = 5800

func discordPayload(m Message) map[string]any {
	text := m.Text
	type fv struct {
		name, value string
		inline      bool
	}
	var fs []fv
	for i, f := range m.Fields {
		if i == 25 {
			break
		}
		v := f.Value
		if m.Untrusted && !f.Trusted {
			v = mdEscaper.Replace(v)
		}
		fs = append(fs, fv{clip(f.Name, 256), clip(v, 1024), f.Inline})
	}
	if m.Untrusted {
		text = mdEscaper.Replace(text)
	}
	title := clip(m.Title, 256)
	text = clip(text, 4000)
	// Łączny limit: skracamy najdłuższy tekst, aż się zmieści.
	for {
		total := len([]rune(title)) + len([]rune(text)) + len("Vardr SIEM")
		longest, ln := -1, len([]rune(text))
		for i, f := range fs {
			n := len([]rune(f.value))
			total += len([]rune(f.name)) + n
			if n > ln {
				longest, ln = i, n
			}
		}
		if total <= discordLimit || ln < 40 {
			break
		}
		cut := max(ln-(total-discordLimit), ln/2)
		if longest < 0 {
			text = clip(text, cut)
		} else {
			fs[longest].value = clip(fs[longest].value, cut)
		}
	}
	embed := map[string]any{
		"title":       title,
		"description": text,
		"color":       sevColor[m.Severity],
		"timestamp":   m.At.UTC().Format(time.RFC3339),
		"footer":      map[string]any{"text": "Vardr SIEM"},
	}
	var fields []map[string]any
	for _, f := range fs {
		fields = append(fields, map[string]any{"name": f.name, "value": f.value, "inline": f.inline})
	}
	if fields != nil {
		embed["fields"] = fields
	}
	return map[string]any{"username": "Vardr", "embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}}
}

func webhookPayload(m Message) map[string]any {
	fields := map[string]string{}
	for _, f := range m.Fields {
		fields[f.Name] = f.Value
	}
	return map[string]any{"source": "vardr", "event": m.Event, "severity": m.Severity, "title": m.Title,
		"text": m.Text, "fields": fields, "at": m.At.UTC().Format(time.RFC3339)}
}

// ValidateURL sprawdza adres kanału: tylko HTTPS, dla Discorda – adres
// webhooka Discorda (panel nie wyśle danych w dowolne miejsce sieci
// wewnętrznej pod pozorem „Discorda”).
func ValidateURL(kind, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return lang.Errorf("adres musi zaczynać się od https:// i nie może zawierać loginu ani hasła", "the address must start with https:// and must not contain a username or password")
	}
	if len(raw) > 2000 {
		return lang.Errorf("adres jest za długi", "the address is too long")
	}
	if kind == KindDiscord {
		host := strings.ToLower(u.Hostname())
		if host != "discord.com" && host != "discordapp.com" && host != "ptb.discord.com" && host != "canary.discord.com" {
			return lang.Errorf("adres webhooka Discorda ma postać https://discord.com/api/webhooks/…", "a Discord webhook address looks like https://discord.com/api/webhooks/…")
		}
		if !strings.HasPrefix(u.Path, "/api/webhooks/") {
			return lang.Errorf("adres webhooka Discorda ma postać https://discord.com/api/webhooks/…", "a Discord webhook address looks like https://discord.com/api/webhooks/…")
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
