// Package graph to źródło logów Entra ID (Azure AD) z Microsoft Graph dla
// konektora (siem-connector): logowania (auditLogs/signIns) i zmiany
// w katalogu (auditLogs/directoryAudits). Konektor odpytuje API co minutę
// z kursorem czasu i zakładką (logi pojawiają się w Graph z opóźnieniem),
// pomija rekordy już wysłane, a identyfikator rekordu z Graph trafia do
// identyfikatora zdarzenia – ponowne pobranie nie tworzy duplikatów.
//
// Wymaga rejestracji aplikacji w Entra ID z uprawnieniami aplikacji
// AuditLog.Read.All i Directory.Read.All (zgoda administratora); logowania
// wymagają licencji Entra ID P1/P2. Adresy logowania i API są konfigurowalne
// – w laboratorium konektor rozmawia z symulatorem (tools/cmd/entrasim).
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"siem/agent/internal/source"
)

// Config to ustawienia połączenia z Graph.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	LoginURL     string // domyślnie https://login.microsoftonline.com
	GraphURL     string // domyślnie https://graph.microsoft.com
	HTTP         *http.Client
}

// Client pobiera dane z Graph (token aplikacji z odnawianiem).
type Client struct {
	cfg     Config
	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// NewClient tworzy klienta.
func NewClient(c Config) *Client {
	if c.LoginURL == "" {
		c.LoginURL = "https://login.microsoftonline.com"
	}
	if c.GraphURL == "" {
		c.GraphURL = "https://graph.microsoft.com"
	}
	c.LoginURL, c.GraphURL = strings.TrimRight(c.LoginURL, "/"), strings.TrimRight(c.GraphURL, "/")
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{cfg: c, now: time.Now}
}

// ErrAuth: odmowa uwierzytelnienia (zły klient, sekret, brak zgody) – ponawianie bez zmiany konfiguracji nic nie da.
var ErrAuth = errors.New("Graph: odmowa dostępu")

func (c *Client) accessToken(ctx context.Context, refresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !refresh && c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret},
		"scope": {c.cfg.GraphURL + "/.default"}, "grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.LoginURL+"/"+url.PathEscape(c.cfg.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t)
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf("%w: token HTTP %d %s %s", ErrAuth, resp.StatusCode, t.Error, firstLine(t.Description))
		}
		return "", fmt.Errorf("token: HTTP %d %s", resp.StatusCode, t.Error)
	}
	c.token = t.AccessToken
	// Odnowienie z zapasem 5 min przed wygaśnięciem.
	c.expires = c.now().Add(time.Duration(max(t.ExpiresIn-300, 60)) * time.Second)
	return c.token, nil
}

// get pobiera stronę wyników (ponowienia przy 429/503 z Retry-After,
// odnowienie tokenu przy 401).
func (c *Client) get(ctx context.Context, u string, out any) error {
	refreshed := false
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx, false)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := c.cfg.HTTP.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return json.Unmarshal(body, out)
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			refreshed = true
			if _, err := c.accessToken(ctx, true); err != nil {
				return err
			}
			continue
		case (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < 5:
			wait := time.Duration(attempt+1) * 2 * time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 300 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return fmt.Errorf("%w: HTTP %d %s", ErrAuth, resp.StatusCode, graphError(body))
		}
		return fmt.Errorf("Graph: HTTP %d %s", resp.StatusCode, graphError(body))
	}
}

func graphError(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
		return e.Error.Code + ": " + firstLine(e.Error.Message)
	}
	return ""
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Kind to rodzaj logu.
type Kind struct {
	Channel   string // kanał w stanie konektora i w identyfikatorach zdarzeń
	Source    string // źródło w paczce (normalizator wybiera dekoder)
	Path      string // ścieżka API
	TimeField string // pole czasu (filtr i kursor)
}

// Rodzaje logów Entra ID.
var (
	SignIns = Kind{Channel: "entra-signin", Source: "entra:signin", Path: "/v1.0/auditLogs/signIns", TimeField: "createdDateTime"}
	Audits  = Kind{Channel: "entra-audit", Source: "entra:audit", Path: "/v1.0/auditLogs/directoryAudits", TimeField: "activityDateTime"}
)

// Source to źródło konektora dla jednego rodzaju logu.
type Source struct {
	Client   *Client
	Kind     Kind
	Interval time.Duration // odstęp między odpytaniami (domyślnie 1 min)
	Overlap  time.Duration // zakładka na opóźnienie logów w Graph (domyślnie 15 min)
	Lookback time.Duration // pierwszy start: ile wstecz (domyślnie 24 h)
	PageSize int           // $top (domyślnie 500)
	Log      *slog.Logger
	// State (opcjonalne): stan źródła w panelu (status.Channel*: ok, access_denied, error).
	State func(state, msg string)

	now func() time.Time
}

// Channel: kanał w stanie konektora.
func (s *Source) Channel() string { return s.Kind.Channel }

type record struct {
	id   string
	at   time.Time
	data json.RawMessage
}

// Run odpytuje Graph do anulowania ctx. Pozycja (RecordID) to czas ostatniego
// rekordu w mikrosekundach (rosnący) – po restarcie odczyt wraca o zakładkę.
func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	if s.now == nil {
		s.now = time.Now
	}
	interval, overlap, lookback, page := s.Interval, s.Overlap, s.Lookback, s.PageSize
	if interval <= 0 {
		interval = time.Minute
	}
	if overlap <= 0 {
		overlap = 15 * time.Minute
	}
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	if page <= 0 || page > 1000 {
		page = 500
	}
	cursor := s.now().Add(-lookback)
	last := uint64(0)
	if start.Valid && start.RecordID > 0 {
		last = start.RecordID
		cursor = time.UnixMicro(int64(start.RecordID))
	}
	pos := func() source.Position { return source.Position{RecordID: last, Valid: last > 0} }
	seen := map[string]time.Time{}
	failures := 0
	for {
		// Zaległości (pierwszy start, długa przerwa) – oknami godzinowymi od
		// najstarszych: Graph zwraca najnowsze pierwsze, więc jedno duże
		// zapytanie trzeba by przyciąć od złej strony.
		var to time.Time
		catchUp := s.now().Sub(cursor) > 2*time.Hour
		if catchUp {
			to = cursor.Add(time.Hour)
		}
		recs, err := s.fetch(ctx, cursor.Add(-overlap), to, page)
		if err != nil {
			if ctx.Err() != nil {
				return pos(), nil
			}
			failures++
			if s.State != nil {
				st := "error"
				if errors.Is(err, ErrAuth) {
					st = "access_denied"
				}
				s.State(st, err.Error())
			}
			// Błąd uwierzytelnienia: ostrzeżenie przy każdej próbie; inne – co dziesiąty raz.
			if errors.Is(err, ErrAuth) || failures == 1 || failures%10 == 0 {
				s.Log.Warn("Graph: odpytanie nieudane – ponowię", "kind", s.Kind.Channel, "err", err, "failures", failures)
			}
		} else {
			if failures > 0 {
				s.Log.Info("Graph: odpytanie znów działa", "kind", s.Kind.Channel, "after_failures", failures)
			}
			if s.State != nil {
				s.State("ok", "")
			}
			failures = 0
			sent := 0
			for _, r := range recs {
				if _, ok := seen[r.id]; ok {
					continue
				}
				id := max(last+1, uint64(r.at.UnixMicro()))
				rec := source.Record{Channel: s.Kind.Channel, RecordID: id, Key: r.id, Raw: string(r.data),
					CreatedAt: r.at, ReadAt: s.now().UTC(), Source: s.Kind.Source}
				select {
				case out <- rec:
				case <-ctx.Done():
					return pos(), nil
				}
				seen[r.id] = r.at
				last = id
				sent++
				if r.at.After(cursor) {
					cursor = r.at
				}
			}
			// Pamięć widzianych tylko w oknie zakładki.
			for id, at := range seen {
				if at.Before(cursor.Add(-overlap - time.Minute)) {
					delete(seen, id)
				}
			}
			if sent > 0 {
				s.Log.Info("Graph: nowe rekordy", "kind", s.Kind.Channel, "records", sent, "cursor", cursor.UTC().Format(time.RFC3339))
			}
			if catchUp {
				if cursor.Before(to) {
					cursor = to
				}
				continue // następne okno od razu
			}
		}
		select {
		case <-ctx.Done():
			return pos(), nil
		case <-time.After(interval):
		}
	}
}

// maxPerPoll: najwięcej rekordów w jednym zapytaniu (ochrona pamięci; przy
// takim ruchu trzeba skrócić odstęp odpytań).
const maxPerPoll = 100000

// fetch pobiera rekordy z [from, to] (to zero – do teraz), wszystkie strony,
// posortowane od najstarszych.
func (s *Source) fetch(ctx context.Context, from, to time.Time, page int) ([]record, error) {
	q := url.Values{}
	filter := s.Kind.TimeField + " ge " + from.UTC().Format("2006-01-02T15:04:05Z")
	if !to.IsZero() {
		filter += " and " + s.Kind.TimeField + " le " + to.UTC().Format("2006-01-02T15:04:05Z")
	}
	q.Set("$filter", filter)
	q.Set("$top", strconv.Itoa(page))
	next := s.Client.cfg.GraphURL + s.Kind.Path + "?" + q.Encode()
	var out []record
	for next != "" && len(out) < maxPerPoll {
		var resp struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := s.Client.get(ctx, next, &resp); err != nil {
			return nil, err
		}
		for _, raw := range resp.Value {
			var h map[string]any
			if err := json.Unmarshal(raw, &h); err != nil {
				continue
			}
			id, _ := h["id"].(string)
			ts, _ := h[s.Kind.TimeField].(string)
			at, err := time.Parse(time.RFC3339Nano, ts)
			if id == "" || err != nil {
				s.Log.Warn("Graph: rekord bez id albo czasu – pominięty", "kind", s.Kind.Channel)
				continue
			}
			out = append(out, record{id: id, at: at, data: raw})
		}
		// Kolejna strona tylko z tego samego serwera (nie wysyłamy tokenu gdzie indziej).
		next = resp.NextLink
		if next != "" && !strings.HasPrefix(next, s.Client.cfg.GraphURL+"/") {
			return nil, fmt.Errorf("Graph: odnośnik do kolejnej strony poza %s", s.Client.cfg.GraphURL)
		}
	}
	if len(out) >= maxPerPoll {
		s.Log.Warn("Graph: limit rekordów w jednym zapytaniu – skróć odstęp odpytań", "kind", s.Kind.Channel, "limit", maxPerPoll)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		return out[i].id < out[j].id
	})
	return out, nil
}
