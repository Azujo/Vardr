package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"siem/panel/internal/api/store"
	"siem/panel/internal/notify"
)

// NotifyStore to kanały powiadomień i dziennik wysyłek (implementuje store.PG).
type NotifyStore interface {
	ListChannels(ctx context.Context) ([]store.Channel, error)
	ChannelByID(ctx context.Context, id int64) (store.Channel, error)
	CreateChannel(ctx context.Context, c store.Channel) (store.Channel, error)
	UpdateChannel(ctx context.Context, c store.Channel) (store.Channel, error)
	DeleteChannel(ctx context.Context, id int64) error
	NotifyLog(ctx context.Context, limit int) ([]store.NotifyLogEntry, error)
}

// Notifications to moduł powiadomień panelu (opcjonalny).
type Notifications struct {
	Store  NotifyStore
	Svc    *notify.Service
	Anchor *notify.Anchor
	// RelayConfigured: Grafana przekazuje alerty przez siem-api (token ustawiony).
	RelayConfigured bool
}

type channelView struct {
	store.Channel
	URLHint string `json:"url_hint"`
}

type logView struct {
	store.NotifyLogEntry
	// AnchorMatch: kotwica nadal zgadza się z manifestem w łańcuchu
	// (nil – nie kotwica albo manifestu już nie ma w spisie).
	AnchorMatch *bool `json:"anchor_match,omitempty"`
}

func (s *Server) notifyEnabled(w http.ResponseWriter) bool {
	if s.Notify == nil {
		writeError(w, http.StatusServiceUnavailable, "notify_disabled", "powiadomienia wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	ctx := r.Context()
	chans, err := s.Notify.Store.ListChannels(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	views := make([]channelView, 0, len(chans))
	for _, c := range chans {
		views = append(views, channelView{Channel: c, URLHint: notify.Hint(c.URL)})
	}
	entries, err := s.Notify.Store.NotifyLog(ctx, 100)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	logs := make([]logView, 0, len(entries))
	var seqs []int64
	for _, e := range entries {
		if e.AnchorSeq != nil {
			seqs = append(seqs, *e.AnchorSeq)
		}
	}
	hashes := map[int64]string{}
	if len(seqs) > 0 && s.Archive != nil {
		if h, err := s.Archive.ManifestHashes(ctx, seqs); err == nil {
			hashes = h
		}
	}
	for _, e := range entries {
		v := logView{NotifyLogEntry: e}
		if e.AnchorSeq != nil {
			if h, ok := hashes[*e.AnchorSeq]; ok {
				match := h == e.AnchorSHA256
				v.AnchorMatch = &match
			}
		}
		logs = append(logs, v)
	}
	anchorHour := -1
	if s.Notify.Anchor != nil {
		anchorHour = s.Notify.Anchor.Hour
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": views, "events": notify.Events, "log": logs,
		"anchor_hour": anchorHour, "relay_configured": s.Notify.RelayConfigured})
}

type channelRequest struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	URL         string            `json:"url"`
	Events      []string          `json:"events"`
	AlertFilter store.AlertFilter `json:"alert_filter"`
	Enabled     *bool             `json:"enabled"`
	Password    string            `json:"password"`
}

// cleanFilter sprawdza filtr alertów kanału.
func cleanFilter(f store.AlertFilter) (store.AlertFilter, bool) {
	if f.MinLevel != "" && !slices.Contains(notify.Levels, f.MinLevel) {
		return f, false
	}
	if f.MinLevel == "informational" {
		f.MinLevel = ""
	}
	switch f.RulesMode {
	case "", "all":
		f.RulesMode, f.Rules = "", nil
	case "only", "except":
		if len(f.Rules) == 0 || len(f.Rules) > 500 {
			return f, false
		}
		var rules []string
		for _, r := range f.Rules {
			if r == "" || len(r) > 128 {
				return f, false
			}
			if !slices.Contains(rules, r) {
				rules = append(rules, r)
			}
		}
		slices.Sort(rules)
		f.Rules = rules
	default:
		return f, false
	}
	return f, true
}

// narrows: nowy filtr może przepuścić mniej alertów niż stary (osłabienie).
func narrows(old, upd store.AlertFilter) bool {
	if slices.Index(notify.Levels, upd.MinLevel) > slices.Index(notify.Levels, old.MinLevel) {
		return true
	}
	if upd.RulesMode == old.RulesMode && slices.Equal(upd.Rules, old.Rules) {
		return false
	}
	return upd.RulesMode != ""
}

func cleanEvents(in []string) ([]string, bool) {
	out := []string{}
	for _, e := range in {
		if !slices.Contains(notify.Events, e) {
			return nil, false
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	slices.Sort(out)
	return out, true
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	a := current(r)
	var req channelRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	events, ok := cleanEvents(req.Events)
	filter, okF := cleanFilter(req.AlertFilter)
	switch {
	case !okF:
		writeError(w, http.StatusBadRequest, "bad_filter", "filtr alertów: poziom z listy, reguły – od 1 do 500 identyfikatorów")
		return
	case req.Name == "" || len([]rune(req.Name)) > 100:
		writeError(w, http.StatusBadRequest, "bad_name", "podaj nazwę kanału (do 100 znaków)")
		return
	case req.Kind != notify.KindDiscord && req.Kind != notify.KindWebhook:
		writeError(w, http.StatusBadRequest, "bad_kind", "rodzaj kanału: discord albo webhook")
		return
	case !ok:
		writeError(w, http.StatusBadRequest, "bad_events", "nieznany rodzaj powiadomień")
		return
	}
	if err := notify.ValidateURL(req.Kind, req.URL); err != nil {
		writeError(w, http.StatusBadRequest, "bad_url", err.Error())
		return
	}
	c, err := s.Notify.Store.CreateChannel(r.Context(), store.Channel{Name: req.Name, Kind: req.Kind, URL: req.URL,
		Events: events, AlertFilter: filter, Enabled: req.Enabled == nil || *req.Enabled, CreatedBy: a.user.Username})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "name_taken", "kanał o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "notify_channel_created", c.Name, map[string]any{"kind": c.Kind, "events": c.Events,
		"alert_filter": c.AlertFilter, "url": notify.Hint(c.URL)})
	writeJSON(w, http.StatusCreated, map[string]any{"channel": channelView{Channel: c, URLHint: notify.Hint(c.URL)}})
}

// updateChannel zmienia kanał. Wyłączenie, rezygnacja z rodzaju powiadomień
// albo zmiana adresu (np. przekierowanie kotwic gdzie indziej) wymaga
// ponownego podania hasła.
func (s *Server) updateChannel(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	a := current(r)
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	var req channelRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	events, okEv := cleanEvents(req.Events)
	filter, okF := cleanFilter(req.AlertFilter)
	if req.Name == "" || len([]rune(req.Name)) > 100 || !okEv || !okF {
		writeError(w, http.StatusBadRequest, "bad_request", "podaj nazwę (do 100 znaków), poprawne rodzaje powiadomień i filtr alertów")
		return
	}
	if req.URL != "" {
		if err := notify.ValidateURL(c.Kind, req.URL); err != nil {
			writeError(w, http.StatusBadRequest, "bad_url", err.Error())
			return
		}
	}
	enabled := c.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	weakening := (c.Enabled && !enabled) || (req.URL != "" && req.URL != c.URL) ||
		slices.ContainsFunc(c.Events, func(e string) bool { return !slices.Contains(events, e) }) ||
		narrows(c.AlertFilter, filter)
	if weakening && !s.reauth(w, r, req.Password, "notify_channel_change") {
		return
	}
	upd, err := s.Notify.Store.UpdateChannel(r.Context(), store.Channel{ID: c.ID, Name: req.Name, Events: events,
		AlertFilter: filter, Enabled: enabled, URL: req.URL})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "name_taken", "kanał o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "notify_channel_changed", upd.Name, map[string]any{"events": upd.Events, "enabled": upd.Enabled,
		"alert_filter": upd.AlertFilter, "url_changed": req.URL != "" && req.URL != c.URL,
		"previous": map[string]any{"name": c.Name, "events": c.Events, "enabled": c.Enabled, "alert_filter": c.AlertFilter}})
	writeJSON(w, http.StatusOK, map[string]any{"channel": channelView{Channel: upd, URLHint: notify.Hint(upd.URL)}})
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	a := current(r)
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.reauth(w, r, req.Password, "notify_channel_delete") {
		return
	}
	if err := s.Notify.Store.DeleteChannel(r.Context(), c.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "notify_channel_deleted", c.Name, map[string]any{"kind": c.Kind, "events": c.Events})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	a := current(r)
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	err := s.Notify.Svc.SendTo(r.Context(), c, notify.Message{Event: notify.EventTest, Severity: notify.SevInfo,
		Title: "Test kanału „" + c.Name + "”", Text: "Wiadomość testowa z panelu Vardr (wysłał " + a.user.Username + ").", At: s.now()})
	s.audit(r, &a.user, "notify_channel_tested", c.Name, map[string]any{"ok": err == nil})
	if err != nil {
		writeError(w, http.StatusBadGateway, "send_failed", "wysyłka nieudana: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "wiadomość testowa wysłana"})
}

// sendAnchor wysyła kotwicę archiwum od razu (poza codziennym terminem).
func (s *Server) sendAnchor(w http.ResponseWriter, r *http.Request) {
	if !s.notifyEnabled(w) {
		return
	}
	a := current(r)
	if s.Notify.Anchor == nil {
		writeError(w, http.StatusServiceUnavailable, "anchor_disabled", "kotwica archiwum wyłączona w konfiguracji")
		return
	}
	m, err := s.Notify.Anchor.Message(r.Context(), s.now())
	if errors.Is(err, notify.ErrNoManifest) {
		writeError(w, http.StatusConflict, "no_manifest", err.Error())
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if ok, err := s.Notify.Svc.HasSubscribers(r.Context(), notify.EventAnchor); err != nil {
		s.internalError(w, r, err)
		return
	} else if !ok {
		writeError(w, http.StatusConflict, "no_channel", "żaden włączony kanał nie odbiera kotwicy archiwum")
		return
	}
	n, err := s.Notify.Svc.Send(r.Context(), m)
	s.audit(r, &a.user, "archive_anchor_sent", "urd", map[string]any{"seq": *m.AnchorSeq, "sha256": m.AnchorSHA256, "channels": n})
	if err != nil {
		writeError(w, http.StatusBadGateway, "send_failed", "wysyłka nieudana: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "kotwica wysłana (" + strconv.Itoa(n) + " kanał/y)"})
}

func (s *Server) channelFromPath(w http.ResponseWriter, r *http.Request) (store.Channel, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return store.Channel{}, false
	}
	c, err := s.Notify.Store.ChannelByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego kanału")
		return c, false
	}
	if err != nil {
		s.internalError(w, r, err)
		return c, false
	}
	return c, true
}
