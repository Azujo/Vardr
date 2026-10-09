package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"siem/internal/contract"
	"siem/internal/decode"
	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

// Dekodery syslog (etap 6c): wbudowane w program i zmienione w panelu.
// Zmiany trafiają do bazy (źródło prawdy, historia) i przez NATS KV do
// normalizatorów, które podmieniają zestaw bez restartu.

// DecoderStore to dekodery zmienione w panelu (implementuje store.PG).
type DecoderStore interface {
	ListDecoders(ctx context.Context) ([]store.SyslogDecoder, error)
	SaveDecoder(ctx context.Context, d store.SyslogDecoder, action, note string) (store.SyslogDecoder, error)
	DeleteDecoder(ctx context.Context, id, note, by string) (store.SyslogDecoder, error)
	DecoderVersions(ctx context.Context, id string, limit int) ([]store.DecoderVersion, error)
}

// DecoderSampler to próbki wiadomości syslog z ClickHouse (implementuje events.Searcher).
type DecoderSampler interface {
	SyslogSamples(ctx context.Context, decoder, peer string, since time.Time, limit int) ([]events.SyslogSample, error)
}

// Decoders to moduł dekoderów panelu (opcjonalny).
type Decoders struct {
	Store DecoderStore
	// Publish dostarcza zmianę do normalizatorów (c == nil – usunięcie);
	// nil – bez NATS (zmiana zadziała po ponownym połączeniu panelu).
	Publish func(ctx context.Context, id string, c *decode.Custom) error
	// Samples (opcjonalne) – próbki z bazy zdarzeń.
	Samples DecoderSampler
	// Loc: strefa czasu nagłówków bez strefy (jak SIEM_SYSLOG_TZ normalizatora).
	Loc *time.Location
}

// maxDecoderSource: najdłuższa definicja (jak ograniczenie w bazie).
const maxDecoderSource = 64 << 10

func (s *Server) decodersEnabled(w http.ResponseWriter) bool {
	if s.Decoders == nil {
		writeError(w, http.StatusServiceUnavailable, "decoders_disabled", "dekodery wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

func (d *Decoders) loc() *time.Location {
	if d.Loc == nil {
		return time.UTC
	}
	return d.Loc
}

// state zwraca dekodery wbudowane i zmiany z bazy.
func (d *Decoders) state(ctx context.Context) ([]*decode.Decoder, map[string]store.SyslogDecoder, error) {
	builtin, err := decode.Builtin(d.loc())
	if err != nil {
		return nil, nil, err
	}
	rows, err := d.Store.ListDecoders(ctx)
	if err != nil {
		return nil, nil, err
	}
	custom := map[string]store.SyslogDecoder{}
	for _, r := range rows {
		custom[r.ID] = r
	}
	return builtin, custom, nil
}

func toCustom(r store.SyslogDecoder) decode.Custom {
	return decode.Custom{Source: r.Source, Enabled: r.Enabled, Revision: r.Revision, By: r.UpdatedBy, At: r.UpdatedAt}
}

// Effective zwraca zestaw działający w normalizatorach (wbudowane + zmiany).
func (d *Decoders) Effective(ctx context.Context) (*decode.Set, error) {
	builtin, custom, err := d.state(ctx)
	if err != nil {
		return nil, err
	}
	set, _ := decode.Merge(builtin, customMap(custom), d.loc())
	return set, nil
}

func customMap(rows map[string]store.SyslogDecoder) map[string]decode.Custom {
	out := make(map[string]decode.Custom, len(rows))
	for id, r := range rows {
		out[id] = toCustom(r)
	}
	return out
}

// All zwraca wszystkie zmiany z bazy (synchronizacja NATS KV przy starcie).
func (d *Decoders) All(ctx context.Context) (map[string]decode.Custom, error) {
	_, custom, err := d.state(ctx)
	if err != nil {
		return nil, err
	}
	return customMap(custom), nil
}

type decoderView struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	Dataset       string     `json:"dataset"`
	Priority      int        `json:"priority"`
	Version       int        `json:"version"`
	Origin        string     `json:"origin"`   // builtin | custom
	Modified      bool       `json:"modified"` // wbudowany z własną definicją z panelu
	Enabled       bool       `json:"enabled"`
	Order         int        `json:"order"` // kolejność sprawdzania (0 – wyłączony)
	Source        string     `json:"source"`
	BuiltinSource string     `json:"builtin_source,omitempty"`
	Samples       int        `json:"samples"`
	Revision      int        `json:"revision,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	UpdatedBy     string     `json:"updated_by,omitempty"`
	Error         string     `json:"error,omitempty"`
}

func (s *Server) listDecoders(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	builtin, custom, err := s.Decoders.state(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	set, errs := decode.Merge(builtin, customMap(custom), s.Decoders.loc())
	order := map[string]int{}
	for i, d := range set.List() {
		order[d.ID] = i + 1
	}
	failed := map[string]string{}
	for _, e := range errs {
		if id, _, ok := strings.Cut(strings.TrimPrefix(e.Error(), "dekoder "), ":"); ok {
			failed[id] = e.Error()
		}
	}
	sources := decode.BuiltinSources()
	views := []decoderView{}
	seen := map[string]bool{}
	fill := func(v *decoderView, d *decode.Decoder) {
		v.Title, v.Description, v.Dataset, v.Priority, v.Version, v.Samples = d.Title, d.Description, d.Dataset, d.Priority, d.Version, len(d.Samples)
	}
	for _, b := range builtin {
		seen[b.ID] = true
		v := decoderView{ID: b.ID, Origin: "builtin", Enabled: true, Source: sources[b.ID], Order: order[b.ID]}
		fill(&v, b)
		if c, ok := custom[b.ID]; ok {
			v.Enabled, v.Revision, v.UpdatedAt, v.UpdatedBy = c.Enabled, c.Revision, &c.UpdatedAt, c.UpdatedBy
			if c.Source != "" {
				v.Modified, v.Source, v.BuiltinSource, v.Error = true, c.Source, sources[b.ID], failed[b.ID]
				if d, err := decode.Parse([]byte(c.Source), s.Decoders.loc()); err == nil {
					fill(&v, d)
				}
			}
		}
		views = append(views, v)
	}
	for id, c := range custom {
		if seen[id] {
			continue
		}
		v := decoderView{ID: id, Origin: "custom", Enabled: c.Enabled, Source: c.Source, Order: order[id], Revision: c.Revision,
			UpdatedAt: &c.UpdatedAt, UpdatedBy: c.UpdatedBy, Error: failed[id], Title: id}
		if d, err := decode.Parse([]byte(c.Source), s.Decoders.loc()); err == nil {
			fill(&v, d)
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"decoders": views, "delivery": s.Decoders.Publish != nil,
		"samples": s.Decoders.Samples != nil, "targets": decode.Targets})
}

func (s *Server) decoderVersions(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	vs, err := s.Decoders.Store.DecoderVersions(r.Context(), r.PathValue("id"), 50)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": nonNilSlice(vs)})
}

type decodeHeader struct {
	Format   string     `json:"format"`
	Host     string     `json:"host,omitempty"`
	App      string     `json:"app,omitempty"`
	PID      string     `json:"pid,omitempty"`
	Severity string     `json:"severity,omitempty"`
	Facility *int       `json:"facility,omitempty"`
	Time     *time.Time `json:"time,omitempty"`
	Message  string     `json:"message"`
}

type decodeResult struct {
	Raw       string            `json:"raw"`
	Header    decodeHeader      `json:"header"`
	Candidate bool              `json:"candidate"` // testowany dekoder pasuje do wiadomości
	Decoder   string            `json:"decoder"`   // dekoder wybrany w zestawie (z testowanym)
	Dataset   string            `json:"dataset"`
	Pattern   bool              `json:"pattern"` // parser rozebrał treść (regex: któryś wzorzec)
	Event     map[string]string `json:"event"`
	Fields    map[string]string `json:"fields"`
	Error     string            `json:"error,omitempty"` // kwarantanna
}

// maxTestSamples: najwięcej wiadomości w jednym teście.
const maxTestSamples = 200

// testDecoder dekoduje próbki dekoderem z edytora (w zestawie działających
// dekoderów, na jego miejscu) – bez zapisu. Pusta definicja: test zestawu.
func (s *Server) testDecoder(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	var req struct {
		Source  string   `json:"source"`
		Samples []string `json:"samples"`
		Peer    string   `json:"peer"`
	}
	if !readJSONLimit(w, r, &req, 1<<20) {
		return
	}
	loc := s.Decoders.loc()
	var cand *decode.Decoder
	if strings.TrimSpace(req.Source) != "" {
		if len(req.Source) > maxDecoderSource {
			writeError(w, http.StatusBadRequest, "too_long", "definicja dłuższa niż 64 KB")
			return
		}
		d, err := decode.Parse([]byte(req.Source), loc)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		cand = d
	}
	samples := req.Samples
	if len(samples) == 0 && cand != nil {
		samples = cand.Samples
	}
	if len(samples) > maxTestSamples {
		samples = samples[:maxTestSamples]
	}
	peer := strings.TrimSpace(req.Peer)
	if peer == "" {
		peer = "192.0.2.1"
	} else if _, err := netip.ParseAddr(peer); err != nil {
		writeError(w, http.StatusBadRequest, "bad_peer", "adres nadawcy: np. 192.168.88.1")
		return
	}
	builtin, custom, err := s.Decoders.state(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cm := customMap(custom)
	if cand != nil {
		cm[cand.ID] = decode.Custom{Source: req.Source, Enabled: true}
	}
	set, _ := decode.Merge(builtin, cm, loc)
	now := s.now().UTC()
	results := make([]decodeResult, 0, len(samples))
	sum := map[string]int{"total": 0, "candidate": 0, "other": 0, "generic": 0, "errors": 0, "no_pattern": 0}
	for i, raw := range samples {
		raw = strings.TrimRight(raw, "\r\n")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		sum["total"]++
		res := decodeOne(raw, peer, i, now, set, loc, cand)
		switch {
		case res.Error != "":
			sum["errors"]++
		case cand != nil && res.Decoder == cand.ID:
			sum["candidate"]++
		case res.Dataset == "syslog.generic":
			sum["generic"]++
		default:
			sum["other"]++
		}
		if res.Decoder != "" && !res.Pattern {
			sum["no_pattern"]++
		}
		results = append(results, res)
	}
	out := map[string]any{"ok": true, "results": results, "summary": sum}
	if cand != nil {
		out["decoder"] = map[string]any{"id": cand.ID, "title": cand.Title, "dataset": cand.Dataset, "priority": cand.Priority}
	}
	writeJSON(w, http.StatusOK, out)
}

func decodeOne(raw, peer string, i int, now time.Time, set *decode.Set, loc *time.Location, cand *decode.Decoder) decodeResult {
	h := decode.ParseHeader(raw, loc, now)
	res := decodeResult{Raw: raw, Header: decodeHeader{Format: h.Format, Host: h.Host, App: h.App, PID: h.PID, Message: h.Message},
		Event: map[string]string{}, Fields: map[string]string{}}
	if h.Severity >= 0 {
		f := h.Facility
		res.Header.Severity, res.Header.Facility = decode.SeverityName(h.Severity), &f
	}
	if !h.Time.IsZero() {
		t := h.Time.UTC()
		res.Header.Time = &t
	}
	addr, _ := netip.ParseAddr(peer)
	if cand != nil {
		res.Candidate = cand.Matches(h, addr)
	}
	e, err := decode.Event(contract.Event{ID: "test:" + strconv.Itoa(i), Raw: raw, Peer: peer}, "test", now, set, loc)
	if err != nil {
		res.Error = err.Error()
		if d := set.Find(h, addr); d != nil {
			res.Decoder, res.Dataset = d.ID, d.Dataset
		}
		return res
	}
	res.Dataset = e.Dataset
	res.Decoder = e.Fields["decoder.id"]
	res.Pattern = res.Decoder != "" && e.Fields["decoder.pattern"] != "none"
	ev := map[string]string{"timestamp": e.Timestamp.Format(time.RFC3339), "time_quality": e.TimeQuality, "host.name": e.HostName,
		"user.name": e.UserName, "user.domain": e.UserDomain, "source.ip": e.SourceIP, "event.action": e.Action,
		"event.outcome": e.Outcome, "event.provider": e.Provider, "process.name": e.ProcessName,
		"process.command_line": e.CommandLine, "message": e.Message}
	if e.Code != 0 {
		ev["event.code"] = strconv.FormatUint(uint64(e.Code), 10)
	}
	for k, v := range ev {
		if v != "" {
			res.Event[k] = v
		}
	}
	for k, v := range e.Fields {
		if !strings.HasPrefix(k, "syslog.") && k != "decoder.id" && k != "decoder.version" {
			res.Fields[k] = v
		}
	}
	return res
}

// saveDecoder zapisuje własną definicję dekodera (nowy albo zastępujący
// wbudowany o tym samym id). Próbki z definicji muszą się nim dekodować.
func (s *Server) saveDecoder(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Source string `json:"source"`
		Note   string `json:"note"`
	}
	if !readJSONLimit(w, r, &req, 256<<10) {
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Source) > maxDecoderSource || len(req.Note) > 500 {
		writeError(w, http.StatusBadRequest, "too_long", "definicja najwyżej 64 KB, opis zmiany najwyżej 500 znaków")
		return
	}
	d, err := decode.Parse([]byte(req.Source), s.Decoders.loc())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_decoder", err.Error())
		return
	}
	if d.ID != id {
		writeError(w, http.StatusBadRequest, "bad_id", "id w definicji ("+d.ID+") różni się od zapisywanego dekodera ("+id+")")
		return
	}
	if len(d.Samples) == 0 {
		writeError(w, http.StatusBadRequest, "no_samples", "dodaj w definicji samples – przykładowe wiadomości, które dekoder rozpoznaje (test i dokumentacja)")
		return
	}
	if err := d.CheckSamples(s.now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "sample_failed", err.Error())
		return
	}
	builtin, custom, err := s.Decoders.state(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	prev, existed := custom[id]
	enabled := !existed || prev.Enabled
	isBuiltin := false
	for _, b := range builtin {
		isBuiltin = isBuiltin || b.ID == id
	}
	saved, err := s.Decoders.Store.SaveDecoder(r.Context(), store.SyslogDecoder{ID: id, Source: req.Source, Enabled: enabled,
		UpdatedBy: a.user.Username}, "saved", req.Note)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "decoder_saved", id, map[string]any{"title": d.Title, "dataset": d.Dataset, "revision": saved.Revision,
		"builtin": isBuiltin, "enabled": enabled, "note": req.Note})
	s.publishDecoder(w, r, id, &saved)
}

// publishDecoder dostarcza zmianę normalizatorom i odpowiada klientowi.
func (s *Server) publishDecoder(w http.ResponseWriter, r *http.Request, id string, d *store.SyslogDecoder) {
	resp := map[string]any{"ok": true}
	if d != nil {
		resp["revision"] = d.Revision
	}
	if s.Decoders.Publish == nil {
		resp["message"] = "zapisano; brak połączenia z NATS – normalizatory dostaną zmianę po jego przywróceniu"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	var c *decode.Custom
	if d != nil {
		cc := toCustom(*d)
		c = &cc
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if err := s.Decoders.Publish(ctx, id, c); err != nil {
		s.Log.Warn("dostarczenie dekodera do NATS nieudane – ponowi synchronizacja okresowa", "id", id, "err", err)
		resp["message"] = "zapisano; dostarczenie do normalizatorów nieudane – panel ponowi je w ciągu 5 minut"
	} else {
		resp["message"] = "zapisano; normalizatory stosują zmianę w ciągu kilku sekund"
	}
	writeJSON(w, http.StatusOK, resp)
}

// setDecoderEnabled włącza albo wyłącza dekoder. Wyłączenie sprawia, że
// wiadomości trafiają do innego dekodera albo jako syslog.generic (reguły
// danego produktu przestają działać): wymaga powodu i hasła.
func (s *Server) setDecoderEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Enabled  bool   `json:"enabled"`
		Reason   string `json:"reason"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	builtin, custom, err := s.Decoders.state(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	prev, existed := custom[id]
	isBuiltin := false
	for _, b := range builtin {
		isBuiltin = isBuiltin || b.ID == id
	}
	if !existed && !isBuiltin {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego dekodera")
		return
	}
	was := !existed || prev.Enabled
	if was == req.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "bez zmian"})
		return
	}
	if !req.Enabled {
		if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
			writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód wyłączenia dekodera")
			return
		}
		if !s.reauth(w, r, req.Password, "decoder_disable") {
			return
		}
	}
	s.audit(r, &a.user, "decoder_enabled_changed", id, map[string]any{"enabled": req.Enabled, "reason": req.Reason, "builtin": isBuiltin})
	// Wbudowany włączony bez własnej definicji – zmiana z panelu niepotrzebna.
	if req.Enabled && isBuiltin && prev.Source == "" {
		if _, err := s.Decoders.Store.DeleteDecoder(r.Context(), id, "włączony ponownie", a.user.Username); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, r, err)
			return
		}
		s.publishDecoder(w, r, id, nil)
		return
	}
	action := "disabled"
	if req.Enabled {
		action = "enabled"
	}
	saved, err := s.Decoders.Store.SaveDecoder(r.Context(), store.SyslogDecoder{ID: id, Source: prev.Source, Enabled: req.Enabled,
		UpdatedBy: a.user.Username}, action, req.Reason)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.publishDecoder(w, r, id, &saved)
}

// revertDecoder cofa zmiany z panelu: wbudowany wraca do wersji z programu,
// własny jest usuwany (to osłabia rozpoznawanie – powód i hasło).
func (s *Server) revertDecoder(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Reason   string `json:"reason"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	builtin, custom, err := s.Decoders.state(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	prev, existed := custom[id]
	if !existed {
		writeError(w, http.StatusNotFound, "not_found", "dekoder nie ma zmian z panelu")
		return
	}
	isBuiltin := false
	for _, b := range builtin {
		isBuiltin = isBuiltin || b.ID == id
	}
	if !isBuiltin {
		if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
			writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód usunięcia dekodera")
			return
		}
		if !s.reauth(w, r, req.Password, "decoder_delete") {
			return
		}
	}
	if _, err := s.Decoders.Store.DeleteDecoder(r.Context(), id, req.Reason, a.user.Username); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "dekoder nie ma zmian z panelu")
			return
		}
		s.internalError(w, r, err)
		return
	}
	action := "decoder_reverted"
	if !isBuiltin {
		action = "decoder_deleted"
	}
	s.audit(r, &a.user, action, id, map[string]any{"reason": req.Reason, "revision": prev.Revision, "was_enabled": prev.Enabled})
	s.publishDecoder(w, r, id, nil)
}

// decoderSamples zwraca najnowsze nierozpoznane wiadomości syslog (albo
// obsłużone przez wskazany dekoder) – materiał do edytora.
func (s *Server) decoderSamples(w http.ResponseWriter, r *http.Request) {
	if !s.decodersEnabled(w) {
		return
	}
	if s.Decoders.Samples == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – próbki niedostępne")
		return
	}
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours < 1 || hours > 168 {
		hours = 24
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > maxTestSamples {
		limit = 50
	}
	peer := strings.TrimSpace(q.Get("peer"))
	if peer != "" {
		if _, err := netip.ParseAddr(peer); err != nil {
			writeError(w, http.StatusBadRequest, "bad_peer", "adres nadawcy: np. 192.168.88.1")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	out, err := s.Decoders.Samples.SyslogSamples(ctx, q.Get("decoder"), peer, s.now().Add(-time.Duration(hours)*time.Hour), limit)
	if err != nil {
		writeError(w, http.StatusBadGateway, "events_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": out})
}

// readJSONLimit działa jak readJSON z innym limitem rozmiaru treści.
func readJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "niepoprawne dane żądania: "+err.Error())
		return false
	}
	return true
}
