package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"siem/internal/urd"
)

// ArchiveReader to odczyt stanu archiwum NIS2 (Urd, implementuje urd.PG).
type ArchiveReader interface {
	Overview(ctx context.Context) (urd.Overview, error)
	RecentManifests(ctx context.Context, limit int) ([]urd.ManifestRecord, error)
	Verifications(ctx context.Context, limit int) ([]urd.Verification, error)
	RequestVerify(ctx context.Context, by string, at time.Time) error
	CreateExport(ctx context.Context, by, reason string, from, to time.Time) (urd.ExportJob, error)
	Exports(ctx context.Context, limit int) ([]urd.ExportJob, error)
	ExportByID(ctx context.Context, id int64) (urd.ExportJob, error)
	CreateReplay(ctx context.Context, by, reason string, from, to time.Time, agents []string) (urd.ReplayJob, error)
	Replays(ctx context.Context, limit int) ([]urd.ReplayJob, error)
}

// Stan zgodności archiwum (pole compliance).
const (
	complianceOK            = "ok"             // archiwizator działa, ostatnia weryfikacja zgodna i aktualna
	complianceProblems      = "problems"       // ostatnia weryfikacja wykryła niezgodności
	complianceDown          = "archiver_down"  // brak sygnału archiwizatora
	complianceDiskFull      = "disk_full"      // archiwizacja wstrzymana z braku miejsca
	complianceDiskLow       = "disk_low"       // mniej niż 15% wolnego miejsca
	complianceStale         = "stale"          // weryfikacja dawno nie przeszła
	complianceNeverVerified = "never_verified" // archiwizator działa, weryfikacji jeszcze nie było
	complianceNotConfigured = "not_configured" // archiwizator nigdy nie działał
)

// archiverDownAfter: archiwizator zapisuje stan co minutę.
const archiverDownAfter = 3 * time.Minute

func compliance(o urd.Overview, now time.Time) string {
	switch {
	case o.State == nil:
		return complianceNotConfigured
	case o.LastVerification != nil && !o.LastVerification.OK:
		return complianceProblems
	case now.Sub(o.State.HeartbeatAt) > archiverDownAfter:
		return complianceDown
	case o.State.Paused != "":
		return complianceDiskFull
	case o.State.DiskTotalBytes > 0 && float64(o.State.DiskFreeBytes) < 0.15*float64(o.State.DiskTotalBytes):
		return complianceDiskLow
	case o.LastVerification == nil:
		return complianceNeverVerified
	case now.Sub(o.LastVerification.FinishedAt) > 2*time.Duration(o.State.VerifyEveryS)*time.Second+time.Hour:
		return complianceStale
	}
	return complianceOK
}

func (s *Server) archiveEnabled(w http.ResponseWriter) bool {
	if s.Archive == nil {
		writeError(w, http.StatusServiceUnavailable, "archive_disabled", "podgląd archiwum wyłączony w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) archiveOverview(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	ctx := r.Context()
	o, err := s.Archive.Overview(ctx)
	if errors.Is(err, urd.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"compliance": complianceNotConfigured})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	manifests, err := s.Archive.RecentManifests(ctx, 72)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	verifs, err := s.Archive.Verifications(ctx, 20)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if manifests == nil {
		manifests = []urd.ManifestRecord{}
	}
	if verifs == nil {
		verifs = []urd.Verification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"compliance":        compliance(o, s.now()),
		"archiver":          o.State,
		"archiver_running":  o.State != nil && s.now().Sub(o.State.HeartbeatAt) <= archiverDownAfter,
		"summary":           o.Summary,
		"last_verification": o.LastVerification,
		"manifests":         manifests,
		"verifications":     verifs,
	})
}

func (s *Server) archiveVerify(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	err := s.Archive.RequestVerify(r.Context(), a.user.Username, s.now())
	if errors.Is(err, urd.ErrNotConfigured) {
		writeError(w, http.StatusConflict, "archive_not_configured", "archiwizator jeszcze nie działał – nie ma czego weryfikować")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_verify_requested", "urd", nil)
	writeJSON(w, http.StatusAccepted, map[string]any{"message": "weryfikacja zlecona – archiwizator rozpocznie ją w ciągu minuty"})
}

type exportRequest struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

func (s *Server) listExports(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	jobs, err := s.Archive.Exports(r.Context(), 50)
	if errors.Is(err, urd.ErrNotConfigured) {
		jobs, err = nil, nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if jobs == nil {
		jobs = []urd.ExportJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": jobs, "downloads": s.ExportDir != ""})
}

// createExport składa zlecenie eksportu dla audytora: pełne godziny
// archiwizacji [from, to), z obowiązkowym powodem (audyt dostępu).
func (s *Server) createExport(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	var req exportRequest
	if !readJSON(w, r, &req) {
		return
	}
	from, to := req.From.UTC().Truncate(time.Hour), req.To.UTC().Truncate(time.Hour)
	if req.To.After(to) {
		to = to.Add(time.Hour) // koniec zakresu zaokrąglany w górę do pełnej godziny
	}
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case req.From.IsZero() || req.To.IsZero() || !to.After(from):
		writeError(w, http.StatusBadRequest, "bad_range", "podaj początek i koniec zakresu (koniec po początku)")
		return
	case to.Sub(from) > urd.MaxExportRange:
		writeError(w, http.StatusBadRequest, "bad_range", "zakres eksportu może mieć najwyżej 31 dni")
		return
	case to.After(s.now().UTC().Truncate(time.Hour).Add(time.Hour)):
		writeError(w, http.StatusBadRequest, "bad_range", "zakres nie może sięgać w przyszłość")
		return
	case len([]rune(req.Reason)) < 5 || len(req.Reason) > 1000:
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód eksportu (5–1000 znaków) – trafi do audytu i do paczki")
		return
	}
	j, err := s.Archive.CreateExport(r.Context(), a.user.Username, req.Reason, from, to)
	if errors.Is(err, urd.ErrNotConfigured) {
		writeError(w, http.StatusConflict, "archive_not_configured", "archiwizator jeszcze nie działał – nie ma czego eksportować")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_export_requested", "urd", map[string]any{
		"export_id": j.ID, "from": from, "to": to, "reason": req.Reason})
	writeJSON(w, http.StatusAccepted, map[string]any{"export": j})
}

// downloadExport wydaje gotową paczkę (tylko administrator, z audytem).
func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	if s.ExportDir == "" {
		writeError(w, http.StatusServiceUnavailable, "exports_disabled", "pobieranie eksportów wyłączone – brak SIEM_ARCHIVE_EXPORT_DIR w siem-api")
		return
	}
	a := current(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	j, err := s.Archive.ExportByID(r.Context(), id)
	if errors.Is(err, urd.ErrExportNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego eksportu")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if j.Status != urd.ExportDone || !urd.ValidExportName(j.FileName) {
		writeError(w, http.StatusConflict, "export_not_ready", "eksport nie jest gotowy do pobrania")
		return
	}
	f, err := os.Open(filepath.Join(s.ExportDir, j.FileName))
	if err != nil {
		writeError(w, http.StatusGone, "export_missing", "plik eksportu jest niedostępny (usunięty po terminie?)")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_export_downloaded", "urd", map[string]any{
		"export_id": j.ID, "file": j.FileName, "sha256": j.SHA256, "bytes": st.Size()})
	// Paczka może mieć wiele GB – bez limitu czasu zapisu serwera.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="`+j.FileName+`"`)
	w.Header().Set("X-Content-SHA256", j.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, j.FileName, st.ModTime(), f)
}

type replayRequest struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Agents []string  `json:"agents"`
	Reason string    `json:"reason"`
}

func (s *Server) listReplays(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	jobs, err := s.Archive.Replays(r.Context(), 50)
	if errors.Is(err, urd.ErrNotConfigured) {
		jobs, err = nil, nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if jobs == nil {
		jobs = []urd.ReplayJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"replays": jobs})
}

// createReplay zleca odtworzenie paczek z archiwum do osobnej tabeli
// (siem.events_replay) – np. do analizy danych starszych niż retencja
// bazy zdarzeń. Wymaga powodu (audyt dostępu do archiwum).
func (s *Server) createReplay(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	var req replayRequest
	if !readJSON(w, r, &req) {
		return
	}
	from, to := req.From.UTC().Truncate(time.Hour), req.To.UTC().Truncate(time.Hour)
	if req.To.After(to) {
		to = to.Add(time.Hour)
	}
	req.Reason = strings.TrimSpace(req.Reason)
	agents := make([]string, 0, len(req.Agents))
	for _, ag := range req.Agents {
		if ag = strings.TrimSpace(ag); ag != "" && !slices.Contains(agents, ag) {
			agents = append(agents, ag)
		}
	}
	switch {
	case req.From.IsZero() || req.To.IsZero() || !to.After(from):
		writeError(w, http.StatusBadRequest, "bad_range", "podaj początek i koniec zakresu (koniec po początku)")
		return
	case to.Sub(from) > urd.MaxExportRange:
		writeError(w, http.StatusBadRequest, "bad_range", "zakres odtworzenia może mieć najwyżej 31 dni")
		return
	case len(agents) > 100:
		writeError(w, http.StatusBadRequest, "bad_agents", "najwyżej 100 agentów w jednym zleceniu")
		return
	case len([]rune(req.Reason)) < 5 || len(req.Reason) > 1000:
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód odtworzenia (5–1000 znaków) – trafi do audytu")
		return
	}
	j, err := s.Archive.CreateReplay(r.Context(), a.user.Username, req.Reason, from, to, agents)
	if errors.Is(err, urd.ErrNotConfigured) {
		writeError(w, http.StatusConflict, "archive_not_configured", "archiwizator jeszcze nie działał – nie ma czego odtwarzać")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_replay_requested", "urd", map[string]any{
		"replay_id": j.ID, "from": from, "to": to, "agents": agents, "reason": req.Reason})
	writeJSON(w, http.StatusAccepted, map[string]any{"replay": j})
}
