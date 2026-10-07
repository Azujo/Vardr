package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"siem/internal/urd"
)

// ArchiveReader to odczyt stanu archiwum NIS2 (Urd, implementuje urd.PG).
type ArchiveReader interface {
	Overview(ctx context.Context) (urd.Overview, error)
	RecentManifests(ctx context.Context, limit int) ([]urd.ManifestRecord, error)
	Verifications(ctx context.Context, limit int) ([]urd.Verification, error)
	RequestVerify(ctx context.Context, by string, at time.Time) error
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
