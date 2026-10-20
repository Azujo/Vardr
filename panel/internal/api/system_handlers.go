package api

import (
	"context"
	"net/http"
	"time"

	"siem/panel/internal/status"
)

// StatusReporter to stan systemu (implementuje status.Prometheus).
type StatusReporter interface {
	Report(ctx context.Context, now time.Time) status.Report
}

// systemStatus: zdrowie usług Vardra (Prometheus) dla strony „Stan systemu”.
func (s *Server) systemStatus(w http.ResponseWriter, r *http.Request) {
	if s.Status == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "grafana_url": s.GrafanaURL})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "report": s.Status.Report(ctx, s.now()),
		"grafana_url": s.GrafanaURL})
}
