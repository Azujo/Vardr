// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// grafanaPayload to część powiadomienia webhook Grafany (Alerting).
type grafanaPayload struct {
	Status string `json:"status"`
	Alerts []struct {
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"startsAt"`
		EndsAt      time.Time         `json:"endsAt"`
	} `json:"alerts"`
}

// GrafanaHandler przyjmuje powiadomienia z Grafany (punkt kontaktowy typu
// webhook z tokenem) i przekazuje je na kanały subskrybujące alerty zdrowia.
// Dzięki temu adres Discorda ustawia się tylko w panelu, a Grafana zna
// jedynie wewnętrzny adres siem-api.
func (s *Service) GrafanaHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "tylko POST", http.StatusMethodNotAllowed)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "brak uprawnień", http.StatusUnauthorized)
			return
		}
		var p grafanaPayload
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
			http.Error(w, "niepoprawne dane", http.StatusBadRequest)
			return
		}
		for _, m := range grafanaMessages(p, s.now()) {
			if _, err := s.Send(r.Context(), m); err != nil {
				// Grafana ponowi wysyłkę przy kolejnej ocenie reguły.
				http.Error(w, "wysyłka nieudana", http.StatusBadGateway)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// grafanaMessages: jedna wiadomość na alert (najwyżej 10 w powiadomieniu).
func grafanaMessages(p grafanaPayload, now time.Time) []Message {
	var out []Message
	for i, a := range p.Alerts {
		if i == 10 {
			out = append(out, Message{Event: EventHealth, Severity: SevWarning, At: now,
				Title: fmt.Sprintf("… i %d kolejnych alertów – szczegóły w Grafanie", len(p.Alerts)-10)})
			break
		}
		summary := a.Annotations["summary"]
		if summary == "" {
			summary = a.Labels["alertname"]
		}
		m := Message{Event: EventHealth, At: now, Text: a.Annotations["description"]}
		if a.Status == "resolved" {
			m.Severity, m.Title = SevOK, "Rozwiązane: "+summary
			if !a.EndsAt.IsZero() {
				m.Fields = append(m.Fields, Field{Name: "Koniec", Value: a.EndsAt.Local().Format("2006-01-02 15:04"), Inline: true})
			}
		} else {
			m.Severity = SevWarning
			if a.Labels["severity"] == "critical" {
				m.Severity = SevCritical
			}
			m.Title = summary
		}
		if !a.StartsAt.IsZero() {
			m.Fields = append(m.Fields, Field{Name: "Początek", Value: a.StartsAt.Local().Format("2006-01-02 15:04"), Inline: true})
		}
		if sev := a.Labels["severity"]; sev != "" {
			m.Fields = append(m.Fields, Field{Name: "Waga", Value: sev, Inline: true})
		}
		out = append(out, m)
	}
	return out
}
