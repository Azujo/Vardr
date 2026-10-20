package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Incident to incydent: grupa alertów z obsługą i – dla poważnych (NIS2) –
// terminami zgłoszeń.
type Incident struct {
	ID          int64      `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Assignee    string     `json:"assignee"`
	Significant bool       `json:"significant"`
	AwareAt     *time.Time `json:"aware_at,omitempty"`
	Malicious   string     `json:"malicious"`
	CrossBorder string     `json:"cross_border"`
	Impact      string     `json:"impact"`
	RootCause   string     `json:"root_cause"`
	Mitigation  string     `json:"mitigation"`
	IOCs        string     `json:"iocs"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	AlertCount  int        `json:"alert_count"`
}

// IncidentAlert to migawka alertu w incydencie.
type IncidentAlert struct {
	AlertID   int64     `json:"alert_id"`
	RuleID    string    `json:"rule_id"`
	RuleTitle string    `json:"rule_title"`
	Level     string    `json:"level"`
	HostName  string    `json:"host_name"`
	AgentID   string    `json:"agent_id"`
	UserName  string    `json:"user_name"`
	Summary   string    `json:"summary"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	AddedBy   string    `json:"added_by"`
	AddedAt   time.Time `json:"added_at"`
}

// IncidentActivity to wpis osi czasu incydentu.
type IncidentActivity struct {
	ID       int64          `json:"id"`
	At       time.Time      `json:"at"`
	Username string         `json:"username"`
	Kind     string         `json:"kind"`
	Text     string         `json:"text"`
	Details  map[string]any `json:"details,omitempty"`
}

// IncidentReport to zgłoszenie do CSIRT (szkic albo wysłane).
type IncidentReport struct {
	Kind        string     `json:"kind"`
	Content     string     `json:"content"`
	UpdatedBy   string     `json:"updated_by"`
	UpdatedAt   time.Time  `json:"updated_at"`
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
	SubmittedBy string     `json:"submitted_by,omitempty"`
	Reference   string     `json:"reference,omitempty"`
}

const incidentCols = `i.id, i.title, i.description, i.severity, i.status, i.assignee, i.significant, i.aware_at, i.malicious,
	i.cross_border, i.impact, i.root_cause, i.mitigation, i.iocs, i.created_by, i.created_at, i.updated_at, i.closed_at,
	(SELECT count(*) FROM incident_alerts a WHERE a.incident_id = i.id)`

func scanIncident(r pgx.Row) (Incident, error) {
	var x Incident
	err := r.Scan(&x.ID, &x.Title, &x.Description, &x.Severity, &x.Status, &x.Assignee, &x.Significant, &x.AwareAt, &x.Malicious,
		&x.CrossBorder, &x.Impact, &x.RootCause, &x.Mitigation, &x.IOCs, &x.CreatedBy, &x.CreatedAt, &x.UpdatedAt, &x.ClosedAt,
		&x.AlertCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, ErrNotFound
	}
	return x, err
}

// CreateIncident zakłada incydent z alertami i pierwszym wpisem osi czasu.
func (s *PG) CreateIncident(ctx context.Context, x Incident, alerts []IncidentAlert, now time.Time) (Incident, error) {
	var id int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO incidents (title, description, severity, assignee, created_by, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id`, x.Title, x.Description, x.Severity, x.Assignee, x.CreatedBy, now).Scan(&id); err != nil {
			return err
		}
		if err := addAlerts(ctx, tx, id, alerts); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO incident_activity (incident_id, at, username, kind, text, details)
			VALUES ($1, $2, $3, 'created', $4, $5)`, id, now, x.CreatedBy, x.Title, map[string]any{"alerts": len(alerts)})
		return err
	})
	if err != nil {
		return Incident{}, err
	}
	return s.Incident(ctx, id)
}

func addAlerts(ctx context.Context, tx pgx.Tx, id int64, alerts []IncidentAlert) error {
	for _, a := range alerts {
		if _, err := tx.Exec(ctx, `INSERT INTO incident_alerts (incident_id, alert_id, rule_id, rule_title, level, host_name, agent_id,
			user_name, summary, first_seen, last_seen, added_by, added_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT DO NOTHING`, id, a.AlertID, a.RuleID, a.RuleTitle, a.Level, a.HostName, a.AgentID, a.UserName, a.Summary,
			a.FirstSeen, a.LastSeen, a.AddedBy, a.AddedAt); err != nil {
			return err
		}
	}
	return nil
}

// Incident zwraca incydent.
func (s *PG) Incident(ctx context.Context, id int64) (Incident, error) {
	return scanIncident(s.pool.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents i WHERE i.id = $1`, id))
}

// Incidents zwraca incydenty: active – niezamknięte, closed – zamknięte, inne – wszystkie.
func (s *PG) Incidents(ctx context.Context, scope string) ([]Incident, error) {
	where := ""
	switch scope {
	case "active":
		where = "WHERE i.status <> 'closed'"
	case "closed":
		where = "WHERE i.status = 'closed'"
	}
	rows, err := s.pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i `+where+` ORDER BY i.updated_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		x, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// UpdateIncident zapisuje pola incydentu (status closed ustawia closed_at)
// i wpisy osi czasu tej zmiany.
func (s *PG) UpdateIncident(ctx context.Context, x Incident, activity []IncidentActivity, now time.Time) (Incident, error) {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE incidents SET title = $2, description = $3, severity = $4, status = $5, assignee = $6,
			significant = $7, aware_at = $8, malicious = $9, cross_border = $10, impact = $11, root_cause = $12, mitigation = $13,
			iocs = $14, updated_at = $15, closed_at = CASE WHEN $5 = 'closed' THEN coalesce(closed_at, $15) ELSE NULL END
			WHERE id = $1 AND status <> 'closed'`, x.ID, x.Title, x.Description, x.Severity, x.Status, x.Assignee, x.Significant, x.AwareAt, x.Malicious,
			x.CrossBorder, x.Impact, x.RootCause, x.Mitigation, x.IOCs, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return closedOrMissing(ctx, tx, x.ID)
		}
		return addActivity(ctx, tx, x.ID, activity)
	})
	if err != nil {
		return Incident{}, err
	}
	return s.Incident(ctx, x.ID)
}

func addActivity(ctx context.Context, tx pgx.Tx, id int64, activity []IncidentActivity) error {
	for _, a := range activity {
		d := a.Details
		if d == nil {
			d = map[string]any{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_activity (incident_id, at, username, kind, text, details)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, a.At, a.Username, a.Kind, a.Text, d); err != nil {
			return err
		}
	}
	return nil
}

// AddIncidentActivity dopisuje wpisy osi czasu (np. notatka) i odświeża updated_at.
func (s *PG) AddIncidentActivity(ctx context.Context, id int64, activity []IncidentActivity, now time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE incidents SET updated_at = $2 WHERE id = $1 AND status <> 'closed'`, id, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return closedOrMissing(ctx, tx, id)
		}
		return addActivity(ctx, tx, id, activity)
	})
}

// AddIncidentEvidence dopisuje do osi czasu zleconą paczkę dowodową – także
// w zamkniętym incydencie (dowody zbiera się i po zamknięciu, np. dla
// audytora); stan incydentu ani updated_at się nie zmieniają.
func (s *PG) AddIncidentEvidence(ctx context.Context, id int64, activity IncidentActivity) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM incidents WHERE id = $1`, id).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		return addActivity(ctx, tx, id, []IncidentActivity{activity})
	})
}

// AddIncidentAlerts dopisuje alerty (istniejące – bez zmian) z wpisem osi czasu.
func (s *PG) AddIncidentAlerts(ctx context.Context, id int64, alerts []IncidentAlert, activity IncidentActivity) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE incidents SET updated_at = $2 WHERE id = $1 AND status <> 'closed'`, id, activity.At)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return closedOrMissing(ctx, tx, id)
		}
		if err := addAlerts(ctx, tx, id, alerts); err != nil {
			return err
		}
		return addActivity(ctx, tx, id, []IncidentActivity{activity})
	})
}

// RemoveIncidentAlert usuwa alert z incydentu (z wpisem osi czasu).
func (s *PG) RemoveIncidentAlert(ctx context.Context, id, alertID int64, activity IncidentActivity) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE incidents SET updated_at = $2 WHERE id = $1 AND status <> 'closed'`, id, activity.At)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return closedOrMissing(ctx, tx, id)
		}
		tag, err = tx.Exec(ctx, `DELETE FROM incident_alerts WHERE incident_id = $1 AND alert_id = $2`, id, alertID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return addActivity(ctx, tx, id, []IncidentActivity{activity})
	})
}

// IncidentAlerts zwraca alerty incydentu (od najwcześniejszego).
func (s *PG) IncidentAlerts(ctx context.Context, id int64) ([]IncidentAlert, error) {
	rows, err := s.pool.Query(ctx, `SELECT alert_id, rule_id, rule_title, level, host_name, agent_id, user_name, summary, first_seen,
		last_seen, added_by, added_at FROM incident_alerts WHERE incident_id = $1 ORDER BY first_seen, alert_id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IncidentAlert])
}

// IncidentActivityLog zwraca oś czasu incydentu.
func (s *PG) IncidentActivityLog(ctx context.Context, id int64) ([]IncidentActivity, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, at, username, kind, text, details FROM incident_activity
		WHERE incident_id = $1 ORDER BY at, id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IncidentActivity])
}

// IncidentReports zwraca zgłoszenia incydentu.
func (s *PG) IncidentReports(ctx context.Context, id int64) ([]IncidentReport, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, content, updated_by, updated_at, submitted_at, submitted_by, reference
		FROM incident_reports WHERE incident_id = $1`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IncidentReport])
}

// ErrSubmitted: zgłoszenie już wysłane – treść zamrożona.
var ErrSubmitted = errors.New("zgłoszenie już wysłane")

// ErrClosed: incydent zamknięty – tylko do odczytu (zamknięcia nie da się cofnąć).
var ErrClosed = errors.New("incydent zamknięty")

// closedOrMissing: po zapisie, który nic nie zmienił – zamknięty albo brak.
func closedOrMissing(ctx context.Context, tx pgx.Tx, id int64) error {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM incidents WHERE id = $1`, id).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return ErrClosed
}

// SaveIncidentReport zapisuje szkic zgłoszenia (wysłanego nie zmienia).
func (s *PG) SaveIncidentReport(ctx context.Context, id int64, kind, content, by string, now time.Time) error {
	if err := s.notClosed(ctx, id); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO incident_reports (incident_id, kind, content, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (incident_id, kind) DO UPDATE SET content = $3, updated_by = $4, updated_at = $5
		WHERE incident_reports.submitted_at IS NULL`, id, kind, content, by, now)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrSubmitted
	}
	return err
}

// SubmitIncidentReport oznacza zgłoszenie jako wysłane do CSIRT (z treścią
// wysłaną w tej chwili) i dopisuje oś czasu.
func (s *PG) SubmitIncidentReport(ctx context.Context, id int64, kind, content, reference, by string, at, now time.Time) error {
	if err := s.notClosed(ctx, id); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO incident_reports (incident_id, kind, content, updated_by, updated_at, submitted_at, submitted_by, reference)
			VALUES ($1, $2, $3, $4, $5, $6, $4, $7)
			ON CONFLICT (incident_id, kind) DO UPDATE SET content = $3, updated_by = $4, updated_at = $5, submitted_at = $6,
				submitted_by = $4, reference = $7
			WHERE incident_reports.submitted_at IS NULL`, id, kind, content, by, now, at, reference)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrSubmitted
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET updated_at = $2 WHERE id = $1`, id, now); err != nil {
			return err
		}
		return addActivity(ctx, tx, id, []IncidentActivity{{At: now, Username: by, Kind: "report_submitted", Text: kind,
			Details: map[string]any{"kind": kind, "reference": reference, "submitted_at": at}}})
	})
}

func (s *PG) notClosed(ctx context.Context, id int64) error {
	var status string
	err := s.pool.QueryRow(ctx, `SELECT status FROM incidents WHERE id = $1`, id).Scan(&status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case status == "closed":
		return ErrClosed
	}
	return nil
}

// IncidentRef to incydent powiązany z alertem.
type IncidentRef struct {
	ID     int64  `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// IncidentsForAlert zwraca incydenty, w których jest alert.
func (s *PG) IncidentsForAlert(ctx context.Context, alertID int64) ([]IncidentRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT i.id, i.title, i.status FROM incidents i JOIN incident_alerts a ON a.incident_id = i.id
		WHERE a.alert_id = $1 ORDER BY i.id`, alertID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IncidentRef])
}

// ReminderSent zapisuje przypomnienie (false – już było).
func (s *PG) ReminderSent(ctx context.Context, id int64, deadline, stage string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO incident_reminders (incident_id, deadline, stage, sent_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, id, deadline, stage, now)
	return tag.RowsAffected() == 1, err
}
