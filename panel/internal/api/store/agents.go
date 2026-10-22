// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent to agent znany panelowi (ostatni heartbeat).
type Agent struct {
	ID           string          `json:"id"`
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Version      string          `json:"version"`
	RemoteIP     string          `json:"remote_ip"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CertNotAfter *time.Time      `json:"cert_not_after,omitempty"`
	CertSerial   string          `json:"cert_serial"`
	Status       json.RawMessage `json:"status"`
	// CertRevoked: ostatni certyfikat agenta unieważniony (agent wycofany –
	// odinstalowany tokenem albo unieważniony w panelu). Tylko odczyt.
	CertRevoked bool `json:"cert_revoked"`
}

// UpsertAgents zapisuje heartbeaty jednym przebiegiem. Starszy heartbeat,
// który dotarł później (np. ponowne dostarczenie), nie nadpisuje nowszego.
func (s *PG) UpsertAgents(ctx context.Context, agents []Agent) error {
	if len(agents) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, a := range agents {
		status := a.Status
		if len(status) == 0 {
			status = json.RawMessage("{}")
		}
		b.Queue(`INSERT INTO agents (id, hostname, os, version, remote_ip, first_seen, last_seen, started_at, cert_not_after, cert_serial, status)
			VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				hostname = EXCLUDED.hostname, os = EXCLUDED.os, version = EXCLUDED.version, remote_ip = EXCLUDED.remote_ip,
				last_seen = EXCLUDED.last_seen, started_at = EXCLUDED.started_at, cert_not_after = EXCLUDED.cert_not_after,
				cert_serial = EXCLUDED.cert_serial, status = EXCLUDED.status
			WHERE agents.last_seen <= EXCLUDED.last_seen`,
			a.ID, a.Hostname, a.OS, a.Version, a.RemoteIP, a.LastSeen, a.StartedAt, a.CertNotAfter, a.CertSerial, []byte(status))
	}
	return s.pool.SendBatch(ctx, b).Close()
}

const agentCols = `id, hostname, os, version, remote_ip, first_seen, last_seen, started_at, cert_not_after, cert_serial, status,
	EXISTS (SELECT 1 FROM agent_certs c WHERE c.serial = agents.cert_serial AND c.revoked_at IS NOT NULL)`

func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	var status []byte
	err := row.Scan(&a.ID, &a.Hostname, &a.OS, &a.Version, &a.RemoteIP, &a.FirstSeen, &a.LastSeen,
		&a.StartedAt, &a.CertNotAfter, &a.CertSerial, &status, &a.CertRevoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	a.Status = status
	return a, err
}

// ListAgents zwraca wszystkich agentów (z pełnym statusem – panel liczy podsumowanie).
func (s *PG) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentByID zwraca agenta.
func (s *PG) AgentByID(ctx context.Context, id string) (Agent, error) {
	return scanAgent(s.pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE id = $1`, id))
}

// DeleteAgent usuwa agenta z listy (np. wycofany komputer). Kolejny
// heartbeat doda go ponownie.
func (s *PG) DeleteAgent(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
