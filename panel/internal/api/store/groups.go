// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"siem/internal/contract"
)

// ErrInUse: grupy z agentami albo grupy domyślnej nie można usunąć.
var ErrInUse = errors.New("grupa jest w użyciu")

// AgentGroup to grupa agentów z profilem zdarzeń i limitami.
type AgentGroup struct {
	ID          int64                `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Profile     string               `json:"profile"`
	Limits      contract.AgentLimits `json:"limits"`
	IsDefault   bool                 `json:"is_default"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Agents      int                  `json:"agents"` // liczba przypisanych agentów
}

// Config zwraca konfigurację agenta wynikającą z grupy.
func (g AgentGroup) Config() contract.AgentConfig {
	c := contract.AgentConfig{GroupID: g.ID, Group: g.Name, Profile: g.Profile, Limits: g.Limits}
	c.Version = c.ComputeVersion()
	return c
}

const groupCols = `g.id, g.name, g.description, g.profile, g.limits, g.is_default, g.created_at, g.updated_at`

func scanGroup(row pgx.Row, withCount bool) (AgentGroup, error) {
	var g AgentGroup
	var limits []byte
	dest := []any{&g.ID, &g.Name, &g.Description, &g.Profile, &limits, &g.IsDefault, &g.CreatedAt, &g.UpdatedAt}
	if withCount {
		dest = append(dest, &g.Agents)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return g, ErrNotFound
		}
		return g, err
	}
	err := json.Unmarshal(limits, &g.Limits)
	return g, err
}

// isFKViolation: naruszenie klucza obcego – 23503 (foreign_key_violation)
// albo 23001 (restrict_violation przy ON DELETE RESTRICT).
func isFKViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "23503" || pg.Code == "23001")
}

// ListGroups zwraca grupy z liczbą agentów (domyślna: agenci bez przypisania).
func (s *PG) ListGroups(ctx context.Context) ([]AgentGroup, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+groupCols+`,
			CASE WHEN g.is_default
				THEN (SELECT count(*) FROM agents a LEFT JOIN agent_assignments x ON x.agent_id = a.id
				      WHERE x.agent_id IS NULL OR x.group_id = g.id)
				ELSE (SELECT count(*) FROM agent_assignments x WHERE x.group_id = g.id) END
		FROM agent_groups g ORDER BY g.is_default DESC, lower(g.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentGroup
	for rows.Next() {
		g, err := scanGroup(rows, true)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupByID zwraca grupę.
func (s *PG) GroupByID(ctx context.Context, id int64) (AgentGroup, error) {
	return scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM agent_groups g WHERE g.id = $1`, id), false)
}

// CreateGroup tworzy grupę.
func (s *PG) CreateGroup(ctx context.Context, g AgentGroup) (AgentGroup, error) {
	limits, _ := json.Marshal(g.Limits)
	created, err := scanGroup(s.pool.QueryRow(ctx, `INSERT INTO agent_groups AS g (name, description, profile, limits)
		VALUES ($1, $2, $3, $4) RETURNING `+groupCols, g.Name, g.Description, g.Profile, limits), false)
	if isUniqueViolation(err) {
		return created, ErrConflict
	}
	return created, err
}

// UpdateGroup zmienia nazwę, opis, profil i limity.
func (s *PG) UpdateGroup(ctx context.Context, g AgentGroup) (AgentGroup, error) {
	limits, _ := json.Marshal(g.Limits)
	updated, err := scanGroup(s.pool.QueryRow(ctx, `UPDATE agent_groups AS g SET name = $2, description = $3, profile = $4,
		limits = $5, updated_at = now() WHERE g.id = $1 RETURNING `+groupCols, g.ID, g.Name, g.Description, g.Profile, limits), false)
	if isUniqueViolation(err) {
		return updated, ErrConflict
	}
	return updated, err
}

// DeleteGroup usuwa pustą, niedomyślną grupę.
func (s *PG) DeleteGroup(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agent_groups WHERE id = $1 AND NOT is_default`, id)
	if isFKViolation(err) {
		return ErrInUse
	}
	if err == nil && tag.RowsAffected() == 0 {
		var isDefault bool
		if s.pool.QueryRow(ctx, `SELECT is_default FROM agent_groups WHERE id = $1`, id).Scan(&isDefault) == nil {
			return ErrInUse
		}
		return ErrNotFound
	}
	return err
}

// AssignAgent przypisuje agenta do grupy.
func (s *PG) AssignAgent(ctx context.Context, agentID string, groupID int64) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_assignments (agent_id, group_id) VALUES ($1, $2)
		ON CONFLICT (agent_id) DO UPDATE SET group_id = EXCLUDED.group_id, updated_at = now()`, agentID, groupID)
	if isFKViolation(err) {
		return ErrNotFound
	}
	return err
}

// GroupForAgent zwraca grupę agenta (domyślną, gdy nie jest przypisany).
func (s *PG) GroupForAgent(ctx context.Context, agentID string) (AgentGroup, error) {
	return scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM agent_groups g
		LEFT JOIN agent_assignments x ON x.agent_id = $1
		WHERE (x.group_id IS NOT NULL AND g.id = x.group_id) OR (x.group_id IS NULL AND g.is_default)
		LIMIT 1`, agentID), false)
}

// AgentGroupIDs zwraca przypisania wszystkich agentów (agent → grupa).
func (s *PG) AgentGroupIDs(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, group_id FROM agent_assignments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var g int64
		if err := rows.Scan(&id, &g); err != nil {
			return nil, err
		}
		out[id] = g
	}
	return out, rows.Err()
}
