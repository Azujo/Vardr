// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"time"
)

// Profile to profil uprawnień (moduł → poziom). Uprawnienia profili
// wbudowanych uzupełnia kod (perm.BuiltinSet).
type Profile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Permissions map[string]string `json:"permissions"`
	Builtin     bool              `json:"builtin"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedBy   string            `json:"updated_by"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Profiles zwraca wszystkie profile (wbudowane pierwsze).
func (s *PG) Profiles(ctx context.Context) ([]Profile, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description, permissions, builtin, created_by, created_at, updated_by, updated_at
		FROM profiles ORDER BY builtin DESC, lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		var p Profile
		var raw []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &raw, &p.Builtin, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &p.Permissions); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveProfile tworzy albo zmienia profil (nie wbudowany).
func (s *PG) SaveProfile(ctx context.Context, p Profile, by string, now time.Time) error {
	perms, err := json.Marshal(p.Permissions)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO profiles (id, name, description, permissions, created_by, created_at, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $5, $6)
		ON CONFLICT (id) DO UPDATE SET name = $2, description = $3, permissions = $4, updated_by = $5, updated_at = $6
		WHERE NOT profiles.builtin`, p.ID, p.Name, p.Description, perms, by, now)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict // profil wbudowany
	}
	return err
}

// DeleteProfile usuwa profil, którego nie ma żadne konto.
func (s *PG) DeleteProfile(ctx context.Context, id string) error {
	var used int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = $1`, id).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return ErrConflict
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM profiles WHERE id = $1 AND NOT builtin`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ProfileUsers liczy konta z każdym profilem.
func (s *PG) ProfileUsers(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT role, count(*) FROM users GROUP BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
