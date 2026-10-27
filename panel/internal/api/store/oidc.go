// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"time"
)

// SourceOIDC: konto z dostawcy tożsamości OIDC (Entra ID) – bez hasła w panelu.
const SourceOIDC = "oidc"

// UpsertOIDCUser zakłada albo aktualizuje konto dostawcy tożsamości
// (po external_id – zmiana nazwy konta u dostawcy nie tworzy drugiego).
func (s *PG) UpsertOIDCUser(ctx context.Context, u User) (User, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO users (username, display_name, password_hash, role, must_change_password, source, external_id)
		VALUES ($1, $2, '!oidc', $3, false, 'oidc', $4)
		ON CONFLICT (external_id) WHERE external_id IS NOT NULL DO UPDATE SET username = $1, display_name = $2, role = $3,
			updated_at = now()
		RETURNING `+userCols, u.Username, u.DisplayName, u.Role, u.ExternalID)
	created, err := scanUser(row)
	if isUniqueViolation(err) {
		return created, ErrConflict
	}
	return created, err
}

// SetSessionReauth zapisuje potwierdzenie tożsamości u dostawcy w sesji.
func (s *PG) SetSessionReauth(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET reauth_at = $2 WHERE id = $1`, id, at)
	return err
}
