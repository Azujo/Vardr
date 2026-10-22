// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "context"

// UpsertLDAPUser zakłada albo aktualizuje konto domenowe (po SID): login,
// nazwa, DN i profil z AD. Wyłączenia konta w panelu nie zdejmuje – to
// decyzja administratora panelu. ErrConflict: login zajęty przez konto
// lokalne albo inne konto domenowe.
func (s *PG) UpsertLDAPUser(ctx context.Context, u User) (User, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO users (username, display_name, password_hash, role, must_change_password, source, external_id, ldap_dn)
		VALUES ($1, $2, '!ldap', $3, false, 'ldap', $4, $5)
		ON CONFLICT (external_id) WHERE external_id IS NOT NULL DO UPDATE SET username = $1, display_name = $2, role = $3, ldap_dn = $5,
			updated_at = now()
		RETURNING `+userCols, u.Username, u.DisplayName, u.Role, u.ExternalID, u.LDAPDN)
	created, err := scanUser(row)
	if isUniqueViolation(err) {
		return created, ErrConflict
	}
	return created, err
}

// UserByExternalID zwraca konto domenowe po SID.
func (s *PG) UserByExternalID(ctx context.Context, sid string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE external_id = $1`, sid))
}
