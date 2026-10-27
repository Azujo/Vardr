// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// WebAuthnKey to klucz bezpieczeństwa albo passkey konta.
type WebAuthnKey struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"-"`
	CredentialID []byte     `json:"-"`
	PublicKey    []byte     `json:"-"`
	Alg          int        `json:"alg"`
	RPID         string     `json:"rp_id"`
	Name         string     `json:"name"`
	AAGUID       []byte     `json:"-"`
	SignCount    uint32     `json:"-"`
	UV           bool       `json:"uv"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// MaxWebAuthnKeys: najwięcej kluczy na konto.
const MaxWebAuthnKeys = 10

// WebAuthnKeys zwraca klucze konta (od najstarszego).
func (s *PG) WebAuthnKeys(ctx context.Context, userID int64) ([]WebAuthnKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, user_id, credential_id, public_key, alg, rp_id, name, aaguid, sign_count, uv,
			created_at, last_used_at FROM user_webauthn WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebAuthnKey{}
	for rows.Next() {
		var k WebAuthnKey
		var count int64
		if err := rows.Scan(&k.ID, &k.UserID, &k.CredentialID, &k.PublicKey, &k.Alg, &k.RPID, &k.Name, &k.AAGUID, &count, &k.UV,
			&k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		k.SignCount = uint32(count)
		out = append(out, k)
	}
	return out, rows.Err()
}

// AddWebAuthnKey zapisuje klucz (najwyżej MaxWebAuthnKeys na konto);
// ErrConflict – ten klucz jest już zarejestrowany albo limit osiągnięty.
func (s *PG) AddWebAuthnKey(ctx context.Context, k WebAuthnKey) (int64, error) {
	var id int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Blokada konta: równoległe rejestracje nie przekroczą limitu.
		if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, k.UserID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_webauthn WHERE user_id = $1`, k.UserID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxWebAuthnKeys {
			return ErrConflict
		}
		return tx.QueryRow(ctx, `INSERT INTO user_webauthn (user_id, credential_id, public_key, alg, rp_id, name, aaguid, sign_count, uv, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (credential_id) DO NOTHING RETURNING id`,
			k.UserID, k.CredentialID, k.PublicKey, k.Alg, k.RPID, k.Name, k.AAGUID, int64(k.SignCount), k.UV, k.CreatedAt).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	return id, err
}

// UseWebAuthnKey zapisuje licznik po logowaniu – tylko gdy rośnie (albo
// klucz nie ma licznika); false: równoległe użycie tego samego podpisu.
func (s *PG) UseWebAuthnKey(ctx context.Context, id int64, signCount uint32, uv bool, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_webauthn SET sign_count = $2, uv = uv OR $3, last_used_at = $4
		WHERE id = $1 AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`, id, int64(signCount), uv, now)
	return tag.RowsAffected() == 1, err
}

// DeleteWebAuthnKey usuwa klucz konta; ErrNotFound – nie ma takiego.
func (s *PG) DeleteWebAuthnKey(ctx context.Context, userID, id int64) (WebAuthnKey, error) {
	var k WebAuthnKey
	err := s.pool.QueryRow(ctx, `DELETE FROM user_webauthn WHERE user_id = $1 AND id = $2 RETURNING id, name`, userID, id).Scan(&k.ID, &k.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// WebAuthnCounts zwraca liczbę kluczy kont (lista kont w panelu).
func (s *PG) WebAuthnCounts(ctx context.Context) (map[int64]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id, count(*) FROM user_webauthn GROUP BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
