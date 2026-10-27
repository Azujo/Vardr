// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// MFA to stan drugiego składnika konta (sekret zaszyfrowany).
type MFA struct {
	SecretEnc    []byte
	EnabledAt    time.Time
	LastStep     int64
	RecoveryLeft int
}

// MFAState zwraca drugi składnik konta; ErrNotFound – konto go nie ma.
func (s *PG) MFAState(ctx context.Context, userID int64) (MFA, error) {
	var m MFA
	err := s.pool.QueryRow(ctx, `SELECT m.secret_enc, m.enabled_at, m.last_step,
			(SELECT count(*) FROM user_recovery_codes c WHERE c.user_id = m.user_id AND c.used_at IS NULL)
		FROM user_mfa m WHERE m.user_id = $1`, userID).Scan(&m.SecretEnc, &m.EnabledAt, &m.LastStep, &m.RecoveryLeft)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// MFAEnabledUsers zwraca konta z włączonym drugim składnikiem (lista kont w panelu).
func (s *PG) MFAEnabledUsers(ctx context.Context) (map[int64]time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id, enabled_at FROM user_mfa`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]time.Time{}
	for rows.Next() {
		var id int64
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = at
	}
	return out, rows.Err()
}

// EnableMFA zapisuje sekret i nowe kody zapasowe (zastępuje poprzednie).
func (s *PG) EnableMFA(ctx context.Context, userID int64, secretEnc []byte, step int64, codeHashes []string, now time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO user_mfa (user_id, secret_enc, enabled_at, last_step) VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id) DO UPDATE SET secret_enc = $2, enabled_at = $3, last_step = $4`, userID, secretEnc, now, step); err != nil {
			return err
		}
		return replaceCodes(ctx, tx, userID, codeHashes)
	})
}

// ReplaceRecoveryCodes wymienia kody zapasowe konta.
func (s *PG) ReplaceRecoveryCodes(ctx context.Context, userID int64, codeHashes []string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return replaceCodes(ctx, tx, userID, codeHashes) })
}

func replaceCodes(ctx context.Context, tx pgx.Tx, userID int64, codeHashes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

// DisableMFA usuwa drugi składnik konta: TOTP, kody zapasowe i klucze WebAuthn.
func (s *PG) DisableMFA(ctx context.Context, userID int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, q := range []string{`DELETE FROM user_mfa WHERE user_id = $1`, `DELETE FROM user_recovery_codes WHERE user_id = $1`,
			`DELETE FROM user_webauthn WHERE user_id = $1`} {
			if _, err := tx.Exec(ctx, q, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

// AdvanceMFAStep zapisuje krok przyjętego kodu – tylko gdy jest późniejszy
// od zapisanego (równoległe logowania tym samym kodem: przejdzie jedno).
func (s *PG) AdvanceMFAStep(ctx context.Context, userID, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_mfa SET last_step = $2 WHERE user_id = $1 AND last_step < $2`, userID, step)
	return tag.RowsAffected() == 1, err
}

// UseRecoveryCode zużywa kod zapasowy (raz); zwraca liczbę pozostałych.
func (s *PG) UseRecoveryCode(ctx context.Context, userID int64, codeHash string, now time.Time) (bool, int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_recovery_codes SET used_at = $3 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, codeHash, now)
	if err != nil || tag.RowsAffected() == 0 {
		return false, 0, err
	}
	var left int
	err = s.pool.QueryRow(ctx, `SELECT count(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&left)
	return true, left, err
}

// MarkSessionMFA oznacza sesję jako potwierdzoną drugim składnikiem.
func (s *PG) MarkSessionMFA(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET mfa = true WHERE id = $1`, id)
	return err
}

// Setting zwraca ustawienie panelu; ErrNotFound – nieustawione.
func (s *PG) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, `SELECT value FROM panel_settings WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting zapisuje ustawienie panelu.
func (s *PG) SetSetting(ctx context.Context, key, value, by string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO panel_settings (key, value, changed_by, changed_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET value = $2, changed_by = $3, changed_at = $4`, key, value, by, now)
	return err
}
