package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"siem/internal/contract"
)

// UninstallToken to token deinstalacji agenta (bez samego tokenu – panel
// pokazuje go tylko przy wygenerowaniu).
type UninstallToken struct {
	ID         int64      `json:"id"`
	AgentID    string     `json:"agent_id"`
	TokenID    string     `json:"token_id"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	UsedAction string     `json:"used_action,omitempty"`
	UsedBy     string     `json:"used_by,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
	State      string     `json:"state"` // active | used | revoked | expired
}

// CreateUninstallToken zapisuje nowy token agenta i unieważnia jego
// poprzednie niewykorzystane tokeny (ważny jest jeden naraz).
func (s *PG) CreateUninstallToken(ctx context.Context, agentID, hash, reason, by string, expires time.Time) (UninstallToken, error) {
	var t UninstallToken
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE agent_uninstall_tokens SET revoked_at = now(), revoked_by = $2
			WHERE agent_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, agentID, by); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO agent_uninstall_tokens (agent_id, token_id, hash, reason, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
			agentID, contract.UninstallTokenID(hash), hash, reason, by, expires).Scan(&t.ID, &t.CreatedAt)
	})
	t.AgentID, t.TokenID, t.Reason, t.CreatedBy, t.ExpiresAt, t.State = agentID, contract.UninstallTokenID(hash), reason, by, expires, "active"
	return t, err
}

// UninstallTokens zwraca tokeny agenta (najnowsze najpierw, najwyżej 20).
func (s *PG) UninstallTokens(ctx context.Context, agentID string, now time.Time) ([]UninstallToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, agent_id, token_id, reason, created_by, created_at, expires_at, used_at, used_action,
		used_by, revoked_at, revoked_by FROM agent_uninstall_tokens WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 20`, agentID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (UninstallToken, error) {
		var t UninstallToken
		err := r.Scan(&t.ID, &t.AgentID, &t.TokenID, &t.Reason, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.UsedAction,
			&t.UsedBy, &t.RevokedAt, &t.RevokedBy)
		switch {
		case t.UsedAt != nil:
			t.State = "used"
		case t.RevokedAt != nil:
			t.State = "revoked"
		case now.After(t.ExpiresAt):
			t.State = "expired"
		default:
			t.State = "active"
		}
		return t, err
	})
}

// ActiveUninstallTokens: ważne tokeny agenta dla jego konfiguracji.
func (s *PG) ActiveUninstallTokens(ctx context.Context, agentID string) ([]contract.UninstallToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT token_id, hash, expires_at FROM agent_uninstall_tokens
		WHERE agent_id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT $2`, agentID, contract.MaxUninstallTokens)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (contract.UninstallToken, error) {
		var t contract.UninstallToken
		err := r.Scan(&t.ID, &t.Hash, &t.ExpiresAt)
		t.ExpiresAt = t.ExpiresAt.UTC()
		return t, err
	})
}

// RevokeUninstallToken unieważnia token (false – nie ma takiego aktywnego).
func (s *PG) RevokeUninstallToken(ctx context.Context, agentID string, id int64, by string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_uninstall_tokens SET revoked_at = now(), revoked_by = $3
		WHERE id = $2 AND agent_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, agentID, id, by)
	return tag.RowsAffected() > 0, err
}

// TokenUse to użycie tokenu zgłoszone przez agenta (status.protection.events).
type TokenUse struct {
	AgentID string
	TokenID string
	Action  string
	User    string
	At      time.Time
}

// MarkUninstallTokensUsed oznacza tokeny jako użyte (raz – pierwsze
// zgłoszenie) i zwraca te, które oznaczyło teraz: token wydany w panelu dla
// tego agenta i jeszcze nieużyty. Ponowne zgłoszenie (kolejny heartbeat
// z tym samym zdarzeniem) i token spoza panelu nic nie zwracają.
func (s *PG) MarkUninstallTokensUsed(ctx context.Context, uses []TokenUse) ([]TokenUse, error) {
	if len(uses) == 0 {
		return nil, nil
	}
	b := &pgx.Batch{}
	for _, u := range uses {
		b.Queue(`UPDATE agent_uninstall_tokens SET used_at = $3, used_action = $4, used_by = left($5, 200)
			WHERE agent_id = $1 AND token_id = $2 AND used_at IS NULL`, u.AgentID, u.TokenID, u.At, u.Action, u.User)
	}
	br := s.pool.SendBatch(ctx, b)
	var applied []TokenUse
	for _, u := range uses {
		tag, err := br.Exec()
		if err != nil {
			br.Close()
			return applied, err
		}
		if tag.RowsAffected() > 0 {
			applied = append(applied, u)
		}
	}
	return applied, br.Close()
}
