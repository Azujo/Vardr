// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"siem/internal/risk"
)

// Scoring ryzyka (wersja 1.3): detektor czyta alerty i ustawienia, liczy
// wyniki (internal/risk) i zapisuje je w gjallarhorn.risk_scores; panel
// czyta wyniki i zmienia ustawienia.

// RiskScore to zapisany wynik osoby albo komputera.
type RiskScore struct {
	risk.Score
	LevelSince time.Time `json:"level_since"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RiskConfig zwraca ustawienia scoringu (domyślne, gdy nikt ich nie zmienił).
func (p *PG) RiskConfig(ctx context.Context) (risk.Config, error) {
	var raw []byte
	err := p.pool.QueryRow(ctx, `SELECT config FROM gjallarhorn.risk_config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return risk.Default(), nil
	}
	if err != nil {
		return risk.Config{}, notConfigured(err)
	}
	var c risk.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return risk.Config{}, err
	}
	return c.Normalize(), nil
}

// SetRiskConfig zapisuje ustawienia scoringu (panel).
func (p *PG) SetRiskConfig(ctx context.Context, c risk.Config, by string, now time.Time) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO gjallarhorn.risk_config (id, config, updated_by, updated_at) VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET config = $1, updated_by = $2, updated_at = $3`, raw, by, now)
	return notConfigured(err)
}

// RiskInputs: alerty do scoringu z ostatnim trafieniem od since, z grupą
// agenta (komputery krytyczne). Grupy są w schemacie panelu – bez niego
// (np. testy samych alertów) grupa jest nieznana.
func (p *PG) RiskInputs(ctx context.Context, since time.Time) ([]risk.Input, error) {
	var groups bool
	if err := p.pool.QueryRow(ctx, `SELECT to_regclass('public.agent_assignments') IS NOT NULL`).Scan(&groups); err != nil {
		return nil, err
	}
	q := `SELECT a.id, a.rule_id, a.rule_title, a.level, a.last_seen, a.host_name, a.user_name, a.user_identity, 0::bigint, a.resolution
		FROM gjallarhorn.alerts a WHERE a.last_seen >= $1`
	if groups {
		q = `SELECT a.id, a.rule_id, a.rule_title, a.level, a.last_seen, a.host_name, a.user_name, a.user_identity,
				coalesce(g.group_id, 0), a.resolution
			FROM gjallarhorn.alerts a LEFT JOIN public.agent_assignments g ON g.agent_id = a.agent_id AND a.agent_id <> ''
			WHERE a.last_seen >= $1`
	}
	rows, err := p.pool.Query(ctx, q, since)
	if err != nil {
		return nil, notConfigured(err)
	}
	defer rows.Close()
	var out []risk.Input
	for rows.Next() {
		var in risk.Input
		if err := rows.Scan(&in.AlertID, &in.RuleID, &in.RuleTitle, &in.Level, &in.LastSeen, &in.HostName, &in.UserName,
			&in.UserIdentity, &in.GroupID, &in.Resolution); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// SaveRiskScores zastępuje wyniki nowymi (jedna transakcja) i zwraca
// poprzednie poziomy (typ\x00encja → poziom) – do wykrycia wejścia
// w poziom krytyczny. level_since zostaje, gdy poziom się nie zmienił.
func (p *PG) SaveRiskScores(ctx context.Context, scores []risk.Score, now time.Time) (map[string]string, error) {
	prev := map[string]string{}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		since := map[string]time.Time{}
		rows, err := tx.Query(ctx, `SELECT entity_type, entity, level, level_since FROM gjallarhorn.risk_scores FOR UPDATE`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var typ, ent, lvl string
			var at time.Time
			if err := rows.Scan(&typ, &ent, &lvl, &at); err != nil {
				rows.Close()
				return err
			}
			prev[typ+"\x00"+ent], since[typ+"\x00"+ent] = lvl, at
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gjallarhorn.risk_scores`); err != nil {
			return err
		}
		_, err = tx.CopyFrom(ctx, pgx.Identifier{"gjallarhorn", "risk_scores"},
			[]string{"entity_type", "entity", "display", "score", "level", "alerts", "elevated", "last_alert_at", "top", "level_since", "updated_at"},
			pgx.CopyFromSlice(len(scores), func(i int) ([]any, error) {
				s := scores[i]
				key := s.Type + "\x00" + s.Entity
				ls := now
				if prev[key] == s.Level {
					ls = since[key]
				}
				top, err := json.Marshal(s.Top)
				if err != nil {
					return nil, err
				}
				return []any{s.Type, s.Entity, s.Display, s.Score, s.Level, s.Alerts, s.Elevated, s.LastAlertAt, top, ls, now}, nil
			}))
		return err
	})
	return prev, notConfigured(err)
}

const riskCols = `entity_type, entity, display, score, level, alerts, elevated, last_alert_at, top, level_since, updated_at`

func scanRisk(r pgx.Row) (RiskScore, error) {
	var s RiskScore
	var top []byte
	err := r.Scan(&s.Type, &s.Entity, &s.Display, &s.Score.Score, &s.Level, &s.Alerts, &s.Elevated, &s.LastAlertAt, &top,
		&s.LevelSince, &s.UpdatedAt)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(top, &s.Top); err != nil {
		return s, err
	}
	if s.Top == nil {
		s.Top = []risk.Contribution{}
	}
	return s, nil
}

// RiskScores: wyniki rodzaju typ od najwyższego, od poziomu minLevel ("" – wszystkie).
func (p *PG) RiskScores(ctx context.Context, typ, minLevel string, limit int) ([]RiskScore, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := p.pool.Query(ctx, `SELECT `+riskCols+` FROM gjallarhorn.risk_scores
		WHERE entity_type = $1 AND ($2 = '' OR array_position(ARRAY['low','medium','high','critical'], level)
			>= array_position(ARRAY['low','medium','high','critical'], $2))
		ORDER BY score DESC, entity LIMIT $3`, typ, minLevel, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	defer rows.Close()
	out := []RiskScore{}
	for rows.Next() {
		s, err := scanRisk(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RiskScoreOf: wynik jednej osoby albo komputera (klucz małymi literami).
func (p *PG) RiskScoreOf(ctx context.Context, typ, entity string) (RiskScore, error) {
	s, err := scanRisk(p.pool.QueryRow(ctx, `SELECT `+riskCols+` FROM gjallarhorn.risk_scores WHERE entity_type = $1 AND entity = $2`,
		typ, entity))
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, notConfigured(err)
}

// RiskLevelCounts: liczba osób i komputerów na każdym poziomie (typ → poziom → liczba).
func (p *PG) RiskLevelCounts(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := p.pool.Query(ctx, `SELECT entity_type, level, count(*) FROM gjallarhorn.risk_scores GROUP BY 1, 2`)
	if err != nil {
		return nil, notConfigured(err)
	}
	defer rows.Close()
	out := map[string]map[string]int{risk.User: {}, risk.Host: {}}
	for rows.Next() {
		var typ, lvl string
		var n int
		if err := rows.Scan(&typ, &lvl, &n); err != nil {
			return nil, err
		}
		if out[typ] == nil {
			out[typ] = map[string]int{}
		}
		out[typ][lvl] = n
	}
	return out, rows.Err()
}
