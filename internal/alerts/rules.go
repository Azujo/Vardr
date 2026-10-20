package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Override to włączenie albo wyłączenie reguły z panelu (ponad plik).
// Trial: tryb próbny – reguła wyłączona (Enabled = false), ale liczy
// trafienia bez alertów (od ChangedAt).
type Override struct {
	Enabled   bool      `json:"enabled"`
	Trial     bool      `json:"trial,omitempty"`
	Reason    string    `json:"reason"`
	ChangedBy string    `json:"changed_by"`
	ChangedAt time.Time `json:"changed_at"`
}

// RuleVersion to treść reguły w danej wersji.
type RuleVersion struct {
	Version  int       `json:"version"`
	SHA256   string    `json:"sha256"`
	File     string    `json:"file"`
	Source   string    `json:"source"`
	LoadedAt time.Time `json:"loaded_at"`
}

// RuleOverrides zwraca ustawienia reguł z panelu i ich podpis (zmiana
// podpisu = detektor przeładowuje reguły).
func (p *PG) RuleOverrides(ctx context.Context) (map[string]Override, string, error) {
	rows, err := p.pool.Query(ctx, `SELECT rule_id, enabled, trial, reason, changed_by, changed_at FROM gjallarhorn.rule_overrides
		ORDER BY rule_id`)
	if err != nil {
		return nil, "", notConfigured(err)
	}
	out := map[string]Override{}
	var sig strings.Builder
	for rows.Next() {
		var id string
		var o Override
		if err := rows.Scan(&id, &o.Enabled, &o.Trial, &o.Reason, &o.ChangedBy, &o.ChangedAt); err != nil {
			rows.Close()
			return nil, "", err
		}
		out[id] = o
		fmt.Fprintf(&sig, "%s=%t/%t@%d;", id, o.Enabled, o.Trial, o.ChangedAt.UnixNano())
	}
	rows.Close()
	return out, sig.String(), rows.Err()
}

// SetOverride ustawia regułę jako włączoną, wyłączoną albo próbną z panelu.
// Rozpoczęcie próby czyści jej wcześniejsze trafienia (liczenie od zera).
func (p *PG) SetOverride(ctx context.Context, rule string, o Override) error {
	if o.Trial {
		o.Enabled = false
	}
	return notConfigured(pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var wasTrial bool
		err := tx.QueryRow(ctx, `SELECT trial FROM gjallarhorn.rule_overrides WHERE rule_id = $1`, rule).Scan(&wasTrial)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if o.Trial && !wasTrial {
			if _, err := tx.Exec(ctx, `DELETE FROM gjallarhorn.rule_trial_hits WHERE rule_id = $1`, rule); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO gjallarhorn.rule_overrides (rule_id, enabled, trial, reason, changed_by, changed_at)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (rule_id) DO UPDATE SET enabled = $2, trial = $3, reason = $4,
			changed_by = $5, changed_at = $6`, rule, o.Enabled, o.Trial, o.Reason, o.ChangedBy, o.ChangedAt)
		return err
	}))
}

// ClearOverride usuwa ustawienie z panelu (obowiązuje plik reguły).
func (p *PG) ClearOverride(ctx context.Context, rule string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.rule_overrides WHERE rule_id = $1`, rule)
	return tag.RowsAffected() > 0, notConfigured(err)
}

// RuleVersions zwraca historię reguły (najnowsze pierwsze).
func (p *PG) RuleVersions(ctx context.Context, rule string) ([]RuleVersion, error) {
	rows, err := p.pool.Query(ctx, `SELECT version, sha256, file, source, loaded_at FROM gjallarhorn.rule_versions
		WHERE rule_id = $1 ORDER BY version DESC LIMIT 100`, rule)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RuleVersion])
}

// recordVersions zapisuje nową wersję reguł, których treść się zmieniła,
// i ustawia numer wersji w gjallarhorn.rules (wywoływane w SyncRules).
func recordVersions(ctx context.Context, tx pgx.Tx, rules []RuleInfo, now time.Time) error {
	if len(rules) == 0 {
		return nil
	}
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (rule_id) rule_id, version, sha256 FROM gjallarhorn.rule_versions
		WHERE rule_id = ANY($1) ORDER BY rule_id, version DESC`, ids)
	if err != nil {
		return err
	}
	type last struct {
		version int
		sha     string
	}
	known := map[string]last{}
	for rows.Next() {
		var id, sha string
		var v int
		if err := rows.Scan(&id, &v, &sha); err != nil {
			rows.Close()
			return err
		}
		known[id] = last{v, sha}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	sorted := append([]RuleInfo(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, r := range sorted {
		sum := sha256.Sum256([]byte(r.Source))
		sha := hex.EncodeToString(sum[:])
		v := known[r.ID].version
		if known[r.ID].sha != sha {
			v++
			if _, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.rule_versions (rule_id, version, sha256, file, source, loaded_at)
				VALUES ($1, $2, $3, $4, $5, $6)`, r.ID, v, sha, r.File, r.Source, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE gjallarhorn.rules SET version = $2 WHERE id = $1`, r.ID, v); err != nil {
			return err
		}
	}
	return nil
}

// PanelRule to reguła zapisana w panelu (kreator korelacji): YAML
// z korelacją i regułami bazowymi, wczytywany przez detektor jako
// panel/<id>.yml.
type PanelRule struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PanelRuleFile to nazwa pliku reguły z panelu (widoczna w panelu i błędach).
func PanelRuleFile(id string) string { return "panel/" + id + ".yml" }

// PanelRules zwraca reguły zapisane w panelu i ich podpis (zmiana podpisu =
// detektor przeładowuje reguły).
func (p *PG) PanelRules(ctx context.Context) ([]PanelRule, string, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, source, created_by, created_at, updated_by, updated_at
		FROM gjallarhorn.panel_rules ORDER BY id`)
	if err != nil {
		return nil, "", notConfigured(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PanelRule])
	if err != nil {
		return nil, "", err
	}
	var sig strings.Builder
	for _, r := range out {
		fmt.Fprintf(&sig, "%s@%d;", r.ID, r.UpdatedAt.UnixNano())
	}
	return out, sig.String(), nil
}

// PanelRule zwraca jedną regułę z panelu.
func (p *PG) PanelRule(ctx context.Context, id string) (PanelRule, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, source, created_by, created_at, updated_by, updated_at
		FROM gjallarhorn.panel_rules WHERE id = $1`, id)
	if err != nil {
		return PanelRule{}, notConfigured(err)
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[PanelRule])
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// SavePanelRule tworzy albo zmienia regułę z panelu.
func (p *PG) SavePanelRule(ctx context.Context, id, source, by string, now time.Time) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO gjallarhorn.panel_rules (id, source, created_by, created_at, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $3, $4) ON CONFLICT (id) DO UPDATE SET source = $2, updated_by = $3, updated_at = $4`,
		id, source, by, now)
	return notConfigured(err)
}

// DeletePanelRule usuwa regułę z panelu (detektor przestaje ją oceniać).
func (p *PG) DeletePanelRule(ctx context.Context, id string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.panel_rules WHERE id = $1`, id)
	return tag.RowsAffected() > 0, notConfigured(err)
}
