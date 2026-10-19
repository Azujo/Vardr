package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"siem/internal/backupcfg"
)

// BackupSecret to stan sekretu kopii (bez treści – panel jej nie zna).
type BackupSecret struct {
	Name      string    `json:"name"`
	KeyID     string    `json:"key_id"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// BackupRunner to stan usługi kopii (siem-backup).
type BackupRunner struct {
	BoxPublicKey string     `json:"-"`
	KeyID        string     `json:"key_id"`
	SSHPublicKey string     `json:"ssh_public_key"`
	HostKey      string     `json:"host_key"`
	PassID       string     `json:"pass_id"`
	LocalDir     string     `json:"local_dir"`
	LocalFree    int64      `json:"local_free"`
	Version      string     `json:"version"`
	SeenAt       *time.Time `json:"seen_at"`
}

// BackupRun to wykonana kopia.
type BackupRun struct {
	ID         int64      `json:"id"`
	Kind       string     `json:"kind"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	File       string     `json:"file"`
	SizeBytes  int64      `json:"size_bytes"`
	Remote     string     `json:"remote"`
	Message    string     `json:"message"`
}

// BackupRequest to zlecenie z panelu.
type BackupRequest struct {
	ID          int64          `json:"id"`
	Action      string         `json:"action"`
	RequestedAt time.Time      `json:"requested_at"`
	RequestedBy string         `json:"requested_by"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	DoneAt      *time.Time     `json:"done_at,omitempty"`
	OK          *bool          `json:"ok,omitempty"`
	Message     string         `json:"message"`
	Params      map[string]any `json:"params,omitempty"`
}

// BackupFile to kopia dostępna do przywrócenia.
type BackupFile struct {
	Location  string     `json:"location"` // local | remote
	Name      string     `json:"name"`
	SizeBytes int64      `json:"size_bytes"`
	Modified  *time.Time `json:"modified,omitempty"`
	Contents  []string   `json:"contents"` // nil – jeszcze nie sprawdzona
	Note      string     `json:"note,omitempty"`
	ListedAt  time.Time  `json:"listed_at"`
}

// BackupState to wszystko, co pokazuje strona kopii.
type BackupState struct {
	Config    backupcfg.Config `json:"config"`
	Saved     bool             `json:"saved"` // false – ustawienia domyślne, jeszcze nie zapisane
	UpdatedAt *time.Time       `json:"updated_at,omitempty"`
	UpdatedBy string           `json:"updated_by,omitempty"`
	Secrets   []BackupSecret   `json:"secrets"`
	Runner    *BackupRunner    `json:"runner"`
	Runs      []BackupRun      `json:"runs"`
	Requests  []BackupRequest  `json:"requests"`
	Files     []BackupFile     `json:"files"`
}

// Backup zwraca ustawienia, stan usługi i ostatnie kopie.
func (s *PG) Backup(ctx context.Context) (BackupState, error) {
	st := BackupState{Config: backupcfg.Default(), Secrets: []BackupSecret{}, Runs: []BackupRun{}, Requests: []BackupRequest{},
		Files: []BackupFile{}}
	var raw []byte
	var at time.Time
	err := s.pool.QueryRow(ctx, `SELECT config, updated_at, updated_by FROM backup_config WHERE id = 1`).Scan(&raw, &at, &st.UpdatedBy)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return st, err
	default:
		if err := json.Unmarshal(raw, &st.Config); err != nil {
			return st, err
		}
		st.Saved, st.UpdatedAt = true, &at
	}
	rows, err := s.pool.Query(ctx, `SELECT name, key_id, updated_at, updated_by FROM backup_secrets ORDER BY name`)
	if err != nil {
		return st, err
	}
	if st.Secrets, err = pgx.CollectRows(rows, pgx.RowToStructByPos[BackupSecret]); err != nil {
		return st, err
	}
	var r BackupRunner
	err = s.pool.QueryRow(ctx, `SELECT box_public_key, ssh_public_key, host_key, pass_id, local_dir, local_free, version, seen_at
		FROM backup_runner WHERE id = 1`).Scan(&r.BoxPublicKey, &r.SSHPublicKey, &r.HostKey, &r.PassID, &r.LocalDir, &r.LocalFree,
		&r.Version, &r.SeenAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return st, err
	default:
		if k, err := backupcfg.DecodeKey(r.BoxPublicKey); err == nil {
			r.KeyID = backupcfg.KeyID(k)
		}
		st.Runner = &r
	}
	rows, err = s.pool.Query(ctx, `SELECT id, kind, started_at, finished_at, status, file, size_bytes, remote, message
		FROM backup_runs ORDER BY started_at DESC LIMIT 30`)
	if err != nil {
		return st, err
	}
	if st.Runs, err = pgx.CollectRows(rows, pgx.RowToStructByPos[BackupRun]); err != nil {
		return st, err
	}
	rows, err = s.pool.Query(ctx, `SELECT id, action, requested_at, requested_by, started_at, done_at, ok, message, params
		FROM backup_requests ORDER BY id DESC LIMIT 10`)
	if err != nil {
		return st, err
	}
	if st.Requests, err = pgx.CollectRows(rows, pgx.RowToStructByPos[BackupRequest]); err != nil {
		return st, err
	}
	rows, err = s.pool.Query(ctx, `SELECT location, name, size_bytes, modified, contents, note, listed_at
		FROM backup_files ORDER BY name DESC, location LIMIT 500`)
	if err != nil {
		return st, err
	}
	st.Files, err = pgx.CollectRows(rows, pgx.RowToStructByPos[BackupFile])
	return st, err
}

// SealedSecret to sekret zaszyfrowany kluczem usługi kopii.
type SealedSecret struct {
	Sealed []byte
	KeyID  string
}

// SaveBackup zapisuje ustawienia, nowe sekrety i usuwa sekrety niepotrzebne.
func (s *PG) SaveBackup(ctx context.Context, cfg backupcfg.Config, secrets map[string]SealedSecret, drop []string, by string) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO backup_config (id, config, updated_at, updated_by) VALUES (1, $1, now(), $2)
			ON CONFLICT (id) DO UPDATE SET config = $1, updated_at = now(), updated_by = $2`, raw, by); err != nil {
			return err
		}
		for name, sec := range secrets {
			if _, err := tx.Exec(ctx, `INSERT INTO backup_secrets (name, sealed, key_id, updated_at, updated_by) VALUES ($1, $2, $3, now(), $4)
				ON CONFLICT (name) DO UPDATE SET sealed = $2, key_id = $3, updated_at = now(), updated_by = $4`,
				name, sec.Sealed, sec.KeyID, by); err != nil {
				return err
			}
		}
		if len(drop) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM backup_secrets WHERE name = ANY($1)`, drop); err != nil {
				return err
			}
		}
		return nil
	})
}

// ErrBackupPending: takie samo zlecenie czeka już na wykonanie.
var ErrBackupPending = errors.New("takie zlecenie już czeka na wykonanie")

// AddBackupRequest dodaje zlecenie dla usługi kopii.
func (s *PG) AddBackupRequest(ctx context.Context, action, by string, params map[string]any) (BackupRequest, error) {
	if params == nil {
		params = map[string]any{}
	}
	var r BackupRequest
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM backup_requests WHERE action = $1 AND done_at IS NULL
			AND requested_at > now() - interval '1 hour' AND (action <> 'inspect' OR params = $2))`, action, params).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return ErrBackupPending
		}
		return tx.QueryRow(ctx, `INSERT INTO backup_requests (action, requested_by, params) VALUES ($1, $2, $3)
			RETURNING id, action, requested_at, requested_by, started_at, done_at, ok, message, params`, action, by, params).
			Scan(&r.ID, &r.Action, &r.RequestedAt, &r.RequestedBy, &r.StartedAt, &r.DoneAt, &r.OK, &r.Message, &r.Params)
	})
	return r, err
}
