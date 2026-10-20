// Package backup to usługa kopii zapasowych Vardra (siem-backup):
// wykonuje kopie według ustawień z panelu (internal/backupcfg, tabele
// backup_* w Sadze), szyfruje je hasłem kopii (gpg, jak dotychczasowy
// backup.sh – restore.sh otwiera obie), trzyma kopie lokalnie z retencją
// i wysyła je poza serwer (rclone: SFTP, SMB, S3) razem z przyrostami
// archiwum NIS2.
//
// Usługa zgłasza się w Sadze co 15 s (stan, klucz publiczny do szyfrowania
// sekretów, klucz SSH), wykonuje zlecenia z panelu (kopia teraz, test
// połączenia, nowy klucz SSH) i kopie z harmonogramu. Wszystko po kolei,
// w jednej gorutynie – dwie kopie naraz nie powstaną.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"siem/internal/backupcfg"
)

// Runner to usługa kopii.
type Runner struct {
	DB  *pgxpool.Pool
	Log *slog.Logger
	// DumpURL: połączenie dla pg_dump (rola z prawem odczytu całej bazy).
	DumpURL string
	Version string
	Loc     *time.Location

	StateDir   string // klucze usługi, klucz SSH, known_hosts (trwałe, tylko root)
	BackupDir  string // kopie lokalne
	PassFile   string // hasło kopii (./backup.sh haslo init)
	StackDir   string // katalog stosu: certs/, .env
	ArchiveDir string // archiwum NIS2 (tylko odczyt)
	GrafanaDir string // dane Grafany (tylko odczyt)
	MetricsDir string // metryki dla node-exporter (textfile)
	// Legacy: dotychczasowe ustawienie wysyłki z .env (SIEM_BACKUP_REMOTE,
	// user@host:/katalog) – przeniesione do panelu przy pierwszym starcie.
	Legacy        string
	LegacyKeepDay int
	// Owner: właściciel plików kopii na serwerze (użytkownik stosu).
	OwnerUID, OwnerGID int

	pub, priv *[32]byte
	started   time.Time
	listed    time.Time // ostatnia lista kopii (backup_files)
}

// Run działa do zakończenia ctx.
func (r *Runner) Run(ctx context.Context) error {
	r.started = time.Now()
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return err
	}
	if err := r.loadBoxKey(); err != nil {
		return err
	}
	r.Log.Info("usługa kopii gotowa", "key_id", backupcfg.KeyID(r.pub), "backup_dir", r.BackupDir)
	if err := svcRetry(ctx, func() error { return r.closeOrphans(ctx) }); err != nil {
		return err
	}
	for {
		if err := r.tick(ctx); err != nil && ctx.Err() == nil {
			r.Log.Warn("przebieg usługi kopii nieudany", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(15 * time.Second):
		}
	}
}

func (r *Runner) tick(ctx context.Context) error {
	if err := r.heartbeat(ctx); err != nil {
		return fmt.Errorf("stan usługi: %w", err)
	}
	cfg, since, err := r.config(ctx)
	if err != nil {
		return fmt.Errorf("ustawienia: %w", err)
	}
	if err := r.requests(ctx, cfg); err != nil {
		return fmt.Errorf("zlecenia: %w", err)
	}
	last, err := r.lastScheduled(ctx)
	if err != nil {
		return err
	}
	if last.After(since) {
		since = last
	}
	if cfg.Due(since, time.Now(), r.Loc) {
		r.backup(ctx, cfg, "scheduled")
		r.listed = time.Time{}
	}
	// Lista kopii do przywracania – co 15 min i po każdej kopii.
	if time.Since(r.listed) > 15*time.Minute {
		if _, err := r.listFiles(ctx, cfg); err != nil {
			r.Log.Warn("lista kopii nieudana", "err", err)
		}
	}
	return nil
}

// ---- stan i klucze ----

func (r *Runner) loadBoxKey() error {
	path := filepath.Join(r.StateDir, "box.key")
	b, err := os.ReadFile(path)
	if err == nil && len(b) == 64 {
		var pub, priv [32]byte
		copy(pub[:], b[:32])
		copy(priv[:], b[32:])
		r.pub, r.priv = &pub, &priv
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pub, priv, err := backupcfg.NewBoxKey()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, append(pub[:], priv[:]...), 0o600); err != nil {
		return err
	}
	r.pub, r.priv = pub, priv
	r.Log.Info("nowy klucz usługi kopii – sekrety zapisane wcześniej trzeba wpisać ponownie w panelu", "key_id", backupcfg.KeyID(pub))
	return nil
}

func (r *Runner) heartbeat(ctx context.Context) error {
	sshPub, _ := os.ReadFile(filepath.Join(r.StateDir, "ssh_key.pub"))
	free := freeBytes(r.BackupDir)
	_, err := r.DB.Exec(ctx, `INSERT INTO backup_runner (id, box_public_key, ssh_public_key, pass_id, local_dir, local_free, version, seen_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (id) DO UPDATE SET box_public_key = $1, ssh_public_key = $2, pass_id = $3, local_dir = $4,
			local_free = $5, version = $6, seen_at = now()`,
		backupcfg.EncodeKey(r.pub), strings.TrimSpace(string(sshPub)), r.passID(), r.BackupDir, free, r.Version)
	return err
}

func (r *Runner) setHostKey(ctx context.Context, fp string) {
	if _, err := r.DB.Exec(ctx, `UPDATE backup_runner SET host_key = $1 WHERE id = 1`, fp); err != nil {
		r.Log.Warn("zapis klucza serwera kopii nieudany", "err", err)
	}
}

// config zwraca ustawienia i czas ich zapisu. Bez ustawień w bazie –
// domyślne, z wysyłką z dotychczasowego .env, zapisane do panelu.
func (r *Runner) config(ctx context.Context) (backupcfg.Config, time.Time, error) {
	var raw []byte
	var at time.Time
	err := r.DB.QueryRow(ctx, `SELECT config, updated_at FROM backup_config WHERE id = 1`).Scan(&raw, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		cfg := r.legacyConfig()
		b, _ := json.Marshal(cfg)
		if _, err := r.DB.Exec(ctx, `INSERT INTO backup_config (id, config, updated_by) VALUES (1, $1, 'siem-backup (ustawienia z .env)')
			ON CONFLICT (id) DO NOTHING`, b); err != nil {
			return cfg, time.Now(), err
		}
		r.Log.Info("ustawienia kopii przeniesione do panelu", "target", cfg.Target.Method)
		return cfg, time.Now(), nil
	}
	if err != nil {
		return backupcfg.Config{}, at, err
	}
	var cfg backupcfg.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, at, err
	}
	return cfg, at, nil
}

func (r *Runner) legacyConfig() backupcfg.Config {
	cfg := backupcfg.Default()
	if r.LegacyKeepDay > 0 {
		cfg.Remote.KeepDays = r.LegacyKeepDay
	}
	userHost, dir, ok := strings.Cut(r.Legacy, ":")
	user, host, ok2 := strings.Cut(userHost, "@")
	if ok && ok2 && dir != "" {
		cfg.Target = backupcfg.Target{Method: backupcfg.MethodSFTP, Host: host, User: user, Auth: backupcfg.AuthServerKey, Path: dir}
		if err := cfg.Validate(); err != nil {
			r.Log.Warn("ustawienie SIEM_BACKUP_REMOTE nieczytelne – wysyłka do ustawienia w panelu", "err", err)
			cfg.Target = backupcfg.Target{Method: backupcfg.MethodNone}
		}
	}
	return cfg
}

func (r *Runner) lastScheduled(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := r.DB.QueryRow(ctx, `SELECT max(started_at) FROM backup_runs WHERE kind = 'scheduled'`).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

// secrets odszyfrowuje sekrety potrzebne przy ustawieniach.
func (r *Runner) secrets(ctx context.Context, t backupcfg.Target) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range t.Secrets() {
		var sealed []byte
		err := r.DB.QueryRow(ctx, `SELECT sealed FROM backup_secrets WHERE name = $1`, name).Scan(&sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("brak sekretu %s – wpisz go w panelu", name)
		}
		if err != nil {
			return nil, err
		}
		v, err := backupcfg.Open(sealed, r.pub, r.priv)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

// ---- zlecenia z panelu ----

func (r *Runner) requests(ctx context.Context, cfg backupcfg.Config) error {
	for {
		var id int64
		var action string
		var params map[string]any
		err := r.DB.QueryRow(ctx, `UPDATE backup_requests SET started_at = now()
			WHERE id = (SELECT id FROM backup_requests WHERE done_at IS NULL AND started_at IS NULL ORDER BY id LIMIT 1)
			RETURNING id, action, params`).Scan(&id, &action, &params)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		r.Log.Info("zlecenie z panelu", "id", id, "action", action)
		var msg string
		var aerr error
		handedOver := false // przywracanie: dokończy restore.sh na serwerze
		str := func(k string) string { s, _ := params[k].(string); return s }
		switch action {
		case "run":
			st := r.backup(ctx, cfg, "manual")
			msg, aerr = st.message, st.err()
		case "test":
			msg, aerr = r.test(ctx, cfg)
		case "genkey":
			msg, aerr = r.genKey(ctx)
		case "list":
			msg, aerr = r.listFiles(ctx, cfg)
		case "inspect":
			msg, aerr = r.inspect(ctx, cfg, str("location"), str("name"))
		case "restore":
			var parts []string
			if l, ok := params["parts"].([]any); ok {
				for _, p := range l {
					if s, ok := p.(string); ok {
						parts = append(parts, s)
					}
				}
			}
			safety, _ := params["safety_backup"].(bool)
			msg, aerr = r.prepareRestore(ctx, cfg, id, str("location"), str("name"), parts, safety)
			handedOver = aerr == nil
		default:
			aerr = fmt.Errorf("nieznane zlecenie %q", action)
		}
		if handedOver {
			if _, err := r.DB.Exec(ctx, `UPDATE backup_requests SET message = $2 WHERE id = $1`, id, truncate(msg, 2000)); err != nil {
				return err
			}
			continue
		}
		ok := aerr == nil
		if aerr != nil {
			msg = aerr.Error()
		}
		if _, err := r.DB.Exec(ctx, `UPDATE backup_requests SET done_at = now(), ok = $2, message = $3 WHERE id = $1`,
			id, ok, truncate(msg, 2000)); err != nil {
			return err
		}
	}
}

// closeOrphans zamyka wpisy „w toku” po poprzednim uruchomieniu usługi
// (usługa wykonuje wszystko w jednej gorutynie, więc przy starcie nic nie
// jest w toku). Powstają przy restarcie w trakcie kopii albo po
// przywróceniu bazy, której zrzut zrobiono w trakcie kopii. Przywracanie
// czekające na restore.sh (plik zlecenia) zostaje.
func (r *Runner) closeOrphans(ctx context.Context) error {
	const why = "przerwane – usługa kopii została uruchomiona ponownie (restart albo przywrócenie bazy z kopii zrobionej w trakcie)"
	tag, err := r.DB.Exec(ctx, `UPDATE backup_runs SET status = 'error', finished_at = now(), message = $1 WHERE status = 'running'`, why)
	if err != nil {
		return err
	}
	pendingRestore := false
	for _, f := range []string{"zlecenie", "zlecenie.wykonywane"} { // czeka albo właśnie trwa
		if _, err := os.Stat(filepath.Join(r.restoreDir(), f)); err == nil {
			pendingRestore = true
		}
	}
	tag2, err := r.DB.Exec(ctx, `UPDATE backup_requests SET done_at = now(), ok = false, message = $1
		WHERE done_at IS NULL AND started_at IS NOT NULL AND NOT (action = 'restore' AND $2)`, why, pendingRestore)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected() + tag2.RowsAffected(); n > 0 {
		r.Log.Warn("zamknięto wpisy przerwane przez restart", "runs", tag.RowsAffected(), "requests", tag2.RowsAffected())
	}
	return nil
}

// svcRetry ponawia operację na bazie przy starcie (Saga może jeszcze startować).
func svcRetry(ctx context.Context, fn func() error) error {
	for delay := time.Second; ; delay = min(delay*2, 30*time.Second) {
		err := fn()
		if err == nil || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (r *Runner) passID() string {
	b, err := os.ReadFile(r.PassFile)
	if err != nil || len(b) == 0 {
		return ""
	}
	return passIDOf(b)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
