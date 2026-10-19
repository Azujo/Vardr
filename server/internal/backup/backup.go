package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"siem/internal/backupcfg"
)

// passIDOf: identyfikator hasła kopii jak w backup.sh (k + 8 znaków
// sha256 pliku) – jest w nazwie każdej kopii.
func passIDOf(b []byte) string {
	h := sha256.Sum256(b)
	return "k" + hex.EncodeToString(h[:])[:8]
}

// status kopii.
type status struct {
	file    string
	size    int64
	remote  string // "", ok, error
	message string
	failed  bool
}

func (s status) err() error {
	if s.failed || s.remote == "error" {
		return errors.New(s.message)
	}
	return nil
}

func (s status) state() string {
	switch {
	case s.failed:
		return "error"
	case s.remote == "error":
		return "partial"
	}
	return "ok"
}

// backup wykonuje kopię i zapisuje jej wynik w Sadze.
func (r *Runner) backup(ctx context.Context, cfg backupcfg.Config, kind string) status {
	var id int64
	if err := r.DB.QueryRow(ctx, `INSERT INTO backup_runs (kind, status) VALUES ($1, 'running') RETURNING id`, kind).Scan(&id); err != nil {
		r.Log.Error("zapis kopii w Sadze nieudany", "err", err)
		return status{failed: true, message: err.Error()}
	}
	t0 := time.Now()
	st := r.doBackup(ctx, cfg)
	r.listed = time.Time{} // nowa kopia na liście do przywracania
	if _, err := r.DB.Exec(context.WithoutCancel(ctx), `UPDATE backup_runs SET finished_at = now(), status = $2, file = $3,
		size_bytes = $4, remote = $5, message = $6 WHERE id = $1`, id, st.state(), st.file, st.size, st.remote, truncate(st.message, 4000)); err != nil {
		r.Log.Error("zapis wyniku kopii nieudany", "err", err)
	}
	log := r.Log.Info
	if st.state() != "ok" {
		log = r.Log.Error
	}
	log("kopia zapasowa", "kind", kind, "status", st.state(), "file", st.file, "size", st.size, "remote", st.remote,
		"took", time.Since(t0).Round(time.Second).String(), "message", st.message)
	return st
}

func (r *Runner) doBackup(ctx context.Context, cfg backupcfg.Config) status {
	pass, err := os.ReadFile(r.PassFile)
	if err != nil || len(bytes.TrimSpace(pass)) == 0 {
		return status{failed: true, message: "brak hasła kopii – administrator musi na serwerze uruchomić ./backup.sh haslo init"}
	}
	kid := passIDOf(pass)
	if err := os.MkdirAll(r.BackupDir, 0o755); err != nil {
		return status{failed: true, message: err.Error()}
	}
	work, err := os.MkdirTemp(r.BackupDir, ".praca-")
	if err != nil {
		return status{failed: true, message: err.Error()}
	}
	defer os.RemoveAll(work)
	stamp := time.Now().UTC().Format("20060102-1504")
	var st status
	var notes []string

	// 1. Kopia lokalna: baza, konfiguracja, Grafana – jedna paczka zaszyfrowana.
	var parts []string
	if cfg.Include.Saga {
		dump := filepath.Join(work, "saga.dump")
		if out, err := r.cmd(ctx, 30*time.Minute, nil, "pg_dump", "--dbname", r.DumpURL, "--format=custom", "--file", dump); err != nil {
			return status{failed: true, message: "zrzut bazy Saga nieudany: " + out}
		}
		// Kopia, której nie da się odczytać, nie jest kopią.
		if out, err := r.cmd(ctx, 5*time.Minute, nil, "pg_restore", "--list", dump); err != nil {
			return status{failed: true, message: "zrzut bazy Saga nieczytelny: " + out}
		}
		parts = append(parts, "saga.dump")
	}
	if cfg.Include.Config {
		if out, err := r.cmd(ctx, time.Minute, nil, "cp", "-r", filepath.Join(r.StackDir, "certs"), filepath.Join(r.StackDir, ".env"), work); err != nil {
			return status{failed: true, message: "kopia certs/ i .env nieudana: " + out}
		}
		parts = append(parts, "certs", ".env")
	}
	if cfg.Include.Grafana {
		// Grafana działa w trakcie kopii: GNU tar kończy się kodem 1, gdy plik
		// (baza Grafany) zmienił się przy odczycie – kopia jest użyteczna
		// (zapis bazy Grafany jest rzadki), więc to ostrzeżenie, nie błąd.
		out, err := r.cmd(ctx, 10*time.Minute, nil, "tar", "-C", r.GrafanaDir, "--exclude=./dashboards", "--warning=no-file-changed",
			"-cf", filepath.Join(work, "grafana.tar"), ".")
		var ee *exec.ExitError
		if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 1) {
			return status{failed: true, message: "kopia danych Grafany nieudana: " + out}
		}
		parts = append(parts, "grafana.tar")
	}
	if len(parts) > 0 {
		host := os.Getenv("SIEM_BACKUP_SERVER_NAME") // adres serwera (kontener ma własną nazwę)
		if host == "" {
			host, _ = os.Hostname()
		}
		about := fmt.Sprintf("Kopia Heimdalla z %s, serwer %s, identyfikator hasła %s.\nZawartość: %s.\n"+
			"Odtworzenie: ./restore.sh (docs/operacje.md, „Kopie zapasowe”).\n",
			time.Now().UTC().Format(time.RFC3339), host, kid, describe(parts))
		if err := os.WriteFile(filepath.Join(work, "KOPIA.txt"), []byte(about), 0o600); err != nil {
			return status{failed: true, message: err.Error()}
		}
		parts = append(parts, "KOPIA.txt")
		name := "heimdall-" + stamp + "-" + kid + ".tar.gpg"
		out := filepath.Join(r.BackupDir, name)
		if err := r.encryptTar(ctx, work, parts, nil, out+".tmp"); err != nil {
			return status{failed: true, message: "szyfrowanie kopii nieudane: " + err.Error()}
		}
		if err := os.Rename(out+".tmp", out); err != nil {
			return status{failed: true, message: err.Error()}
		}
		r.own(out)
		fi, _ := os.Stat(out)
		st.file, st.size = name, fi.Size()
		notes = append(notes, fmt.Sprintf("kopia %s (%s)", name, human(st.size)))
		if n := r.localRetention(cfg.Local); n > 0 {
			notes = append(notes, fmt.Sprintf("usunięte stare kopie lokalne: %d", n))
		}
		r.metrics(st.size, false)
	}

	// 2. Wysyłka poza serwer.
	if cfg.Target.Method != backupcfg.MethodNone {
		msg, err := r.upload(ctx, cfg, work, st.file, stamp, kid, pass)
		if err != nil {
			st.remote = "error"
			notes = append(notes, "wysyłka nieudana: "+err.Error())
		} else {
			st.remote = "ok"
			notes = append(notes, msg)
			r.metrics(st.size, true)
		}
	}
	st.message = strings.Join(notes, "; ")
	return st
}

func describe(parts []string) string {
	labels := map[string]string{"saga.dump": "saga.dump (pg_dump --format=custom)", "certs": "certs/", ".env": ".env",
		"grafana.tar": "grafana.tar (dane Grafany)"}
	var out []string
	for _, p := range parts {
		out = append(out, labels[p])
	}
	return strings.Join(out, ", ")
}

// encryptTar: tar z plików (parts z katalogu dir albo lista z pliku listFile)
// zaszyfrowany gpg hasłem kopii – ten sam format co backup.sh.
func (r *Runner) encryptTar(ctx context.Context, dir string, parts []string, listFile *string, out string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	args := []string{"-C", dir, "-cf", "-"}
	if listFile != nil {
		args = append(args, "-T", *listFile)
	} else {
		args = append(args, parts...)
	}
	tarCmd := exec.CommandContext(ctx, "tar", args...)
	gpg := exec.CommandContext(ctx, "gpg", "--batch", "--quiet", "--yes", "--pinentry-mode", "loopback",
		"--passphrase-file", r.PassFile, "--symmetric", "--cipher-algo", "AES256", "--s2k-digest-algo", "SHA512",
		"--s2k-count", "65011712", "--homedir", filepath.Join(r.StateDir, "gnupg"), "--output", out)
	if err := os.MkdirAll(filepath.Join(r.StateDir, "gnupg"), 0o700); err != nil {
		return err
	}
	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return err
	}
	gpg.Stdin = pipe
	var tarErr, gpgErr bytes.Buffer
	tarCmd.Stderr, gpg.Stderr = &tarErr, &gpgErr
	if err := gpg.Start(); err != nil {
		return err
	}
	if err := tarCmd.Run(); err != nil {
		_ = gpg.Wait()
		return fmt.Errorf("tar: %v %s", err, strings.TrimSpace(tarErr.String()))
	}
	if err := gpg.Wait(); err != nil {
		return fmt.Errorf("gpg: %v %s", err, strings.TrimSpace(gpgErr.String()))
	}
	return nil
}

// localRetention usuwa stare kopie lokalne; zwraca liczbę usuniętych.
func (r *Runner) localRetention(ret backupcfg.Retention) int {
	matches, _ := filepath.Glob(filepath.Join(r.BackupDir, "heimdall-*.tar.gpg"))
	var files []remoteFile
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil {
			files = append(files, remoteFile{Name: filepath.Base(m), ModTime: fi.ModTime()})
		}
	}
	n := 0
	for _, f := range expired(files, ret, time.Now()) {
		if os.Remove(filepath.Join(r.BackupDir, f)) == nil {
			n++
		}
	}
	return n
}

type remoteFile struct {
	Name    string
	ModTime time.Time
}

// expired: pliki do usunięcia według retencji (starsze niż KeepDays albo
// spoza KeepCount najnowszych; najnowszy zostaje zawsze). Wiek z nazwy
// (zawiera czas kopii), a gdy jej brak – z czasu modyfikacji: na serwerze
// kopii to bywa czas wysyłki.
func expired(files []remoteFile, ret backupcfg.Retention, now time.Time) []string {
	when := func(f remoteFile) time.Time {
		if t, ok := stampOf(f.Name); ok {
			return t
		}
		return f.ModTime
	}
	sort.SliceStable(files, func(i, j int) bool { return when(files[i]).After(when(files[j])) })
	var out []string
	for i, f := range files {
		if i == 0 {
			continue
		}
		old := ret.KeepDays > 0 && now.Sub(when(f)) > time.Duration(ret.KeepDays)*24*time.Hour
		if old || (ret.KeepCount > 0 && i >= ret.KeepCount) {
			out = append(out, f.Name)
		}
	}
	return out
}

// stampOf: czas z nazwy kopii (heimdall-20261019-0215-k1234abcd.tar.gpg).
func stampOf(name string) (time.Time, bool) {
	parts := strings.Split(name, "-")
	if len(parts) < 4 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102-1504", parts[1]+"-"+parts[2])
	return t, err == nil
}

// metrics: plik dla node-exporter (alerty Grafany o kopiach – jak backup.sh).
func (r *Runner) metrics(size int64, remote bool) {
	if r.MetricsDir == "" {
		return
	}
	now := time.Now().Unix()
	lastRemote := filepath.Join(r.MetricsDir, "backup-remote.last")
	if remote {
		_ = os.WriteFile(lastRemote, []byte(fmt.Sprint(now)), 0o644)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP heimdall_backup_last_success_timestamp_seconds Czas ostatniej udanej kopii zapasowej.\n")
	fmt.Fprintf(&b, "# TYPE heimdall_backup_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "heimdall_backup_last_success_timestamp_seconds %d\n", now)
	fmt.Fprintf(&b, "# HELP heimdall_backup_size_bytes Rozmiar ostatniej kopii (zaszyfrowanej).\n")
	fmt.Fprintf(&b, "# TYPE heimdall_backup_size_bytes gauge\n")
	fmt.Fprintf(&b, "heimdall_backup_size_bytes %d\n", size)
	if v, err := os.ReadFile(lastRemote); err == nil {
		fmt.Fprintf(&b, "# HELP heimdall_backup_remote_last_success_timestamp_seconds Czas ostatniej udanej wysyłki kopii poza VM.\n")
		fmt.Fprintf(&b, "# TYPE heimdall_backup_remote_last_success_timestamp_seconds gauge\n")
		fmt.Fprintf(&b, "heimdall_backup_remote_last_success_timestamp_seconds %s\n", strings.TrimSpace(string(v)))
	}
	path := filepath.Join(r.MetricsDir, "backup.prom")
	if err := writeFileAtomic(path, []byte(b.String()), 0o644); err != nil {
		r.Log.Warn("zapis metryk kopii nieudany", "err", err)
	}
	r.own(path)
	r.own(lastRemote)
}

// own: pliki kopii należą do użytkownika stosu (usługa działa jako root,
// żeby czytać dane Grafany i hasło kopii).
func (r *Runner) own(path string) {
	if r.OwnerUID > 0 {
		_ = os.Chown(path, r.OwnerUID, r.OwnerGID)
	}
}

// cmd uruchamia polecenie z limitem czasu; zwraca wyjście (do komunikatu).
func (r *Runner) cmd(ctx context.Context, timeout time.Duration, stdin io.Reader, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = stdin
	out, err := c.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil && msg == "" {
		msg = err.Error()
	}
	return truncate(msg, 1500), err
}

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
