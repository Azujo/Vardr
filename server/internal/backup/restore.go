// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"siem/internal/backupcfg"
	"siem/internal/lang"
)

// Przywracanie z panelu. Usługa kopii przygotowuje przywrócenie: lista
// kopii, sprawdzenie zawartości (odszyfrowanie hasłem kopii), kopia
// obecnego stanu, pobranie kopii z miejsca docelowego. Samo przywrócenie
// wymaga zatrzymania usług, więc robi je restore.sh na serwerze (cron co
// minutę) na podstawie pliku zlecenia w <kopie>/.przywracanie/ – usługa
// kopii nie ma dostępu do Dockera.

// backupName: nazwy kopii (żadna inna nazwa nie trafia do poleceń);
// heimdall- to kopie sprzed zmiany nazwy na Vardr.
var backupName = regexp.MustCompile(`^(vardr|heimdall)-[0-9]{8}-[0-9]{4}-k[0-9a-f]{8}\.tar\.gpg$`)

// backupFiles: kopie w katalogu (obecne i sprzed zmiany nazwy).
func backupFiles(dir string) []string {
	var out []string
	for _, p := range []string{"vardr-*.tar.gpg", "heimdall-*.tar.gpg"} {
		m, _ := filepath.Glob(filepath.Join(dir, p))
		out = append(out, m...)
	}
	return out
}

// restoreDir: kopie pobrane z miejsca docelowego i zlecenie dla restore.sh.
func (r *Runner) restoreDir() string { return filepath.Join(r.BackupDir, ".przywracanie") }

type listedFile struct {
	location, name string
	size           int64
	mod            time.Time
}

// listFiles odświeża listę kopii (lokalne i w miejscu docelowym). Zawartość
// sprawdzonych kopii zostaje.
func (r *Runner) listFiles(ctx context.Context, cfg backupcfg.Config) (string, error) {
	r.listed = time.Now()
	// Kopie pobrane do sprawdzenia albo przywrócenia – po dobie zbędne.
	if old := backupFiles(r.restoreDir()); len(old) > 0 {
		for _, f := range old {
			if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > 24*time.Hour {
				_ = os.Remove(f)
			}
		}
	}
	var files []listedFile
	matches := backupFiles(r.BackupDir)
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && backupName.MatchString(fi.Name()) {
			files = append(files, listedFile{"local", fi.Name(), fi.Size(), fi.ModTime()})
		}
	}
	nLocal, nRemote := len(files), 0
	var remoteErr error
	if cfg.Target.Method != backupcfg.MethodNone {
		work, err := os.MkdirTemp(r.BackupDir, ".lista-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(work)
		conf, base, err := r.rcloneConfig(ctx, cfg, work)
		if err == nil {
			var out string
			out, err = r.rcloneOut(ctx, 2*time.Minute, conf, "lsjson", "--files-only", base+"/config")
			if err == nil {
				var items []struct {
					Name    string    `json:"Name"`
					Size    int64     `json:"Size"`
					ModTime time.Time `json:"ModTime"`
				}
				if err = json.Unmarshal([]byte(out), &items); err == nil {
					for _, it := range items {
						if backupName.MatchString(it.Name) {
							files = append(files, listedFile{"remote", it.Name, it.Size, it.ModTime})
							nRemote++
						}
					}
				}
			}
		}
		remoteErr = err
	}
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	// Bez dostępu do miejsca docelowego zostaje jego poprzednia lista.
	scope := []string{"local", "remote"}
	if remoteErr != nil {
		scope = []string{"local"}
	}
	var keep []string
	for _, f := range files {
		keep = append(keep, f.location+"/"+f.name)
		if _, err := tx.Exec(ctx, `INSERT INTO backup_files (location, name, size_bytes, modified, listed_at) VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (location, name) DO UPDATE SET size_bytes = $3, modified = $4, listed_at = now()`,
			f.location, f.name, f.size, f.mod); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM backup_files WHERE location = ANY($1) AND NOT (location || '/' || name = ANY($2))`,
		scope, keep); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	msg := fmt.Sprintf(r.tr(ctx, "kopie lokalne: %d", "local backups: %d"), nLocal)
	if cfg.Target.Method != backupcfg.MethodNone {
		if remoteErr != nil {
			return msg, fmt.Errorf(r.tr(ctx, "%s; miejsce docelowe niedostępne: %v", "%s; destination unavailable: %v"), msg, remoteErr)
		}
		msg += fmt.Sprintf(r.tr(ctx, ", w miejscu docelowym: %d", ", at the destination: %d"), nRemote)
	}
	return msg, nil
}

// localCopy zwraca ścieżkę kopii na dysku serwera (z miejsca docelowego –
// pobraną do .przywracanie/).
func (r *Runner) localCopy(ctx context.Context, cfg backupcfg.Config, location, name string) (string, error) {
	if !backupName.MatchString(name) {
		return "", r.errf(ctx, "niepoprawna nazwa kopii", "invalid backup name")
	}
	switch location {
	case "local":
		p := filepath.Join(r.BackupDir, name)
		if _, err := os.Stat(p); err != nil {
			return "", r.errf(ctx, "kopii %s nie ma już na serwerze – odśwież listę", "backup %s is no longer on the server – refresh the list", name)
		}
		return p, nil
	case "remote":
		if err := os.MkdirAll(r.restoreDir(), 0o755); err != nil {
			return "", err
		}
		r.own(r.restoreDir())
		p := filepath.Join(r.restoreDir(), name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		work, err := os.MkdirTemp(r.BackupDir, ".pobieranie-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(work)
		conf, base, err := r.rcloneConfig(ctx, cfg, work)
		if err != nil {
			return "", err
		}
		if out, err := r.rclone(ctx, 2*time.Hour, conf, "copyto", base+"/config/"+name, p+".tmp"); err != nil {
			return "", r.errf(ctx, "pobranie kopii nieudane: %s", "downloading the backup failed: %s", out)
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return "", err
		}
		r.own(p)
		return p, nil
	}
	return "", r.errf(ctx, "niepoprawne miejsce kopii", "invalid backup location")
}

// contentsOf odszyfrowuje kopię hasłem kopii i zwraca jej części.
func (r *Runner) contentsOf(ctx context.Context, path string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	gpg := exec.CommandContext(ctx, "gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase-file", r.PassFile,
		"--homedir", filepath.Join(r.StateDir, "gnupg"), "--decrypt", path)
	tar := exec.CommandContext(ctx, "tar", "-tf", "-")
	pipe, err := gpg.StdoutPipe()
	if err != nil {
		return nil, err
	}
	tar.Stdin = pipe
	var gpgErr strings.Builder
	gpg.Stderr = &gpgErr
	if err := gpg.Start(); err != nil {
		return nil, err
	}
	out, terr := tar.Output()
	gerr := gpg.Wait()
	if gerr != nil {
		msg := strings.TrimSpace(gpgErr.String())
		if strings.Contains(msg, "decryption failed") || strings.Contains(msg, "Bad session key") {
			return nil, r.errf(ctx, "kopii nie da się odszyfrować obecnym hasłem kopii – zaszyfrowano ją innym (identyfikator w nazwie)",
				"the backup cannot be decrypted with the current backup password – it was encrypted with another one (identifier in the name)")
		}
		return nil, r.errf(ctx, "odszyfrowanie nieudane: %s", "decryption failed: %s", truncate(msg, 500))
	}
	if terr != nil {
		return nil, r.errf(ctx, "kopia uszkodzona: %v", "the backup is damaged: %v", terr)
	}
	names := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		names[strings.TrimPrefix(strings.TrimSpace(l), "./")] = true
	}
	var parts []string
	if names["saga.dump"] {
		parts = append(parts, "saga")
	}
	if names[".env"] {
		parts = append(parts, "config")
	}
	if names["grafana.tar"] {
		parts = append(parts, "grafana")
	}
	if len(parts) == 0 {
		return nil, r.errf(ctx, "kopia nie zawiera niczego, co da się przywrócić", "the backup contains nothing that can be restored")
	}
	return parts, nil
}

func partsLabel(parts []string, l string) string {
	labels := map[string]string{"saga": lang.Pick(l, "baza Saga", "Saga database"), "config": lang.Pick(l, "konfiguracja", "configuration"),
		"grafana": lang.Pick(l, "dane Grafany", "Grafana data")}
	var out []string
	for _, p := range parts {
		out = append(out, labels[p])
	}
	return strings.Join(out, ", ")
}

// inspect sprawdza zawartość kopii i zapisuje ją na liście.
func (r *Runner) inspect(ctx context.Context, cfg backupcfg.Config, location, name string) (string, error) {
	path, err := r.localCopy(ctx, cfg, location, name)
	if err != nil {
		return "", err
	}
	parts, err := r.contentsOf(ctx, path)
	note := ""
	if err != nil {
		note = err.Error()
	}
	if _, dberr := r.DB.Exec(ctx, `UPDATE backup_files SET contents = $3, note = $4 WHERE location = $1 AND name = $2`,
		location, name, parts, note); dberr != nil {
		return "", dberr
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: %s", name, partsLabel(parts, r.Lang.Get(ctx))), nil
}

// restoreJob to zlecenie dla restore.sh (proste linie klucz=wartość –
// skrypt ich nie wykonuje, tylko czyta; nazwy sprawdzone wyrażeniem).
func restoreJob(id int64, file string, parts []string, by string) string {
	safe := regexp.MustCompile(`[^A-Za-z0-9._@-]`).ReplaceAllString(by, "_")
	return fmt.Sprintf("id=%d\nfile=%s\nparts=%s\nby=%s\n", id, file, strings.Join(parts, ","), safe)
}

// prepareRestore: kopia obecnego stanu, kopia do przywrócenia na dysku,
// sprawdzenie zawartości i zlecenie dla restore.sh.
func (r *Runner) prepareRestore(ctx context.Context, cfg backupcfg.Config, id int64, location, name string, parts []string, safety bool) (string, error) {
	if len(parts) == 0 {
		return "", r.errf(ctx, "nie wybrano, co przywrócić", "nothing selected to restore")
	}
	job := filepath.Join(r.restoreDir(), "zlecenie")
	if _, err := os.Stat(job); err == nil {
		return "", r.errf(ctx, "inne przywracanie czeka na wykonanie przez serwer", "another restore is waiting to be performed by the server")
	}
	path, err := r.localCopy(ctx, cfg, location, name)
	if err != nil {
		return "", err
	}
	have, err := r.contentsOf(ctx, path)
	if err != nil {
		return "", err
	}
	for _, p := range parts {
		if !contains(have, p) {
			return "", r.errf(ctx, "kopia nie zawiera części %q", "the backup does not contain part %q", p)
		}
	}
	var notes []string
	if safety {
		st := r.backup(ctx, cfg, "manual")
		if st.failed {
			return "", r.errf(ctx, "kopia obecnego stanu przed przywróceniem nieudana – przywracanie przerwane: %s",
				"backup of the current state before restoring failed – restore aborted: %s", st.message)
		}
		notes = append(notes, r.tr(ctx, "kopia obecnego stanu: ", "backup of the current state: ")+st.file)
	}
	rel, err := filepath.Rel(r.BackupDir, path)
	if err != nil {
		return "", err
	}
	var by string
	_ = r.DB.QueryRow(ctx, `SELECT requested_by FROM backup_requests WHERE id = $1`, id).Scan(&by)
	if err := os.MkdirAll(r.restoreDir(), 0o755); err != nil {
		return "", err
	}
	r.own(r.restoreDir())
	if err := writeFileAtomic(job, []byte(restoreJob(id, rel, parts, by)), 0o600); err != nil {
		return "", err
	}
	r.own(job)
	notes = append(notes, fmt.Sprintf(r.tr(ctx, "przygotowane: %s (%s) – serwer przywraca w ciągu minuty, panel będzie chwilę niedostępny",
		"prepared: %s (%s) – the server restores within a minute, the panel will be unavailable for a moment"),
		name, partsLabel(parts, r.Lang.Get(ctx))))
	r.Log.Info("restore prepared – waiting for restore.sh", "file", rel, "parts", parts)
	return strings.Join(notes, "; "), nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
