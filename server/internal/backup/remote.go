// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/backupcfg"
)

// Wysyłka poza serwer przez rclone (SFTP, SMB, S3). Konfiguracja rclone
// powstaje na czas operacji w katalogu roboczym (0600) i znika z nim.
// Na serwerze kopii: <katalog>/config/ – kopie, <katalog>/urd/ – przyrosty
// archiwum NIS2 (jak dotychczas w backup.sh, restore.sh czyta oba).

const remoteName = "cel"

// rcloneConfig zapisuje konfigurację rclone i zwraca ścieżkę oraz katalog
// docelowy („cel:ścieżka”).
func (r *Runner) rcloneConfig(ctx context.Context, cfg backupcfg.Config, work string) (string, string, error) {
	t := cfg.Target
	sec, err := r.secrets(ctx, t)
	if err != nil {
		return "", "", err
	}
	obscure := func(v string) (string, error) {
		out, err := r.cmd(ctx, 30*time.Second, strings.NewReader(v), "rclone", "obscure", "-")
		if err != nil {
			return "", fmt.Errorf("rclone obscure: %s", out)
		}
		return strings.TrimSpace(out), nil
	}
	lines := []string{"[" + remoteName + "]"}
	set := func(k, v string) { lines = append(lines, k+" = "+v) }
	var base string
	switch t.Method {
	case backupcfg.MethodSFTP:
		set("type", "sftp")
		set("host", t.Host)
		set("user", t.User)
		set("port", strconv.Itoa(portOr(t.Port, 22)))
		kh, err := r.ensureHostKey(ctx, t)
		if err != nil {
			return "", "", err
		}
		set("known_hosts_file", kh)
		switch t.Auth {
		case backupcfg.AuthServerKey:
			key := filepath.Join(r.StateDir, "ssh_key")
			if _, err := os.Stat(key); err != nil {
				return "", "", fmt.Errorf("brak klucza SSH usługi kopii – wygeneruj go w panelu")
			}
			set("key_file", key)
		case backupcfg.AuthPrivateKey:
			key := filepath.Join(work, "ssh_key")
			pem := strings.TrimSpace(sec[backupcfg.SecretPrivateKey]) + "\n"
			if err := os.WriteFile(key, []byte(pem), 0o600); err != nil {
				return "", "", err
			}
			set("key_file", key)
		case backupcfg.AuthPassword:
			p, err := obscure(sec[backupcfg.SecretPassword])
			if err != nil {
				return "", "", err
			}
			set("pass", p)
		}
		set("shell_type", "unix")
		base = t.Path
	case backupcfg.MethodSMB:
		set("type", "smb")
		set("host", t.Host)
		set("user", t.User)
		set("port", strconv.Itoa(portOr(t.Port, 445)))
		if t.Domain != "" {
			set("domain", t.Domain)
		}
		p, err := obscure(sec[backupcfg.SecretPassword])
		if err != nil {
			return "", "", err
		}
		set("pass", p)
		base = strings.TrimSuffix(t.Share+"/"+t.Path, "/")
	case backupcfg.MethodS3:
		set("type", "s3")
		if t.Endpoint == "" {
			set("provider", "AWS")
		} else {
			set("provider", "Other")
			set("endpoint", t.Endpoint)
		}
		if t.Region != "" {
			set("region", t.Region)
		}
		set("access_key_id", t.AccessKey)
		set("secret_access_key", sec[backupcfg.SecretS3Key])
		set("no_check_bucket", "true")
		base = strings.TrimSuffix(t.Bucket+"/"+t.Path, "/")
	default:
		return "", "", fmt.Errorf("brak miejsca docelowego")
	}
	for _, l := range lines {
		if strings.ContainsAny(l, "\n\r") {
			return "", "", fmt.Errorf("niepoprawny znak w ustawieniach miejsca docelowego")
		}
	}
	path := filepath.Join(work, "rclone.conf")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return path, remoteName + ":" + base, nil
}

func portOr(p, def int) int {
	if p > 0 {
		return p
	}
	return def
}

func (r *Runner) rclone(ctx context.Context, timeout time.Duration, conf string, args ...string) (string, error) {
	return r.cmd(ctx, timeout, nil, "rclone", append([]string{"--config", conf, "--retries", "3", "--low-level-retries", "5",
		"--contimeout", "20s", "--timeout", "5m"}, args...)...)
}

// rcloneOut zwraca pełne wyjście (lista plików – bez skracania jak w komunikatach).
func (r *Runner) rcloneOut(ctx context.Context, timeout time.Duration, conf string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "rclone", append([]string{"--config", conf, "--retries", "3", "--contimeout", "20s"}, args...)...)
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("%s", truncate(strings.TrimSpace(stderr.String()), 1500))
	}
	return string(out), nil
}

// upload wysyła kopię i przyrosty archiwum, potem stosuje retencję zdalną.
func (r *Runner) upload(ctx context.Context, cfg backupcfg.Config, work, file, stamp, kid string, pass []byte) (string, error) {
	conf, base, err := r.rcloneConfig(ctx, cfg, work)
	if err != nil {
		return "", err
	}
	var notes []string
	if file != "" {
		if out, err := r.rclone(ctx, 2*time.Hour, conf, "copyto", filepath.Join(r.BackupDir, file), base+"/config/"+file); err != nil {
			return "", fmt.Errorf("kopia: %s", out)
		}
		notes = append(notes, "wysłano kopię")
	}
	if cfg.Include.Archive {
		n, size, err := r.uploadArchive(ctx, conf, base, work, stamp, kid)
		if err != nil {
			return "", fmt.Errorf("archiwum NIS2: %w", err)
		}
		if n > 0 {
			notes = append(notes, fmt.Sprintf("archiwum NIS2: %d nowych plików (%s)", n, human(size)))
		}
	}
	if n, err := r.remoteRetention(ctx, conf, base+"/config", cfg.Remote); err != nil {
		notes = append(notes, "retencja zdalna nieudana: "+err.Error())
	} else if n > 0 {
		notes = append(notes, fmt.Sprintf("usunięte stare kopie zdalne: %d", n))
	}
	// Przyrosty archiwum: tylko po wieku – liczba paczek nie mówi nic
	// o zakresie archiwum, a każda niesie inne segmenty.
	if n, err := r.remoteRetention(ctx, conf, base+"/urd", backupcfg.Retention{KeepDays: cfg.Remote.KeepDays}); err == nil && n > 0 {
		notes = append(notes, fmt.Sprintf("usunięte stare paczki archiwum: %d", n))
	}
	return strings.Join(notes, "; "), nil
}

// uploadArchive wysyła pliki archiwum NIS2, których jeszcze nie wysłano
// (segmenty się nie zmieniają); lista wysłanych w <kopie>/urd-sent.list.
func (r *Runner) uploadArchive(ctx context.Context, conf, base, work, stamp, kid string) (int, int64, error) {
	var now []string
	for _, sub := range []string{"segments", "manifests"} {
		root := filepath.Join(r.ArchiveDir, sub)
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			// Pliki .tmp to segmenty jeszcze zapisywane przez archiwizator
			// (zmieniają nazwę po zamknięciu) – trafią do kolejnej kopii.
			if err == nil && !d.IsDir() && !strings.HasSuffix(d.Name(), ".tmp") && !strings.HasPrefix(d.Name(), ".") {
				rel, _ := filepath.Rel(r.ArchiveDir, p)
				now = append(now, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	if len(now) == 0 {
		return 0, 0, nil
	}
	sort.Strings(now)
	sentPath := filepath.Join(r.BackupDir, "urd-sent.list")
	sent := map[string]bool{}
	if f, err := os.Open(sentPath); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			sent[sc.Text()] = true
		}
		f.Close()
	}
	var fresh []string
	for _, p := range now {
		if !sent[p] {
			fresh = append(fresh, p)
		}
	}
	if len(fresh) == 0 {
		return 0, 0, nil
	}
	list := fresh
	// Znacznik katalogu archiwum w każdej paczce (starsze paczki mogą wygasnąć).
	if _, err := os.Stat(filepath.Join(r.ArchiveDir, ".urd-archive")); err == nil {
		list = append(list, ".urd-archive")
	}
	listFile := filepath.Join(work, "urd.list")
	if err := os.WriteFile(listFile, []byte(strings.Join(list, "\n")+"\n"), 0o600); err != nil {
		return 0, 0, err
	}
	name := "urd-" + stamp + "-" + kid + ".tar.gpg"
	out := filepath.Join(work, name)
	if err := r.encryptTar(ctx, r.ArchiveDir, nil, &listFile, out); err != nil {
		return 0, 0, err
	}
	fi, _ := os.Stat(out)
	if msg, err := r.rclone(ctx, 6*time.Hour, conf, "copyto", out, base+"/urd/"+name); err != nil {
		return 0, 0, fmt.Errorf("%s", msg)
	}
	// Wysłane = to, co jest teraz (pliki usunięte przez retencję wypadają z listy).
	if err := writeFileAtomic(sentPath, []byte(strings.Join(now, "\n")+"\n"), 0o644); err != nil {
		return 0, 0, err
	}
	r.own(sentPath)
	return len(fresh), fi.Size(), nil
}

// remoteRetention usuwa stare paczki w katalogu zdalnym.
func (r *Runner) remoteRetention(ctx context.Context, conf, dir string, ret backupcfg.Retention) (int, error) {
	out, err := r.rcloneOut(ctx, 5*time.Minute, conf, "lsjson", "--files-only", dir)
	if err != nil {
		if strings.Contains(err.Error(), "directory not found") {
			return 0, nil
		}
		return 0, err
	}
	var items []struct {
		Name    string    `json:"Name"`
		ModTime time.Time `json:"ModTime"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return 0, err
	}
	var files []remoteFile
	for _, it := range items {
		if strings.HasSuffix(it.Name, ".tar.gpg") {
			files = append(files, remoteFile{Name: it.Name, ModTime: it.ModTime})
		}
	}
	n := 0
	for _, name := range expired(files, ret, time.Now()) {
		if msg, err := r.rclone(ctx, 5*time.Minute, conf, "deletefile", dir+"/"+name); err != nil {
			return n, fmt.Errorf("%s", msg)
		}
		n++
	}
	return n, nil
}

// test sprawdza połączenie z miejscem docelowym (zapis i odczyt katalogu).
func (r *Runner) test(ctx context.Context, cfg backupcfg.Config) (string, error) {
	if cfg.Target.Method == backupcfg.MethodNone {
		return "", fmt.Errorf("nie ustawiono miejsca docelowego – kopie są tylko lokalne")
	}
	work, err := os.MkdirTemp(r.BackupDir, ".test-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	conf, base, err := r.rcloneConfig(ctx, cfg, work)
	if err != nil {
		return "", err
	}
	if out, err := r.rclone(ctx, 2*time.Minute, conf, "mkdir", base+"/config"); err != nil {
		return "", fmt.Errorf("utworzenie katalogu nieudane: %s", out)
	}
	probe := filepath.Join(work, ".vardr-test")
	_ = os.WriteFile(probe, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
	if out, err := r.rclone(ctx, 2*time.Minute, conf, "copyto", probe, base+"/config/.vardr-test"); err != nil {
		return "", fmt.Errorf("zapis nieudany: %s", out)
	}
	_, _ = r.rclone(ctx, time.Minute, conf, "deletefile", base+"/config/.vardr-test")
	out, err := r.rclone(ctx, 2*time.Minute, conf, "lsf", "--files-only", base+"/config")
	if err != nil {
		return "", fmt.Errorf("odczyt katalogu nieudany: %s", out)
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), ".tar.gpg") {
			n++
		}
	}
	msg := fmt.Sprintf("połączenie działa: zapis i odczyt w %s, kopii w katalogu: %d", strings.TrimPrefix(base, remoteName+":"), n)
	return msg, nil
}

// ensureHostKey: klucz serwera SFTP zapamiętany przy pierwszym połączeniu
// (jak ssh przy pierwszym logowaniu); później zmiana klucza zatrzymuje
// wysyłkę (ochrona przed podszyciem). Odcisk widać w panelu.
func (r *Runner) ensureHostKey(ctx context.Context, t backupcfg.Target) (string, error) {
	kh := filepath.Join(r.StateDir, "known_hosts")
	port := portOr(t.Port, 22)
	name := t.Host
	if port != 22 {
		name = fmt.Sprintf("[%s]:%d", t.Host, port)
	}
	if _, err := r.cmd(ctx, 10*time.Second, nil, "ssh-keygen", "-F", name, "-f", kh); err == nil {
		return kh, nil
	}
	out, err := r.cmd(ctx, 30*time.Second, nil, "ssh-keyscan", "-T", "10", "-p", strconv.Itoa(port), "-t", "ed25519,ecdsa,rsa", t.Host)
	var keys []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	if err != nil || len(keys) == 0 {
		return "", fmt.Errorf("serwer %s:%d nie odpowiada na SSH (%s)", t.Host, port, out)
	}
	f, err := os.OpenFile(kh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(strings.Join(keys, "\n") + "\n")
	f.Close()
	if err != nil {
		return "", err
	}
	fp, _ := r.cmd(ctx, 10*time.Second, strings.NewReader(keys[0]+"\n"), "ssh-keygen", "-l", "-f", "-")
	r.setHostKey(ctx, t.Host+": "+fp)
	r.Log.Info("zapamiętano klucz serwera kopii", "host", t.Host, "fingerprint", fp)
	return kh, nil
}

// genKey tworzy nowy klucz SSH usługi kopii (stary przestaje działać).
func (r *Runner) genKey(ctx context.Context) (string, error) {
	key := filepath.Join(r.StateDir, "ssh_key")
	_ = os.Remove(key)
	_ = os.Remove(key + ".pub")
	host, _ := os.Hostname()
	if out, err := r.cmd(ctx, 30*time.Second, nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vardr-backup@"+host, "-f", key); err != nil {
		return "", fmt.Errorf("ssh-keygen: %s", out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		return "", err
	}
	if err := r.heartbeat(ctx); err != nil {
		return "", err
	}
	return "nowy klucz SSH: dopisz klucz publiczny do authorized_keys na serwerze kopii – " + strings.TrimSpace(string(pub)), nil
}
