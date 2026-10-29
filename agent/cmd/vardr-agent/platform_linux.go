// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"siem/agent/internal/auditd"
	"siem/agent/internal/config"
	"siem/agent/internal/journald"
	"siem/agent/internal/logfile"
	"siem/agent/internal/state"
	"siem/agent/internal/status"
	"siem/agent/internal/timesync"
	"siem/internal/lang"
)

// Część agenta zależna od Linuksa: dziennik systemd, uprawnienia plików
// (root, 0600/0700), usługa systemd. Kopii stanu poza katalogiem stanu,
// ochrony usługi i automatycznych aktualizacji (MSI) tu nie ma.

const autoUpdate = false

func isPrivileged() bool { return os.Geteuid() == 0 }

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

// protectFiles: katalog stanu i klucz prywatny tylko dla roota.
func protectFiles(cfg *config.Config, log *slog.Logger) []string {
	if !isPrivileged() {
		w := lang.L("agent działa bez uprawnień roota – część dziennika (np. wpisy innych użytkowników) może być niedostępna",
			"the agent runs without root privileges – part of the journal (e.g. other users' entries) may be unavailable")
		log.Warn("the agent runs without root privileges – part of the journal may be unavailable")
		return []string{w}
	}
	var warns []string
	for _, p := range []struct {
		path string
		mode fs.FileMode
	}{{cfg.StateDir, 0o700}, {cfg.Server.KeyFile, 0o600}} {
		if err := os.Chmod(p.path, p.mode); err != nil {
			warns = append(warns, errText(err))
			log.Error("securing agent files failed", "path", p.path, "err", err)
		}
	}
	return warns
}

// programWarning: plik programu (i jego katalog) musi należeć do roota i nie
// być zapisywalny dla grupy ani innych – inaczej zwykły użytkownik
// podmieniłby program działający jako root.
func programWarning() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return rootOnly(exe)
}

// rootOnly sprawdza właściciela i prawa zapisu pliku oraz katalogów nad nim.
func rootOnly(path string) string {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err.Error()
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if ok && st.Uid != 0 {
			return fmt.Sprintf(lang.L("%s nie należy do roota (uid %d)", "%s is not owned by root (uid %d)"), p, st.Uid)
		}
		// Katalog z bitem sticky (np. /tmp) też odpada – program nie powinien tam leżeć.
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Sprintf(lang.L("%s jest zapisywalny dla grupy albo innych (%v)", "%s is writable by group or others (%v)"), p, fi.Mode().Perm())
		}
		if p == "/" || p == filepath.Dir(p) {
			return ""
		}
	}
}

func stateBackup(bool, string) (state.Backup, string) { return nil, "" }

func serviceRunning() bool { return unitActive() == "active" }

// systemProbes: usługa synchronizacji czasu co 5 min (Sysmona brak).
func systemProbes(ctx context.Context, tracker *status.Tracker) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		tracker.SetTimeService(timesync.ServiceState())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func processCPUTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// platformSources: dziennik systemd, dziennik auditd i pliki logów.
func platformSources(cfg *config.Config, _ *status.Tracker, log *slog.Logger) pipelineSources {
	var p pipelineSources
	host, _ := os.Hostname()
	host = strings.ToLower(host)
	oldest := cfg.StartAt == config.StartAtOldest
	if j := cfg.Journald; j.Enabled {
		p.sources = append(p.sources, &journald.Source{Journalctl: j.Journalctl, Oldest: oldest,
			Filter: journald.Filter{All: j.All, Units: j.Units, Identifiers: j.Identifiers}, Host: host, Log: log})
	}
	if a := cfg.Auditd; a.Enabled {
		self, _ := os.Executable()
		p.sources = append(p.sources, &auditd.Source{Path: a.Path, Exclude: auditExclude(a), Oldest: oldest, Host: host, SelfExe: self, Log: log})
	}
	// Pliki logów: wzorzec rozwijany przy starcie, każdy plik osobnym kanałem.
	for _, f := range cfg.Files {
		for _, path := range logfile.Expand([]string{f.Path}, cfg.StateDir) {
			p.sources = append(p.sources, &logfile.Source{Path: path, App: f.App, Host: host, Oldest: oldest, Log: log})
		}
	}
	return p
}

// auditExclude: pomijane typy rekordów auditd (domyślne, gdy brak listy).
func auditExclude(a config.AuditdConfig) map[string]bool {
	list := a.Exclude
	if list == nil {
		list = auditd.DefaultExclude
	}
	m := make(map[string]bool, len(list))
	for _, t := range list {
		m[t] = true
	}
	return m
}

// retryDelay: brak journalctl sprawdzamy rzadko, inne błędy szybciej.
func retryDelay(err error) time.Duration {
	if errors.Is(err, journald.ErrNotFound) {
		return 5 * time.Minute
	}
	return 10 * time.Second
}

func classifyError(err error) string {
	if errors.Is(err, journald.ErrNotFound) {
		return status.ChannelNotFound
	}
	return status.ChannelError
}
