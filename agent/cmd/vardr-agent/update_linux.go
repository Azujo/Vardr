// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"time"

	"siem/agent/internal/config"
	"siem/agent/internal/update"
	"siem/internal/lang"
)

// Automatyczna aktualizacja agenta Linux (1.9.0). Usługa ma /usr tylko do
// odczytu (ProtectSystem), więc pobrany i sprawdzony program uruchamia
// jako osobną, przejściową usługę systemd (systemd-run) z poleceniem
// apply-update. Ta – już w nowej wersji – działa poza ograniczeniami usługi
// i poza jej grupą procesów: podmienia program jak upgrade, uruchamia
// usługę ponownie i czeka, aż nowa wersja potwierdzi start (usunie
// update.json). Bez potwierdzenia przywraca poprzednią wersję.

// applyTimeout: ile apply-update czeka na potwierdzenie nowej wersji.
const applyTimeout = 3 * time.Minute

// startSelfUpdate (update.Updater.Install): uruchamia apply-update pobranego
// programu; funkcja wait kończy się błędem, gdy podmiana się nie udała przed
// ponownym uruchomieniem usługi (po nim ten proces już nie działa).
func startSelfUpdate(pkg, logPath string) (func() error, error) {
	if err := os.Chmod(pkg, 0o700); err != nil {
		return nil, err
	}
	unit := "vardr-agent-update-" + strconv.FormatInt(time.Now().Unix(), 10)
	cmd := exec.Command("systemd-run", "--unit="+unit, "--description=Vardr agent update", "--collect", "--quiet", "--wait",
		pkg, "-config", installCfg, "apply-update", "-log", logPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("systemd-run: %w", err)
	}
	return cmd.Wait, nil
}

// applyUpdate: polecenie apply-update (nowa wersja programu, przejściowa
// usługa systemd uruchomiona przez agenta).
func applyUpdate(cfgPath, logPath string) error {
	if err := requireAdmin("apply-update"); err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	out := io.Writer(os.Stdout) // dziennik przejściowej usługi (journalctl)
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer f.Close()
			out = io.MultiWriter(os.Stdout, f)
		}
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src == installExe {
		return errors.New("apply-update: run the downloaded program, not " + installExe)
	}
	if !update.Pending(cfg.StateDir) {
		return errors.New("apply-update: no update attempt in " + cfg.StateDir)
	}
	log.Info("replacing the agent program", "from", installExe, "with", src, "version", version)

	fail := func(err error) error {
		log.Error("automatic update failed", "err", err)
		_ = update.MarkFailed(cfg.StateDir, err.Error())
		return err
	}
	// Znacznik instalatora: zatrzymanie i ponowny start to nie sabotaż;
	// ochronę usługi (RefuseManualStop) nowa wersja włączy według grupy.
	markInstaller(cfg.StateDir, "auto-update")
	if err := openService(); err != nil {
		return fail(fmt.Errorf("opening the service: %w", err))
	}
	if err := copyFile(installExe, installExe+".previous", 0o755); err != nil {
		return fail(fmt.Errorf("copy of the previous version: %w", err))
	}
	if err := copyFile(src, installExe, 0o755); err != nil {
		return fail(fmt.Errorf("replacing the program: %w", err))
	}
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return fail(err)
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return fail(err)
	}
	if _, err := systemctl("restart", unitName); err != nil {
		return rollback(cfg.StateDir, log, fmt.Errorf("restart: %w", err))
	}
	deadline := time.Now().Add(applyTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if !update.Pending(cfg.StateDir) {
			// Potwierdzenie przychodzi zaraz po starcie – usługa musi jeszcze
			// chwilę działać (nie kończy się błędem w pętli restartów).
			time.Sleep(15 * time.Second)
			if st := unitActive(); st != "active" {
				return rollback(cfg.StateDir, log, fmt.Errorf("version %s started but the service is %s", version, st))
			}
			log.Info("the new agent version is running", "version", version)
			_ = os.Remove(installExe + ".previous")
			return nil
		}
	}
	return rollback(cfg.StateDir, log, fmt.Errorf("version %s did not confirm its start within %v", version, applyTimeout))
}

// rollback przywraca poprzedni program i uruchamia go ponownie; błąd próby
// zostaje w update.json – stara wersja zgłosi go po starcie.
func rollback(dir string, log *slog.Logger, cause error) error {
	log.Error("restoring the previous agent version", "err", cause)
	msg := lang.L("nowa wersja nie wystartowała (", "the new version did not start (") + cause.Error() +
		lang.L(") – przywrócono poprzednią", ") – the previous one was restored")
	_ = update.MarkFailed(dir, msg)
	markInstaller(dir, "auto-update")
	_ = openService()
	if err := copyFile(installExe+".previous", installExe, 0o755); err != nil {
		log.Error("restoring the previous version failed", "err", err)
		return fmt.Errorf("%w; restoring %s.previous: %v", cause, installExe, err)
	}
	if _, err := systemctl("restart", unitName); err != nil {
		log.Error("starting the previous version failed", "err", err)
	}
	return cause
}
