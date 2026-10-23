// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-backup to usługa kopii zapasowych Vardra (kontener
// backup w stosie): kopie według ustawień z panelu (Administracja → Kopie
// zapasowe), szyfrowane hasłem kopii, z retencją lokalną i zdalną, wysyłka
// przez rclone (SFTP, SMB, S3) razem z przyrostami archiwum NIS2.
//
//	siem-backup serve     usługa (domyślnie)
//	siem-backup run       kopia teraz (zlecenie dla działającej usługi; czeka na wynik)
//
// Hasłem kopii zarządza administrator na serwerze: ./backup.sh haslo init|pokaz|zmien.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"siem/internal/lang/langdb"
	"siem/internal/svc"
	"siem/server/internal/backup"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	// „run” to polecenie dla administratora w konsoli – bez logu JSON.
	log := slog.New(slog.DiscardHandler)
	if cmd == "serve" {
		log = svc.Logger("backup")
	}
	ctx, cancel := svc.Context()
	defer cancel()
	dbURL := svc.MustEnv(log, "SIEM_BACKUP_DB_URL")
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Error("connecting to Saga failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	switch cmd {
	case "serve":
		err = serve(ctx, log, pool, dbURL)
	case "run":
		err = runNow(ctx, pool)
	default:
		fmt.Fprintln(os.Stderr, "usage: siem-backup [serve|run]")
		os.Exit(2)
	}
	if err != nil {
		log.Error("exited with an error", "err", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, dbURL string) error {
	loc, err := time.LoadLocation(svc.Env("SIEM_BACKUP_TZ", "Europe/Warsaw"))
	if err != nil {
		return fmt.Errorf("SIEM_BACKUP_TZ: %w", err)
	}
	keep, _ := strconv.Atoi(os.Getenv("SIEM_BACKUP_REMOTE_KEEP_DAYS"))
	uid, _ := strconv.Atoi(svc.Env("SIEM_BACKUP_UID", "1000"))
	gid, _ := strconv.Atoi(svc.Env("SIEM_BACKUP_GID", "1000"))
	// Saga może jeszcze startować – usługa czeka, zamiast się restartować.
	if err := svc.Retry(ctx, log, "connecting to Saga", func() error { return pool.Ping(ctx) }); err != nil {
		return err
	}
	r := &backup.Runner{
		DB: pool, Log: log, DumpURL: dbURL, Version: svc.Version, Loc: loc,
		StateDir:   svc.Env("SIEM_BACKUP_STATE_DIR", "/state"),
		BackupDir:  svc.Env("SIEM_BACKUP_DIR", "/backup"),
		PassFile:   svc.Env("SIEM_BACKUP_PASS_FILE", "/secrets/backup.pass"),
		StackDir:   svc.Env("SIEM_BACKUP_STACK_DIR", "/stack"),
		ArchiveDir: svc.Env("SIEM_BACKUP_ARCHIVE_DIR", "/archive"),
		GrafanaDir: svc.Env("SIEM_BACKUP_GRAFANA_DIR", "/grafana"),
		MetricsDir: svc.Env("SIEM_BACKUP_METRICS_DIR", "/metrics"),
		Legacy:     os.Getenv("SIEM_BACKUP_REMOTE"), LegacyKeepDay: keep,
		OwnerUID: uid, OwnerGID: gid,
		Lang: &langdb.System{DB: pool},
	}
	return r.Run(ctx)
}

// runNow zleca kopię działającej usłudze i czeka na wynik (backup.sh bez
// argumentów) – dwie kopie naraz nie powstaną.
func runNow(ctx context.Context, pool *pgxpool.Pool) error {
	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO backup_requests (action, requested_by) VALUES ('run', 'server (backup.sh)') RETURNING id`).
		Scan(&id); err != nil {
		return err
	}
	fmt.Printf("backup requested (#%d) – waiting for the backup service…\n", id)
	deadline := time.Now().Add(6 * time.Hour)
	for time.Now().Before(deadline) {
		var ok *bool
		var msg string
		if err := pool.QueryRow(ctx, `SELECT ok, message FROM backup_requests WHERE id = $1`, id).Scan(&ok, &msg); err != nil {
			return err
		}
		if ok != nil {
			fmt.Println(msg)
			if !*ok {
				return fmt.Errorf("backup failed")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("the backup service did not complete the request within 6 h")
}
