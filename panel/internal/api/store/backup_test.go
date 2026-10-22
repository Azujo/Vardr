// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"siem/internal/backupcfg"
)

func TestPostgresBackup(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, "TRUNCATE backup_config, backup_secrets, backup_runner, backup_runs, backup_requests, backup_files"); err != nil {
		t.Fatal(err)
	}
	// Bez zapisu – ustawienia domyślne.
	st, err := db.Backup(ctx)
	if err != nil || st.Saved || st.Runner != nil || st.Config.Schedule.Hour != 2 {
		t.Fatalf("domyślne: %+v %v", st, err)
	}
	cfg := backupcfg.Default()
	cfg.Target = backupcfg.Target{Method: backupcfg.MethodSMB, Host: "nas", User: "kopie", Share: "vardr"}
	if err := db.SaveBackup(ctx, cfg, map[string]SealedSecret{"password": {Sealed: []byte{1, 2, 3}, KeyID: "abc"}}, nil, "adam"); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := backupcfg.NewBoxKey()
	if _, err := db.pool.Exec(ctx, `INSERT INTO backup_runner (id, box_public_key, pass_id, seen_at) VALUES (1, $1, 'k12345678', now())`,
		backupcfg.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, `INSERT INTO backup_runs (kind, status, size_bytes) VALUES ('scheduled', 'ok', 1024)`); err != nil {
		t.Fatal(err)
	}
	st, err = db.Backup(ctx)
	if err != nil || !st.Saved || st.Config.Target.Share != "vardr" || len(st.Secrets) != 1 || st.Secrets[0].KeyID != "abc" ||
		st.Runner == nil || st.Runner.KeyID != backupcfg.KeyID(pub) || len(st.Runs) != 1 {
		t.Fatalf("po zapisie: %+v %v", st, err)
	}
	// Usunięcie sekretu przy zmianie metody.
	if err := db.SaveBackup(ctx, backupcfg.Default(), nil, []string{"password"}, "adam"); err != nil {
		t.Fatal(err)
	}
	if st, _ = db.Backup(ctx); len(st.Secrets) != 0 {
		t.Fatalf("sekret po usunięciu: %+v", st.Secrets)
	}
	// Zlecenia: drugie takie samo czeka – odrzucone.
	if r, err := db.AddBackupRequest(ctx, "run", "adam", nil); err != nil || r.ID == 0 {
		t.Fatalf("zlecenie: %+v %v", r, err)
	}
	if _, err := db.AddBackupRequest(ctx, "run", "adam", nil); !errors.Is(err, ErrBackupPending) {
		t.Fatalf("drugie zlecenie: %v", err)
	}
	if _, err := db.AddBackupRequest(ctx, "test", "adam", nil); err != nil {
		t.Fatal(err)
	}
	if st, _ = db.Backup(ctx); len(st.Requests) != 2 {
		t.Fatalf("zlecenia: %+v", st.Requests)
	}
	// Sprawdzenie zawartości: osobne zlecenie dla każdej kopii; lista kopii.
	f1 := map[string]any{"location": "local", "name": "vardr-20261019-0215-k1.tar.gpg"}
	if _, err := db.AddBackupRequest(ctx, "inspect", "adam", f1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBackupRequest(ctx, "inspect", "adam", map[string]any{"location": "remote", "name": "x"}); err != nil {
		t.Fatalf("inna kopia: %v", err)
	}
	if _, err := db.AddBackupRequest(ctx, "inspect", "adam", f1); !errors.Is(err, ErrBackupPending) {
		t.Fatalf("ta sama kopia: %v", err)
	}
	if _, err := db.pool.Exec(ctx, `INSERT INTO backup_files (location, name, size_bytes, contents) VALUES ('local', 'a', 10, '{saga,config}')`); err != nil {
		t.Fatal(err)
	}
	if st, _ = db.Backup(ctx); len(st.Files) != 1 || len(st.Files[0].Contents) != 2 || st.Requests[0].Params["location"] != "remote" {
		t.Fatalf("kopie: %+v %+v", st.Files, st.Requests[0])
	}
}
