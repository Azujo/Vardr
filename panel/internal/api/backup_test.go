package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/internal/backupcfg"
	"siem/panel/internal/api/store"
)

type memBackup struct {
	st      store.BackupState
	sealed  map[string]store.SealedSecret
	actions []string
	params  map[string]any
}

func (m *memBackup) Backup(context.Context) (store.BackupState, error) {
	st := m.st
	st.Secrets = []store.BackupSecret{}
	for name, s := range m.sealed {
		st.Secrets = append(st.Secrets, store.BackupSecret{Name: name, KeyID: s.KeyID})
	}
	return st, nil
}

func (m *memBackup) SaveBackup(_ context.Context, cfg backupcfg.Config, secrets map[string]store.SealedSecret, drop []string, by string) error {
	m.st.Config, m.st.Saved, m.st.UpdatedBy = cfg, true, by
	for k, v := range secrets {
		m.sealed[k] = v
	}
	for _, k := range drop {
		delete(m.sealed, k)
	}
	return nil
}

func (m *memBackup) AddBackupRequest(_ context.Context, action, by string, params map[string]any) (store.BackupRequest, error) {
	if slices.Contains(m.actions, action) {
		return store.BackupRequest{}, store.ErrBackupPending
	}
	m.actions = append(m.actions, action)
	m.params = params
	return store.BackupRequest{ID: int64(len(m.actions)), Action: action, RequestedBy: by, Params: params}, nil
}

func TestBackupAPI(t *testing.T) {
	e := newEnv(t)
	mb := &memBackup{st: store.BackupState{Config: backupcfg.Default()}, sealed: map[string]store.SealedSecret{}}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Backups: mb}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	if code, _, _ := analyst.do("GET", "/api/v1/backup", nil); code != 403 {
		t.Fatalf("kopie dla analityka: %d", code)
	}
	cfg := backupcfg.Default()
	cfg.Target = backupcfg.Target{Method: backupcfg.MethodSFTP, Host: "192.168.88.180", User: "vardr", Auth: backupcfg.AuthPassword, Path: "/mnt/kopie"}
	body := func(c backupcfg.Config, secrets map[string]string, pw string) map[string]any {
		return map[string]any{"config": c, "secrets": secrets, "password": pw}
	}
	// Bez ponownego hasła – odmowa.
	if code, out, _ := admin.do("PUT", "/api/v1/backup", body(cfg, map[string]string{"password": "tajne"}, "")); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("bez hasła: %d %v", code, out)
	}
	// Usługa kopii jeszcze się nie zgłosiła – sekretu nie da się zaszyfrować.
	if code, out, _ := admin.do("PUT", "/api/v1/backup", body(cfg, map[string]string{"password": "tajne"}, "haslo-adama-123")); code != 409 {
		t.Fatalf("bez klucza usługi: %d %v", code, out)
	}
	pub, priv, _ := backupcfg.NewBoxKey()
	mb.st.Runner = &store.BackupRunner{BoxPublicKey: backupcfg.EncodeKey(pub), KeyID: backupcfg.KeyID(pub)}
	// Wymagany sekret nie podany.
	if code, out, _ := admin.do("PUT", "/api/v1/backup", body(cfg, nil, "haslo-adama-123")); code != 400 || out["error"] != "secret_required" {
		t.Fatalf("brak hasła SFTP: %d %v", code, out)
	}
	// Złe ustawienia.
	bad := cfg
	bad.Target.Host = "a;rm"
	if code, _, _ := admin.do("PUT", "/api/v1/backup", body(bad, map[string]string{"password": "x"}, "haslo-adama-123")); code != 400 {
		t.Fatalf("zły host: %d", code)
	}
	// Poprawny zapis: sekret zaszyfrowany kluczem usługi, panel go nie zwraca.
	if code, out, _ := admin.do("PUT", "/api/v1/backup", body(cfg, map[string]string{"password": "tajne hasło"}, "haslo-adama-123")); code != 200 {
		t.Fatalf("zapis: %d %v", code, out)
	}
	s, ok := mb.sealed[backupcfg.SecretPassword]
	if !ok || s.KeyID != backupcfg.KeyID(pub) {
		t.Fatalf("sekret: %+v", mb.sealed)
	}
	if v, err := backupcfg.Open(s.Sealed, pub, priv); err != nil || v != "tajne hasło" {
		t.Fatalf("odszyfrowanie przez usługę: %q %v", v, err)
	}
	_, out, _ := admin.do("GET", "/api/v1/backup", nil)
	if b, _ := json.Marshal(out); out["online"] != false || strings.Contains(string(b), "tajne") {
		t.Fatalf("odczyt: %v", out)
	}
	// Ponowny zapis bez wpisywania hasła – zostaje; zmiana na S3 usuwa niepotrzebne hasło.
	if code, _, _ := admin.do("PUT", "/api/v1/backup", body(cfg, nil, "haslo-adama-123")); code != 200 {
		t.Fatalf("zapis bez zmiany sekretu: %d", code)
	}
	s3 := cfg
	s3.Target = backupcfg.Target{Method: backupcfg.MethodS3, Bucket: "kopie-vardr", AccessKey: "AKIA123"}
	if code, _, _ := admin.do("PUT", "/api/v1/backup", body(s3, map[string]string{"s3_secret": "sekret"}, "haslo-adama-123")); code != 200 ||
		len(mb.sealed) != 1 || mb.sealed[backupcfg.SecretS3Key].KeyID == "" {
		t.Fatalf("S3: %d %v", code, mb.sealed)
	}
	// Zlecenia.
	if code, _, _ := admin.do("POST", "/api/v1/backup/requests", map[string]any{"action": "run"}); code != 200 {
		t.Fatalf("zlecenie: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/backup/requests", map[string]any{"action": "run"}); code != 409 {
		t.Fatalf("drugie zlecenie: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/backup/requests", map[string]any{"action": "rm"}); code != 400 {
		t.Fatalf("złe zlecenie: %d", code)
	}
	// Przywracanie.
	mb.st.Files = []store.BackupFile{{Location: "local", Name: "nowa"}, {Location: "remote", Name: "stara", Contents: []string{"saga", "config", "grafana"}}}
	restore := func(name string, parts []string, confirm, pw string) (int, map[string]any) {
		code, out, _ := admin.do("POST", "/api/v1/backup/restore", map[string]any{"location": map[bool]string{true: "local", false: "remote"}[name == "nowa"],
			"name": name, "parts": parts, "safety_backup": true, "confirm": confirm, "password": pw})
		return code, out
	}
	if code, out := restore("brak", []string{"saga"}, "PRZYWRÓĆ", "haslo-adama-123"); code != 404 {
		t.Fatalf("nieznana kopia: %d %v", code, out)
	}
	if code, out := restore("nowa", []string{"saga"}, "PRZYWRÓĆ", "haslo-adama-123"); code != 400 || out["error"] != "not_inspected" {
		t.Fatalf("niesprawdzona: %d %v", code, out)
	}
	if code, out := restore("stara", []string{"saga"}, "PRZYWRÓĆ", "haslo-adama-123"); code != 400 || out["error"] != "bad_part" {
		t.Fatalf("baza bez konfiguracji: %d %v", code, out)
	}
	if code, out := restore("stara", []string{"saga", "config"}, "tak", "haslo-adama-123"); code != 400 || out["error"] != "confirm_required" {
		t.Fatalf("bez słowa: %d %v", code, out)
	}
	if code, out := restore("stara", []string{"saga", "config"}, "PRZYWRÓĆ", "złe"); code != 403 {
		t.Fatalf("złe hasło: %d %v", code, out)
	}
	if code, out := restore("stara", []string{"grafana", "saga", "config"}, "PRZYWRÓĆ", "haslo-adama-123"); code != 200 ||
		mb.params["name"] != "stara" || len(mb.params["parts"].([]string)) != 3 {
		t.Fatalf("przywrócenie: %d %v %v", code, out, mb.params)
	}
	if code, _, _ := admin.do("POST", "/api/v1/backup/requests", map[string]any{"action": "inspect", "location": "local", "name": "nowa"}); code != 200 ||
		mb.params["name"] != "nowa" {
		t.Fatalf("sprawdzenie zawartości: %d", code)
	}
	for _, a := range []string{"backup_config_changed", "backup_requested", "backup_restore_requested"} {
		if !slices.Contains(e.st.actions(), a) {
			t.Fatalf("brak audytu %s", a)
		}
	}
}
