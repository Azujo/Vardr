// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"siem/internal/backupcfg"
	"siem/panel/internal/api/store"
)

// Kopie zapasowe (panel → Administracja → Kopie zapasowe): ustawienia
// harmonogramu, zawartości, retencji i miejsca docelowego dla usługi
// siem-backup, zlecenia (kopia teraz, test, nowy klucz SSH) i wyniki.

// BackupStore to magazyn ustawień kopii (implementuje store.PG).
type BackupStore interface {
	Backup(ctx context.Context) (store.BackupState, error)
	SaveBackup(ctx context.Context, cfg backupcfg.Config, secrets map[string]store.SealedSecret, drop []string, by string) error
	AddBackupRequest(ctx context.Context, action, by string, params map[string]any) (store.BackupRequest, error)
}

// runnerOnline: usługa kopii zgłasza się co 15 s.
const runnerOnline = 2 * time.Minute

func (s *Server) backupEnabled(w http.ResponseWriter) bool {
	if s.Backups == nil {
		writeError(w, http.StatusServiceUnavailable, "backup_disabled", "kopie zapasowe wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled(w) {
		return
	}
	st, err := s.Backups.Backup(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	online := st.Runner != nil && st.Runner.SeenAt != nil && s.now().Sub(*st.Runner.SeenAt) < runnerOnline
	// Sekret zaszyfrowany innym kluczem niż obecny klucz usługi trzeba wpisać ponownie.
	stale := []string{}
	if st.Runner != nil && st.Runner.KeyID != "" {
		for _, sec := range st.Secrets {
			if sec.KeyID != st.Runner.KeyID {
				stale = append(stale, sec.Name)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st, "online": online, "stale_secrets": stale,
		"needed_secrets": nonNilSlice(st.Config.Target.Secrets())})
}

func (s *Server) saveBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Config   backupcfg.Config  `json:"config"`
		Secrets  map[string]string `json:"secrets"` // nowe wartości (puste – bez zmian)
		Password string            `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := req.Config.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_config", err.Error())
		return
	}
	// Zmiana kopii dotyczy poświadczeń do miejsca, gdzie trafiają dane
	// całego systemu – zawsze z ponownym hasłem (i do audytu).
	if !s.reauth(w, r, req.Password, "backup_config") {
		return
	}
	st, err := s.Backups.Backup(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	needed := req.Config.Target.Secrets()
	have := map[string]bool{}
	for _, sec := range st.Secrets {
		have[sec.Name] = true
	}
	sealed := map[string]store.SealedSecret{}
	changed := []string{}
	for name, val := range req.Secrets {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if !contains(needed, name) {
			writeError(w, http.StatusBadRequest, "bad_secret", "sekret "+name+" nie jest potrzebny przy tych ustawieniach")
			return
		}
		if len(val) > 16384 {
			writeError(w, http.StatusBadRequest, "bad_secret", "sekret za długi")
			return
		}
		if name == backupcfg.SecretPrivateKey && !strings.Contains(val, "PRIVATE KEY-----") {
			writeError(w, http.StatusBadRequest, "bad_secret", "klucz prywatny w formacie OpenSSH albo PEM (-----BEGIN … PRIVATE KEY-----)")
			return
		}
		if st.Runner == nil || st.Runner.BoxPublicKey == "" {
			writeError(w, http.StatusConflict, "runner_missing",
				"usługa kopii (siem-backup) jeszcze się nie zgłosiła – bez jej klucza nie da się bezpiecznie zapisać sekretu")
			return
		}
		pub, err := backupcfg.DecodeKey(st.Runner.BoxPublicKey)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		b, err := backupcfg.Seal(val, pub)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		sealed[name] = store.SealedSecret{Sealed: b, KeyID: backupcfg.KeyID(pub)}
		changed = append(changed, name)
		have[name] = true
	}
	for _, name := range needed {
		if !have[name] {
			writeError(w, http.StatusBadRequest, "secret_required", secretLabel(name)+": wpisz wartość")
			return
		}
	}
	// Sekrety niepotrzebne przy nowych ustawieniach są usuwane.
	var drop []string
	for _, sec := range st.Secrets {
		if !contains(needed, sec.Name) {
			drop = append(drop, sec.Name)
		}
	}
	if err := s.Backups.SaveBackup(r.Context(), req.Config, sealed, drop, a.user.Username); err != nil {
		s.internalError(w, r, err)
		return
	}
	before := map[string]any{"saved": st.Saved}
	if st.Saved {
		before["config"] = st.Config
	}
	s.audit(r, &a.user, "backup_config_changed", "backup", map[string]any{"before": before, "after": req.Config,
		"secrets_changed": changed, "secrets_removed": drop})
	writeJSON(w, http.StatusOK, map[string]any{"message": "zapisano – usługa kopii zastosuje ustawienia w ciągu minuty"})
}

func (s *Server) addBackupRequest(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Action   string `json:"action"`
		Location string `json:"location"`
		Name     string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var params map[string]any
	switch req.Action {
	case "run", "test", "genkey", "list":
	case "inspect":
		f, ok := s.backupFile(w, r, req.Location, req.Name)
		if !ok {
			return
		}
		params = map[string]any{"location": f.Location, "name": f.Name}
	default:
		writeError(w, http.StatusBadRequest, "bad_action", "zlecenie: run, test, genkey, list albo inspect")
		return
	}
	rq, err := s.Backups.AddBackupRequest(r.Context(), req.Action, a.user.Username, params)
	if errors.Is(err, store.ErrBackupPending) {
		writeError(w, http.StatusConflict, "pending", "takie zlecenie już czeka na wykonanie")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "backup_requested", "backup", map[string]any{"action": req.Action, "request": rq.ID})
	writeJSON(w, http.StatusOK, map[string]any{"request": rq})
}

// backupFile szuka kopii na liście (nazwy nie przychodzą z zewnątrz do
// poleceń usługi kopii inaczej niż z tej listy).
func (s *Server) backupFile(w http.ResponseWriter, r *http.Request, location, name string) (store.BackupFile, bool) {
	st, err := s.Backups.Backup(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return store.BackupFile{}, false
	}
	for _, f := range st.Files {
		if f.Location == location && f.Name == name {
			return f, true
		}
	}
	writeError(w, http.StatusNotFound, "no_backup", "nie ma takiej kopii na liście – odśwież listę")
	return store.BackupFile{}, false
}

// Części kopii, które da się przywrócić z panelu.
var restoreParts = map[string]string{"saga": "baza Saga", "config": "konfiguracja (certs/, .env)", "grafana": "dane Grafany"}

// restoreConfirm: słowo do wpisania przy przywracaniu.
const restoreConfirm = "PRZYWRÓĆ"

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Location     string   `json:"location"`
		Name         string   `json:"name"`
		Parts        []string `json:"parts"`
		SafetyBackup bool     `json:"safety_backup"`
		Confirm      string   `json:"confirm"`
		Password     string   `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	f, ok := s.backupFile(w, r, req.Location, req.Name)
	if !ok {
		return
	}
	if f.Contents == nil {
		writeError(w, http.StatusBadRequest, "not_inspected", "najpierw sprawdź zawartość kopii")
		return
	}
	parts := []string{}
	for _, p := range req.Parts {
		if restoreParts[p] == "" || !contains(f.Contents, p) {
			writeError(w, http.StatusBadRequest, "bad_part", "kopia nie zawiera części „"+p+"”")
			return
		}
		if !contains(parts, p) {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		writeError(w, http.StatusBadRequest, "bad_part", "wybierz, co przywrócić")
		return
	}
	// Konfiguracja bez bazy (albo odwrotnie z innego dnia) rozjeżdża hasła ról
	// bazy z .env – przywracane razem, jeśli kopia ma obie.
	if contains(parts, "config") != contains(parts, "saga") && contains(f.Contents, "saga") && contains(f.Contents, "config") {
		writeError(w, http.StatusBadRequest, "bad_part", "bazę Saga i konfigurację przywraca się razem – hasła ról bazy są w .env")
		return
	}
	if strings.TrimSpace(req.Confirm) != restoreConfirm {
		writeError(w, http.StatusBadRequest, "confirm_required", "wpisz "+restoreConfirm+", aby potwierdzić")
		return
	}
	if !s.reauth(w, r, req.Password, "backup_restore") {
		return
	}
	rq, err := s.Backups.AddBackupRequest(r.Context(), "restore", a.user.Username,
		map[string]any{"location": f.Location, "name": f.Name, "parts": parts, "safety_backup": req.SafetyBackup})
	if errors.Is(err, store.ErrBackupPending) {
		writeError(w, http.StatusConflict, "pending", "przywracanie już czeka na wykonanie")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "backup_restore_requested", f.Name, map[string]any{"location": f.Location, "parts": parts,
		"safety_backup": req.SafetyBackup, "request": rq.ID})
	writeJSON(w, http.StatusOK, map[string]any{"request": rq,
		"message": "zlecono przywrócenie – usługa kopii przygotuje kopię, a serwer przywróci ją w ciągu kilku minut"})
}

func secretLabel(name string) string {
	switch name {
	case backupcfg.SecretPassword:
		return "hasło"
	case backupcfg.SecretPrivateKey:
		return "klucz prywatny SSH"
	case backupcfg.SecretS3Key:
		return "klucz tajny S3 (secret access key)"
	}
	return name
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
