// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"siem/internal/lang"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/enroll"
)

// Enrollment to konfiguracja rejestracji agentów tokenem (Bifröst).
type Enrollment struct {
	Signer *enroll.Signer
	// Revoke rozsyła unieważnione numery seryjne do siem-ingest (NATS KV).
	Revoke func(ctx context.Context, serials []string, reason string) error
	// Paczka instalacyjna: program agenta, główne CA i adres serwera dla agentów.
	AgentExe     string
	RootCA       string
	PublicServer string // np. 192.168.88.98 – adres siem-ingest dla agentów
}

// Profile agentów (zestawy zdarzeń, roadmapa załącznik B).
var enrollProfiles = map[string]string{"workstation": "stacja robocza", "server": "serwer", "dc": "kontroler domeny"}

// Token: prefiks (rozpoznawalny w logach i skanerach sekretów) + 32 losowe bajty.
const tokenPrefix = "hdt_"

var tokenPattern = regexp.MustCompile(`^hdt_[A-Za-z0-9_-]{43}$`)

func (s *Server) enrollEnabled(w http.ResponseWriter) bool {
	if s.Enroll == nil || s.Enroll.Signer == nil {
		writeError(w, http.StatusServiceUnavailable, "enroll_disabled",
			"rejestracja agentów wyłączona – brak CA agentów (siem-pki agents-ca, SIEM_AGENTS_CA_KEY)")
		return false
	}
	return true
}

// ---- tokeny (administrator) ----

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.Store.ListEnrollTokens(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if tokens == nil {
		tokens = []store.EnrollToken{}
	}
	server := ""
	if s.Enroll != nil {
		server = s.Enroll.PublicServer
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens, "profiles": enrollProfiles, "enabled": s.Enroll != nil && s.Enroll.Signer != nil, "public_server": server})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	var req struct {
		Name       string `json:"name"`
		Profile    string `json:"profile"`
		ValidHours int    `json:"valid_hours"`
		MaxUses    int    `json:"max_uses"`
		GroupID    int64  `json:"group_id"` // 0 = grupa domyślna
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	switch {
	case req.Name == "" || len(req.Name) > 128:
		writeError(w, http.StatusBadRequest, "bad_name", "nazwa tokenu: 1–128 znaków (np. „Księgowość – stacje”)")
		return
	case enrollProfiles[req.Profile] == "":
		writeError(w, http.StatusBadRequest, "bad_profile", "profil: workstation, server albo dc")
		return
	case req.ValidHours < 1 || req.ValidHours > 90*24:
		writeError(w, http.StatusBadRequest, "bad_validity", "ważność tokenu: od 1 godziny do 90 dni")
		return
	case req.MaxUses < 0 || req.MaxUses > 100000:
		writeError(w, http.StatusBadRequest, "bad_max_uses", "limit użyć: 0 (bez limitu) do 100 000")
		return
	}
	// Grupa decyduje o profilu – nowi agenci od razu dostają jej konfigurację.
	var groupID *int64
	if req.GroupID > 0 {
		g, err := s.Store.GroupByID(r.Context(), req.GroupID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "bad_group", "nie ma takiej grupy")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		groupID, req.Profile = &g.ID, g.Profile
	}
	secret := tokenPrefix + auth.NewToken()
	t, err := s.Store.CreateEnrollToken(r.Context(), store.EnrollToken{
		Name: req.Name, TokenHash: auth.TokenID(secret), Profile: req.Profile, MaxUses: req.MaxUses,
		ExpiresAt: s.now().Add(time.Duration(req.ValidHours) * time.Hour), CreatedBy: a.user.Username,
		GroupID: groupID,
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "enroll_token_created", t.Name, map[string]any{"profile": t.Profile, "max_uses": t.MaxUses, "expires_at": t.ExpiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": secret})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator tokenu")
		return
	}
	t, err := s.Store.RevokeEnrollToken(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego tokenu")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "enroll_token_revoked", t.Name, nil)
	writeJSON(w, http.StatusOK, map[string]any{"token": t})
}

// tokenPackage buduje paczkę instalacyjną ZIP dla tokenu: program agenta,
// główne CA, adres serwera, token i skrypt instalacji – BEZ klucza
// prywatnego (agent wygeneruje go u siebie).
func (s *Server) tokenPackage(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if !s.enrollEnabled(w) {
		return
	}
	var req struct {
		Secret string `json:"secret"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !tokenPattern.MatchString(req.Secret) {
		writeError(w, http.StatusBadRequest, "bad_token", "niepoprawny token")
		return
	}
	t, err := s.Store.EnrollTokenByHash(r.Context(), auth.TokenID(req.Secret), s.now())
	if errors.Is(err, store.ErrTokenInvalid) {
		writeError(w, http.StatusBadRequest, "bad_token", "token jest nieważny (wygasł, unieważniony lub wyczerpany)")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	exe, err := os.Open(s.Enroll.AgentExe)
	if err != nil {
		s.Log.Error("agent program for the package is missing", "path", s.Enroll.AgentExe, "err", err)
		writeError(w, http.StatusServiceUnavailable, "no_agent_exe", "na serwerze brak programu agenta (SIEM_AGENT_EXE) – skopiuj vardr-agent.exe")
		return
	}
	defer exe.Close()
	ca, err := os.ReadFile(s.Enroll.RootCA)
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	name := "vardr-agent-" + safeFileName(t.Name) + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	add := func(fname string, data []byte) error {
		f, err := zw.Create(fname)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	crlf := func(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }
	err = func() error {
		f, err := zw.Create("vardr-agent.exe")
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, exe); err != nil {
			return err
		}
		for _, x := range []struct {
			name string
			data []byte
		}{
			{"ca.crt", ca},
			{"server.txt", []byte(s.Enroll.PublicServer + "\n")},
			{"token.txt", []byte(req.Secret + "\n")},
			{"install.cmd", crlf(installCmd)},
			{"install-msi.cmd", crlf(fmt.Sprintf(installMSICmd, s.Enroll.PublicServer, req.Secret))},
			{"INSTRUKCJA.txt", crlf(fmt.Sprintf(packageReadme, t.Name, enrollProfiles[t.Profile], t.ExpiresAt.Local().Format("2006-01-02 15:04"), s.Enroll.PublicServer))},
		} {
			if err := add(x.name, x.data); err != nil {
				return err
			}
		}
		// Instalator MSI (budowany przez deploy.sh obok programu agenta), jeśli jest.
		if msi, err := os.Open(filepath.Join(filepath.Dir(s.Enroll.AgentExe), "vardr-agent.msi")); err == nil {
			defer msi.Close()
			f, err := zw.Create("vardr-agent.msi")
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, msi); err != nil {
				return err
			}
		}
		return zw.Close()
	}()
	if err != nil {
		s.Log.Error("building the package failed", "err", err)
		return
	}
	s.audit(r, &a.user, "enroll_package_downloaded", t.Name, nil)
}

func safeFileName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "paczka"
	}
	return out
}

const installCmd = `@echo off
rem Instalacja agenta Vardr (Huginn). Uruchom jako administrator
rem (prawy przycisk myszy -> Uruchom jako administrator).
"%~dp0vardr-agent.exe" install
pause
`

// installMSICmd: instalacja z MSI na jednym komputerze (adres i token wpisane).
const installMSICmd = `@echo off
rem Instalacja agenta Vardr z pakietu MSI. Uruchom jako administrator.
msiexec /i "%%~dp0vardr-agent.msi" /qn SERVER=%s TOKEN=%s /l*v "%%TEMP%%\vardr-agent-msi.log"
if errorlevel 1 (echo Instalacja nieudana - dziennik: %%TEMP%%\vardr-agent-msi.log oraz %%ProgramData%%\SiemAgent\msi.log) else (echo Agent zainstalowany.)
pause
`

const packageReadme = `Vardr – paczka instalacyjna agenta (Huginn)
==============================================

Token:   %s
Profil:  %s
Ważny do: %s
Serwer:  %s

Instalacja na jednym komputerze:
  1. Rozpakuj paczkę.
  2. Uruchom install.cmd jako administrator.
     Agent wygeneruje własny klucz prywatny (nie opuszcza komputera),
     zarejestruje się tokenem i zainstaluje jako usługa Windows.

Wdrożenie masowe (Intune / SCCM / skrypt GPO), z konta SYSTEM lub
administratora – instalator MSI (vardr-agent.msi, jeśli jest w paczce):
  msiexec /i vardr-agent.msi /qn SERVER=<adres> TOKEN=<token>
albo bez MSI:
  vardr-agent.exe install -server <adres> -token <token>
(install-msi.cmd robi to samo z adresem i tokenem tej paczki.)

Aktualizacja: nowszy vardr-agent.msi bez TOKEN (rejestracja zostaje):
  msiexec /i vardr-agent.msi /qn
Odinstalowanie: Programy i funkcje albo msiexec /x vardr-agent.msi /qn
(dane i certyfikaty zostają w C:\ProgramData\SiemAgent).

Paczka NIE zawiera klucza prywatnego, ale zawiera token – przechowuj ją
jak hasło do czasu wygaśnięcia tokenu albo unieważnij token w panelu
(Bifröst), gdy wdrożenie się zakończy.
`

// ---- unieważnianie certyfikatów agenta (administrator) ----

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = truncate(strings.TrimSpace(req.Reason), 256)
	if req.Reason == "" {
		req.Reason = "unieważniony w panelu"
	}
	serials, err := s.Store.RevokeAgentCerts(r.Context(), id, req.Reason)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(serials) > 0 && s.Enroll != nil && s.Enroll.Revoke != nil {
		if err := s.Enroll.Revoke(r.Context(), serials, req.Reason); err != nil {
			s.internalError(w, r, fmt.Errorf("broadcasting the revocation: %w", err))
			return
		}
	}
	s.audit(r, &a.user, "agent_certs_revoked", id, map[string]any{"serials": serials, "reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": len(serials), "serials": serials})
}

// ---- endpointy dla agentów (bez sesji) ----

type enrollResponse struct {
	AgentID       string    `json:"agent_id"`
	Certificate   string    `json:"certificate"`
	NotAfter      time.Time `json:"not_after"`
	Profile       string    `json:"profile,omitempty"`
	RenewBeforeS  int       `json:"renew_before_s"`
	ServerAddress string    `json:"server_address,omitempty"`
}

// register: agent z tokenem prosi o certyfikat (TLS bez certyfikatu klienta).
func (s *Server) enrollRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allow("enroll:"+ip, 60, 60) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele rejestracji z tego adresu – ponów za minutę")
		return
	}
	if !s.enrollEnabled(w) {
		return
	}
	var req struct {
		Token    string `json:"token"`
		CSR      string `json:"csr"`
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Version  string `json:"version"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	csr, err := enroll.ParseCSR(req.CSR) // przed zużyciem tokenu
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_csr", lang.Errorf("niepoprawna prośba o certyfikat: %w", "invalid certificate request: %w", err))
		return
	}
	if !tokenPattern.MatchString(strings.TrimSpace(req.Token)) {
		s.audit(r, nil, "agent_enroll_failed", truncate(req.Hostname, 64), map[string]any{"reason": "bad_token_format"})
		writeError(w, http.StatusForbidden, "bad_token", "token rejestracyjny jest nieważny")
		return
	}
	now := s.now()
	t, err := s.Store.UseEnrollToken(r.Context(), auth.TokenID(strings.TrimSpace(req.Token)), now)
	if errors.Is(err, store.ErrTokenInvalid) {
		s.audit(r, nil, "agent_enroll_failed", truncate(req.Hostname, 64), map[string]any{"reason": "invalid_token"})
		writeError(w, http.StatusForbidden, "bad_token", "token rejestracyjny jest nieważny (wygasł, unieważniony lub wyczerpany)")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	// Identyfikator z nazwy hosta; zajęty (np. ponowna instalacja albo próba
	// przejęcia cudzej nazwy) dostaje losowy dopisek – nigdy nie przejmujemy
	// tożsamości istniejącego agenta.
	base := enroll.AgentIDFor(req.Hostname)
	agentID := base
	for i := 0; ; i++ {
		taken, err := s.Store.AgentIDTaken(r.Context(), agentID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !taken {
			break
		}
		if i == 5 {
			s.internalError(w, r, errors.New("could not assign a unique identifier"))
			return
		}
		agentID = truncate(base, 50) + "-" + enroll.RandomSuffix()
	}

	iss, err := s.Enroll.Signer.Sign(csr, agentID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	tokenID := t.ID
	profile := t.Profile
	if t.GroupID != nil {
		if err := s.Store.AssignAgent(r.Context(), agentID, *t.GroupID); err != nil {
			s.internalError(w, r, err)
			return
		}
		if g, err := s.Store.GroupByID(r.Context(), *t.GroupID); err == nil {
			profile = g.Profile
		}
	}
	if err := s.Store.RecordAgentCert(r.Context(), store.AgentCert{Serial: iss.Serial, AgentID: agentID, IssuedAt: now,
		NotAfter: iss.NotAfter, TokenID: &tokenID, Hostname: truncate(req.Hostname, 255), RemoteIP: ip}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, nil, "agent_enrolled", agentID, map[string]any{"token": t.Name, "hostname": truncate(req.Hostname, 255),
		"version": truncate(req.Version, 64), "serial": iss.Serial})
	s.Log.Info("agent enrolled", "agent_id", agentID, "token", t.Name, "ip", ip)
	writeJSON(w, http.StatusOK, enrollResponse{AgentID: agentID, Certificate: iss.PEM, NotAfter: iss.NotAfter, Profile: profile,
		RenewBeforeS: int(enroll.RenewBefore.Seconds()), ServerAddress: s.Enroll.PublicServer})
}

// renew: agent z ważnym certyfikatem prosi o nowy (TLS z certyfikatem klienta).
func (s *Server) enrollRenew(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allow("renew:"+ip, 60, 60) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "zbyt wiele żądań – ponów później")
		return
	}
	if !s.enrollEnabled(w) {
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		writeError(w, http.StatusUnauthorized, "no_client_cert", "odnowienie wymaga ważnego certyfikatu agenta")
		return
	}
	old := r.TLS.PeerCertificates[0]
	agentID := old.Subject.CommonName
	oldSerial := old.SerialNumber.Text(16)
	if !agentIDPattern.MatchString(agentID) {
		writeError(w, http.StatusForbidden, "bad_identity", "niepoprawny identyfikator agenta w certyfikacie")
		return
	}
	if c, err := s.Store.AgentCertBySerial(r.Context(), oldSerial); err == nil && c.RevokedAt != nil {
		s.audit(r, nil, "agent_renew_failed", agentID, map[string]any{"reason": "revoked", "serial": oldSerial})
		writeError(w, http.StatusForbidden, "revoked", "certyfikat agenta został unieważniony")
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		// ErrNotFound: certyfikat laboratoryjny z siem-pki – też może przejść na CA agentów.
		s.internalError(w, r, err)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	csr, err := enroll.ParseCSR(req.CSR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_csr", lang.Errorf("niepoprawna prośba o certyfikat: %w", "invalid certificate request: %w", err))
		return
	}
	now := s.now()
	iss, err := s.Enroll.Signer.Sign(csr, agentID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.RecordAgentCert(r.Context(), store.AgentCert{Serial: iss.Serial, AgentID: agentID, IssuedAt: now,
		NotAfter: iss.NotAfter, RenewedFrom: oldSerial, RemoteIP: ip}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, nil, "agent_cert_renewed", agentID, map[string]any{"serial": iss.Serial, "previous": oldSerial})
	writeJSON(w, http.StatusOK, enrollResponse{AgentID: agentID, Certificate: iss.PEM, NotAfter: iss.NotAfter,
		RenewBeforeS: int(enroll.RenewBefore.Seconds())})
}
