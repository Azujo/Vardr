// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"siem/internal/contract"
)

// Automatyczne aktualizacje agentów (1.7.0): grupa z włączoną opcją
// auto_update dostaje w konfiguracji wersję i sumę bazowego instalatora MSI
// z serwera; agent starszy niż ta wersja pobiera go (mTLS) i uruchamia
// msiexec – jak aktualizacja przez GPO. Wersję instalatora podaje plik
// AGENT_VERSION obok niego (paczka serwera, deploy.sh agent).

type agentUpdateCache struct {
	mu      sync.Mutex
	modTime time.Time
	size    int64
	verTime time.Time
	info    *contract.AgentUpdate
}

// agentUpdate zwraca instalator dostępny dla agentów (nil – brak MSI albo
// AGENT_VERSION). Suma liczona ponownie po zmianie pliku.
func (s *Server) agentUpdate() *contract.AgentUpdate {
	if s.Enroll == nil || s.Enroll.AgentExe == "" {
		return nil
	}
	msi := s.agentMSIPath()
	st, err := os.Stat(msi)
	if err != nil || st.Size() <= 0 || st.Size() > contract.MaxAgentMSISize {
		return nil
	}
	verFile := filepath.Join(filepath.Dir(msi), "AGENT_VERSION")
	vst, err := os.Stat(verFile)
	if err != nil {
		return nil
	}
	c := &s.updCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.info != nil && c.modTime.Equal(st.ModTime()) && c.size == st.Size() && c.verTime.Equal(vst.ModTime()) {
		return c.info
	}
	ver, err := os.ReadFile(verFile)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(msi)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	u := &contract.AgentUpdate{Version: strings.TrimSpace(string(ver)), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if err := u.Validate(); err != nil {
		s.Log.Warn("agent installer not offered for automatic updates", "err", err)
		return nil
	}
	c.modTime, c.size, c.verTime, c.info = st.ModTime(), st.Size(), vst.ModTime(), u
	return u
}

// agentIdentity sprawdza certyfikat klienta agenta (mTLS) i zwraca jego
// identyfikator; false – odpowiedź z błędem już wysłana.
func (s *Server) agentIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		writeError(w, http.StatusUnauthorized, "no_client_cert", "wymagany certyfikat agenta")
		return "", false
	}
	cert := r.TLS.PeerCertificates[0]
	agentID := cert.Subject.CommonName
	if !agentIDPattern.MatchString(agentID) {
		writeError(w, http.StatusForbidden, "bad_identity", "niepoprawny identyfikator agenta w certyfikacie")
		return "", false
	}
	if c, err := s.Store.AgentCertBySerial(r.Context(), cert.SerialNumber.Text(16)); err == nil && c.RevokedAt != nil {
		writeError(w, http.StatusForbidden, "revoked", "certyfikat agenta został unieważniony")
		return "", false
	}
	return agentID, true
}

// agentMSI: bazowy instalator dla agenta z grupy z automatycznymi
// aktualizacjami (agent sprawdza sumę z konfiguracji).
func (s *Server) agentMSI(w http.ResponseWriter, r *http.Request) {
	agentID, ok := s.agentIdentity(w, r)
	if !ok {
		return
	}
	g, err := s.Store.GroupForAgent(r.Context(), agentID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !g.Limits.AutoUpdateOn() {
		writeError(w, http.StatusForbidden, "auto_update_off", "grupa agenta nie ma włączonych automatycznych aktualizacji")
		return
	}
	f, err := os.Open(s.agentMSIPath())
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "no_agent_msi", "na serwerze brak instalatora MSI agenta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Log.Info("agent downloads the installer for an automatic update", "agent", agentID, "group", g.Name)
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}
