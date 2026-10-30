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
// AGENT_VERSION obok niego (paczka serwera, deploy.sh agent). Agent Linux
// (1.9.0) dostaje tak samo program dla swojej architektury
// (vardr-agent-linux-<arch> z tej samej paczki, ta sama wersja).

type agentUpdateCache struct {
	mu    sync.Mutex
	files map[string]cachedUpdate
}

type cachedUpdate struct {
	modTime, verTime time.Time
	size             int64
	info             *contract.AgentUpdate
}

// agentUpdate zwraca instalator dostępny dla agentów (nil – brak MSI albo
// AGENT_VERSION).
func (s *Server) agentUpdate() *contract.AgentUpdate {
	if s.Enroll == nil || s.Enroll.AgentExe == "" {
		return nil
	}
	return s.fileUpdate(s.agentMSIPath())
}

// linuxUpdates: programy agenta Linux dostępne dla agentów (nil – brak).
func (s *Server) linuxUpdates() map[string]*contract.AgentUpdate {
	if s.Enroll == nil || s.Enroll.AgentExe == "" {
		return nil
	}
	var out map[string]*contract.AgentUpdate
	for _, arch := range contract.LinuxArchs {
		if u := s.fileUpdate(s.linuxAgentPath(arch)); u != nil {
			if out == nil {
				out = map[string]*contract.AgentUpdate{}
			}
			out[arch] = u
		}
	}
	return out
}

// fileUpdate: wersja (AGENT_VERSION obok), rozmiar i suma pliku dla
// agentów; suma liczona ponownie po zmianie pliku.
func (s *Server) fileUpdate(path string) *contract.AgentUpdate {
	st, err := os.Stat(path)
	if err != nil || st.Size() <= 0 || st.Size() > contract.MaxAgentMSISize {
		return nil
	}
	verFile := filepath.Join(filepath.Dir(path), "AGENT_VERSION")
	vst, err := os.Stat(verFile)
	if err != nil {
		return nil
	}
	c := &s.updCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.files[path]; ok && e.modTime.Equal(st.ModTime()) && e.size == st.Size() && e.verTime.Equal(vst.ModTime()) {
		return e.info
	}
	ver, err := os.ReadFile(verFile)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	u := &contract.AgentUpdate{Version: strings.TrimSpace(string(ver)), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if err := u.Validate(); err != nil {
		s.Log.Warn("agent program not offered for automatic updates", "file", filepath.Base(path), "err", err)
		u = nil
	}
	if c.files == nil {
		c.files = map[string]cachedUpdate{}
	}
	c.files[path] = cachedUpdate{modTime: st.ModTime(), verTime: vst.ModTime(), size: st.Size(), info: u}
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
	s.serveAgentUpdate(w, r, s.agentMSIPath(), "application/x-msi", "no_agent_msi", "na serwerze brak instalatora MSI agenta")
}

// agentLinux: program agenta Linux dla architektury z adresu.
func (s *Server) agentLinux(w http.ResponseWriter, r *http.Request) {
	arch := r.PathValue("arch")
	if !linuxArchs[arch] {
		writeError(w, http.StatusNotFound, "bad_arch", "architektura: amd64 albo arm64")
		return
	}
	s.serveAgentUpdate(w, r, s.linuxAgentPath(arch), "application/octet-stream", "no_linux_agent", "na serwerze brak programu agenta Linux ("+arch+")")
}

func (s *Server) serveAgentUpdate(w http.ResponseWriter, r *http.Request, path, ctype, missingCode, missing string) {
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
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, missingCode, missing)
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
	s.Log.Info("agent downloads the program for an automatic update", "agent", agentID, "group", g.Name, "file", filepath.Base(path))
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}
