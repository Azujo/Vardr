// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"siem/internal/contract"
	"siem/internal/msipatch"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

// Jeden plik MSI zamiast paczki ZIP: instalator agenta z wpisanym adresem
// serwera i tokenem (wypełniacze podmienione w pliku – internal/msipatch).
// Podwójne kliknięcie instaluje i rejestruje agenta, na komputerze z agentem
// – aktualizuje go (token jest wtedy pomijany). Ten sam plik wdraża się przez
// GPO, Intune albo SCCM bez parametrów.

// agentMSIPath: instalator budowany przez deploy.sh obok programu agenta.
func (s *Server) agentMSIPath() string {
	return filepath.Join(filepath.Dir(s.Enroll.AgentExe), "vardr-agent.msi")
}

func (s *Server) readAgentMSI(w http.ResponseWriter) ([]byte, bool) {
	data, err := os.ReadFile(s.agentMSIPath())
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusServiceUnavailable, "no_agent_msi",
			"na serwerze brak instalatora MSI agenta – zbuduj go (deploy.sh agent)")
		return nil, false
	}
	if err != nil {
		s.Log.Error("odczyt instalatora MSI nieudany", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "odczyt instalatora nieudany")
		return nil, false
	}
	return data, true
}

func sendMSI(w http.ResponseWriter, name string, data []byte) {
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// tokenMSI: instalator z adresem serwera i tokenem (administrator – jak paczka ZIP).
func (s *Server) tokenMSI(w http.ResponseWriter, r *http.Request) {
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
	data, ok := s.readAgentMSI(w)
	if !ok {
		return
	}
	out, _, err := msipatch.Replace(data, contract.MSIServerPlaceholder, s.Enroll.PublicServer)
	if err == nil {
		out, _, err = msipatch.Replace(out, contract.MSITokenPlaceholder, req.Secret)
	}
	if err != nil {
		s.Log.Error("wpisanie adresu i tokenu do instalatora nieudane", "err", err)
		writeError(w, http.StatusServiceUnavailable, "msi_patch_failed",
			"instalatora nie da się przygotować: "+err.Error()+" – zbuduj agenta ponownie (deploy.sh agent)")
		return
	}
	s.audit(r, &a.user, "enroll_msi_downloaded", t.Name, nil)
	sendMSI(w, "vardr-agent-"+safeFileName(t.Name)+".msi", out)
}

// agentUpdateMSI: bazowy instalator bez tokenu – aktualizacja agentów
// (podwójne kliknięcie albo wdrożenie GPO/Intune). Nowy komputer z tym
// plikiem się nie zarejestruje (brak tokenu) – instalator to zgłosi.
func (s *Server) agentUpdateMSI(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if !s.enrollEnabled(w) {
		return
	}
	data, ok := s.readAgentMSI(w)
	if !ok {
		return
	}
	s.audit(r, &a.user, "agent_update_msi_downloaded", "", nil)
	sendMSI(w, "vardr-agent-aktualizacja.msi", data)
}
