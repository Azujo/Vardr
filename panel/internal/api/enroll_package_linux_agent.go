// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"siem/panel/internal/api/store"
)

// linuxArchs: architektury agenta Linux (program agent-dist/vardr-agent-linux-<arch>).
var linuxArchs = map[string]bool{"amd64": true, "arm64": true}

// linuxAgentPath: program agenta Linux obok programu Windows (deploy.sh agent).
func (s *Server) linuxAgentPath(arch string) string {
	return filepath.Join(filepath.Dir(s.Enroll.AgentExe), "vardr-agent-linux-"+arch)
}

// linuxPackage buduje paczkę tar.gz agenta Linux: program, główne CA, adres
// serwera, token i install.sh – bez klucza prywatnego. false: odpowiedź
// z błędem już wysłana albo paczka urwana.
func (s *Server) linuxPackage(w http.ResponseWriter, r *http.Request, t store.EnrollToken, secret, arch string) bool {
	if !linuxArchs[arch] {
		writeError(w, http.StatusBadRequest, "bad_arch", "architektura: amd64 albo arm64")
		return false
	}
	exe, err := os.Open(s.linuxAgentPath(arch))
	if err != nil {
		s.Log.Error("linux agent program for the package is missing", "arch", arch, "err", err)
		writeError(w, http.StatusServiceUnavailable, "no_linux_agent", "na serwerze brak programu agenta Linux ("+arch+") – zbuduj go: deploy.sh agent")
		return false
	}
	defer exe.Close()
	st, err := exe.Stat()
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	ca, err := os.ReadFile(s.Enroll.RootCA)
	if err != nil {
		s.internalError(w, r, err)
		return false
	}

	dir := "vardr-agent-" + safeFileName(t.Name)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+dir+"-linux-"+arch+`.tar.gz"`)
	w.Header().Set("Cache-Control", "no-store")
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, mode int64, size int64, body io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: dir + "/" + name, Mode: mode, Size: size, ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := io.Copy(tw, body)
		return err
	}
	text := func(name string, mode int64, s string) error {
		return add(name, mode, int64(len(s)), strings.NewReader(s))
	}
	err = func() error {
		if err := tw.WriteHeader(&tar.Header{Name: dir + "/", Mode: 0o755, ModTime: now, Typeflag: tar.TypeDir}); err != nil {
			return err
		}
		if err := add("vardr-agent", 0o755, st.Size(), exe); err != nil {
			return err
		}
		for _, f := range []struct {
			name string
			mode int64
			data string
		}{
			{"ca.crt", 0o644, string(ca)},
			{"server.txt", 0o644, s.Enroll.PublicServer + "\n"},
			{"token.txt", 0o600, secret + "\n"},
			{"install.sh", 0o755, linuxInstallSh},
			{"INSTRUKCJA.txt", 0o644, fmt.Sprintf(linuxReadme, t.Name, t.ExpiresAt.Local().Format("2006-01-02 15:04"), s.Enroll.PublicServer, arch)},
		} {
			if err := text(f.name, f.mode, f.data); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		return gz.Close()
	}()
	if err != nil {
		s.Log.Error("building the linux package failed", "err", err)
		return false
	}
	return true
}

// linuxInstallSh: instalacja z folderu paczki (adres i token z plików obok).
const linuxInstallSh = `#!/bin/sh
# Instalacja agenta Vardr (Linux, systemd). Uruchom: sudo ./install.sh
set -e
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi
./vardr-agent install "$@"
echo
echo "Zalecane: auditd z regułami Vardra (polecenia, zmiany plików kont, sudoers, kluczy SSH):"
echo "  apt install auditd   # albo: dnf install audit"
echo "  vardr-agent audit-rules > /etc/audit/rules.d/50-vardr.rules && augenrules --load"
`

const linuxReadme = `Vardr – paczka instalacyjna agenta Linux (Huginn)
==================================================

Token:        %s
Ważny do:     %s
Serwer:       %s
Architektura: %s

Wymagania: Linux z systemd (Ubuntu, Debian, RHEL i pochodne, SUSE).

Instalacja:
  tar xzf vardr-agent-*.tar.gz
  cd vardr-agent-*/
  sudo ./install.sh
Agent wygeneruje własny klucz prywatny (nie opuszcza serwera),
zarejestruje się tokenem i zainstaluje jako usługa vardr-agent.service.
Wdrożenie masowe (Ansible, skrypt): skopiuj folder i uruchom
  sudo ./vardr-agent install -server <adres> -token <token>

Źródła: dziennik systemd (uwierzytelnianie, ostrzeżenia) i auditd –
zalecany, z regułami Vardra:
  sudo apt install auditd           (albo: sudo dnf install audit)
  vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules
  sudo augenrules --load

Sterowanie: sudo vardr-agent status | restart | test | check
Aktualizacja: sudo ./vardr-agent upgrade (z folderu nowej wersji)
Agent chroniony (grupa w panelu): stop, upgrade i uninstall tylko
z tokenem deinstalacji z panelu (-token).

Paczka NIE zawiera klucza prywatnego, ale zawiera token – przechowuj ją
jak hasło do czasu wygaśnięcia tokenu albo unieważnij token w panelu
(Bifröst), gdy wdrożenie się zakończy.
`
