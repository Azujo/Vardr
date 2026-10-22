// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"siem/agent/internal/config"
)

func TestServerURL(t *testing.T) {
	cases := map[string]string{
		"192.168.88.98":                       "https://192.168.88.98:8443/v1/ingest",
		" siem.firma.local ":                  "https://siem.firma.local:8443/v1/ingest",
		"siem.firma.local:9443":               "https://siem.firma.local:9443/v1/ingest",
		"https://10.0.0.5:8443/v1/ingest":     "https://10.0.0.5:8443/v1/ingest",
		"https://10.0.0.5/":                   "https://10.0.0.5:8443/v1/ingest",
		"[fd00::5]":                           "https://[fd00::5]:8443/v1/ingest",
		"https://siem:8443/inny/endpoint?x=1": "https://siem:8443/inny/endpoint",
	}
	for in, want := range cases {
		got, err := ServerURL(in)
		if err != nil || got != want {
			t.Errorf("ServerURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "   ", "http://10.0.0.5", "https://"} {
		if _, err := ServerURL(bad); err == nil {
			t.Errorf("ServerURL(%q): oczekiwano błędu", bad)
		}
	}
}

func TestGeneratedConfigLoadsForEveryProfile(t *testing.T) {
	for profile := range Profiles {
		text, err := GenerateConfig(Options{ServerURL: "https://192.168.88.98:8443/v1/ingest", Profile: profile})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		p := filepath.Join(dir, "agent.yaml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(p)
		if err != nil {
			t.Fatalf("profil %s: konfiguracja nie przechodzi walidacji: %v\n%s", profile, err, text)
		}
		if c.Server.CAFile != filepath.Join(dir, "certs", "ca.crt") || c.StartAt != "now" || c.Channels[0].Name != "Security" {
			t.Errorf("profil %s: %+v", profile, c)
		}
	}
	dc, _ := ProfileChannels("dc")
	ws, _ := ProfileChannels("workstation")
	if len(dc[0].EventIDs) <= len(ws[0].EventIDs) {
		t.Error("profil dc powinien zbierać więcej zdarzeń Security niż stacja")
	}
	if _, err := GenerateConfig(Options{ServerURL: "x", Profile: "laptop"}); err == nil {
		t.Error("nieznany profil powinien dać błąd")
	}
}

func TestSetServerURLKeepsCommentsAndSettings(t *testing.T) {
	in := []byte(`# komentarz na górze
server:
  url: https://stary:8443/v1/ingest # stary serwer
  ca_file: certs/ca.crt
start_at: now
channels:
  - name: System
`)
	out, err := SetServerURL(in, "https://10.0.0.9:8443/v1/ingest")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"# komentarz na górze", "url: https://10.0.0.9:8443/v1/ingest", "ca_file: certs/ca.crt", "- name: System"} {
		if !strings.Contains(s, want) {
			t.Errorf("brak %q w:\n%s", want, s)
		}
	}
	if strings.Contains(s, "stary:8443") {
		t.Errorf("stary adres pozostał:\n%s", s)
	}
}

func TestPathHelpers(t *testing.T) {
	const dir = `C:\Program Files\SiemAgent`
	p, changed := AddToPath(`C:\Windows;C:\Windows\System32;`, dir)
	if !changed || p != `C:\Windows;C:\Windows\System32;C:\Program Files\SiemAgent` {
		t.Fatalf("AddToPath: %q %v", p, changed)
	}
	if _, changed := AddToPath(p, `c:\program files\siemagent\`); changed {
		t.Error("katalog już jest w PATH (inna wielkość liter / ukośnik)")
	}
	p, changed = RemoveFromPath(p, dir)
	if !changed || p != `C:\Windows;C:\Windows\System32` {
		t.Fatalf("RemoveFromPath: %q %v", p, changed)
	}
}
