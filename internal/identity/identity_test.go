// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import "testing"

func TestResolve(t *testing.T) {
	r := New(Config{Domains: []string{"AZUJO", "azujo.centrala", "azujo.pl"},
		Aliases: map[string]string{"J.Kowalski": "jkowalski", `desktop-1\admin`: "ewa"}})
	for _, c := range []struct{ user, domain, want string }{
		{"JKowalski", "AZUJO", "jkowalski"},
		{`AZUJO\jkowalski`, "", "jkowalski"},
		{"jkowalski@azujo.pl", "", "jkowalski"},
		{"j.kowalski", "", "jkowalski"},            // alias (np. login VPN)
		{"admin", "DESKTOP-2", `desktop-2\admin`},  // konto lokalne – osobna tożsamość
		{"admin", "desktop-1", "ewa"},              // alias pełnej nazwy
		{"partner@obca.pl", "", "partner@obca.pl"}, // gość spoza organizacji
		{"WIN-DC01$", "AZUJO", ""},                 // konto komputera
		{"SYSTEM", "NT AUTHORITY", ""},
		{"USŁUGA LOKALNA", "ZARZĄDZANIE NT", ""},
		{"sshd_4784", "VIRTUAL USERS", ""},
		{"S-1-5-111-3847866527-469524349-4784", "", ""},
		{"jakaś-usługa", "ZARZĄDZANIE NT", ""},
		{`NT SERVICE\MSSQLSERVER`, "", ""},
		{"LOCAL SERVICE", "", ""},
		{"DWM-3", "Window Manager", ""},
		{"-", "-", ""},
		{"", "", ""},
		{"admin", "", "admin"}, // bez domeny (np. MikroTik)
	} {
		if got := r.Resolve(c.user, c.domain); got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, oczekiwano %q", c.user, c.domain, got, c.want)
		}
	}
	// Konta wspólne urządzeń: bez domeny – „urządzenie\konto”; z domeną jak dotąd.
	s := New(Config{Domains: []string{"azujo"}, Shared: []string{"Admin", "root"},
		Aliases: map[string]string{`fw01\admin`: "jkowalski"}})
	for _, c := range []struct{ user, domain, host, want string }{
		{"admin", "", "MikroTik", `mikrotik\admin`},
		{"admin", "", "fw02.azujo.pl", `fw02\admin`},
		{"root", "-", "192.168.88.1", `192.168.88.1\root`},
		{"admin", "", "fw01", "jkowalski"},  // alias konta na urządzeniu
		{"admin", "", "", ""},               // bez urządzenia – bez osoby
		{"admin", "AZUJO", "dc01", "admin"}, // konto domenowe
		{"jkowalski", "", "MikroTik", "jkowalski"},
	} {
		if got := s.ResolveOn(c.user, c.domain, c.host); got != c.want {
			t.Errorf("ResolveOn(%q, %q, %q) = %q, oczekiwano %q", c.user, c.domain, c.host, got, c.want)
		}
	}
	// Bez domen organizacji: każda domena „swoja”.
	if got := New(Config{}).Resolve("admin", "DESKTOP-2"); got != "admin" {
		t.Errorf("bez domen: %q", got)
	}
}
