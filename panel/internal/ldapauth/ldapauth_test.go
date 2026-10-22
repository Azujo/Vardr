// SPDX-License-Identifier: AGPL-3.0-or-later

package ldapauth

import (
	"bytes"
	"context"
	"testing"
)

func TestSID(t *testing.T) {
	// S-1-5-21-1004336348-1177238915-682003330-512 (Domain Admins przykładowej domeny).
	raw := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xdc, 0xf4, 0xdc, 0x3b, 0x83, 0x3d, 0x2b, 0x46, 0x82, 0x8b, 0xa6, 0x28, 0x00, 0x02, 0, 0}
	s := sidString(raw)
	if s != "S-1-5-21-1004336348-1177238915-682003330-512" {
		t.Fatalf("SID: %s", s)
	}
	back, err := sidBytes(s)
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatalf("SID z powrotem: %v %v", back, err)
	}
	if sidString([]byte{1, 2, 3}) != "" {
		t.Fatal("uszkodzony SID")
	}
}

func TestConfigAndProfile(t *testing.T) {
	c := Config{URLs: []string{"ldap://dc01.firma.pl"}, BindDN: "svc@firma.pl", BaseDN: "DC=firma,DC=pl"}
	if c.Validate() == nil {
		t.Fatal("ldap:// bez szyfrowania przyjęty")
	}
	c.URLs = []string{"ldaps://dc01.firma.pl:636"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.CAPEM = "nie PEM"
	if c.Validate() == nil {
		t.Fatal("zły PEM przyjęty")
	}
	c.Mappings = []Mapping{{SID: "S-1-5-21-1-512", Profile: "admin"}, {SID: "S-1-5-21-1-1100", Profile: "analyst"}}
	if m, ok := c.ProfileFor([]string{"S-1-5-21-1-1100", "S-1-5-21-1-512"}); !ok || m.Profile != "admin" {
		t.Fatalf("kolejność: %+v", m)
	}
	if _, ok := c.ProfileFor([]string{"S-1-5-21-1-9"}); ok {
		t.Fatal("brak grupy – profil")
	}
	if _, err := c.Authenticate(context.Background(), "jan", ""); err != ErrBadCredentials {
		t.Fatalf("puste hasło: %v", err)
	}
	if NormalizeLogin(` FIRMA\jan.kowalski `) != "jan.kowalski" {
		t.Fatal("login NetBIOS")
	}
}
