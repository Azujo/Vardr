// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("poprawne hasło 123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=2,p=2$") {
		t.Fatalf("format: %s", h)
	}
	if ok, rehash, err := VerifyPassword(h, "poprawne hasło 123"); !ok || rehash || err != nil {
		t.Fatalf("poprawne: %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := VerifyPassword(h, "poprawne hasło 124"); ok {
		t.Fatal("złe hasło przyjęte")
	}
	h2, _ := HashPassword("poprawne hasło 123")
	if h == h2 {
		t.Fatal("ta sama sól dla dwóch hashy")
	}
	if _, _, err := VerifyPassword("$2a$10$bcrypt", "x"); err == nil {
		t.Fatal("obcy format powinien dać błąd")
	}
}

func TestWeakParamsNeedRehash(t *testing.T) {
	// Hash z m=19456,t=2 (minimum OWASP) – do przeliczenia po zalogowaniu.
	weak := "$argon2id$v=19$m=19456,t=2,p=1$c29sc29sc29sc29sc29s$" + b64.EncodeToString(make([]byte, 32))
	if ok, rehash, err := VerifyPassword(weak, "x"); ok || rehash || err != nil {
		t.Fatalf("%v %v %v", ok, rehash, err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, c := range []struct {
		user, pass string
		ok         bool
	}{
		{"admin", "krotkie", false},
		{"admin", "Admin-ma-dlugie-haslo", false},
		{"jkowalski", "zielona herbata o świcie", true},
		{"x", strings.Repeat("a", 257), false},
	} {
		if err := CheckPasswordPolicy(c.user, c.pass); (err == nil) != c.ok {
			t.Errorf("%q/%q: %v", c.user, c.pass, err)
		}
	}
}

func TestTokens(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b || len(a) != 43 || TokenID(a) == TokenID(b) || len(TokenID(a)) != 64 {
		t.Fatalf("%q %q", a, b)
	}
	if p := TempPassword(); len(p) != 20 || CheckPasswordPolicy("admin", p) != nil {
		t.Fatalf("hasło startowe %q", p)
	}
}
