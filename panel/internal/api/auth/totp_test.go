// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Wektory testowe RFC 6238 (SHA-1, sekret "12345678901234567890"), 6 cyfr.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := TOTPCode(secret, time.Unix(unix, 0)); got != want {
			t.Errorf("t=%d: %s, oczekiwane %s", unix, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Date(2026, 10, 20, 12, 0, 10, 0, time.UTC)
	code := TOTPCode(secret, now.Add(-30*time.Second)) // poprzedni krok – tolerancja zegara
	step, ok := VerifyTOTP(secret, code[:3]+" "+code[3:], now, 0)
	if !ok {
		t.Fatal("kod z poprzedniego kroku odrzucony")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("ten sam kod drugi raz przyjęty (powtórka)")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("kod sprzed 90 s przyjęty")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("krótki kod przyjęty")
	}
}

func TestRecoveryAndSeal(t *testing.T) {
	codes := NewRecoveryCodes()
	if len(codes) != 10 || len(codes[0]) != 11 || codes[0][5] != '-' || !LooksLikeRecovery(codes[0]) || LooksLikeRecovery("123456") {
		t.Fatalf("kody zapasowe: %v", codes)
	}
	if RecoveryHash(strings.ToUpper(codes[0])) != RecoveryHash(strings.ReplaceAll(codes[0], "-", "")) {
		t.Fatal("skrót kodu zależy od zapisu")
	}
	key, err := ParseMFAKey(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := NewTOTPSecret()
	sealed, err := SealSecret(key, secret, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenSecret(key, sealed, 7); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("odszyfrowanie: %v", err)
	}
	if _, err := OpenSecret(key, sealed, 8); err == nil {
		t.Fatal("sekret innego konta odszyfrowany")
	}
	if u := OTPAuthURI("Vardr", "adam", secret); !strings.HasPrefix(u, "otpauth://totp/Vardr:adam?") || !strings.Contains(u, "issuer=Vardr") {
		t.Fatalf("URI: %s", u)
	}
	if q, err := QRDataURL("otpauth://totp/x"); err != nil || !strings.HasPrefix(q, "data:image/png;base64,") {
		t.Fatalf("QR: %v", err)
	}
}
