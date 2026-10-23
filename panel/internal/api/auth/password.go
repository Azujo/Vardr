// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth zawiera hashowanie haseł, generowanie tokenów i reguły haseł
// panelu Hliðskjálf.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"siem/internal/lang"
)

// Parametry argon2id (zalecenia OWASP: m ≥ 19 MiB, t ≥ 2). Zapisywane
// w hashu, więc można je później podnieść bez unieważniania haseł.
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 2
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var b64 = base64.RawStdEncoding

// HashPassword zwraca hash w formacie PHC: $argon2id$v=19$m=…,t=…,p=…$sól$klucz.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("unsupported password hash format")

// VerifyPassword sprawdza hasło w czasie stałym względem treści klucza.
// needsRehash=true, gdy hash ma słabsze parametry niż bieżące.
func VerifyPassword(hash, password string) (ok, needsRehash bool, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, errBadHash
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 {
		return false, false, errBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && (m < argonMemory || t < argonTime), nil
}

// DummyVerify wykonuje tyle samo pracy co weryfikacja – dla nieistniejących
// kont, żeby czas odpowiedzi nie zdradzał, czy login istnieje.
func DummyVerify(password string) {
	_ = argon2.IDKey([]byte(password), make([]byte, saltLen), argonTime, argonMemory, argonThreads, argonKeyLen)
}

// MinPasswordLen to minimalna długość hasła (w znakach).
const MinPasswordLen = 12

// CheckPasswordPolicy sprawdza nowe hasło. Długość ponad złożoność
// (NIST SP 800-63B); odrzucamy hasła zawierające login.
func CheckPasswordPolicy(username, password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLen:
		return lang.Errorf("hasło musi mieć co najmniej %d znaków", "the password must have at least %d characters", MinPasswordLen)
	case n > 256:
		return lang.Errorf("hasło jest za długie (maks. 256 znaków)", "the password is too long (max 256 characters)")
	case username != "" && strings.Contains(strings.ToLower(password), strings.ToLower(username)):
		return lang.Errorf("hasło nie może zawierać nazwy użytkownika", "the password must not contain the username")
	}
	return nil
}

// NewToken zwraca losowy token (32 B, base64url) do ciasteczka sesji lub CSRF.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // brak losowości systemu – nie da się bezpiecznie działać
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TokenID zwraca skrót tokenu przechowywany w bazie (sam token zna tylko
// przeglądarka – wyciek bazy nie daje dostępu do sesji).
func TokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TempPassword generuje hasło startowe (do jednorazowego przekazania).
func TempPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
