package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"
)

// Drugi składnik logowania: TOTP (RFC 6238 – SHA-1, 6 cyfr, krok 30 s; tak
// liczą Microsoft/Google Authenticator, Aegis, 1Password) i jednorazowe
// kody zapasowe.
const (
	TOTPStep      = 30 * time.Second
	totpDigits    = 6
	totpSkew      = 1 // akceptowane kroki obok bieżącego (zegar telefonu)
	recoveryCount = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret losuje sekret (160 bitów, jak zaleca RFC 4226).
func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// SecretText: sekret do ręcznego wpisania w aplikacji (base32, grupy po 4).
func SecretText(secret []byte) string {
	s := b32.EncodeToString(secret)
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}

// OTPAuthURI: adres dla aplikacji uwierzytelniającej (kod QR).
func OTPAuthURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {strconv.Itoa(totpDigits)}, "period": {strconv.Itoa(int(TOTPStep / time.Second))}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// QRDataURL: kod QR adresu jako obraz PNG (data: URL do <img>).
func QRDataURL(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	c.Scale = 6
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()), nil
}

func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// TOTPCode: kod dla chwili t (testy, narzędzia).
func TOTPCode(secret []byte, t time.Time) string {
	return totpAt(secret, t.Unix()/int64(TOTPStep/time.Second))
}

// VerifyTOTP sprawdza kod (z tolerancją jednego kroku zegara) i zwraca krok,
// któremu odpowiada. Kod z kroku nie późniejszego niż lastStep jest
// odrzucany – ten sam kod nie zaloguje drugi raz (przechwycenie, powtórka).
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / int64(TOTPStep/time.Second)
	for d := -totpSkew; d <= totpSkew; d++ {
		step := cur + int64(d)
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// Kody zapasowe: 10 znaków z alfabetu bez znaków mylących (ok. 50 bitów),
// wyświetlane jako xxxxx-xxxxx; w bazie tylko skrót SHA-256.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes losuje kody zapasowe.
func NewRecoveryCodes() []string {
	out := make([]string, recoveryCount)
	for i := range out {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		var s strings.Builder
		for j, x := range b {
			if j == 5 {
				s.WriteByte('-')
			}
			s.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		out[i] = s.String()
	}
	return out
}

// NormalizeRecovery: kod zapasowy bez spacji i myślników, małymi literami.
func NormalizeRecovery(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		case r == '-' || r == ' ':
			return -1
		}
		return r
	}, strings.TrimSpace(code))
}

// LooksLikeRecovery: wpisany kod to kod zapasowy (10 znaków), nie TOTP.
func LooksLikeRecovery(code string) bool { return len(NormalizeRecovery(code)) == 10 }

// RecoveryHash: skrót kodu zapasowego do zapisu i porównania.
func RecoveryHash(code string) string {
	sum := sha256.Sum256([]byte("vardr-recovery-v1\x00" + NormalizeRecovery(code)))
	return hex.EncodeToString(sum[:])
}

// ParseMFAKey wczytuje klucz szyfrujący sekrety TOTP (64 znaki hex – 256 bitów).
func ParseMFAKey(text string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(k) != 32 {
		return nil, errors.New("klucz MFA: oczekiwane 64 znaki szesnastkowe (openssl rand -hex 32)")
	}
	return k, nil
}

// SealSecret szyfruje sekret TOTP (AES-256-GCM, konto jako dane powiązane –
// sekretu nie da się przenieść na inne konto w bazie).
func SealSecret(key, secret []byte, userID int64) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, secret, aad(userID)), nil
}

// OpenSecret odszyfrowuje sekret TOTP.
func OpenSecret(key, sealed []byte, userID int64) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("sekret MFA: uszkodzony zapis")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad(userID))
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aad(userID int64) []byte { return []byte("vardr-totp-v1:" + strconv.FormatInt(userID, 10)) }
