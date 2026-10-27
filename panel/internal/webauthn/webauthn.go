// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthn sprawdza klucze bezpieczeństwa i passkeys (WebAuthn
// poziom 2) jako drugi składnik logowania do panelu: rejestracja klucza
// (atestacja nie jest weryfikowana – panel prosi o „none”) i logowanie
// (podpis wyzwania, licznik użyć). Algorytmy: ES256, RS256, Ed25519.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
)

// Algorytmy COSE.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Algorithms: obsługiwane algorytmy w kolejności preferencji.
var Algorithms = []int{AlgES256, AlgEdDSA, AlgRS256}

// Flagi authenticatorData.
const (
	flagUP = 0x01 // użytkownik obecny (dotknięcie klucza)
	flagUV = 0x04 // użytkownik zweryfikowany (PIN, biometria)
	flagAT = 0x40 // dane poświadczenia (rejestracja)
)

var (
	ErrBadClientData = errors.New("webauthn: invalid client data")
	ErrBadOrigin     = errors.New("webauthn: origin does not match the panel address")
	ErrBadChallenge  = errors.New("webauthn: challenge mismatch")
	ErrBadAuthData   = errors.New("webauthn: invalid authenticator data")
	ErrNoPresence    = errors.New("webauthn: user presence not confirmed")
	ErrBadSignature  = errors.New("webauthn: invalid signature")
	ErrUnsupported   = errors.New("webauthn: unsupported key algorithm")
	ErrCloned        = errors.New("webauthn: signature counter went back – possibly a cloned key")
)

// B64 koduje base64url bez dopełnienia (format WebAuthn w JSON).
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// FromB64 dekoduje base64url (z dopełnieniem albo bez).
func FromB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// NewChallenge: 32 losowe bajty.
func NewChallenge() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RPID wyznacza identyfikator strony z adresu panelu (nazwa hosta bez
// portu). Adres IP nie może być identyfikatorem strony WebAuthn.
func RPID(host string) (string, error) {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if h == "" || net.ParseIP(h) != nil {
		return "", fmt.Errorf("webauthn needs the panel to be opened by name, not IP address (%s)", host)
	}
	return h, nil
}

// Credential to zarejestrowany klucz.
type Credential struct {
	ID        []byte
	PublicKey []byte // PKIX DER
	Alg       int
	SignCount uint32
	UV        bool   // klucz zweryfikował użytkownika (PIN, biometria)
	AAGUID    []byte // model klucza (passkey: dostawca)
	RPID      string
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// checkClientData sprawdza clientDataJSON: typ, wyzwanie i pochodzenie
// (https://<rpID>[:port]).
func checkClientData(raw []byte, typ string, challenge []byte, rpID string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ErrBadClientData
	}
	if cd.Type != typ || cd.CrossOrigin {
		return ErrBadClientData
	}
	got, err := FromB64(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrBadChallenge
	}
	u, err := url.Parse(cd.Origin)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), rpID) {
		return ErrBadOrigin
	}
	return nil
}

type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	aaguid    []byte
	credID    []byte
	coseKey   map[any]any
}

func parseAuthData(b []byte, attested bool) (authData, error) {
	var a authData
	if len(b) < 37 {
		return a, ErrBadAuthData
	}
	a.rpIDHash, a.flags, a.signCount = b[:32], b[32], binary.BigEndian.Uint32(b[33:37])
	if !attested {
		return a, nil
	}
	rest := b[37:]
	if a.flags&flagAT == 0 || len(rest) < 18 {
		return a, ErrBadAuthData
	}
	a.aaguid = rest[:16]
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if n == 0 || n > 1023 || len(rest) < n {
		return a, ErrBadAuthData
	}
	a.credID, rest = rest[:n], rest[n:]
	k, _, err := decodeCBOR(rest)
	if err != nil {
		return a, ErrBadAuthData
	}
	m, ok := k.(map[any]any)
	if !ok {
		return a, ErrBadAuthData
	}
	a.coseKey = m
	return a, nil
}

func checkRP(a authData, rpID string) error {
	h := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.rpIDHash, h[:]) {
		return ErrBadOrigin
	}
	if a.flags&flagUP == 0 {
		return ErrNoPresence
	}
	return nil
}

// Register sprawdza odpowiedź navigator.credentials.create() i zwraca
// klucz do zapisania.
func Register(rpID string, challenge, clientDataJSON, attestationObject []byte) (Credential, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, rpID); err != nil {
		return Credential{}, err
	}
	v, _, err := decodeCBOR(attestationObject)
	if err != nil {
		return Credential{}, ErrBadAuthData
	}
	obj, ok := v.(map[any]any)
	if !ok {
		return Credential{}, ErrBadAuthData
	}
	raw, ok := obj["authData"].([]byte)
	if !ok {
		return Credential{}, ErrBadAuthData
	}
	a, err := parseAuthData(raw, true)
	if err != nil {
		return Credential{}, err
	}
	if err := checkRP(a, rpID); err != nil {
		return Credential{}, err
	}
	pub, alg, err := coseToPKIX(a.coseKey)
	if err != nil {
		return Credential{}, err
	}
	return Credential{ID: a.credID, PublicKey: pub, Alg: alg, SignCount: a.signCount, UV: a.flags&flagUV != 0,
		AAGUID: a.aaguid, RPID: rpID}, nil
}

// Assertion to odpowiedź navigator.credentials.get().
type Assertion struct {
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// Verify sprawdza podpis logowania kluczem c; zwraca nowy licznik i czy
// klucz zweryfikował użytkownika.
func Verify(c Credential, challenge []byte, as Assertion) (signCount uint32, uv bool, err error) {
	if err := checkClientData(as.ClientDataJSON, "webauthn.get", challenge, c.RPID); err != nil {
		return 0, false, err
	}
	a, err := parseAuthData(as.AuthenticatorData, false)
	if err != nil {
		return 0, false, err
	}
	if err := checkRP(a, c.RPID); err != nil {
		return 0, false, err
	}
	h := sha256.Sum256(as.ClientDataJSON)
	signed := append(append([]byte(nil), as.AuthenticatorData...), h[:]...)
	if err := verifySig(c, signed, as.Signature); err != nil {
		return 0, false, err
	}
	// Licznik: klucze bez licznika (passkeys) zawsze 0; inny nie może się cofnąć.
	if (a.signCount != 0 || c.SignCount != 0) && a.signCount <= c.SignCount {
		return 0, false, ErrCloned
	}
	return a.signCount, a.flags&flagUV != 0, nil
}

func verifySig(c Credential, msg, sig []byte) error {
	pk, err := x509.ParsePKIXPublicKey(c.PublicKey)
	if err != nil {
		return ErrUnsupported
	}
	switch c.Alg {
	case AlgES256:
		k, ok := pk.(*ecdsa.PublicKey)
		h := sha256.Sum256(msg)
		if ok && ecdsa.VerifyASN1(k, h[:], sig) {
			return nil
		}
	case AlgRS256:
		k, ok := pk.(*rsa.PublicKey)
		h := sha256.Sum256(msg)
		if ok && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil {
			return nil
		}
	case AlgEdDSA:
		k, ok := pk.(ed25519.PublicKey)
		if ok && ed25519.Verify(k, msg, sig) {
			return nil
		}
	default:
		return ErrUnsupported
	}
	return ErrBadSignature
}

// coseToPKIX zamienia klucz COSE (RFC 9053) na PKIX DER.
func coseToPKIX(m map[any]any) ([]byte, int, error) {
	num := func(k int64) (int64, bool) { v, ok := m[k].(int64); return v, ok }
	byt := func(k int64) []byte { v, _ := m[k].([]byte); return v }
	kty, _ := num(1)
	alg, ok := num(3)
	if !ok {
		return nil, 0, ErrUnsupported
	}
	var pub any
	switch {
	case alg == AlgES256 && kty == 2:
		crv, _ := num(-1)
		x, y := byt(-2), byt(-3)
		if crv != 1 || len(x) != 32 || len(y) != 32 {
			return nil, 0, ErrUnsupported
		}
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		// Punkt musi leżeć na krzywej (ECDH sprawdza to przy konwersji).
		if _, err := k.ECDH(); err != nil {
			return nil, 0, ErrUnsupported
		}
		pub = k
	case alg == AlgRS256 && kty == 3:
		n, e := byt(-1), byt(-2)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, 0, ErrUnsupported
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	case alg == AlgEdDSA && kty == 1:
		crv, _ := num(-1)
		x := byt(-2)
		if crv != 6 || len(x) != ed25519.PublicKeySize {
			return nil, 0, ErrUnsupported
		}
		pub = ed25519.PublicKey(x)
	default:
		return nil, 0, ErrUnsupported
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, 0, ErrUnsupported
	}
	return der, int(alg), nil
}
