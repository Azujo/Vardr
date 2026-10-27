// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthntest to programowy klucz bezpieczeństwa (ES256) do testów
// panelu: odpowiedzi navigator.credentials.create() i get().
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"

	"siem/panel/internal/webauthn"
)

// Authenticator to klucz ES256 dla jednej strony (RPID).
type Authenticator struct {
	RPID   string
	Origin string // np. https://vardr.firma.pl:8444
	ID     []byte
	Count  uint32
	key    *ecdsa.PrivateKey
}

// New tworzy klucz dla strony rpID.
func New(rpID, origin string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Authenticator{RPID: rpID, Origin: origin, ID: id, key: k}
}

func head(major byte, n int) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	if n < 256 {
		return []byte{major<<5 | 24, byte(n)}
	}
	return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
}

func cborInt(v int) []byte {
	if v >= 0 {
		return head(0, v)
	}
	return head(1, -1-v)
}

func cborBytes(b []byte) []byte { return append(head(2, len(b)), b...) }
func cborText(s string) []byte  { return append(head(3, len(s)), s...) }

func (a *Authenticator) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	flags := byte(0x01 | 0x04)
	if attested {
		flags |= 0x40
	}
	b := append(h[:], flags)
	b = binary.BigEndian.AppendUint32(b, a.Count)
	if attested {
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.X.FillBytes(x)
		a.key.Y.FillBytes(y)
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.ID)))
		b = append(b, a.ID...)
		b = append(b, head(5, 5)...)
		b = append(append(b, cborInt(1)...), cborInt(2)...)
		b = append(append(b, cborInt(3)...), cborInt(webauthn.AlgES256)...)
		b = append(append(b, cborInt(-1)...), cborInt(1)...)
		b = append(append(b, cborInt(-2)...), cborBytes(x)...)
		b = append(append(b, cborInt(-3)...), cborBytes(y)...)
	}
	return b
}

func (a *Authenticator) clientData(typ string, challenge []byte) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": webauthn.B64(challenge), "origin": a.Origin})
	return b
}

// Create: clientDataJSON i attestationObject (base64url) dla wyzwania.
func (a *Authenticator) Create(challenge []byte) (clientData, attestation string) {
	att := head(5, 3)
	att = append(append(att, cborText("fmt")...), cborText("none")...)
	att = append(append(att, cborText("attStmt")...), head(5, 0)...)
	att = append(append(att, cborText("authData")...), cborBytes(a.authData(true))...)
	return webauthn.B64(a.clientData("webauthn.create", challenge)), webauthn.B64(att)
}

// Get: podpis wyzwania – id, clientDataJSON, authenticatorData, podpis (base64url).
func (a *Authenticator) Get(challenge []byte) (id, clientData, authData, signature string) {
	a.Count++
	cd := a.clientData("webauthn.get", challenge)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte(nil), ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, d[:])
	if err != nil {
		panic(err)
	}
	return webauthn.B64(a.ID), webauthn.B64(cd), webauthn.B64(ad), webauthn.B64(sig)
}
