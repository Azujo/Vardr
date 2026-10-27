// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

// Prosty koder CBOR do budowania odpowiedzi „klucza” w testach.
func enc(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		case n < 65536:
			return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
		}
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return head(0, uint64(x))
		}
		return head(1, uint64(-1-x))
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case string:
		return append(head(3, uint64(len(x))), x...)
	case [][2]any: // mapa z zachowaniem kolejności
		out := head(5, uint64(len(x)))
		for _, kv := range x {
			out = append(append(out, enc(kv[0])...), enc(kv[1])...)
		}
		return out
	}
	panic("enc")
}

type authenticator struct {
	rpID  string
	id    []byte
	alg   int
	ec    *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	rsa   *rsa.PrivateKey
	count uint32
	flags byte
}

func newAuth(t *testing.T, alg int) *authenticator {
	a := &authenticator{rpID: "vardr.firma.pl", id: []byte("klucz-1"), alg: alg, flags: flagUP | flagUV}
	switch alg {
	case AlgES256:
		a.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, a.ed, _ = ed25519.GenerateKey(rand.Reader)
	case AlgRS256:
		a.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	return a
}

func (a *authenticator) cose() []byte {
	switch a.alg {
	case AlgES256:
		x, y := make([]byte, 32), make([]byte, 32)
		a.ec.X.FillBytes(x)
		a.ec.Y.FillBytes(y)
		return enc([][2]any{{1, 2}, {3, AlgES256}, {-1, 1}, {-2, x}, {-3, y}})
	case AlgEdDSA:
		return enc([][2]any{{1, 1}, {3, AlgEdDSA}, {-1, 6}, {-2, []byte(a.ed.Public().(ed25519.PublicKey))}})
	}
	return enc([][2]any{{1, 3}, {3, AlgRS256}, {-1, a.rsa.N.Bytes()}, {-2, []byte{1, 0, 1}}})
}

func (a *authenticator) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	b := append(h[:], a.flags)
	b = binary.BigEndian.AppendUint32(b, a.count)
	if attested {
		b[32] |= flagAT
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.id)))
		b = append(append(b, a.id...), a.cose()...)
	}
	return b
}

func clientJSON(typ string, ch []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": B64(ch), "origin": origin})
	return b
}

func (a *authenticator) create(ch []byte, origin string) (cd, att []byte) {
	return clientJSON("webauthn.create", ch, origin),
		enc([][2]any{{"fmt", "none"}, {"attStmt", [][2]any{}}, {"authData", a.authData(true)}})
}

func (a *authenticator) get(ch []byte, origin string) Assertion {
	cd := clientJSON("webauthn.get", ch, origin)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	msg := append(append([]byte(nil), ad...), h[:]...)
	var sig []byte
	switch a.alg {
	case AlgES256:
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, a.ec, d[:])
	case AlgEdDSA:
		sig = ed25519.Sign(a.ed, msg)
	case AlgRS256:
		d := sha256.Sum256(msg)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, a.rsa, crypto.SHA256, d[:])
	}
	return Assertion{ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig}
}

func TestRegisterAndVerify(t *testing.T) {
	const origin = "https://vardr.firma.pl:8444"
	for _, alg := range Algorithms {
		a := newAuth(t, alg)
		ch := NewChallenge()
		cd, att := a.create(ch, origin)
		c, err := Register("vardr.firma.pl", ch, cd, att)
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if string(c.ID) != "klucz-1" || c.Alg != alg || !c.UV || c.RPID != "vardr.firma.pl" {
			t.Fatalf("alg %d: %+v", alg, c)
		}
		// Logowanie z licznikiem.
		a.count = 5
		ch = NewChallenge()
		n, uv, err := Verify(c, ch, a.get(ch, origin))
		if err != nil || n != 5 || !uv {
			t.Fatalf("alg %d: logowanie %d %v %v", alg, n, uv, err)
		}
		c.SignCount = n
		// Cofnięty licznik – klon.
		if _, _, err := Verify(c, ch, a.get(ch, origin)); !errors.Is(err, ErrCloned) {
			t.Fatalf("alg %d: licznik %v", alg, err)
		}
		a.count = 6
		// Inne wyzwanie, inne pochodzenie, zmieniony podpis.
		if _, _, err := Verify(c, NewChallenge(), a.get(ch, origin)); !errors.Is(err, ErrBadChallenge) {
			t.Fatalf("alg %d: wyzwanie %v", alg, err)
		}
		if _, _, err := Verify(c, ch, a.get(ch, "https://vardr.firma.pl.zly.example")); !errors.Is(err, ErrBadOrigin) {
			t.Fatalf("alg %d: pochodzenie %v", alg, err)
		}
		as := a.get(ch, origin)
		as.Signature[len(as.Signature)-1] ^= 1
		if _, _, err := Verify(c, ch, as); err == nil {
			t.Fatalf("alg %d: zmieniony podpis przyjęty", alg)
		}
	}
}

func TestRegisterRejects(t *testing.T) {
	a := newAuth(t, AlgES256)
	ch := NewChallenge()
	cd, att := a.create(ch, "https://vardr.firma.pl")
	if _, err := Register("inny.firma.pl", ch, clientJSON("webauthn.create", ch, "https://inny.firma.pl"), att); !errors.Is(err, ErrBadOrigin) {
		t.Fatalf("rpId: %v", err)
	}
	if _, err := Register("vardr.firma.pl", ch, clientJSON("webauthn.get", ch, "https://vardr.firma.pl"), att); !errors.Is(err, ErrBadClientData) {
		t.Fatalf("typ: %v", err)
	}
	if _, err := Register("vardr.firma.pl", ch, clientJSON("webauthn.create", ch, "http://vardr.firma.pl"), att); !errors.Is(err, ErrBadOrigin) {
		t.Fatalf("http: %v", err)
	}
	a.flags = 0 // bez dotknięcia klucza
	_, att = a.create(ch, "https://vardr.firma.pl")
	if _, err := Register("vardr.firma.pl", ch, cd, att); !errors.Is(err, ErrNoPresence) {
		t.Fatalf("UP: %v", err)
	}
	if _, err := Register("vardr.firma.pl", ch, cd, []byte{0xbf, 0xff}); err == nil {
		t.Fatal("zepsuty CBOR przyjęty")
	}
}

func TestRPID(t *testing.T) {
	for host, want := range map[string]string{"Vardr.Firma.pl:8444": "vardr.firma.pl", "panel.local": "panel.local", "192.168.88.98:8444": "", "[::1]:8444": ""} {
		got, err := RPID(host)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%s: %q %v", host, got, err)
		}
	}
}

func TestCBORLimits(t *testing.T) {
	// Długość większa niż dane, za głębokie zagnieżdżenie.
	for _, b := range [][]byte{{0x5a, 0xff, 0xff, 0xff, 0xff}, {0x9a, 0xff, 0xff, 0xff, 0xff}, bytesOf(0x81, 40)} {
		if _, _, err := decodeCBOR(b); err == nil {
			t.Errorf("% x przyjęte", b)
		}
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
