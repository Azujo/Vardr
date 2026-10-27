// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

// Minimalny dekoder CBOR (RFC 8949) – tylko to, czego używa WebAuthn:
// liczby, ciągi bajtów i tekst, tablice, mapy, wartości proste. Bez
// długości nieokreślonych (WebAuthn wymaga kodowania kanonicznego CTAP2).

var errCBOR = errors.New("invalid CBOR")

const maxDepth = 16

// decodeCBOR dekoduje jedną wartość z początku b i zwraca resztę.
// Mapy: map[any]any z kluczami int64 albo string.
func decodeCBOR(b []byte) (any, []byte, error) { return decodeItem(b, 0) }

func decodeItem(b []byte, depth int) (any, []byte, error) {
	if depth > maxDepth || len(b) == 0 {
		return nil, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info == 24 && len(b) >= 1:
		arg, b = uint64(b[0]), b[1:]
	case info == 25 && len(b) >= 2:
		arg, b = uint64(binary.BigEndian.Uint16(b)), b[2:]
	case info == 26 && len(b) >= 4:
		arg, b = uint64(binary.BigEndian.Uint32(b)), b[4:]
	case info == 27 && len(b) >= 8:
		arg, b = binary.BigEndian.Uint64(b), b[8:]
	default:
		return nil, nil, errCBOR
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return int64(arg), b, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return -1 - int64(arg), b, nil
	case 2, 3:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		if major == 2 {
			return append([]byte(nil), b[:arg]...), b[arg:], nil
		}
		return string(b[:arg]), b[arg:], nil
	case 4:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make([]any, 0, arg)
		for range arg {
			v, rest, err := decodeItem(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out, b = append(out, v), rest
		}
		return out, b, nil
	case 5:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make(map[any]any, arg)
		for range arg {
			k, rest, err := decodeItem(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, errCBOR
			}
			v, rest, err := decodeItem(rest, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out[k], b = v, rest
		}
		return out, b, nil
	case 6: // znacznik – wartość bez znacznika
		return decodeItem(b, depth+1)
	case 7:
		switch info {
		case 20:
			return false, b, nil
		case 21:
			return true, b, nil
		case 22, 23:
			return nil, b, nil
		case 25, 26, 27:
			return float64(0), b, nil // liczby zmiennoprzecinkowe nie są używane
		}
	}
	return nil, nil, errCBOR
}
