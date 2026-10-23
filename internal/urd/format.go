// SPDX-License-Identifier: AGPL-3.0-or-later

// Package urd to archiwum NIS2 (Urd): format plików archiwum, łańcuch
// manifestów i ich weryfikacja. Używają go archiwizator (siem-archiver)
// i panel (odczyt stanu).
//
// Układ katalogu archiwum:
//
//	segments/RRRR/MM/DD/GG/seg-<unixnano>.urd   paczki z jednej godziny archiwizacji
//	manifests/RRRR/MM/DD/GG.json                manifest godziny (łańcuch hashy)
//
// Segment to nagłówek Magic, a po nim rekordy: uint32 BE długość metadanych,
// metadane (JSON, RecordMeta), uint32 BE długość treści, treść – oryginalna
// wiadomość z kolejki SIEM_RAW (paczka agenta, skompresowana tak, jak przyszła).
package urd

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"siem/internal/lang"
)

// Magic otwiera każdy plik segmentu (wersja formatu w ostatnim znaku).
const Magic = "HEIMURD1"

// Limity rekordu przy odczycie (ochrona przed uszkodzonym plikiem).
const (
	maxMetaBytes    = 64 << 10
	maxPayloadBytes = 64 << 20
)

// RecordMeta opisuje jedną zarchiwizowaną paczkę.
type RecordMeta struct {
	Agent      string    `json:"agent"`
	Batch      string    `json:"batch,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Encoding   string    `json:"encoding,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	StreamSeq  uint64    `json:"stream_seq,omitempty"`
	// SHA256 treści – pozwala sprawdzić każdą paczkę osobno (np. w eksporcie).
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// SumHex zwraca SHA-256 w zapisie szesnastkowym.
func SumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// WriteRecord dopisuje rekord (uzupełnia SHA256 i Bytes w metadanych).
func WriteRecord(w io.Writer, meta RecordMeta, payload []byte) (int64, error) {
	meta.SHA256, meta.Bytes = SumHex(payload), len(payload)
	mb, err := json.Marshal(meta)
	if err != nil {
		return 0, err
	}
	var hdr [4]byte
	var n int64
	for _, part := range [][]byte{mb, payload} {
		binary.BigEndian.PutUint32(hdr[:], uint32(len(part)))
		k, err := w.Write(hdr[:])
		n += int64(k)
		if err != nil {
			return n, err
		}
		k, err = w.Write(part)
		n += int64(k)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// ErrCorrupt oznacza plik segmentu niezgodny z formatem.
var ErrCorrupt = lang.Errorf("uszkodzony segment", "damaged segment")

// Reader czyta rekordy segmentu.
type Reader struct {
	r   *bufio.Reader
	hdr [4]byte
}

// NewReader sprawdza nagłówek segmentu.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 256<<10)
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != Magic {
		return nil, lang.Errorf("%w: brak nagłówka %s", "%w: missing header %s", ErrCorrupt, Magic)
	}
	return &Reader{r: br}, nil
}

func (r *Reader) part(limit uint32) ([]byte, error) {
	if _, err := io.ReadFull(r.r, r.hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(r.hdr[:])
	if n > limit {
		return nil, lang.Errorf("%w: rekord %d B", "%w: record %d B", ErrCorrupt, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return nil, lang.Errorf("%w: ucięty rekord", "%w: truncated record", ErrCorrupt)
	}
	return b, nil
}

// Next zwraca kolejny rekord albo io.EOF na końcu pliku.
func (r *Reader) Next() (RecordMeta, []byte, error) {
	var meta RecordMeta
	mb, err := r.part(maxMetaBytes)
	if errors.Is(err, io.EOF) {
		return meta, nil, io.EOF
	}
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = lang.Errorf("%w: ucięty nagłówek rekordu", "%w: truncated record header", ErrCorrupt)
		}
		return meta, nil, err
	}
	if err := json.Unmarshal(mb, &meta); err != nil {
		return meta, nil, lang.Errorf("%w: metadane: %v", "%w: metadata: %v", ErrCorrupt, err)
	}
	payload, err := r.part(maxPayloadBytes)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = lang.Errorf("%w: brak treści rekordu", "%w: missing record content", ErrCorrupt)
		}
		return meta, nil, err
	}
	return meta, payload, nil
}

// SegmentPath buduje ścieżkę segmentu (względem katalogu archiwum).
func SegmentPath(hour time.Time, created time.Time) string {
	return path.Join("segments", hour.UTC().Format("2006/01/02/15"), fmt.Sprintf("seg-%d.urd", created.UnixNano()))
}

// ManifestPath buduje ścieżkę manifestu godziny.
func ManifestPath(hour time.Time) string {
	return path.Join("manifests", hour.UTC().Format("2006/01/02/15")+".json")
}
