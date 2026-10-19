package urd

import (
	"encoding/json"
	"strings"
	"time"
)

// ManifestFormat identyfikuje wersję formatu manifestu.
const ManifestFormat = "heimdall-urd-manifest/1"

// GenesisPrev to „poprzedni hash” pierwszego manifestu w łańcuchu.
var GenesisPrev = strings.Repeat("0", 64)

// Segment to zamknięty plik archiwum.
type Segment struct {
	Path            string    `json:"path"`
	SHA256          string    `json:"sha256"`
	Bytes           int64     `json:"bytes"`
	Records         int       `json:"records"`
	FirstReceivedAt time.Time `json:"first_received_at"`
	LastReceivedAt  time.Time `json:"last_received_at"`
	Hour            time.Time `json:"-"`
	CreatedAt       time.Time `json:"-"`
	// RegisteredAt: wpisanie do spisu później niż zatwierdzenie (segment
	// przyjęty przez Reconcile); zero – razem z zatwierdzeniem.
	RegisteredAt time.Time `json:"-"`
}

// Manifest podsumowuje jedną godzinę archiwizacji i wiąże się z poprzednim
// manifestem jego sumą SHA-256. Zmiana, usunięcie lub dodanie segmentu albo
// całej godziny zmienia hash i przerywa łańcuch.
//
// Godzina bez danych też ma (pusty) manifest – brak manifestu dla godziny
// jest więc wykrywalny.
type Manifest struct {
	Format     string    `json:"format"`
	Seq        int64     `json:"seq"`
	Hour       time.Time `json:"hour"`
	PrevSHA256 string    `json:"prev_sha256"`
	CreatedAt  time.Time `json:"created_at"`
	Segments   []Segment `json:"segments"`
	Records    int64     `json:"records"`
	Bytes      int64     `json:"bytes"`
}

// NewManifest buduje manifest godziny.
func NewManifest(seq int64, hour time.Time, prev string, segs []Segment, now time.Time) Manifest {
	m := Manifest{Format: ManifestFormat, Seq: seq, Hour: hour.UTC(), PrevSHA256: prev, CreatedAt: now.UTC(),
		Segments: segs}
	if m.Segments == nil {
		m.Segments = []Segment{}
	}
	for _, s := range segs {
		m.Records += int64(s.Records)
		m.Bytes += s.Bytes
	}
	return m
}

// Encode zwraca treść manifestu; hash liczony jest z dokładnie tych bajtów
// (zapisanych w pliku i w bazie), więc kanoniczność serializacji nie ma
// znaczenia.
func (m Manifest) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ManifestRecord to manifest zapisany w bazie (treść + hash).
type ManifestRecord struct {
	Seq        int64      `json:"seq"`
	Hour       time.Time  `json:"hour"`
	SHA256     string     `json:"sha256"`
	PrevSHA256 string     `json:"prev_sha256"`
	Segments   int        `json:"segments"`
	Records    int64      `json:"records"`
	Bytes      int64      `json:"bytes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiredAt  *time.Time `json:"expired_at,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Body       []byte     `json:"-"`
}
