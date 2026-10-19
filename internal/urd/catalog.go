package urd

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"
)

// Verification to wynik weryfikacji integralności archiwum.
type Verification struct {
	ID         int64     `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	OK         bool      `json:"ok"`
	Manifests  int       `json:"manifests"`
	Segments   int       `json:"segments"`
	Records    int64     `json:"records"`
	Bytes      int64     `json:"bytes"`
	// Pełne sprawdzenie treści (w ramach budżetu): liczba manifestów w tym
	// przebiegu, manifesty jeszcze nigdy niesprawdzone w całości i najdawniejsze
	// pełne sprawdzenie danych w retencji (nil, gdy Unverified > 0).
	FullManifests   int        `json:"full_manifests"`
	Unverified      int        `json:"unverified"`
	OldestFullCheck *time.Time `json:"oldest_full_check,omitempty"`
	Problems        []string   `json:"problems"`
	// Unknown: pliki na dysku nieznane spisowi (do decyzji administratora:
	// przyjęcie albo kwarantanna – Reconcile, Quarantine).
	Unknown []string `json:"unknown"`
}

// Catalog to spis archiwum: segmenty, manifesty (łańcuch) i wyniki
// weryfikacji. Implementacja produkcyjna: PG (baza Saga, schemat urd).
type Catalog interface {
	// AddSegment rejestruje zamknięty segment (jeszcze bez manifestu).
	AddSegment(ctx context.Context, s Segment) error
	// OpenSegments zwraca segmenty bez manifestu, rosnąco po czasie utworzenia.
	OpenSegments(ctx context.Context) ([]Segment, error)
	// LastManifest zwraca ostatni manifest łańcucha.
	LastManifest(ctx context.Context) (ManifestRecord, bool, error)
	// AddManifest zapisuje manifest i oznacza jego segmenty (atomowo).
	AddManifest(ctx context.Context, m ManifestRecord, segPaths []string) error
	// Manifests zwraca cały łańcuch rosnąco po numerze; treść (Body) tylko
	// dla manifestów, których dane nie wygasły.
	Manifests(ctx context.Context) ([]ManifestRecord, error)
	// MarkVerified zapisuje czas pełnego, zgodnego sprawdzenia manifestów.
	MarkVerified(ctx context.Context, seqs []int64, at time.Time) error
	// ExpireManifest oznacza manifest jako wygasły (dane usunięte po retencji).
	// Wpis w łańcuchu zostaje – ciągłość nadal da się sprawdzić.
	ExpireManifest(ctx context.Context, seq int64, at time.Time) error
	SaveVerification(ctx context.Context, v Verification) (int64, error)
	LastVerification(ctx context.Context) (Verification, bool, error)
}

// MemCatalog to katalog w pamięci (testy).
type MemCatalog struct {
	mu        sync.Mutex
	segments  map[string]Segment
	segSeq    map[string]int64
	manifests []ManifestRecord
	verifs    []Verification
}

// NewMemCatalog tworzy pusty katalog w pamięci.
func NewMemCatalog() *MemCatalog {
	return &MemCatalog{segments: map[string]Segment{}, segSeq: map[string]int64{}}
}

func (c *MemCatalog) AddSegment(_ context.Context, s Segment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.segments[s.Path] = s
	return nil
}

func (c *MemCatalog) OpenSegments(context.Context) ([]Segment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Segment
	for p, s := range c.segments {
		if c.segSeq[p] == 0 {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (c *MemCatalog) LastManifest(context.Context) (ManifestRecord, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.manifests) == 0 {
		return ManifestRecord{}, false, nil
	}
	return c.manifests[len(c.manifests)-1], true, nil
}

func (c *MemCatalog) AddManifest(_ context.Context, m ManifestRecord, segPaths []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifests = append(c.manifests, m)
	for _, p := range segPaths {
		c.segSeq[p] = m.Seq
	}
	return nil
}

func (c *MemCatalog) Manifests(context.Context) ([]ManifestRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := slices.Clone(c.manifests)
	for i := range out {
		if out[i].ExpiredAt != nil {
			out[i].Body = nil
		}
	}
	return out, nil
}

func (c *MemCatalog) ExpireManifest(_ context.Context, seq int64, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.manifests {
		if c.manifests[i].Seq == seq {
			c.manifests[i].ExpiredAt = &at
		}
	}
	for p, s := range c.segSeq {
		if s == seq {
			delete(c.segments, p)
			delete(c.segSeq, p)
		}
	}
	return nil
}

func (c *MemCatalog) SaveVerification(_ context.Context, v Verification) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v.ID = int64(len(c.verifs) + 1)
	c.verifs = append(c.verifs, v)
	return v.ID, nil
}

func (c *MemCatalog) LastVerification(context.Context) (Verification, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.verifs) == 0 {
		return Verification{}, false, nil
	}
	return c.verifs[len(c.verifs)-1], true, nil
}

// Tamper* pozwalają testom symulować manipulację katalogiem.

// DeleteManifestRow usuwa wpis manifestu (jak napastnik z dostępem do bazy).
func (c *MemCatalog) DeleteManifestRow(seq int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifests = slices.DeleteFunc(c.manifests, func(m ManifestRecord) bool { return m.Seq == seq })
}

func (c *MemCatalog) MarkVerified(_ context.Context, seqs []int64, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.manifests {
		if slices.Contains(seqs, c.manifests[i].Seq) {
			t := at
			c.manifests[i].VerifiedAt = &t
		}
	}
	return nil
}
