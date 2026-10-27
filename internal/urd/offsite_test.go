// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"siem/internal/s3"
)

type memStore struct {
	objects map[string][]byte
	locks   map[string]s3.Lock
	fail    error
}

func (m *memStore) Put(_ context.Context, key string, body []byte, lock *s3.Lock) error {
	if m.fail != nil {
		return m.fail
	}
	m.objects[key] = append([]byte(nil), body...)
	m.locks[key] = *lock
	return nil
}

func TestOffsite(t *testing.T) {
	a, cat, _ := fill(t)
	ctx := context.Background()
	st := &memStore{objects: map[string][]byte{}, locks: map[string]s3.Lock{}}
	opt := OffsiteOptions{Prefix: "vardr/", Mode: s3.ModeCompliance, Retention: 30 * 24 * time.Hour, Limit: 2}

	if n, oldest, _ := cat.OffsiteBacklog(ctx); n != 4 || oldest == nil || oldest.Hour() != 10 {
		t.Fatalf("zaległość: %d %v", n, oldest)
	}
	// Dwie godziny w przebiegu (limit), potem reszta.
	if n, err := a.Offsite(ctx, st, cat, opt); n != 2 || err != nil {
		t.Fatalf("pierwszy przebieg: %d %v", n, err)
	}
	if n, err := a.Offsite(ctx, st, cat, opt); n != 2 || err != nil {
		t.Fatalf("drugi przebieg: %d %v", n, err)
	}
	if n, err := a.Offsite(ctx, st, cat, opt); n != 0 || err != nil {
		t.Fatalf("nic do wysłania: %d %v", n, err)
	}
	ms, _ := cat.Manifests(ctx)
	segs := 0
	for _, m := range ms {
		key := "vardr/" + ManifestPath(m.Hour)
		if string(st.objects[key]) != string(m.Body) {
			t.Fatalf("manifest %d nie trafił do magazynu", m.Seq)
		}
		want := m.Hour.Add(time.Hour + opt.Retention)
		if l := st.locks[key]; l.Mode != s3.ModeCompliance || !l.RetainUntil.Equal(want) {
			t.Fatalf("blokada %s: %+v", key, l)
		}
		segs += m.Segments
	}
	if len(st.objects) != len(ms)+segs {
		t.Fatalf("obiekty: %d, chcę %d", len(st.objects), len(ms)+segs)
	}
	for k, v := range st.objects {
		if strings.HasSuffix(k, ".json") {
			continue
		}
		local, err := os.ReadFile(a.abs(strings.TrimPrefix(k, "vardr/")))
		if err != nil || string(local) != string(v) {
			t.Fatalf("segment %s różni się od archiwum", k)
		}
	}
	if n, _, _ := cat.OffsiteBacklog(ctx); n != 0 {
		t.Fatalf("zaległość po wysłaniu: %d", n)
	}
}

func TestOffsiteStopsOnErrors(t *testing.T) {
	a, cat, _ := fill(t)
	ctx := context.Background()
	opt := OffsiteOptions{Mode: s3.ModeCompliance, Retention: time.Hour}

	// Błąd magazynu: nic nie oznaczone jako wysłane.
	st := &memStore{objects: map[string][]byte{}, locks: map[string]s3.Lock{}, fail: errors.New("HTTP 503")}
	if n, err := a.Offsite(ctx, st, cat, opt); n != 0 || err == nil {
		t.Fatalf("błąd magazynu: %d %v", n, err)
	}
	if n, _, _ := cat.OffsiteBacklog(ctx); n != 4 {
		t.Fatalf("zaległość: %d", n)
	}

	// Segment zmieniony na dysku nie trafia do kopii.
	ms, _ := cat.Manifests(ctx)
	var first Segment
	for _, s := range manifestSegments(t, ms[0]) {
		first = s
		break
	}
	os.Chmod(a.abs(first.Path), 0o640)
	os.WriteFile(a.abs(first.Path), []byte("podmienione"), 0o640)
	st.fail = nil
	if n, err := a.Offsite(ctx, st, cat, opt); n != 0 || err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("zmieniony segment: %d %v", n, err)
	}
	if _, ok := st.objects[first.Path]; ok {
		t.Fatal("zmieniony segment wysłany")
	}
}

func manifestSegments(t *testing.T, m ManifestRecord) []Segment {
	t.Helper()
	var body Manifest
	if err := json.Unmarshal(m.Body, &body); err != nil {
		t.Fatal(err)
	}
	return body.Segments
}
