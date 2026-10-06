package chwriter

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/server/model"
)

func events(n int) []model.Event {
	out := make([]model.Event, n)
	for i := range out {
		out[i].ID = fmt.Sprint(i)
	}
	return out
}

// fakeInsert odrzuca paczkę, jeśli zawiera któryś ze złych identyfikatorów.
func fakeInsert(bad map[string]bool, calls *int) func(context.Context, []model.Event) error {
	return func(_ context.Context, evs []model.Event) error {
		*calls++
		for _, e := range evs {
			if bad[e.ID] {
				return &clickhouse.Exception{Code: 321, Message: "value out of range"}
			}
		}
		return nil
	}
}

func TestBisectIsolatesBadRows(t *testing.T) {
	var calls int
	var written []model.Event
	rej, err := Bisect(context.Background(), events(1000),
		fakeInsert(map[string]bool{"17": true, "640": true}, &calls),
		func(ok []model.Event) { written = append(written, ok...) })
	if err != nil {
		t.Fatal(err)
	}
	if len(rej) != 2 || rej[0].Event.ID != "17" || rej[1].Event.ID != "640" {
		t.Fatalf("odrzucone = %+v", rej)
	}
	if len(written) != 998 {
		t.Fatalf("zapisane = %d, chcę 998", len(written))
	}
	if calls > 45 {
		t.Fatalf("za dużo prób zapisu: %d", calls)
	}
	if q := rej[0].Quarantined(); q.EventID != "17" || q.Reason == "" {
		t.Fatalf("wpis kwarantanny = %+v", q)
	}
}

func TestBisectStopsOnOutage(t *testing.T) {
	outage := errors.New("connection refused")
	calls := 0
	rej, err := Bisect(context.Background(), events(100),
		func(context.Context, []model.Event) error { calls++; return outage },
		func([]model.Event) { t.Fatal("nic nie powinno zostać zapisane") })
	if !errors.Is(err, outage) || len(rej) != 0 || calls != 1 {
		t.Fatalf("err=%v rej=%d calls=%d", err, len(rej), calls)
	}
}

func TestIsDataError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&clickhouse.Exception{Code: 321}, true},
		{fmt.Errorf("zapis: %w", &clickhouse.Exception{Code: 41}), true},
		{&clickhouse.Exception{Code: 241}, false}, // MEMORY_LIMIT_EXCEEDED – awaria
		{&dataError{errors.New("append")}, true},
		{errors.New("EOF"), false},
	} {
		if got := IsDataError(c.err); got != c.want {
			t.Errorf("IsDataError(%v) = %v, chcę %v", c.err, got, c.want)
		}
	}
}
