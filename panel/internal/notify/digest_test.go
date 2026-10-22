// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"siem/internal/alerts"
	"siem/panel/internal/api/store"
)

// outboxMem: outbox w pamięci (jak alerts.PG) do testu burzy alertów.
type outboxMem struct {
	items    []*outboxItem
	digested map[string]bool
}

type outboxItem struct {
	p      alerts.Pending
	sentAt *time.Time
	held   bool
	digest bool
}

func (o *outboxMem) ClaimOutbox(_ context.Context, _ time.Time, limit int) ([]alerts.Pending, error) {
	var out []alerts.Pending
	for _, it := range o.items {
		if it.sentAt == nil && len(out) < limit {
			out = append(out, it.p)
		}
	}
	return out, nil
}

func (o *outboxMem) find(id int64) *outboxItem {
	for _, it := range o.items {
		if it.p.OutboxID == id {
			return it
		}
	}
	return nil
}

func (o *outboxMem) MarkSent(_ context.Context, id int64, now time.Time) error {
	o.find(id).sentAt = &now
	return nil
}

func (o *outboxMem) MarkFailed(context.Context, int64, string, time.Time) error { return nil }

func (o *outboxMem) SentPerRule(_ context.Context, since time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, it := range o.items {
		if it.sentAt != nil && !it.held && it.p.Kind == "new" && !it.sentAt.Before(since) {
			out[it.p.Alert.RuleID]++
		}
	}
	return out, nil
}

func (o *outboxMem) Hold(_ context.Context, id int64, now time.Time) error {
	it := o.find(id)
	it.held, it.sentAt = true, &now
	return nil
}

func (o *outboxMem) DueDigests(_ context.Context, olderThan time.Time) ([]alerts.Digest, error) {
	by := map[string]*alerts.Digest{}
	for _, it := range o.items {
		if !it.held || it.digest {
			continue
		}
		d := by[it.p.Alert.RuleID]
		if d == nil {
			d = &alerts.Digest{RuleID: it.p.Alert.RuleID, RuleTitle: it.p.Alert.RuleTitle, First: *it.sentAt}
			by[d.RuleID] = d
		}
		d.Count++
		d.Levels = append(d.Levels, it.p.Alert.Level)
		d.Hosts = append(d.Hosts, it.p.Alert.HostName)
		d.HostCount++
		d.Upto = *it.sentAt
	}
	var out []alerts.Digest
	for _, d := range by {
		if !d.First.After(olderThan) {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (o *outboxMem) MarkDigested(_ context.Context, rule string, upto, _ time.Time) error {
	for _, it := range o.items {
		if it.held && it.p.Alert.RuleID == rule && !it.sentAt.After(upto) {
			it.digest = true
		}
	}
	return nil
}

func TestAlertStormDigest(t *testing.T) {
	hook, got := receiver(t, http.StatusOK)
	ms := &memStore{chans: []store.Channel{{ID: 1, Name: "d", Kind: KindWebhook, URL: hook.URL + "/h", Events: []string{EventAlert}, Enabled: true}}}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	svc := &Service{Store: ms, Log: slog.New(slog.DiscardHandler), Client: hook.Client(), Now: func() time.Time { return now }}
	title := func(i int) string { return (*got)[i]["title"].(string) }
	ob := &outboxMem{}
	for i := 1; i <= 12; i++ {
		level := "medium"
		if i == 12 {
			level = "critical"
		}
		ob.items = append(ob.items, &outboxItem{p: alerts.Pending{OutboxID: int64(i), Kind: "new", Alert: alerts.Alert{ID: int64(i),
			RuleID: "bf", RuleTitle: "Brute force", Level: level, HostName: fmt.Sprintf("pc%d", i)}}})
	}
	a := &AlertSender{Store: ob, Svc: svc, Log: slog.New(slog.DiscardHandler), PanelURL: "https://siem"}
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 5 osobnych + krytyczny zawsze osobno; 6 wstrzymanych, zbiorcza jeszcze nie.
	if len(*got) != 6 || !strings.Contains(title(5), "KRYTYCZNY") {
		t.Fatalf("po pierwszej porcji: %d wiadomości", len(*got))
	}
	now = now.Add(11 * time.Minute)
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 7 || title(6) != "[ZBIORCZO] Brute force – 6 alertów" || !strings.Contains(fmt.Sprint((*got)[6]["fields"]), "rule=bf") {
		t.Fatalf("wiadomość zbiorcza: %v", (*got)[len(*got)-1])
	}
	if err := a.tick(context.Background()); err != nil || len(*got) != 7 {
		t.Fatalf("zbiorcza wysłana ponownie: %d %v", len(*got), err)
	}
}
