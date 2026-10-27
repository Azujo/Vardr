// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kandydaci na wyjątki reguł (narzędzie fp_candidates, wersja 1.5.3):
// alerty zamknięte jako fałszywy alarm albo uzasadnione działanie,
// zgrupowane po regule – z najczęstszymi komputerami i kontami oraz liczbą
// otwartych alertów tej reguły. Liczone tu, nie przez model (jak
// correlate_alerts); model sprawdza potem zdarzenia przykładowych alertów
// i proponuje wąski wyjątek, który analityk sprawdza na historii i zapisuje.

const (
	fpPages   = 5  // stron po 100 zamkniętych alertów
	fpMaxOut  = 10 // reguł w wyniku
	fpTop     = 3  // najczęstszych wartości
	fpSamples = 3  // przykładowych alertów
)

type fpAlert struct {
	ID         int64     `json:"id"`
	RuleID     string    `json:"rule_id"`
	RuleTitle  string    `json:"rule_title"`
	Status     string    `json:"status"`
	Resolution string    `json:"resolution"`
	Hits       int       `json:"hits"`
	LastSeen   time.Time `json:"last_seen"`
	HostName   string    `json:"host_name"`
	UserName   string    `json:"user_name"`
	Reason     string    `json:"close_reason"`
}

type fpValue struct {
	Value  string `json:"value"`
	Alerts int    `json:"alerts"`
}

type fpRule struct {
	RuleID        string    `json:"rule_id"`
	Title         string    `json:"rule_title"`
	FalsePositive int       `json:"false_positive"`
	Benign        int       `json:"benign"`
	Hits          int       `json:"hits"`
	LastSeen      time.Time `json:"last_seen"`
	TopHosts      []fpValue `json:"top_hosts"`
	TopUsers      []fpValue `json:"top_users"`
	CloseReasons  []string  `json:"close_reasons,omitempty"`
	SampleAlerts  []int64   `json:"sample_alert_ids"`
	OpenAlerts    int       `json:"open_alerts"`
	Exceptions    int       `json:"existing_exceptions"`
}

type fpResult struct {
	Rules     []fpRule `json:"rules"`
	Reviewed  int      `json:"closed_alerts_reviewed"`
	Truncated bool     `json:"truncated,omitempty"`
	Hint      string   `json:"hint"`
}

func top(m map[string]int) []fpValue {
	out := make([]fpValue, 0, len(m))
	for v, n := range m {
		if v != "" {
			out = append(out, fpValue{v, n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alerts != out[j].Alerts {
			return out[i].Alerts > out[j].Alerts
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > fpTop {
		out = out[:fpTop]
	}
	return out
}

// fpGroup grupuje zamknięte alerty z rozstrzygnięciem fałszywy alarm albo
// uzasadnione działanie po regule (najwięcej alertów pierwsze).
func fpGroup(all []fpAlert) []fpRule {
	type acc struct {
		r            fpRule
		hosts, users map[string]int
		reasons      map[string]bool
	}
	by := map[string]*acc{}
	for _, a := range all {
		if a.Resolution != "false_positive" && a.Resolution != "benign" {
			continue
		}
		g := by[a.RuleID]
		if g == nil {
			g = &acc{r: fpRule{RuleID: a.RuleID, Title: a.RuleTitle}, hosts: map[string]int{}, users: map[string]int{},
				reasons: map[string]bool{}}
			by[a.RuleID] = g
		}
		if a.Resolution == "false_positive" {
			g.r.FalsePositive++
		} else {
			g.r.Benign++
		}
		g.r.Hits += a.Hits
		if a.LastSeen.After(g.r.LastSeen) {
			g.r.LastSeen = a.LastSeen
		}
		g.hosts[a.HostName]++
		g.users[strings.ToLower(a.UserName)]++
		if rs := strings.TrimSpace(a.Reason); rs != "" && len(g.reasons) < fpSamples && !g.reasons[rs] {
			g.reasons[rs] = true
			g.r.CloseReasons = append(g.r.CloseReasons, rs)
		}
		if len(g.r.SampleAlerts) < fpSamples {
			g.r.SampleAlerts = append(g.r.SampleAlerts, a.ID)
		}
	}
	out := make([]fpRule, 0, len(by))
	for _, g := range by {
		g.r.TopHosts, g.r.TopUsers = top(g.hosts), top(g.users)
		out = append(out, g.r)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := out[i].FalsePositive+out[i].Benign, out[j].FalsePositive+out[j].Benign
		if ni != nj {
			return ni > nj
		}
		return out[i].RuleID < out[j].RuleID
	})
	if len(out) > fpMaxOut {
		out = out[:fpMaxOut]
	}
	return out
}

func fpCandidates(ctx context.Context, c Caller, args map[string]any) (any, error) {
	q := query(args, "since")
	q.Set("status", "closed")
	var all []fpAlert
	truncated := false
	for page := 0; page < fpPages; page++ {
		var out struct {
			Alerts []fpAlert `json:"alerts"`
			Total  int       `json:"total"`
		}
		if err := c.Get(ctx, "/api/v1/alerts", q, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Alerts...)
		if len(out.Alerts) < 100 || len(all) >= out.Total {
			break
		}
		if page == fpPages-1 {
			truncated = true
			break
		}
		q = cloneValues(q)
		q.Set("before", strconv.FormatInt(out.Alerts[len(out.Alerts)-1].ID, 10))
	}
	res := fpResult{Rules: fpGroup(all), Reviewed: len(all), Truncated: truncated,
		Hint: "Check the events of sample alerts (get_alert, get_event) for the fields that make these alerts harmless, then propose a narrow exception."}
	if len(res.Rules) == 0 {
		return res, nil
	}
	// Otwarte alerty i obowiązujące wyjątki reguł – kontekst dla propozycji.
	var rules struct {
		Rules []struct {
			ID         string `json:"id"`
			OpenAlerts int    `json:"open_alerts"`
		} `json:"rules"`
		Exceptions map[string]int `json:"exceptions"`
	}
	if err := c.Get(ctx, "/api/v1/rules", url.Values{}, &rules); err == nil {
		open := map[string]int{}
		for _, r := range rules.Rules {
			open[r.ID] = r.OpenAlerts
		}
		for i := range res.Rules {
			res.Rules[i].OpenAlerts = open[res.Rules[i].RuleID]
			res.Rules[i].Exceptions = rules.Exceptions[res.Rules[i].RuleID]
		}
	}
	return res, nil
}
