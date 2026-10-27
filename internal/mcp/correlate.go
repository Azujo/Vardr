// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Korelacja alertów (narzędzie correlate_alerts): grupy alertów
// połączonych wspólnym komputerem, kontem (osobą) albo adresem IP –
// liczone tu, a nie przez model: model lokalny z krótkim kontekstem nie
// porówna setek alertów, a policzone grupy są powtarzalne. Dane przechodzą
// przez API panelu, więc polityka AI i maskowanie działają jak zwykle
// (pseudonimy są stałe – ta sama wartość łączy alerty także po maskowaniu).

const (
	correlatePages    = 3  // stron po 100 alertów
	correlateMaxGroup = 8  // alertów wypisanych w grupie
	correlateMaxOut   = 10 // grup w wyniku
)

// corrAlert: pola alertu potrzebne do korelacji.
type corrAlert struct {
	ID           int64     `json:"id"`
	RuleID       string    `json:"rule_id"`
	RuleTitle    string    `json:"rule_title"`
	Level        string    `json:"level"`
	Status       string    `json:"status"`
	Hits         int       `json:"hits"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	HostName     string    `json:"host_name"`
	UserName     string    `json:"user_name"`
	UserIdentity string    `json:"user_identity"`
	SourceIP     string    `json:"source_ip"`
}

// Konta i adresy, które nie łączą alertów (są wszędzie).
var corrIgnored = map[string]bool{
	"": true, "-": true, "system": true, "nt authority\\system": true, "local service": true, "network service": true,
	"anonymous logon": true, "anonymous": true, "unknown": true, "127.0.0.1": true, "::1": true, "0.0.0.0": true,
}

// entities: wspólne cechy alertu („host:PC-1”, „user:jan”, „ip:10.0.0.5”).
func (a corrAlert) entities() []string {
	var out []string
	add := func(kind, v string) {
		v = strings.TrimSpace(v)
		if !corrIgnored[strings.ToLower(v)] && !strings.HasSuffix(v, "$") { // konto komputera – jak host
			out = append(out, kind+":"+v)
		}
	}
	add("host", a.HostName)
	if a.UserIdentity != "" {
		add("user", a.UserIdentity)
	} else {
		add("user", strings.ToLower(a.UserName))
	}
	add("ip", a.SourceIP)
	return out
}

type corrAlertOut struct {
	ID        int64     `json:"id"`
	Rule      string    `json:"rule"`
	Level     string    `json:"level"`
	Hits      int       `json:"hits"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
}

type corrGroup struct {
	Alerts     int            `json:"alerts"`
	Shared     []string       `json:"shared"` // cechy wspólne co najmniej dwóm alertom grupy
	Rules      []string       `json:"rules"`
	Levels     map[string]int `json:"levels"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	List       []corrAlertOut `json:"list"`
	MoreAlerts int            `json:"more_alerts,omitempty"`
}

type corrSpread struct {
	Rule   string  `json:"rule"`
	Hosts  int     `json:"hosts"`
	Alerts []int64 `json:"alerts"`
}

type corrResult struct {
	Analyzed  int          `json:"analyzed_alerts"`
	Truncated bool         `json:"truncated,omitempty"` // więcej alertów niż przejrzano
	Groups    []corrGroup  `json:"groups"`
	Unrelated int          `json:"unrelated_alerts"`
	Common    []string     `json:"common_entities,omitempty"` // cechy zbyt częste, by łączyć (np. serwer centralny)
	Spread    []corrSpread `json:"same_rule_many_hosts,omitempty"`
	Note      string       `json:"note"`
}

// correlate grupuje alerty połączone wspólnymi cechami (spójne składowe).
// Cecha obecna w bardzo wielu alertach (np. kontroler domeny) nie łączy –
// skleiłaby wszystko w jedną grupę; trafia do common_entities.
func correlate(list []corrAlert) corrResult {
	res := corrResult{Analyzed: len(list), Groups: []corrGroup{},
		Note: "Groups are alerts sharing a computer, account (person) or source IP – a pointer for analysis, not proof of one attack. Check timing and the events of each alert."}
	byEnt := map[string][]int{}
	for i, a := range list {
		for _, e := range a.entities() {
			byEnt[e] = append(byEnt[e], i)
		}
	}
	hub := max(10, len(list)*2/5)
	parent := make([]int, len(list))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	for e, idx := range byEnt {
		if len(idx) > hub {
			res.Common = append(res.Common, e+" ("+strconv.Itoa(len(idx))+" alerts)")
			continue
		}
		for _, j := range idx[1:] {
			parent[find(j)] = find(idx[0])
		}
	}
	slices.Sort(res.Common)

	comp := map[int][]int{}
	for i := range list {
		r := find(i)
		comp[r] = append(comp[r], i)
	}
	for _, idx := range comp {
		if len(idx) < 2 {
			res.Unrelated++
			continue
		}
		g := corrGroup{Alerts: len(idx), Levels: map[string]int{}}
		count := map[string]int{}
		rules := map[string]bool{}
		for _, i := range idx {
			a := list[i]
			for _, e := range a.entities() {
				count[e]++
			}
			if !rules[a.RuleTitle] {
				rules[a.RuleTitle] = true
				g.Rules = append(g.Rules, a.RuleTitle)
			}
			g.Levels[a.Level]++
			if g.FirstSeen.IsZero() || a.FirstSeen.Before(g.FirstSeen) {
				g.FirstSeen = a.FirstSeen
			}
			if a.LastSeen.After(g.LastSeen) {
				g.LastSeen = a.LastSeen
			}
		}
		for e, n := range count {
			if n >= 2 && len(byEnt[e]) <= hub {
				g.Shared = append(g.Shared, e+" ("+strconv.Itoa(n)+")")
			}
		}
		slices.Sort(g.Shared)
		slices.SortFunc(idx, func(x, y int) int { return list[x].FirstSeen.Compare(list[y].FirstSeen) })
		for _, i := range idx {
			if len(g.List) == correlateMaxGroup {
				g.MoreAlerts = len(idx) - correlateMaxGroup
				break
			}
			a := list[i]
			user := a.UserIdentity
			if user == "" {
				user = a.UserName
			}
			g.List = append(g.List, corrAlertOut{ID: a.ID, Rule: a.RuleTitle, Level: a.Level, Hits: a.Hits, FirstSeen: a.FirstSeen,
				LastSeen: a.LastSeen, Host: a.HostName, User: user, SourceIP: a.SourceIP})
		}
		res.Groups = append(res.Groups, g)
	}
	// Najpierw grupy z wyższym poziomem i większe.
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
	score := func(g corrGroup) int {
		s := 0
		for l, n := range g.Levels {
			s += rank[l] * rank[l] * n
		}
		return s
	}
	slices.SortFunc(res.Groups, func(a, b corrGroup) int { return score(b) - score(a) })
	if len(res.Groups) > correlateMaxOut {
		res.Groups = res.Groups[:correlateMaxOut]
	}

	// Ta sama reguła na wielu komputerach (np. rozprzestrzenianie, wspólna przyczyna).
	type ruleHosts struct {
		hosts  map[string]bool
		alerts []int64
	}
	byRule := map[string]*ruleHosts{}
	for _, a := range list {
		if a.HostName == "" {
			continue
		}
		rh := byRule[a.RuleTitle]
		if rh == nil {
			rh = &ruleHosts{hosts: map[string]bool{}}
			byRule[a.RuleTitle] = rh
		}
		rh.hosts[a.HostName] = true
		rh.alerts = append(rh.alerts, a.ID)
	}
	for rule, rh := range byRule {
		if len(rh.hosts) >= 3 {
			ids := rh.alerts
			if len(ids) > correlateMaxGroup {
				ids = ids[:correlateMaxGroup]
			}
			res.Spread = append(res.Spread, corrSpread{Rule: rule, Hosts: len(rh.hosts), Alerts: ids})
		}
	}
	slices.SortFunc(res.Spread, func(a, b corrSpread) int { return b.Hosts - a.Hosts })
	return res
}

// correlateAlerts: alerty z API panelu (do correlatePages stron) i korelacja.
func correlateAlerts(ctx context.Context, c Caller, args map[string]any) (any, error) {
	q := query(args, "level", "since")
	status := str(args, "status")
	if status == "" {
		status = "open"
	}
	if status != "all" {
		q.Set("status", status)
	}
	var all []corrAlert
	seen := map[int64]bool{}
	truncated := false
	for page := 0; page < correlatePages; page++ {
		var out struct {
			Alerts []corrAlert `json:"alerts"`
			Total  int         `json:"total"`
		}
		if err := c.Get(ctx, "/api/v1/alerts", q, &out); err != nil {
			return nil, err
		}
		for _, a := range out.Alerts {
			if !seen[a.ID] {
				seen[a.ID] = true
				all = append(all, a)
			}
		}
		if len(out.Alerts) < 100 || len(all) >= out.Total {
			break
		}
		if page == correlatePages-1 {
			truncated = true
			break
		}
		q = cloneValues(q)
		q.Set("before", strconv.FormatInt(out.Alerts[len(out.Alerts)-1].ID, 10))
	}
	res := correlate(all)
	res.Truncated = truncated
	return res, nil
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}
