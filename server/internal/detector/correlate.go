package detector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"siem/internal/alerts"
	"siem/internal/detect"
)

// Korelacje międzyźródłowe (etap 7d) – reguły wbudowane, oceniane co minutę
// zapytaniami do ClickHouse po osobie (user.identity), niezależnie od źródła
// (AD, Entra ID, VPN FortiGate, router MikroTik). Sigma z progami nie wyraża
// sekwencji („udane po nieudanych”) ani porównania z historią („nowy kraj”).
// Alert dotyczy zdarzenia zamykającego sekwencję – para (reguła, zdarzenie)
// jest w alercie najwyżej raz, więc zakładka okien i restart nie dublują.
const (
	SuccessAfterFailuresID = "heimdall-success-after-failures"
	NewCountryID           = "heimdall-signin-new-country"
)

// Logowania nieudane i udane we wszystkich źródłach (SQL na siem.events).
// Korelacje czytają tabelę logowań, którą zasila widok zmaterializowany
// z tymi samymi warunkami (clickhouse/init/03-auth-events.sh); tu – opis
// reguły w panelu i test zgodności warunków.
const (
	authFailureSQL = `((event_dataset = 'windows.security' AND event_code IN (4625, 4771))
		OR (event_dataset = 'azure.signinlogs' AND event_outcome = 'failure')
		OR (event_dataset = 'fortinet.fortigate' AND (event_action = 'ssl-login-fail' OR (event_action = 'login' AND event_outcome = 'failure')))
		OR (event_dataset = 'mikrotik.routeros' AND event_action = 'login' AND event_outcome = 'failure'))`
	authSuccessSQL = `((event_dataset = 'windows.security' AND event_code = 4624)
		OR (event_dataset = 'azure.signinlogs' AND event_outcome = 'success')
		OR (event_dataset = 'fortinet.fortigate' AND (event_action IN ('ssl-login', 'tunnel-up') OR (event_action = 'login' AND event_outcome = 'success')))
		OR (event_dataset = 'mikrotik.routeros' AND event_action = 'login' AND event_outcome = 'success'))`
)

// geoDatasets: zbiory z krajem logowania (source.geo.country_iso_code).
// VPN i inne – po dodaniu lokalnej bazy GeoIP.
var geoDatasets = []string{"azure.signinlogs"}

// Parametry korelacji.
const (
	failuresNeeded = 5
	failureWindow  = 30 * time.Minute
	historyWindow  = 30 * 24 * time.Hour
)

// CorrelationRules opisuje korelacje dla panelu.
func CorrelationRules() []alerts.RuleInfo {
	src := "# Reguła wbudowana w siem-detector (server/internal/detector/correlate.go),\n" +
		"# oceniana co minutę w ClickHouse po osobie (user.identity) we wszystkich źródłach.\n"
	return []alerts.RuleInfo{
		{ID: SuccessAfterFailuresID, Title: "Udane logowanie po serii nieudanych (wiele źródeł)", Level: "high", Mode: "correlation",
			Enabled: true, FileEnabled: true, File: "(wbudowana)", GroupBy: []string{"user.identity"}, SuppressS: 3600,
			Tags: []string{"attack.credential_access", "attack.t1110", "attack.initial_access", "attack.t1078"},
			Description: fmt.Sprintf("Udane logowanie osoby (AD, Entra ID, VPN, router) poprzedzone co najmniej %d nieudanymi "+
				"logowaniami tej osoby w ciągu %s – w dowolnych źródłach. Typowe dla odgadniętego hasła: seria prób na VPN "+
				"albo w chmurze, a potem udane wejście.", failuresNeeded, fmtWindow(failureWindow)),
			Source: src + fmt.Sprintf("# Nieudane: %s\n# Udane: %s\n", oneLine(authFailureSQL), oneLine(authSuccessSQL)),
			Instructions: "Ustal z osobą, czy to ona się logowała (telefon, nie e-mail). Porównaj adresy prób i udanego " +
				"logowania – inny adres albo kraj to prawie na pewno przejęte konto: zablokuj logowanie, unieważnij sesje " +
				"(Entra: revoke sessions), zmień hasło i sprawdź MFA oraz reguły skrzynki pocztowej."},
		{ID: NewCountryID, Title: "Logowanie z nowego kraju", Level: "medium", Mode: "correlation",
			Enabled: true, FileEnabled: true, File: "(wbudowana)", GroupBy: []string{"user.identity", "source.geo.country_iso_code"},
			SuppressS: 86400, Tags: []string{"attack.initial_access", "attack.t1078.004"},
			Description: fmt.Sprintf("Udane logowanie osoby z kraju, z którego w ostatnich %d dniach się nie logowała "+
				"(osoby bez historii – pomijane). Kraj z lokalizacji Microsoftu (Entra ID).", int(historyWindow.Hours()/24)),
			Source: src + "# Zbiory z krajem: " + strings.Join(geoDatasets, ", ") + "\n",
			Instructions: "Sprawdź z osobą, czy była w tym kraju (podróż, VPN prywatny). Jeśli nie – traktuj jak przejęte " +
				"konto: unieważnij sesje, zmień hasło, sprawdź metody MFA dodane ostatnio i aktywność po logowaniu."},
	}
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// Correlator ocenia korelacje na zdarzeniach w ClickHouse.
type Correlator struct {
	Conn driver.Conn
	// Table: tabela logowań zasilana przy zapisie zdarzeń (etap 8,
	// clickhouse/init/03-auth-events.sh) – domyślnie siem.auth_events.
	Table string
	// Disabled (opcjonalne): korelacja wyłączona w panelu.
	Disabled func(id string) bool
}

func (c *Correlator) off(id string) bool { return c.Disabled != nil && c.Disabled(id) }

// CorrelationInfos: opisy korelacji z ustawieniem z panelu (wyłączenie).
func CorrelationInfos(ov map[string]alerts.Override) ([]alerts.RuleInfo, map[string]bool) {
	infos := CorrelationRules()
	disabled := map[string]bool{}
	for i := range infos {
		if o, ok := ov[infos[i].ID]; ok {
			infos[i].Enabled = o.Enabled
			disabled[infos[i].ID] = !o.Enabled
		}
	}
	return infos, disabled
}

func (c *Correlator) table() string {
	if c.Table == "" {
		return "siem.auth_events"
	}
	return c.Table
}

// Run ocenia zdarzenia przyjęte w (from, to] i zwraca trafienia.
func (c *Correlator) Run(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	var hits []alerts.Hit
	if !c.off(SuccessAfterFailuresID) {
		a, err := c.successAfterFailures(ctx, from, to)
		if err != nil {
			return nil, fmt.Errorf("udane po nieudanych: %w", err)
		}
		hits = a
	}
	if !c.off(NewCountryID) {
		b, err := c.newCountry(ctx, from, to)
		if err != nil {
			return nil, fmt.Errorf("nowy kraj: %w", err)
		}
		hits = append(hits, b...)
	}
	return hits, nil
}

// successAfterFailures: udane logowanie poprzedzone co najmniej failuresNeeded
// nieudanymi logowaniami tej osoby w ciągu failureWindow.
//
// Skala (etap 8): złączenie każdego udanego logowania z każdą nieudaną próbą
// osoby przekraczało limit pamięci ClickHouse przy setkach nieudanych
// logowań na sekundę. Dlatego udane logowania są zwijane do ostatniego
// w minucie (osoba, minuta), a nieudane – liczone w minutowych kubełkach;
// kubełki na brzegach okna liczą się dokładnie z czasów prób (do 1000 prób
// na osobę i minutę). Próby do osi czasu alertu pobiera osobne, małe
// zapytanie tylko dla trafień.
func (c *Correlator) successAfterFailures(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	t := c.table()
	win := int(failureWindow / time.Second)
	q := fmt.Sprintf(`WITH s AS (
		SELECT user_identity, toStartOfMinute(timestamp) AS m, max(timestamp) AS ts, argMax(event_id, timestamp) AS id,
			argMax(event_dataset, timestamp) AS ds, argMax(host_name, timestamp) AS host, argMax(user_name, timestamp) AS user,
			argMax(agent_id, timestamp) AS agent, argMax(ip, timestamp) AS ip
		FROM %[1]s
		WHERE outcome = 'success' AND ingested > fromUnixTimestamp64Milli(%[2]d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%[3]d, 'UTC')
		GROUP BY user_identity, m),
	f AS (
		SELECT user_identity, toStartOfMinute(timestamp) AS m, uniq(event_id) AS n, groupUniqArray(1000)((event_id, timestamp)) AS times,
			groupUniqArray(event_dataset) AS fds, groupUniqArray(20)(ip) AS fips
		FROM %[1]s
		WHERE outcome = 'failure' AND timestamp >= (SELECT min(ts) FROM s) - INTERVAL %[4]d SECOND
			AND ingested >= (SELECT min(ts) FROM s) - INTERVAL %[4]d SECOND - INTERVAL 1 HOUR
			AND timestamp <= (SELECT max(ts) FROM s)
			AND user_identity IN (SELECT user_identity FROM s)
		GROUP BY user_identity, m)
	SELECT s.id, s.ts, s.user_identity, s.ds, s.host, s.user, s.agent, s.ip,
		sum(if(f.m > toStartOfMinute(s.ts - INTERVAL %[4]d SECOND) AND f.m < s.m, f.n,
			arrayCount(x -> x.2 >= s.ts - INTERVAL %[4]d SECOND AND x.2 < s.ts, f.times))) AS n,
		arraySort(arrayDistinct(arrayFlatten(groupArray(f.fds)))), arraySort(arrayDistinct(arrayFlatten(groupArray(f.fips))))
	FROM s INNER JOIN f ON f.user_identity = s.user_identity
	WHERE f.m >= toStartOfMinute(s.ts - INTERVAL %[4]d SECOND) AND f.m <= s.m
	GROUP BY s.id, s.ts, s.user_identity, s.ds, s.host, s.user, s.agent, s.ip
	HAVING n >= %[5]d`, t, from.UnixMilli(), to.UnixMilli(), win, failuresNeeded)
	rows, err := c.Conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rule := CorrelationRules()[0]
	var hits []alerts.Hit
	first := map[string]time.Time{} // osoba → najwcześniejsze udane logowanie z trafieniem
	for rows.Next() {
		var (
			id, identity, ds, host, user, agent, ip string
			ts                                      time.Time
			n                                       uint64
			fds, fips                               []string
		)
		if err := rows.Scan(&id, &ts, &identity, &ds, &host, &user, &agent, &ip, &n, &fds, &fips); err != nil {
			return nil, err
		}
		summary := fmt.Sprintf("osoba %s: %d nieudanych logowań w %s (%s; adresy %s), potem udane w %s jako %s z %s",
			identity, n, fmtWindow(failureWindow), strings.Join(fds, ", "), short(fips, 5), ds, user, orDash(ip))
		instr := fmt.Sprintf("Osoba %s: %d nieudanych logowań (%s) z adresów %s, a o %s UTC udane logowanie w %s z adresu %s. ",
			identity, n, strings.Join(fds, ", "), short(fips, 5), ts.UTC().Format("2006-01-02 15:04:05"), ds, orDash(ip)) + rule.Instructions
		hits = append(hits, alerts.Hit{RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level, Engine: "correlation",
			GroupFields: map[string]string{"user.identity": identity}, GroupKey: identity, Suppress: time.Hour,
			EventID: id, EventTime: ts, AgentID: agent, HostName: host, UserName: user, SourceIP: ip,
			Summary: summary, Instructions: instr})
		if f, ok := first[identity]; !ok || ts.Before(f) {
			first[identity] = ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return c.withAttempts(ctx, hits, first)
}

// withAttempts dokłada do alertów próby z serii (oś zdarzeń, Mímir): do 50
// ostatnich nieudanych logowań osoby przed jej udanym logowaniem.
func (c *Correlator) withAttempts(ctx context.Context, hits []alerts.Hit, first map[string]time.Time) ([]alerts.Hit, error) {
	if len(hits) == 0 {
		return hits, nil
	}
	ids := make([]string, 0, len(first))
	var lo, hi time.Time
	for id, ts := range first {
		ids = append(ids, id)
		if lo.IsZero() || ts.Before(lo) {
			lo = ts
		}
	}
	for _, h := range hits {
		if h.EventTime.After(hi) {
			hi = h.EventTime
		}
	}
	sort.Strings(ids)
	t := c.table()
	q := fmt.Sprintf(`SELECT user_identity, event_id, any(timestamp) AS ts, any(agent_id), any(host_name)
		FROM %[1]s
		WHERE outcome = 'failure' AND timestamp >= fromUnixTimestamp64Milli(%[2]d, 'UTC') - INTERVAL %[4]d SECOND
			AND timestamp < fromUnixTimestamp64Milli(%[3]d, 'UTC')
			AND ingested >= fromUnixTimestamp64Milli(%[2]d, 'UTC') - INTERVAL %[4]d SECOND - INTERVAL 1 HOUR
			AND user_identity IN ?
		GROUP BY user_identity, event_id
		ORDER BY ts DESC
		LIMIT 200 BY user_identity`, t, lo.UnixMilli(), hi.UnixMilli(), int(failureWindow/time.Second))
	rows, err := c.Conn.Query(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type attempt struct {
		id, agent, host string
		ts              time.Time
	}
	byIdentity := map[string][]attempt{}
	for rows.Next() {
		var identity string
		var a attempt
		if err := rows.Scan(&identity, &a.id, &a.ts, &a.agent, &a.host); err != nil {
			return nil, err
		}
		byIdentity[identity] = append(byIdentity[identity], a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := hits
	for _, h := range hits {
		n := 0
		for _, a := range byIdentity[h.GroupKey] { // od najnowszych
			if n == 50 || !a.ts.Before(h.EventTime) || a.ts.Before(h.EventTime.Add(-failureWindow)) {
				continue
			}
			x := h
			x.EventID, x.EventTime, x.AgentID, x.HostName = a.id, a.ts, a.agent, a.host
			out = append(out, x)
			n++
		}
	}
	return out, nil
}

func (c *Correlator) newCountry(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	t := c.table()
	ds := make([]string, len(geoDatasets))
	for i, d := range geoDatasets {
		ds[i] = detect.Quote(d)
	}
	geo := "event_dataset IN (" + strings.Join(ds, ", ") + ")"
	q := fmt.Sprintf(`WITH s AS (
		SELECT event_id, timestamp, user_identity, country, city, event_dataset, host_name, user_name, agent_id, ip
		FROM %[1]s
		WHERE outcome = 'success' AND %[4]s AND ingested > fromUnixTimestamp64Milli(%[2]d, 'UTC')
			AND ingested <= fromUnixTimestamp64Milli(%[3]d, 'UTC') AND country != ''
		LIMIT 1 BY event_id)
	SELECT s.event_id, any(s.timestamp), s.user_identity, any(s.country), any(s.city), any(s.event_dataset), any(s.host_name),
		any(s.user_name), any(s.agent_id), any(s.ip), count() AS prior, countIf(h.country = s.country) AS same,
		arraySort(groupUniqArray(10)(h.country))
	FROM s INNER JOIN (
		SELECT user_identity, timestamp, country
		FROM %[1]s
		WHERE outcome = 'success' AND %[4]s AND timestamp >= (SELECT min(timestamp) FROM s) - INTERVAL %[5]d SECOND
			AND ingested >= (SELECT min(timestamp) FROM s) - INTERVAL %[5]d SECOND - INTERVAL 1 DAY
			AND user_identity IN (SELECT user_identity FROM s) AND country != '') AS h
		ON h.user_identity = s.user_identity
	WHERE h.timestamp < s.timestamp AND h.timestamp >= s.timestamp - INTERVAL %[5]d SECOND
	GROUP BY s.event_id, s.user_identity
	HAVING prior > 0 AND same = 0`, t, from.UnixMilli(), to.UnixMilli(), geo, int(historyWindow/time.Second))
	rows, err := c.Conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rule := CorrelationRules()[1]
	var hits []alerts.Hit
	for rows.Next() {
		var (
			id, identity, country, city, ds, host, user, agent, ip string
			ts                                                     time.Time
			prior, same                                            uint64
			known                                                  []string
		)
		if err := rows.Scan(&id, &ts, &identity, &country, &city, &ds, &host, &user, &agent, &ip, &prior, &same, &known); err != nil {
			return nil, err
		}
		where := country
		if city != "" {
			where = country + " (" + city + ")"
		}
		hits = append(hits, alerts.Hit{RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level, Engine: "correlation",
			GroupFields: map[string]string{"user.identity": identity, "source.geo.country_iso_code": country},
			GroupKey:    identity + "\x1f" + country, Suppress: 24 * time.Hour,
			EventID: id, EventTime: ts, AgentID: agent, HostName: host, UserName: user, SourceIP: ip,
			Summary: fmt.Sprintf("osoba %s: udane logowanie z %s, adres %s; wcześniej tylko z: %s", identity, where, orDash(ip),
				strings.Join(known, ", ")),
			Instructions: fmt.Sprintf("Osoba %s zalogowała się (%s, konto %s) z %s, adres %s – w ostatnich %d dniach logowała się tylko z: %s. ",
				identity, ds, user, where, orDash(ip), int(historyWindow.Hours()/24), strings.Join(known, ", ")) + rule.Instructions})
	}
	return hits, rows.Err()
}

func short(l []string, n int) string {
	sort.Strings(l)
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" i %d innych", len(l)-n)
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}
