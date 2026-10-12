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
		{ID: SuccessAfterFailuresID, Title: "Udane logowanie po serii nieudanych (wiele źródeł)", Level: "high", Mode: "system",
			Enabled: true, FileEnabled: true, File: "(wbudowana)", GroupBy: []string{"user.identity"}, SuppressS: 3600,
			Tags: []string{"attack.credential_access", "attack.t1110", "attack.initial_access", "attack.t1078"},
			Description: fmt.Sprintf("Udane logowanie osoby (AD, Entra ID, VPN, router) poprzedzone co najmniej %d nieudanymi "+
				"logowaniami tej osoby w ciągu %s – w dowolnych źródłach. Typowe dla odgadniętego hasła: seria prób na VPN "+
				"albo w chmurze, a potem udane wejście.", failuresNeeded, fmtWindow(failureWindow)),
			Source: src + fmt.Sprintf("# Nieudane: %s\n# Udane: %s\n", oneLine(authFailureSQL), oneLine(authSuccessSQL)),
			Instructions: "Ustal z osobą, czy to ona się logowała (telefon, nie e-mail). Porównaj adresy prób i udanego " +
				"logowania – inny adres albo kraj to prawie na pewno przejęte konto: zablokuj logowanie, unieważnij sesje " +
				"(Entra: revoke sessions), zmień hasło i sprawdź MFA oraz reguły skrzynki pocztowej."},
		{ID: NewCountryID, Title: "Logowanie z nowego kraju", Level: "medium", Mode: "system",
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
	Conn  driver.Conn
	Table string // domyślnie siem.events (testy: inna tabela)
}

func (c *Correlator) table() string {
	if c.Table == "" {
		return "siem.events"
	}
	return c.Table
}

// Run ocenia zdarzenia przyjęte w (from, to] i zwraca trafienia.
func (c *Correlator) Run(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	a, err := c.successAfterFailures(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("udane po nieudanych: %w", err)
	}
	b, err := c.newCountry(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("nowy kraj: %w", err)
	}
	return append(a, b...), nil
}

func (c *Correlator) successAfterFailures(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	t := c.table()
	q := fmt.Sprintf(`WITH s AS (
		SELECT event_id, timestamp, user_identity, event_dataset, host_name, user_name, agent_id, %[2]s AS ip
		FROM %[1]s
		WHERE ingested > fromUnixTimestamp64Milli(%[3]d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%[4]d, 'UTC')
			AND user_identity != '' AND %[5]s
		LIMIT 1 BY event_id)
	SELECT s.event_id, any(s.timestamp), s.user_identity, any(s.event_dataset), any(s.host_name), any(s.user_name),
		any(s.agent_id), any(s.ip), count() AS n, arraySort(groupUniqArray(f.event_dataset)), arraySort(groupUniqArray(f.ip)),
		groupArray(50)(f.event_id), groupArray(50)(f.timestamp), groupArray(50)(f.agent_id), groupArray(50)(f.host_name)
	FROM s INNER JOIN (
		SELECT event_id, timestamp, user_identity, event_dataset, %[2]s AS ip, agent_id, host_name
		FROM %[1]s
		WHERE timestamp >= (SELECT min(timestamp) FROM s) - INTERVAL %[7]d SECOND
			AND ingested >= (SELECT min(timestamp) FROM s) - INTERVAL %[7]d SECOND - INTERVAL 1 HOUR
			AND user_identity IN (SELECT user_identity FROM s) AND %[6]s
		LIMIT 1 BY event_id) AS f ON f.user_identity = s.user_identity
	WHERE f.timestamp >= s.timestamp - INTERVAL %[7]d SECOND AND f.timestamp < s.timestamp
	GROUP BY s.event_id, s.user_identity
	HAVING n >= %[8]d`, t, detect.IPExpr, from.UnixMilli(), to.UnixMilli(), authSuccessSQL, authFailureSQL,
		int(failureWindow/time.Second), failuresNeeded)
	rows, err := c.Conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rule := CorrelationRules()[0]
	var hits []alerts.Hit
	for rows.Next() {
		var (
			id, identity, ds, host, user, agent, ip string
			ts                                      time.Time
			n                                       uint64
			fds, fips, fids, fagents, fhosts        []string
			fts                                     []time.Time
		)
		if err := rows.Scan(&id, &ts, &identity, &ds, &host, &user, &agent, &ip, &n, &fds, &fips, &fids, &fts, &fagents, &fhosts); err != nil {
			return nil, err
		}
		summary := fmt.Sprintf("osoba %s: %d nieudanych logowań w %s (%s; adresy %s), potem udane w %s jako %s z %s",
			identity, n, fmtWindow(failureWindow), strings.Join(fds, ", "), short(fips, 5), ds, user, orDash(ip))
		instr := fmt.Sprintf("Osoba %s: %d nieudanych logowań (%s) z adresów %s, a o %s UTC udane logowanie w %s z adresu %s. ",
			identity, n, strings.Join(fds, ", "), short(fips, 5), ts.UTC().Format("2006-01-02 15:04:05"), ds, orDash(ip)) + rule.Instructions
		hit := alerts.Hit{RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level, Engine: "correlation",
			GroupFields: map[string]string{"user.identity": identity}, GroupKey: identity, Suppress: time.Hour,
			EventID: id, EventTime: ts, AgentID: agent, HostName: host, UserName: user, SourceIP: ip,
			Summary: summary, Instructions: instr}
		hits = append(hits, hit)
		// Próby z serii też w alercie (oś zdarzeń, Mímir).
		for i := range fids {
			h := hit
			h.EventID, h.EventTime, h.AgentID, h.HostName = fids[i], fts[i], fagents[i], fhosts[i]
			hits = append(hits, h)
		}
	}
	return hits, rows.Err()
}

func (c *Correlator) newCountry(ctx context.Context, from, to time.Time) ([]alerts.Hit, error) {
	t := c.table()
	ds := make([]string, len(geoDatasets))
	for i, d := range geoDatasets {
		ds[i] = detect.Quote(d)
	}
	geo := "event_dataset IN (" + strings.Join(ds, ", ") + ")"
	q := fmt.Sprintf(`WITH s AS (
		SELECT event_id, timestamp, user_identity, fields['source.geo.country_iso_code'] AS country, fields['source.geo.city_name'] AS city,
			event_dataset, host_name, user_name, agent_id, %[2]s AS ip
		FROM %[1]s
		WHERE ingested > fromUnixTimestamp64Milli(%[3]d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%[4]d, 'UTC')
			AND %[5]s AND user_identity != '' AND event_outcome = 'success' AND country != ''
		LIMIT 1 BY event_id)
	SELECT s.event_id, any(s.timestamp), s.user_identity, any(s.country), any(s.city), any(s.event_dataset), any(s.host_name),
		any(s.user_name), any(s.agent_id), any(s.ip), count() AS prior, countIf(h.country = s.country) AS same,
		arraySort(groupUniqArray(10)(h.country))
	FROM s INNER JOIN (
		SELECT user_identity, timestamp, fields['source.geo.country_iso_code'] AS country
		FROM %[1]s
		WHERE %[5]s AND timestamp >= (SELECT min(timestamp) FROM s) - INTERVAL %[6]d SECOND
			AND ingested >= (SELECT min(timestamp) FROM s) - INTERVAL %[6]d SECOND - INTERVAL 1 DAY
			AND user_identity IN (SELECT user_identity FROM s) AND event_outcome = 'success' AND country != '') AS h
		ON h.user_identity = s.user_identity
	WHERE h.timestamp < s.timestamp AND h.timestamp >= s.timestamp - INTERVAL %[6]d SECOND
	GROUP BY s.event_id, s.user_identity
	HAVING prior > 0 AND same = 0`, t, detect.IPExpr, from.UnixMilli(), to.UnixMilli(), geo, int(historyWindow/time.Second))
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
