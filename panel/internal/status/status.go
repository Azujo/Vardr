// SPDX-License-Identifier: AGPL-3.0-or-later

// Package status to „Stan systemu” w panelu: zdrowie usług Vardra
// z metryk Prometheusa (te same progi co alerty Grafany), czytelne dla
// administratora bez otwierania Grafany.
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// Stany kontroli (od najlepszego).
const (
	OK       = "ok"
	Warn     = "warn"
	Crit     = "crit"
	Unknown  = "unknown"
	Disabled = "off" // element wyłączony w konfiguracji (np. silnik zapytań)
)

var rank = map[string]int{OK: 0, Disabled: 0, Unknown: 1, Warn: 2, Crit: 3}

// Check to wynik jednej kontroli.
type Check struct {
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Value  string `json:"value"`
	Hint   string `json:"hint,omitempty"` // co zrobić, gdy nie OK
	// Identyfikatory dla panelu: kontrola, grupa i wartość jako kod
	// z parametrami – panel pokazuje je w języku użytkownika, a polskie
	// Name/Value/Hint są zapasowe.
	ID       string         `json:"id"`
	GroupID  string         `json:"group_id"`
	ValueKey string         `json:"value_key"`
	Args     map[string]any `json:"args,omitempty"`
}

// Report to stan całego systemu.
type Report struct {
	Overall     string    `json:"overall"`
	Checks      []Check   `json:"checks"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Prometheus czyta metryki przez HTTP API.
type Prometheus struct {
	URL    string // np. http://prometheus:9090
	Client *http.Client
}

type sample struct {
	labels map[string]string
	value  float64
}

func (p *Prometheus) query(ctx context.Context, q string) ([]sample, error) {
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+"/api/v1/query?query="+url.QueryEscape(q), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var r struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("Prometheus: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("Prometheus: %s", r.Error)
	}
	out := make([]sample, 0, len(r.Data.Result))
	for _, x := range r.Data.Result {
		s, _ := x.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, sample{labels: x.Metric, value: v})
	}
	return out, nil
}

// one: pierwsza wartość albo ok=false (brak danych).
func one(s []sample) (float64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	return s[0].value, true
}

// value: wynik kontroli – kod dla panelu z parametrami i tekst po polsku.
type value struct {
	key  string
	args map[string]any
	text string
}

func val(key, text string) value { return value{key: key, text: text} }

func num(key string, n float64, text string) value {
	return value{key: key, args: map[string]any{"n": n}, text: text}
}

var noData = val("no_data", "brak danych")

func ago(sec float64) value {
	d := time.Duration(sec * float64(time.Second))
	var text string
	switch {
	case d < time.Minute:
		text = fmt.Sprintf("%.0f s temu", sec)
	case d < time.Hour:
		text = fmt.Sprintf("%d min temu", int(d.Minutes()))
	case d < 48*time.Hour:
		text = fmt.Sprintf("%.1f h temu", d.Hours())
	default:
		text = fmt.Sprintf("%d dni temu", int(d.Hours()/24))
	}
	return num("ago", math.Round(sec), text)
}

func pct(v float64) value { return num("pct", math.Round(v*100), fmt.Sprintf("%.0f%%", v*100)) }

// def to definicja kontroli: zapytanie i ocena wyniku.
type def struct {
	id, group, name, query, hint string
	eval                         func(s []sample) (status string, v value)
}

// thresholdHigh: wartość powyżej warn/crit jest zła.
func thresholdHigh(warn, crit float64, format func(float64) value) func([]sample) (string, value) {
	return func(s []sample) (string, value) {
		v, ok := one(s)
		if !ok {
			return Unknown, noData
		}
		st := OK
		if v > warn {
			st = Warn
		}
		if v > crit {
			st = Crit
		}
		return st, format(v)
	}
}

// thresholdLow: wartość poniżej warn/crit jest zła.
func thresholdLow(warn, crit float64, format func(float64) value) func([]sample) (string, value) {
	return func(s []sample) (string, value) {
		v, ok := one(s)
		if !ok {
			return Unknown, noData
		}
		st := OK
		if v < warn {
			st = Warn
		}
		if v < crit {
			st = Crit
		}
		return st, format(v)
	}
}

func count(v float64) value { return num("count", math.Round(v), fmt.Sprintf("%.0f", v)) }

func up(service, name, hint string) def {
	return def{id: "up." + service, group: "Usługi", name: name, query: fmt.Sprintf(`max(up{service=%q})`, service), hint: hint,
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			switch {
			case !ok:
				return Crit, val("service_missing", "nie widać usługi")
			case v < 1:
				return Crit, val("not_responding", "nie odpowiada")
			}
			return OK, val("running", "działa")
		}}
}

var defs = []def{
	up("ingest", "Przyjmowanie zdarzeń (siem-ingest)", "Agenci buforują zdarzenia u siebie; sprawdź `docker compose logs ingest`."),
	up("normalizer", "Normalizator", "Paczki czekają w kolejce SIEM_RAW; sprawdź logi normalizatora."),
	up("writer", "Zapis do ClickHouse (siem-writer)", "Zdarzenia czekają w kolejce SIEM_EVENTS; sprawdź logi writera i ClickHouse."),
	up("archiver", "Archiwum NIS2 (siem-archiver)", "Paczki czekają w kolejce; po jej zapełnieniu serwer przestanie przyjmować zdarzenia."),
	up("detector", "Detekcja (siem-detector)", "Reguły nie są wykonywane – ataki nie wywołają alertów; sprawdź logi detektora."),
	up("clickhouse", "ClickHouse", "Wyszukiwarka i silnik zapytań nie działają; writer ponawia zapis."),
	{id: "pipeline.events", group: "Potok", name: "Zdarzenia przyjmowane (5 min)", query: `sum(rate(siem_ingest_events_total[5m]))`,
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			if !ok {
				return Unknown, noData
			}
			return OK, num("eps", math.Round(v*10)/10, fmt.Sprintf("%.1f zdarzeń/s", v))
		}},
	{id: "pipeline.throttled", group: "Potok", name: "Odmowy przyjęcia (kolejka pełna)", query: `sum(rate(siem_ingest_batches_total{result="throttled_queue_full"}[5m])) or vector(0)`,
		hint: "Kolejka jest pełna – któryś etap nie nadąża. Sprawdź zapełnienie kolejek poniżej.",
		eval: thresholdHigh(0, 0, func(v float64) value {
			if v == 0 {
				return val("none", "brak")
			}
			return num("batches_per_s", math.Round(v*100)/100, fmt.Sprintf("%.2f paczek/s", v))
		})},
	{id: "pipeline.queue", group: "Potok", name: "Najbardziej zapełniona kolejka", query: `topk(1, siem_queue_fill_ratio)`,
		hint: "Odbiorca kolejki nie nadąża (wskazany w nawiasie). Powyżej 80% ingest zaczyna odmawiać przyjęcia.",
		eval: func(s []sample) (string, value) {
			if len(s) == 0 {
				return Unknown, noData
			}
			v := s[0].value
			st := OK
			if v > 0.5 {
				st = Warn
			}
			if v > 0.8 {
				st = Crit
			}
			c := s[0].labels["consumer"]
			return st, value{key: "queue", args: map[string]any{"n": math.Round(v * 100), "consumer": c},
				text: fmt.Sprintf("%s (%s)", pct(v).text, c)}
		}},
	{id: "pipeline.write_errors", group: "Potok", name: "Błędy zapisu do ClickHouse (15 min)", query: `sum(increase(siem_writer_insert_errors_total[15m])) or vector(0)`,
		hint: "Writer ponawia zapis; sprawdź logi writera i stan ClickHouse.",
		eval: thresholdHigh(0, 50, count)},
	{id: "pipeline.quarantine", group: "Potok", name: "Kwarantanna (ostatnia godzina)", query: `sum(increase(siem_normalizer_quarantined_total[1h])) + sum(increase(siem_writer_quarantined_total[1h]))`,
		hint: "Zdarzenia, których nie udało się znormalizować albo zapisać – są w siem.quarantine.",
		eval: thresholdHigh(0, 1000, func(v float64) value { return num("events", math.Round(v), fmt.Sprintf("%.0f zdarzeń", v)) })},
	{id: "pipeline.unreadable", group: "Potok", name: "Nieczytelne paczki (24 h)", query: `sum(increase(siem_normalizer_batches_total{result="poison"}[24h])) or vector(0)`,
		hint: "Paczki, których normalizator nie odczytał (uszkodzony gzip albo JSON) – ich zdarzeń nie ma w wyszukiwaniu, oryginał jest w archiwum NIS2. Szczegóły w logach normalizatora (unreadable batch).",
		eval: thresholdHigh(0, 10, count)},
	{id: "detection.rules", group: "Detekcja", name: "Włączone reguły", query: `max(siem_detector_rules) > 0 or max(siem_detector_index_rules)`,
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			if !ok {
				return Unknown, noData
			}
			if v == 0 {
				return Warn, num("rules", 0, "0 reguł")
			}
			return OK, num("rules", math.Round(v), fmt.Sprintf("%.0f reguł", v))
		}, hint: "Detektor nie ma włączonych reguł – sprawdź katalog reguł i panel."},
	{id: "detection.rule_errors", group: "Detekcja", name: "Reguły z błędami", query: `max(siem_detector_rule_errors) + (max(siem_detector_index_rule_errors) or vector(0))`,
		hint: "Część reguł nie działa – szczegóły w panelu (Reguły detekcji) i w logach detektora.",
		eval: thresholdHigh(0, 0, count)},
	{id: "detection.index_lag", group: "Detekcja", name: "Silnik zapytań – zaległość", query: `max(siem_detector_index_lag_seconds)`,
		hint: "Punkt kontrolny silnika zapytań stoi – sprawdź logi detektora i obciążenie ClickHouse.",
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			if !ok {
				return Disabled, val("stream_only", "wyłączony (SIEM_DETECTION_MODE=stream)")
			}
			st := OK
			if v > 900 {
				st = Warn
			}
			if v > 3600 {
				st = Crit
			}
			return st, num("lag", math.Round(v), fmt.Sprintf("%.0f s (w tym opóźnienie 2 min)", v))
		}},
	{id: "archive.integrity", group: "Archiwum NIS2", name: "Weryfikacja integralności", query: `min(siem_archive_verify_ok)`,
		hint: "Dane w archiwum zmieniono, usunięto albo dodano poza archiwizatorem – szczegóły: panel → Urd.",
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			switch {
			case !ok:
				return Unknown, noData
			case v < 1:
				return Crit, val("integrity_problems", "wykryto niezgodności")
			}
			return OK, val("compliant", "zgodne")
		}},
	{id: "archive.last_verify", group: "Archiwum NIS2", name: "Ostatnia weryfikacja", query: `time() - max(siem_archive_last_verify_timestamp_seconds)`,
		hint: "Weryfikacja powinna przechodzić co 6 h – sprawdź logi archiwizatora.",
		eval: thresholdHigh(13*3600, 26*3600, ago)},
	{id: "archive.enabled", group: "Archiwum NIS2", name: "Archiwizacja", query: `min(siem_archive_policy_enabled) * (1 - max(siem_archive_paused))`,
		hint: "Archiwizacja wyłączona w polityce albo wstrzymana z braku miejsca – panel → Urd.",
		eval: func(s []sample) (string, value) {
			v, ok := one(s)
			switch {
			case !ok:
				return Unknown, noData
			case v < 1:
				return Crit, val("disabled_or_paused", "wyłączona albo wstrzymana")
			}
			return OK, val("enabled", "włączona")
		}},
	{id: "archive.disk_free", group: "Archiwum NIS2", name: "Wolne miejsce na dysku archiwum", query: `min(siem_archive_disk_free_bytes / siem_archive_disk_total_bytes)`,
		hint: "Po zapełnieniu archiwizacja się wstrzyma – powiększ dysk albo skróć retencję.",
		eval: thresholdLow(0.15, 0.05, pct)},
	{id: "backup.last", group: "Kopie zapasowe", name: "Ostatnia kopia", query: `time() - max(vardr_backup_last_success_timestamp_seconds or heimdall_backup_last_success_timestamp_seconds)`,
		hint: "Kopia powinna powstawać co noc (cron 02:15, backup.sh) – sprawdź ~/siem-lab/backup.log.",
		eval: thresholdHigh(26*3600, 50*3600, ago)},
	{id: "backup.remote", group: "Kopie zapasowe", name: "Ostatnia kopia poza VM (NAS)", query: `time() - max(vardr_backup_remote_last_success_timestamp_seconds or heimdall_backup_remote_last_success_timestamp_seconds)`,
		hint: "Kopia nie trafia poza VM – sprawdź połączenie z NAS i klucz SSH kopii.",
		eval: thresholdHigh(26*3600, 50*3600, ago)},
	{id: "server.disk_free", group: "Serwer", name: "Wolne miejsce na dysku systemowym", query: `min(node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})`,
		hint: "Brak miejsca zatrzyma ClickHouse i kolejki – usuń stare dane albo powiększ dysk.",
		eval: thresholdLow(0.15, 0.05, pct)},
	{id: "server.cpu", group: "Serwer", name: "Obciążenie CPU (5 min)", query: `1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))`,
		hint: "Długotrwale wysokie obciążenie – potok może nie nadążać przy szczycie zdarzeń.",
		eval: thresholdHigh(0.85, 0.95, pct)},
	{id: "server.memory", group: "Serwer", name: "Wolna pamięć", query: `min(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)`,
		hint: "Mało pamięci – ryzyko zabicia usług przez system (OOM).",
		eval: thresholdLow(0.10, 0.05, pct)},
}

// Report odpytuje Prometheusa i ocenia wszystkie kontrole.
func (p *Prometheus) Report(ctx context.Context, now time.Time) Report {
	rep := Report{Overall: OK, GeneratedAt: now}
	if _, err := p.query(ctx, "vector(1)"); err != nil {
		rep.Overall = Crit
		rep.Checks = []Check{{Group: "Monitorowanie", Name: "Prometheus", Status: Crit, Value: "niedostępny",
			Hint: "Panel nie ma skąd wziąć stanu usług – sprawdź kontener prometheus (" + err.Error() + ").",
			ID:   "monitoring.prometheus", GroupID: "monitoring", ValueKey: "unavailable", Args: map[string]any{"error": err.Error()}}}
		return rep
	}
	for _, d := range defs {
		c := Check{Group: d.group, Name: d.name, ID: d.id, GroupID: groupIDs[d.group]}
		v := val("query_error", "błąd zapytania")
		s, err := p.query(ctx, d.query)
		if err != nil {
			c.Status = Unknown
		} else {
			c.Status, v = d.eval(s)
		}
		c.Value, c.ValueKey, c.Args = v.text, v.key, v.args
		if c.Status != OK && c.Status != Disabled {
			c.Hint = d.hint
		}
		if rank[c.Status] > rank[rep.Overall] {
			rep.Overall = c.Status
		}
		rep.Checks = append(rep.Checks, c)
	}
	sort.SliceStable(rep.Checks, func(i, j int) bool { return groupOrder(rep.Checks[i].Group) < groupOrder(rep.Checks[j].Group) })
	return rep
}

var groups = []string{"Usługi", "Potok", "Detekcja", "Archiwum NIS2", "Kopie zapasowe", "Serwer"}

// groupIDs: identyfikatory grup dla panelu (nazwy w tłumaczeniach).
var groupIDs = map[string]string{"Usługi": "services", "Potok": "pipeline", "Detekcja": "detection",
	"Archiwum NIS2": "archive", "Kopie zapasowe": "backup", "Serwer": "server"}

func groupOrder(g string) int {
	for i, x := range groups {
		if x == g {
			return i
		}
	}
	return math.MaxInt
}
