// Package status to „Stan systemu” w panelu: zdrowie usług Heimdalla
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

func ago(sec float64) string {
	d := time.Duration(sec * float64(time.Second))
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0f s temu", sec)
	case d < time.Hour:
		return fmt.Sprintf("%d min temu", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h temu", d.Hours())
	}
	return fmt.Sprintf("%d dni temu", int(d.Hours()/24))
}

func pct(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }

// def to definicja kontroli: zapytanie i ocena wyniku.
type def struct {
	group, name, query, hint string
	eval                     func(s []sample) (status, value string)
}

// thresholdHigh: wartość powyżej warn/crit jest zła.
func thresholdHigh(warn, crit float64, format func(float64) string) func([]sample) (string, string) {
	return func(s []sample) (string, string) {
		v, ok := one(s)
		if !ok {
			return Unknown, "brak danych"
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
func thresholdLow(warn, crit float64, format func(float64) string) func([]sample) (string, string) {
	return func(s []sample) (string, string) {
		v, ok := one(s)
		if !ok {
			return Unknown, "brak danych"
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

func up(service, name, hint string) def {
	return def{group: "Usługi", name: name, query: fmt.Sprintf(`max(up{service=%q})`, service), hint: hint,
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			switch {
			case !ok:
				return Crit, "nie widać usługi"
			case v < 1:
				return Crit, "nie odpowiada"
			}
			return OK, "działa"
		}}
}

var defs = []def{
	up("ingest", "Przyjmowanie zdarzeń (siem-ingest)", "Agenci buforują zdarzenia u siebie; sprawdź `docker compose logs ingest`."),
	up("normalizer", "Normalizator", "Paczki czekają w kolejce SIEM_RAW; sprawdź logi normalizatora."),
	up("writer", "Zapis do ClickHouse (siem-writer)", "Zdarzenia czekają w kolejce SIEM_EVENTS; sprawdź logi writera i ClickHouse."),
	up("archiver", "Archiwum NIS2 (siem-archiver)", "Paczki czekają w kolejce; po jej zapełnieniu serwer przestanie przyjmować zdarzenia."),
	up("detector", "Detekcja (siem-detector)", "Reguły nie są wykonywane – ataki nie wywołają alertów; sprawdź logi detektora."),
	up("clickhouse", "ClickHouse", "Wyszukiwarka i silnik zapytań nie działają; writer ponawia zapis."),
	{group: "Potok", name: "Zdarzenia przyjmowane (5 min)", query: `sum(rate(siem_ingest_events_total[5m]))`,
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			if !ok {
				return Unknown, "brak danych"
			}
			return OK, fmt.Sprintf("%.1f zdarzeń/s", v)
		}},
	{group: "Potok", name: "Odmowy przyjęcia (kolejka pełna)", query: `sum(rate(siem_ingest_batches_total{result="throttled_queue_full"}[5m])) or vector(0)`,
		hint: "Kolejka jest pełna – któryś etap nie nadąża. Sprawdź zapełnienie kolejek poniżej.",
		eval: thresholdHigh(0, 0, func(v float64) string {
			if v == 0 {
				return "brak"
			}
			return fmt.Sprintf("%.2f paczek/s", v)
		})},
	{group: "Potok", name: "Najbardziej zapełniona kolejka", query: `topk(1, siem_queue_fill_ratio)`,
		hint: "Odbiorca kolejki nie nadąża (wskazany w nawiasie). Powyżej 80% ingest zaczyna odmawiać przyjęcia.",
		eval: func(s []sample) (string, string) {
			if len(s) == 0 {
				return Unknown, "brak danych"
			}
			v := s[0].value
			st := OK
			if v > 0.5 {
				st = Warn
			}
			if v > 0.8 {
				st = Crit
			}
			return st, fmt.Sprintf("%s (%s)", pct(v), s[0].labels["consumer"])
		}},
	{group: "Potok", name: "Błędy zapisu do ClickHouse (15 min)", query: `sum(increase(siem_writer_insert_errors_total[15m])) or vector(0)`,
		hint: "Writer ponawia zapis; sprawdź logi writera i stan ClickHouse.",
		eval: thresholdHigh(0, 50, func(v float64) string { return fmt.Sprintf("%.0f", v) })},
	{group: "Potok", name: "Kwarantanna (ostatnia godzina)", query: `sum(increase(siem_normalizer_quarantined_total[1h])) + sum(increase(siem_writer_quarantined_total[1h]))`,
		hint: "Zdarzenia, których nie udało się znormalizować albo zapisać – są w siem.quarantine.",
		eval: thresholdHigh(0, 1000, func(v float64) string { return fmt.Sprintf("%.0f zdarzeń", v) })},
	{group: "Detekcja", name: "Włączone reguły", query: `max(siem_detector_rules) > 0 or max(siem_detector_index_rules)`,
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			if !ok {
				return Unknown, "brak danych"
			}
			if v == 0 {
				return Warn, "0 reguł"
			}
			return OK, fmt.Sprintf("%.0f reguł", v)
		}, hint: "Detektor nie ma włączonych reguł – sprawdź katalog reguł i panel."},
	{group: "Detekcja", name: "Reguły z błędami", query: `max(siem_detector_rule_errors) + (max(siem_detector_index_rule_errors) or vector(0))`,
		hint: "Część reguł nie działa – szczegóły w panelu (Reguły detekcji) i w logach detektora.",
		eval: thresholdHigh(0, 0, func(v float64) string { return fmt.Sprintf("%.0f", v) })},
	{group: "Detekcja", name: "Silnik zapytań – zaległość", query: `max(siem_detector_index_lag_seconds)`,
		hint: "Punkt kontrolny silnika zapytań stoi – sprawdź logi detektora i obciążenie ClickHouse.",
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			if !ok {
				return Disabled, "wyłączony (SIEM_DETECTION_MODE=stream)"
			}
			st := OK
			if v > 900 {
				st = Warn
			}
			if v > 3600 {
				st = Crit
			}
			return st, fmt.Sprintf("%.0f s (w tym opóźnienie 2 min)", v)
		}},
	{group: "Archiwum NIS2", name: "Weryfikacja integralności", query: `min(siem_archive_verify_ok)`,
		hint: "Dane w archiwum zmieniono, usunięto albo dodano poza archiwizatorem – szczegóły: panel → Urd.",
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			switch {
			case !ok:
				return Unknown, "brak danych"
			case v < 1:
				return Crit, "wykryto niezgodności"
			}
			return OK, "zgodne"
		}},
	{group: "Archiwum NIS2", name: "Ostatnia weryfikacja", query: `time() - max(siem_archive_last_verify_timestamp_seconds)`,
		hint: "Weryfikacja powinna przechodzić co 6 h – sprawdź logi archiwizatora.",
		eval: thresholdHigh(13*3600, 26*3600, ago)},
	{group: "Archiwum NIS2", name: "Archiwizacja", query: `min(siem_archive_policy_enabled) * (1 - max(siem_archive_paused))`,
		hint: "Archiwizacja wyłączona w polityce albo wstrzymana z braku miejsca – panel → Urd.",
		eval: func(s []sample) (string, string) {
			v, ok := one(s)
			switch {
			case !ok:
				return Unknown, "brak danych"
			case v < 1:
				return Crit, "wyłączona albo wstrzymana"
			}
			return OK, "włączona"
		}},
	{group: "Archiwum NIS2", name: "Wolne miejsce na dysku archiwum", query: `min(siem_archive_disk_free_bytes / siem_archive_disk_total_bytes)`,
		hint: "Po zapełnieniu archiwizacja się wstrzyma – powiększ dysk albo skróć retencję.",
		eval: thresholdLow(0.15, 0.05, pct)},
	{group: "Kopie zapasowe", name: "Ostatnia kopia", query: `time() - max(heimdall_backup_last_success_timestamp_seconds)`,
		hint: "Kopia powinna powstawać co noc (cron 02:15, backup.sh) – sprawdź ~/siem-lab/backup.log.",
		eval: thresholdHigh(26*3600, 50*3600, ago)},
	{group: "Kopie zapasowe", name: "Ostatnia kopia poza VM (NAS)", query: `time() - max(heimdall_backup_remote_last_success_timestamp_seconds)`,
		hint: "Kopia nie trafia poza VM – sprawdź połączenie z NAS i klucz SSH kopii.",
		eval: thresholdHigh(26*3600, 50*3600, ago)},
	{group: "Serwer", name: "Wolne miejsce na dysku systemowym", query: `min(node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})`,
		hint: "Brak miejsca zatrzyma ClickHouse i kolejki – usuń stare dane albo powiększ dysk.",
		eval: thresholdLow(0.15, 0.05, pct)},
	{group: "Serwer", name: "Obciążenie CPU (5 min)", query: `1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))`,
		hint: "Długotrwale wysokie obciążenie – potok może nie nadążać przy szczycie zdarzeń.",
		eval: thresholdHigh(0.85, 0.95, pct)},
	{group: "Serwer", name: "Wolna pamięć", query: `min(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)`,
		hint: "Mało pamięci – ryzyko zabicia usług przez system (OOM).",
		eval: thresholdLow(0.10, 0.05, pct)},
}

// Report odpytuje Prometheusa i ocenia wszystkie kontrole.
func (p *Prometheus) Report(ctx context.Context, now time.Time) Report {
	rep := Report{Overall: OK, GeneratedAt: now}
	if _, err := p.query(ctx, "vector(1)"); err != nil {
		rep.Overall = Crit
		rep.Checks = []Check{{Group: "Monitorowanie", Name: "Prometheus", Status: Crit, Value: "niedostępny",
			Hint: "Panel nie ma skąd wziąć stanu usług – sprawdź kontener prometheus (" + err.Error() + ")."}}
		return rep
	}
	for _, d := range defs {
		c := Check{Group: d.group, Name: d.name}
		s, err := p.query(ctx, d.query)
		if err != nil {
			c.Status, c.Value = Unknown, "błąd zapytania"
		} else {
			c.Status, c.Value = d.eval(s)
		}
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

func groupOrder(g string) int {
	for i, x := range groups {
		if x == g {
			return i
		}
	}
	return math.MaxInt
}
