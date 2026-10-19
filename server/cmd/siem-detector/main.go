// Command siem-detector (Gjallarhorn) ocenia znormalizowane zdarzenia
// regułami (Sigma, katalog SIEM_RULES_DIR) i zapisuje alerty w bazie Saga
// (schemat gjallarhorn). Powiadomienia wysyła panel (outbox).
//
// SIEM_DETECTION_MODE wybiera silniki:
//
//	stream       w locie – odbiorca strumienia SIEM_EVENTS (profil wydajnościowy)
//	index_query  zapytania na ClickHouse co SIEM_INDEX_INTERVAL (profil pełny)
//	both         oba; para (reguła, zdarzenie) i tak trafia do alertu raz,
//	             a silnik zapytań łapie zdarzenia spóźnione ponad pamięć progów
//
// Polecenia:
//
//	siem-detector                praca ciągła (usługa)
//	siem-detector check <katalog> sprawdza reguły (kod wyjścia 1 = błędy)
//	siem-detector disable        usuwa konsumenta SIEM_EVENTS (wyłączenie detekcji w locie)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/internal/model"
	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/detector"
	"siem/server/internal/metrics"
	"siem/server/internal/queue"
)

// corrDisabled: korelacje wyłączone w panelu (odświeżane przy przeładowaniu reguł).
var corrDisabled atomic.Pointer[map[string]bool]

// sigmaCorr: reguły korelacyjne Sigma z katalogu reguł (przeładowanie podmienia).
var sigmaCorr atomic.Pointer[[]*detect.Correlation]

func main() {
	log := svc.Logger("detector")
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "check":
		dir := svc.Env("SIEM_RULES_DIR", "/rules")
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		os.Exit(check(dir))
	case "disable":
		err = disable()
	default:
		fmt.Fprintln(os.Stderr, "użycie: siem-detector [serve|check <katalog>|disable]")
		os.Exit(2)
	}
	if err != nil {
		log.Error("zakończono z błędem", "err", err)
		os.Exit(1)
	}
}

func check(dir string) int {
	set, errs, err := detect.LoadSet(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, r := range set.Rules {
		note := ""
		if r.CorrelationOnly {
			note = "  [tylko korelacja]"
		}
		fmt.Printf("OK     %-8s %s  (%s)%s\n", r.Level, r.Title, r.File, note)
	}
	for _, c := range set.Correlations {
		fmt.Printf("OK     %-8s %s  (%s)  [korelacja %s, %s]\n", c.Level, c.Title, c.File, c.Type, c.Timespan)
	}
	for _, e := range errs {
		fmt.Printf("BŁĄD   %s: %s\n", e.File, e.Err)
	}
	if len(errs) > 0 {
		return 1
	}
	return 0
}

func disable() error {
	ctx, stop := svc.Context()
	defer stop()
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-detector-disable")
	if err != nil {
		return err
	}
	defer nc.Close()
	return bus.DisableDetector(ctx, js)
}

func serve(log *slog.Logger) error {
	ctx, stop := svc.Context()
	defer stop()
	dir := svc.Env("SIEM_RULES_DIR", "/rules")
	dbURL := svc.MustEnv(log, "SIEM_DETECTOR_DB_URL")
	mode := svc.Env("SIEM_DETECTION_MODE", "stream")
	if mode != "stream" && mode != "index_query" && mode != "both" {
		return fmt.Errorf("SIEM_DETECTION_MODE: stream, index_query albo both (jest %q)", mode)
	}
	streamOn, indexOn := mode != "index_query", mode != "stream"

	var store *alerts.PG
	if err := svc.Retry(ctx, log, "baza Saga", func() error {
		var err error
		store, err = alerts.Open(ctx, dbURL)
		return err
	}); err != nil {
		return err
	}
	defer store.Close()
	if applied, err := store.Migrate(ctx); err != nil {
		return err
	} else if len(applied) > 0 {
		log.Info("migracje schematu gjallarhorn", "applied", applied)
	}
	log.Info("oczekiwanie na blokadę jedynego detektora")
	release, err := store.LockDetector(ctx)
	if err != nil {
		return err
	}
	defer release()

	m := metrics.NewDetector()
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	eng := detector.NewEngine()
	fp := ""
	// restore: stan progów z bazy (po starcie i po nieudanym zapisie alertów).
	restore := func() {
		obs, err := store.Observations(ctx, time.Now().UTC())
		if err != nil {
			m.Errors.WithLabelValues("thresholds").Inc()
			log.Warn("odczyt stanu progów nieudany – liczniki od zera", "err", err)
		}
		if n := eng.RestoreThresholds(obs); n > 0 {
			log.Info("stan progów odtworzony", "events", n)
		}
	}
	reload := func() {
		// Ustawienia z panelu (włączenie/wyłączenie reguły) – ich zmiana też przeładowuje reguły.
		ov, sig, err := store.RuleOverrides(ctx)
		if err != nil {
			m.Errors.WithLabelValues("rule_overrides").Inc()
			log.Warn("odczyt ustawień reguł z panelu nieudany – zostają poprzednie", "err", err)
			return
		}
		// Reguły zapisane w panelu (kreator korelacji) – obok plików.
		prs, psig, err := store.PanelRules(ctx)
		if err != nil {
			m.Errors.WithLabelValues("panel_rules").Inc()
			log.Warn("odczyt reguł z panelu nieudany – zostają poprzednie", "err", err)
			return
		}
		cur := detector.Fingerprint(dir) + "|" + sig + "|" + psig
		if cur == fp {
			return
		}
		extra := make([]detect.Source, 0, len(prs))
		for _, pr := range prs {
			extra = append(extra, detect.Source{File: alerts.PanelRuleFile(pr.ID), Data: []byte(pr.Source)})
		}
		set, errs, err := detect.LoadSetWith(dir, extra)
		if err != nil {
			m.Errors.WithLabelValues("rules").Inc()
			log.Error("odczyt katalogu reguł nieudany – zostają poprzednie", "dir", dir, "err", err)
			return
		}
		rules := set.Rules
		fileEnabled := detector.ApplyOverrides(rules, ov)
		sigmaInfos := detector.ApplyCorrelationOverrides(set.Correlations, ov)
		sigma := set.Correlations
		sigmaCorr.Store(&sigma)
		for id, o := range ov {
			log.Info("reguła ustawiona w panelu", "rule", id, "enabled", o.Enabled, "by", o.ChangedBy)
		}
		n := eng.SetRules(rules)
		var rerrs []alerts.RuleError
		for _, e := range errs {
			rerrs = append(rerrs, alerts.RuleError{File: e.File, Error: e.Err})
			log.Warn("reguła odrzucona", "file", e.File, "err", e.Err)
		}
		infos := append(detector.Infos(rules, fileEnabled), detector.HeartbeatRule(), detector.TamperRule())
		corrInfos, corrOff := detector.CorrelationInfos(ov)
		infos = append(infos, corrInfos...)
		infos = append(infos, sigmaInfos...)
		corrDisabled.Store(&corrOff)
		if err := store.SyncRules(ctx, infos, rerrs, time.Now().UTC()); err != nil {
			m.Errors.WithLabelValues("rules_sync").Inc()
			log.Warn("zapis reguł w bazie nieudany", "err", err)
		}
		fp = cur
		m.Rules.Set(float64(n))
		m.RuleErrors.Set(float64(len(errs)))
		log.Info("reguły wczytane", "dir", dir, "loaded", len(rules), "stream", n, "correlations", len(sigma), "panel", len(prs), "errors", len(errs))
	}
	reload()
	restore()
	// Zapisy alertów z gorutyn idą równolegle – alerts.PG blokuje w bazie
	// tylko te same klucze alertów (etap 8; wcześniej jedna blokada tutaj).
	go runHeartbeat(ctx, log, store, m)
	go runRetention(ctx, log, store, m)
	var chConn driver.Conn
	if indexOn {
		idx, err := openIndex(ctx, log, store)
		if err != nil {
			return err
		}
		chConn = idx.Conn
		go runIndex(ctx, log, idx, eng, store, m)
	} else if os.Getenv("SIEM_DETECTOR_CH_PASSWORD") != "" {
		if idx, err := openIndex(ctx, log, store); err == nil {
			chConn = idx.Conn
		}
	}
	// Korelacje międzyźródłowe (etap 7d) – zapytania do ClickHouse.
	if chConn != nil {
		corr := &detector.Correlator{Conn: chConn, Disabled: func(id string) bool {
			off := corrDisabled.Load()
			return off != nil && (*off)[id]
		}, Open: store.OpenAlerts}
		go runCorrelation(ctx, log, corr, store, m)
		go runSilence(ctx, log, corr, store, m)
	} else {
		log.Warn("brak połączenia z ClickHouse (SIEM_DETECTOR_CH_PASSWORD) – korelacje międzyźródłowe wyłączone")
	}
	if !streamOn {
		// Tylko zapytania: konsument strumienia nie może zostać, bo
		// zatrzymywałby zdarzenia w kolejce (retencja „interest”).
		nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-detector")
		if err != nil {
			return err
		}
		if err := bus.DisableDetector(ctx, js); err != nil {
			log.Warn("usunięcie konsumenta detekcji w locie nieudane", "err", err)
		}
		nc.Close()
		log.Info("detektor uruchomiony – tylko silnik zapytań", "rules_dir", dir)
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
				reload()
			}
		}
		return nil
	}

	limits, err := queue.Limits()
	if err != nil {
		return err
	}
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-detector")
	if err != nil {
		return err
	}
	defer nc.Close()
	var cons jetstream.Consumer
	if err := svc.Retry(ctx, log, "konsument detekcji", func() error {
		if err := bus.EnsurePipeline(ctx, js, limits); err != nil {
			return err
		}
		var err error
		cons, err = bus.EnsureDetector(ctx, js)
		return err
	}); err != nil {
		return err
	}
	go queue.Watch(ctx, log, js, bus.StreamEvents, bus.ConsumerDetector, 0.5, 0.8, metrics.NewQueue())

	log.Info("detektor uruchomiony", "rules_dir", dir, "mode", mode)
	lastReload := time.Now()
	var beat atomic.Int64
	beat.Store(time.Now().UnixNano())
	go watchdog(ctx, log, "pętla detekcji w locie", &beat, 3*time.Minute)
	for ctx.Err() == nil {
		beat.Store(time.Now().UnixNano())
		if time.Since(lastReload) > 30*time.Second {
			reload()
			lastReload = time.Now()
			keys, dropped := eng.SweepThresholds()
			m.ThresholdKeys.Set(float64(keys))
			if dropped > 0 {
				m.Errors.WithLabelValues("threshold_limit").Add(float64(dropped))
				log.Warn("stan progów: zdarzenia pominięte przez limit kluczy", "dropped", dropped)
			}
			if _, err := store.PruneObservations(ctx, time.Now().UTC()); err != nil {
				log.Warn("czyszczenie stanu progów nieudane", "err", err)
			}
		}
		msgs, err := cons.Fetch(256, jetstream.FetchMaxWait(time.Second))
		if err != nil {
			log.Warn("pobranie z kolejki nieudane", "err", err)
			time.Sleep(time.Second)
			continue
		}
		var batch []jetstream.Msg
		var hits []alerts.Hit
		var obs []alerts.Observation
		for msg := range msgs.Messages() {
			data, err := bus.Gunzip(msg.Data(), 256<<20)
			var b model.Batch
			if err == nil {
				err = json.Unmarshal(data, &b)
			}
			if err != nil {
				m.Errors.WithLabelValues("decode").Inc()
				log.Error("nieczytelna wiadomość w SIEM_EVENTS – pominięta", "subject", msg.Subject(), "err", err)
				_ = msg.Term()
				continue
			}
			t0 := time.Now()
			h, o := eng.Evaluate(&b)
			obs = append(obs, o...)
			m.EvalTime.Add(time.Since(t0).Seconds())
			m.Events.Add(float64(len(b.Events)))
			if n := len(b.Events); n > 0 {
				m.LastEvent.Set(float64(b.Events[n-1].Ingested.Unix()))
			}
			for _, x := range h {
				m.Matches.WithLabelValues(x.RuleID).Inc()
			}
			hits = append(hits, h...)
			batch = append(batch, msg)
		}
		if len(batch) == 0 {
			continue
		}
		res, err := store.Record(ctx, hits, obs)
		if err != nil {
			// Alerty nie zapisane – zdarzenia wrócą (zapis jest idempotentny),
			// a stan progów wraca do ostatniej udanej transakcji.
			m.Errors.WithLabelValues("record").Inc()
			log.Error("zapis alertów nieudany – paczki wrócą z kolejki", "hits", len(hits), "err", err)
			for _, msg := range batch {
				_ = msg.NakWithDelay(5 * time.Second)
			}
			if len(obs) > 0 {
				restore()
			}
			continue
		}
		for _, msg := range batch {
			_ = msg.Ack()
		}
		m.Alerts.WithLabelValues("new").Add(float64(res.NewAlerts))
		m.Alerts.WithLabelValues("merged").Add(float64(res.Merged))
		m.Alerts.WithLabelValues("duplicate").Add(float64(res.Duplicates))
		if res.NewAlerts > 0 {
			log.Info("nowe alerty", "count", res.NewAlerts, "merged", res.Merged)
		}
	}
	return nil
}

func openIndex(ctx context.Context, log *slog.Logger, store *alerts.PG) (*detector.Index, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{svc.Env("SIEM_DETECTOR_CH_ADDR", "clickhouse:9000")},
		Auth: clickhouse.Auth{Database: "siem", Username: svc.Env("SIEM_DETECTOR_CH_USER", "siem_detector"),
			Password: svc.MustEnv(log, "SIEM_DETECTOR_CH_PASSWORD")},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := svc.Retry(ctx, log, "ClickHouse (silnik zapytań)", func() error { return conn.Ping(ctx) }); err != nil {
		return nil, err
	}
	maxRows, err := svc.EnvInt("SIEM_INDEX_MAX_ROWS", detector.MaxIndexRows)
	if err != nil {
		return nil, err
	}
	return &detector.Index{Conn: conn, Known: store.KnownEvents, MaxRows: maxRows}, nil
}

// runIndex: przebiegi silnika zapytań. Każdy ocenia zdarzenia przyjęte od
// punktu kontrolnego (z zakładką SIEM_INDEX_OVERLAP na zapis spóźniony
// w ClickHouse) do teraz − SIEM_INDEX_DELAY; zaległość nadrabia krokami,
// a po limicie wierszy kolejny przebieg zaczyna dokładnie za ostatnim
// wierszem (bez zakładki – inaczej duża zakładka blokowałaby postęp).
func runIndex(ctx context.Context, log *slog.Logger, idx *detector.Index, eng *detector.Engine, store *alerts.PG,
	m *metrics.Detector) {
	interval, _ := svc.EnvDuration("SIEM_INDEX_INTERVAL", time.Minute)
	delay, _ := svc.EnvDuration("SIEM_INDEX_DELAY", 2*time.Minute)
	overlap, _ := svc.EnvDuration("SIEM_INDEX_OVERLAP", 5*time.Minute)
	lookback, _ := svc.EnvDuration("SIEM_INDEX_LOOKBACK", time.Hour)
	const step = 6 * time.Hour
	log.Info("silnik zapytań uruchomiony", "interval", interval, "delay", delay, "overlap", overlap)
	wait := 10 * time.Second
	var beat atomic.Int64
	beat.Store(time.Now().UnixNano())
	go watchdog(ctx, log, "silnik zapytań", &beat, max(15*time.Minute, 3*interval))
	var resume *detector.Cursor // dalszy ciąg przebiegu przerwanego limitem wierszy
	var resumeTo time.Time
	failing := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		beat.Store(time.Now().UnixNano())
		wait = interval
		rules := eng.IndexRules()
		m.IndexRules.Set(float64(len(rules)))
		var from detector.Cursor
		var to time.Time
		if resume != nil {
			from, to = *resume, resumeTo
		} else {
			to = time.Now().UTC().Add(-delay).Truncate(time.Millisecond)
			cp, ok, err := store.IndexCheckpoint(ctx)
			if err != nil {
				m.IndexRuns.WithLabelValues("error").Inc()
				log.Warn("odczyt punktu kontrolnego nieudany", "err", err)
				continue
			}
			from = detector.Cursor{Ingested: to.Add(-lookback)}
			if ok {
				from = detector.Cursor{Ingested: cp.Add(-overlap)}
				m.IndexLag.Set(time.Since(cp).Seconds())
			}
			if to.Sub(from.Ingested) > step+overlap {
				to = from.Ingested.Add(step + overlap) // zaległość – kolejny krok zaraz
				wait = time.Second
			}
		}
		t0 := time.Now()
		res, err := idx.Run(ctx, rules, from, to)
		m.IndexTime.Add(time.Since(t0).Seconds())
		if err != nil {
			m.IndexRuns.WithLabelValues("error").Inc()
			log.Error("przebieg silnika zapytań nieudany", "from", from.Ingested, "to", to, "err", err)
			resume = nil
			continue
		}
		// Reguły, których SQL nie przechodzi w ClickHouse – pominięte (metryka
		// i log przy zmianie, alert Grafany „reguły detekcji z błędami”).
		now := map[string]bool{}
		for _, f := range res.Failed {
			now[f.RuleID] = true
			if !failing[f.RuleID] {
				log.Error("reguła odrzucona przez ClickHouse – pominięta w silniku zapytań", "rule", f.RuleID, "err", f.Err)
			}
		}
		failing = now
		m.IndexRuleErrors.Set(float64(len(failing)))
		hits := res.Hits
		if len(hits) > 0 {
			// Zakładka i praca silnika w locie: większość trafień już jest w alertach.
			if fresh, err := store.FilterNew(ctx, hits); err == nil {
				m.Alerts.WithLabelValues("duplicate").Add(float64(len(hits) - len(fresh)))
				hits = fresh
			}
		}
		rec, err := store.RecordIndex(ctx, hits, res.Reached)
		if err != nil {
			m.IndexRuns.WithLabelValues("error").Inc()
			m.Errors.WithLabelValues("record").Inc()
			log.Error("zapis alertów silnika zapytań nieudany", "hits", len(hits), "err", err)
			resume = nil
			continue
		}
		resume = nil
		if res.More {
			next := res.Next
			resume, resumeTo, wait = &next, to, time.Second
		}
		m.IndexRuns.WithLabelValues("ok").Inc()
		m.IndexRows.Add(float64(res.Rows))
		m.IndexLag.Set(time.Since(res.Reached).Seconds())
		m.Alerts.WithLabelValues("new").Add(float64(rec.NewAlerts))
		m.Alerts.WithLabelValues("merged").Add(float64(rec.Merged))
		m.Alerts.WithLabelValues("duplicate").Add(float64(rec.Duplicates))
		if rec.NewAlerts > 0 {
			log.Info("nowe alerty (silnik zapytań)", "count", rec.NewAlerts, "merged", rec.Merged)
		}
	}
}

// runHeartbeat: reguła wbudowana „utrata łączności z agentem” – co 30 s
// porównuje ostatni heartbeat agentów z progiem ich grupy; alert zamyka się
// sam, gdy agent wróci.
func runHeartbeat(ctx context.Context, log *slog.Logger, store *alerts.PG, m *metrics.Detector) {
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		now := time.Now().UTC()
		beats, err := store.AgentBeats(ctx)
		if err != nil {
			m.Errors.WithLabelValues("heartbeat").Inc()
			if !warned {
				log.Warn("odczyt heartbeatu agentów nieudany – reguła utraty łączności nie działa", "err", err)
				warned = true
			}
			continue
		}
		warned = false
		runTamper(ctx, log, store, m, now)
		hits, back := detector.HeartbeatCheck(beats, now)
		if len(hits) > 0 {
			res, err := store.Record(ctx, hits, nil)
			if err != nil {
				m.Errors.WithLabelValues("record").Inc()
				log.Error("zapis alertów utraty łączności nieudany", "err", err)
				continue
			}
			m.Alerts.WithLabelValues("new").Add(float64(res.NewAlerts))
			if res.NewAlerts > 0 {
				log.Info("utrata łączności z agentem – nowe alerty", "count", res.NewAlerts)
			}
		}
		open, err := store.OpenAgents(ctx, detector.HeartbeatRuleID)
		if err != nil || len(open) == 0 {
			continue
		}
		for _, b := range back {
			if !open[b.ID] {
				continue
			}
			reason := "Agent znów wysyła heartbeat (" + now.Format("2006-01-02 15:04") + " UTC) – zamknięte automatycznie."
			if n, err := store.CloseOpen(ctx, detector.HeartbeatRuleID, detector.HeartbeatKey(b.ID), reason, b.NotifyReturn, now); err != nil {
				log.Warn("zamknięcie alertu utraty łączności nieudane", "agent", b.ID, "err", err)
			} else if n > 0 {
				log.Info("agent wrócił – alert zamknięty", "agent", b.ID)
			}
		}
	}
}

// tamperSeen: zdarzenia ochrony już zapisane (heartbeat powtarza je przez
// 7 dni) – używane tylko w pętli heartbeatu. Po restarcie detektora
// powtórki odrzuca baza (alert_events).
var tamperSeen = map[string]time.Time{}

// runTamper: reguła wbudowana „próba sabotażu agenta” – zdarzenia ochrony
// z heartbeatu agentów (co 30 s, razem z utratą łączności).
func runTamper(ctx context.Context, log *slog.Logger, store *alerts.PG, m *metrics.Detector, now time.Time) {
	beats, err := store.TamperBeats(ctx)
	if err != nil {
		m.Errors.WithLabelValues("tamper").Inc()
		log.Warn("odczyt zdarzeń ochrony agentów nieudany", "err", err)
		return
	}
	var hits []alerts.Hit
	for _, h := range detector.TamperCheck(beats, now) {
		if _, ok := tamperSeen[h.EventID]; !ok {
			hits = append(hits, h)
		}
	}
	for id, at := range tamperSeen {
		if now.Sub(at) > 8*24*time.Hour {
			delete(tamperSeen, id)
		}
	}
	if len(hits) == 0 {
		return
	}
	res, err := store.Record(ctx, hits, nil)
	if err != nil {
		m.Errors.WithLabelValues("record").Inc()
		log.Error("zapis alertów sabotażu agenta nieudany", "err", err)
		return
	}
	for _, h := range hits {
		tamperSeen[h.EventID] = now
	}
	m.Alerts.WithLabelValues("new").Add(float64(res.NewAlerts))
	if res.NewAlerts > 0 {
		log.Info("próba sabotażu agenta – nowe alerty", "count", res.NewAlerts)
	}
}

// watchdog kończy proces, gdy pętla nie robi postępu dłużej niż limit
// (zawieszony zapis, zablokowane połączenie). Docker uruchamia detektor
// ponownie (restart: unless-stopped), a stan progów wraca z Sagi – lepsze
// niż detektor, który żyje, ale niczego nie wykrywa.
func watchdog(ctx context.Context, log *slog.Logger, what string, beat *atomic.Int64, limit time.Duration) {
	t := time.NewTicker(limit / 6)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if idle := time.Since(time.Unix(0, beat.Load())); idle > limit {
			log.Error("brak postępu – kończę proces, Docker uruchomi detektor ponownie", "loop", what, "idle", idle.Round(time.Second))
			os.Exit(3)
		}
	}
}

// runRetention: co 6 h usuwa alerty zamknięte dawniej niż
// SIEM_ALERT_RETENTION_DAYS (domyślnie 365; 0 = bez usuwania) i wysłane
// powiadomienia starsze niż 30 dni. Otwarte alerty zostają zawsze.
func runRetention(ctx context.Context, log *slog.Logger, store *alerts.PG, m *metrics.Detector) {
	days, err := svc.EnvInt("SIEM_ALERT_RETENTION_DAYS", 365)
	if err != nil {
		log.Error("SIEM_ALERT_RETENTION_DAYS – zostaje 365", "err", err)
		days = 365
	}
	wait := 5 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 6 * time.Hour
		now := time.Now().UTC()
		closedBefore := time.Time{} // 0 dni = alerty zostają
		if days > 0 {
			closedBefore = now.AddDate(0, 0, -days)
		}
		res, err := store.Prune(ctx, closedBefore, now.AddDate(0, 0, -30), 5000)
		if err != nil {
			m.Errors.WithLabelValues("retention").Inc()
			log.Warn("sprzątanie alertów nieudane", "err", err)
			continue
		}
		if res.Alerts > 0 || res.Outbox > 0 {
			log.Info("sprzątanie alertów", "closed_alerts", res.Alerts, "outbox", res.Outbox, "retention_days", days)
		}
	}
}

// runCorrelation: korelacje międzyźródłowe co minutę na zdarzeniach przyjętych
// w ostatnich 15 min (do teraz − 2 min: zapis w ClickHouse); pierwszy
// przebieg – 2 h wstecz. Zakładka okien jest bezpieczna: para (reguła,
// zdarzenie) trafia do alertu raz.
func runCorrelation(ctx context.Context, log *slog.Logger, c *detector.Correlator, store *alerts.PG, m *metrics.Detector) {
	lookback := 2 * time.Hour
	for {
		to := time.Now().UTC().Add(-2 * time.Minute)
		qctx, cancel := context.WithTimeout(ctx, 50*time.Second)
		hits, err := c.Run(qctx, to.Add(-lookback), to)
		if err != nil {
			m.Errors.WithLabelValues("correlation").Inc()
			log.Warn("korelacje międzyźródłowe nieudane", "err", err)
			hits = nil
		}
		// Reguły korelacyjne Sigma – błąd jednej nie zatrzymuje pozostałych.
		if p := sigmaCorr.Load(); p != nil && len(*p) > 0 {
			sh, errs := c.RunSigma(qctx, *p, to.Add(-lookback), to)
			for _, e := range errs {
				m.Errors.WithLabelValues("correlation").Inc()
				log.Warn("reguła korelacyjna nieudana", "err", e)
			}
			hits = append(hits, sh...)
		}
		cancel()
		if err == nil || len(hits) > 0 {
			lookback = 15 * time.Minute
			if len(hits) > 0 {
				res, err := store.Record(ctx, hits, nil)
				if err != nil {
					m.Errors.WithLabelValues("record").Inc()
					log.Error("zapis alertów korelacji nieudany", "err", err)
				} else {
					m.Alerts.WithLabelValues("new").Add(float64(res.NewAlerts))
					m.Alerts.WithLabelValues("merged").Add(float64(res.Merged))
					if res.NewAlerts > 0 {
						log.Info("korelacje – nowe alerty", "count", res.NewAlerts, "merged", res.Merged)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// runSilence: reguła „cisza źródła” co 5 minut (SIEM_SOURCE_SILENCE_MIN –
// najkrótszy próg, domyślnie 1 h). Alert zamyka się sam, gdy źródło wróci.
func runSilence(ctx context.Context, log *slog.Logger, c *detector.Correlator, store *alerts.PG, m *metrics.Detector) {
	minSilence, _ := svc.EnvDuration("SIEM_SOURCE_SILENCE_MIN", time.Hour)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
		if c.Disabled != nil && c.Disabled(detector.SourceSilentID) {
			continue
		}
		now := time.Now().UTC()
		qctx, cancel := context.WithTimeout(ctx, time.Minute)
		srcs, err := c.Sources(qctx, now)
		cancel()
		if err != nil {
			m.Errors.WithLabelValues("silence").Inc()
			log.Warn("cisza źródła: odczyt źródeł nieudany", "err", err)
			continue
		}
		hits, back := detector.SilenceCheck(srcs, now, minSilence)
		if len(hits) > 0 {
			res, err := store.Record(ctx, hits, nil)
			if err != nil {
				m.Errors.WithLabelValues("record").Inc()
				log.Error("zapis alertów ciszy źródła nieudany", "err", err)
				continue
			}
			m.Alerts.WithLabelValues("new").Add(float64(res.NewAlerts))
			if res.NewAlerts > 0 {
				log.Info("cisza źródła – nowe alerty", "count", res.NewAlerts)
			}
		}
		open, err := store.OpenAlerts(ctx, detector.SourceSilentID, now.Add(-365*24*time.Hour))
		if err != nil || len(open) == 0 {
			continue
		}
		for _, key := range back {
			found := false
			for k := range open {
				found = found || strings.HasPrefix(k, key)
			}
			if !found {
				continue
			}
			reason := "Źródło znów przysyła zdarzenia (" + now.Format("2006-01-02 15:04") + " UTC) – zamknięte automatycznie."
			if n, err := store.CloseOpen(ctx, detector.SourceSilentID, key, reason, true, now); err != nil {
				log.Warn("zamknięcie alertu ciszy źródła nieudane", "source", key, "err", err)
			} else if n > 0 {
				log.Info("źródło wróciło – alert zamknięty", "source", key)
			}
		}
	}
}
