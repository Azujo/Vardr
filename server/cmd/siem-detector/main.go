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
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/alerts"
	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/detect"
	"siem/server/internal/detector"
	"siem/server/internal/metrics"
	"siem/server/internal/model"
	"siem/server/internal/queue"
)

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
	rules, errs, err := detect.LoadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, r := range rules {
		fmt.Printf("OK     %-8s %s  (%s)\n", r.Level, r.Title, r.File)
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
		cur := detector.Fingerprint(dir)
		if cur == fp {
			return
		}
		rules, errs, err := detect.LoadDir(dir)
		if err != nil {
			m.Errors.WithLabelValues("rules").Inc()
			log.Error("odczyt katalogu reguł nieudany – zostają poprzednie", "dir", dir, "err", err)
			return
		}
		n := eng.SetRules(rules)
		var rerrs []alerts.RuleError
		for _, e := range errs {
			rerrs = append(rerrs, alerts.RuleError{File: e.File, Error: e.Err})
			log.Warn("reguła odrzucona", "file", e.File, "err", e.Err)
		}
		if err := store.SyncRules(ctx, detector.Infos(rules), rerrs, time.Now().UTC()); err != nil {
			m.Errors.WithLabelValues("rules_sync").Inc()
			log.Warn("zapis reguł w bazie nieudany", "err", err)
		}
		fp = cur
		m.Rules.Set(float64(n))
		m.RuleErrors.Set(float64(len(errs)))
		log.Info("reguły wczytane", "dir", dir, "loaded", len(rules), "stream", n, "errors", len(errs))
	}
	reload()
	restore()
	// Oba silniki zapisują przez jedną blokadę – łączenie trafień w alert
	// (SELECT … FOR UPDATE) nie widzi alertu tworzonego równolegle.
	var recordMu sync.Mutex
	if indexOn {
		idx, err := openIndex(ctx, log, store)
		if err != nil {
			return err
		}
		go runIndex(ctx, log, idx, eng, store, &recordMu, m)
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
	for ctx.Err() == nil {
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
		recordMu.Lock()
		res, err := store.Record(ctx, hits, obs)
		recordMu.Unlock()
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
	return &detector.Index{Conn: conn, Known: store.KnownEvents}, nil
}

// runIndex: przebiegi silnika zapytań. Każdy ocenia zdarzenia przyjęte od
// punktu kontrolnego (z zakładką SIEM_INDEX_OVERLAP na zapis spóźniony
// w ClickHouse) do teraz − SIEM_INDEX_DELAY; zaległość nadrabia krokami.
func runIndex(ctx context.Context, log *slog.Logger, idx *detector.Index, eng *detector.Engine, store *alerts.PG,
	mu *sync.Mutex, m *metrics.Detector) {
	interval, _ := svc.EnvDuration("SIEM_INDEX_INTERVAL", time.Minute)
	delay, _ := svc.EnvDuration("SIEM_INDEX_DELAY", 2*time.Minute)
	overlap, _ := svc.EnvDuration("SIEM_INDEX_OVERLAP", 5*time.Minute)
	lookback, _ := svc.EnvDuration("SIEM_INDEX_LOOKBACK", time.Hour)
	const step = 6 * time.Hour
	log.Info("silnik zapytań uruchomiony", "interval", interval, "delay", delay, "overlap", overlap)
	wait := 10 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = interval
		rules := eng.IndexRules()
		m.IndexRules.Set(float64(len(rules)))
		to := time.Now().UTC().Add(-delay).Truncate(time.Millisecond)
		cp, ok, err := store.IndexCheckpoint(ctx)
		if err != nil {
			m.IndexRuns.WithLabelValues("error").Inc()
			log.Warn("odczyt punktu kontrolnego nieudany", "err", err)
			continue
		}
		from := to.Add(-lookback)
		if ok {
			from = cp.Add(-overlap)
			m.IndexLag.Set(time.Since(cp).Seconds())
		}
		if to.Sub(from) > step+overlap {
			to = from.Add(step + overlap) // zaległość – kolejny krok zaraz
			wait = time.Second
		}
		t0 := time.Now()
		res, err := idx.Run(ctx, rules, from, to)
		m.IndexTime.Add(time.Since(t0).Seconds())
		if err != nil {
			m.IndexRuns.WithLabelValues("error").Inc()
			log.Error("przebieg silnika zapytań nieudany", "from", from, "to", to, "err", err)
			continue
		}
		mu.Lock()
		rec, err := store.RecordIndex(ctx, res.Hits, res.Reached)
		mu.Unlock()
		if err != nil {
			m.IndexRuns.WithLabelValues("error").Inc()
			m.Errors.WithLabelValues("record").Inc()
			log.Error("zapis alertów silnika zapytań nieudany", "hits", len(res.Hits), "err", err)
			continue
		}
		if res.Reached.Before(to) {
			wait = time.Second // limit wierszy – reszta w następnym przebiegu
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
