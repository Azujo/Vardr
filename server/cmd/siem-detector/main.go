// Command siem-detector (Gjallarhorn) ocenia znormalizowane zdarzenia
// regułami (Sigma, katalog SIEM_RULES_DIR) w locie i zapisuje alerty
// w bazie Saga (schemat gjallarhorn). Powiadomienia wysyła panel (outbox).
//
// Polecenia:
//
//	siem-detector                praca ciągła (usługa)
//	siem-detector check <katalog> sprawdza reguły (kod wyjścia 1 = błędy)
//	siem-detector disable        usuwa konsumenta SIEM_EVENTS (wyłączenie detekcji w locie)
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

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

	log.Info("detektor uruchomiony", "rules_dir", dir)
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
