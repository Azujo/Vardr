// Command siem-archiver (Urd) zapisuje oryginalne paczki agentów do
// archiwum NIS2: segmenty na dysku, godzinowe manifesty połączone łańcuchem
// hashy (spis w bazie Saga) i okresowa weryfikacja integralności.
//
// Polecenia:
//
//	siem-archiver            praca ciągła (usługa)
//	siem-archiver verify     jednorazowa weryfikacja w ramach budżetu (kod wyjścia 1 = niezgodności)
//	siem-archiver verify --full   jak wyżej, ale całe archiwum czytane w całości
//	siem-archiver check-export <plik.tar>  sprawdza paczkę eksportu dla audytora
//	                         (bez dostępu do systemu; kod wyjścia 1 = niezgodności)
//	siem-archiver disable    wyłącza archiwizację nowych paczek (usuwa konsumenta
//	                         kolejki; dane w archiwum zostają do końca retencji)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/svc"
	"siem/internal/urd"
	"siem/server/internal/archiver"
	"siem/server/internal/bus"
	"siem/server/internal/metrics"
	"siem/server/internal/normalize"
	"siem/server/internal/queue"
)

func main() {
	log := svc.Logger("archiver")
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "verify":
		var ok bool
		ok, err = verify(log)
		if err == nil && !ok {
			os.Exit(1)
		}
	case "check-export":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "użycie: siem-archiver check-export <plik.tar>")
			os.Exit(2)
		}
		ok, cerr := checkExport(os.Args[2])
		if cerr == nil && !ok {
			os.Exit(1)
		}
		err = cerr
	case "disable":
		err = disable(log)
	default:
		fmt.Fprintln(os.Stderr, "użycie: siem-archiver [serve|verify [--full]|check-export <plik.tar>|disable]")
		os.Exit(2)
	}
	if err != nil {
		log.Error("zakończono z błędem", "err", err)
		os.Exit(1)
	}
}

type settings struct {
	dir          string
	dbURL        string
	retention    time.Duration
	segBytes     int64
	segAge       time.Duration
	verifyEvery  time.Duration
	exclude      []string
	minFreeGB    int
	minFreePct   float64
	warnFreePct  float64
	verifyBudget int64
	exportDir    string
	exportKeep   time.Duration
	bounds       urd.PolicyBounds
	grace        time.Duration
}

func load(log *slog.Logger) (settings, error) {
	s := settings{dir: svc.Env("SIEM_ARCHIVE_DIR", "/archive"), dbURL: svc.MustEnv(log, "SIEM_ARCHIVE_DB_URL")}
	days, err := svc.EnvInt("SIEM_ARCHIVE_RETENTION_DAYS", 30)
	if err != nil {
		return s, err
	}
	if days < 1 {
		return s, fmt.Errorf("SIEM_ARCHIVE_RETENTION_DAYS musi być ≥ 1")
	}
	s.retention = time.Duration(days) * 24 * time.Hour
	// Granice polityki ustawianej w panelu: przejęcie panelu nie pozwala
	// skrócić retencji poniżej minimum ani wyłączyć ochrony bez karencji.
	if s.bounds.MinRetentionDays, err = svc.EnvInt("SIEM_ARCHIVE_MIN_RETENTION_DAYS", 30); err != nil {
		return s, err
	}
	if s.bounds.MaxRetentionDays, err = svc.EnvInt("SIEM_ARCHIVE_MAX_RETENTION_DAYS", 3650); err != nil {
		return s, err
	}
	if s.bounds.MinRetentionDays < 1 || s.bounds.MaxRetentionDays < s.bounds.MinRetentionDays {
		return s, fmt.Errorf("SIEM_ARCHIVE_MIN_RETENTION_DAYS musi być ≥ 1 i ≤ SIEM_ARCHIVE_MAX_RETENTION_DAYS")
	}
	if err := s.bounds.Check(days); err != nil {
		return s, fmt.Errorf("SIEM_ARCHIVE_RETENTION_DAYS: %w", err)
	}
	if s.grace, err = svc.EnvDuration("SIEM_ARCHIVE_POLICY_GRACE", 24*time.Hour); err != nil {
		return s, err
	}
	mb, err := svc.EnvInt("SIEM_ARCHIVE_SEGMENT_MB", 64)
	if err != nil {
		return s, err
	}
	s.segBytes = int64(max(1, mb)) << 20
	if s.segAge, err = svc.EnvDuration("SIEM_ARCHIVE_SEGMENT_AGE", 30*time.Second); err != nil {
		return s, err
	}
	if s.verifyEvery, err = svc.EnvDuration("SIEM_ARCHIVE_VERIFY_EVERY", 6*time.Hour); err != nil {
		return s, err
	}
	for _, p := range strings.Split(os.Getenv("SIEM_ARCHIVE_EXCLUDE_AGENTS"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			s.exclude = append(s.exclude, p)
		}
	}
	s.exportDir = svc.Env("SIEM_ARCHIVE_EXPORT_DIR", "/exports")
	keepDays, err := svc.EnvInt("SIEM_ARCHIVE_EXPORT_KEEP_DAYS", 7)
	if err != nil {
		return s, err
	}
	s.exportKeep = time.Duration(max(1, keepDays)) * 24 * time.Hour
	budgetGB, err := svc.EnvInt("SIEM_ARCHIVE_VERIFY_BUDGET_GB", 50)
	if err != nil {
		return s, err
	}
	s.verifyBudget = int64(max(0, budgetGB)) << 30
	if s.minFreeGB, err = svc.EnvInt("SIEM_ARCHIVE_MIN_FREE_GB", 2); err != nil {
		return s, err
	}
	if s.minFreePct, err = svc.EnvFloat("SIEM_ARCHIVE_MIN_FREE_PERCENT", 5); err != nil {
		return s, err
	}
	if s.warnFreePct, err = svc.EnvFloat("SIEM_ARCHIVE_WARN_FREE_PERCENT", 15); err != nil {
		return s, err
	}
	if st, err := os.Stat(s.dir); err != nil || !st.IsDir() {
		return s, fmt.Errorf("katalog archiwum %s niedostępny: %v", s.dir, err)
	}
	return s, nil
}

func openCatalog(ctx context.Context, log *slog.Logger, url string) (*urd.PG, error) {
	var cat *urd.PG
	err := svc.Retry(ctx, log, "baza Saga", func() error {
		var err error
		cat, err = urd.OpenPG(ctx, url)
		return err
	})
	if err != nil {
		return nil, err
	}
	applied, err := cat.Migrate(ctx)
	if err != nil {
		cat.Close()
		return nil, err
	}
	if len(applied) > 0 {
		log.Info("migracje schematu urd", "applied", applied)
	}
	return cat, nil
}

func serve(log *slog.Logger) error {
	ctx, stop := svc.Context()
	defer stop()
	cfg, err := load(log)
	if err != nil {
		return err
	}
	cat, err := openCatalog(ctx, log, cfg.dbURL)
	if err != nil {
		return err
	}
	defer cat.Close()
	log.Info("oczekiwanie na blokadę jedynego archiwizatora")
	release, err := cat.LockWriter(ctx)
	if err != nil {
		return err
	}
	defer release()

	// Polityka: przy pierwszym starcie z konfiguracji serwera, potem z panelu.
	initial, created, err := cat.InitPolicy(ctx, urd.Policy{Enabled: true, RetentionDays: int(cfg.retention / (24 * time.Hour)),
		UpdatedAt: time.Now().UTC(), UpdatedBy: "konfiguracja serwera"})
	if err != nil {
		return fmt.Errorf("polityka archiwum: %w", err)
	}
	if created {
		log.Info("założono politykę archiwum z konfiguracji serwera (dalsze zmiany w panelu)", "retention_days", initial.RetentionDays)
	} else {
		log.Info("polityka archiwum z panelu", "enabled", initial.Enabled, "retention_days", initial.RetentionDays,
			"excluded_groups", initial.ExcludedGroups, "excluded_agents", initial.ExcludedAgents)
	}
	policy := archiver.NewPolicy(initial, cfg.bounds, cfg.grace)

	a := urd.New(cfg.dir, cat)
	if err := a.CheckDir(ctx); err != nil {
		return fmt.Errorf("%s: %w", cfg.dir, err)
	}
	if n, err := a.CleanTemp(); err != nil {
		return fmt.Errorf("sprzątanie niezatwierdzonych segmentów: %w", err)
	} else if n > 0 {
		log.Warn("usunięto niezatwierdzone segmenty po przerwanej pracy (ich paczki wrócą z kolejki)", "files", n)
	}

	limits, err := queue.Limits()
	if err != nil {
		return err
	}
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-archiver")
	if err != nil {
		return err
	}
	defer nc.Close()
	// Czytelna część eksportu: syslog dekodowany tak jak w bazie (z dekoderami z panelu).
	go normalize.WatchDecoders(ctx, js, log)
	go normalize.WatchIdentity(ctx, js, log)
	var cons jetstream.Consumer
	if err := svc.Retry(ctx, log, "konsument archiwum", func() error {
		if err := bus.EnsurePipeline(ctx, js, limits); err != nil {
			return err
		}
		var err error
		// Ścieżka odtwarzania musi istnieć (z odbiorcami), zanim archiwizator
		// cokolwiek do niej wyśle – inaczej paczki zostałyby odrzucone.
		if err := bus.Replay.Ensure(ctx, js, limits); err != nil {
			return err
		}
		cons, err = bus.EnsureArchiver(ctx, js, cfg.segAge)
		return err
	}); err != nil {
		return err
	}

	m := metrics.NewArchiver()
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	go queue.Watch(ctx, log, js, bus.StreamRaw, bus.ConsumerArchiver, 0.5, 0.8, metrics.NewQueue())
	health := &archiver.Health{}
	dataLock := &sync.Mutex{}
	go (&archiver.Exporter{A: a, Store: cat, Dir: cfg.exportDir, Keep: cfg.exportKeep, MinFreeBytes: uint64(cfg.minFreeGB) << 30,
		ToolsDir: svc.Env("SIEM_ARCHIVE_EXPORT_TOOLS", "/export-tools"),
		Version:  svc.Version, Log: log, Lock: dataLock}).Run(ctx)
	go (&archiver.Replayer{A: a, Store: cat, Pub: js, Log: log, Lock: dataLock}).Run(ctx)
	go archiver.Maintain(ctx, a, log, m, archiver.MaintainConfig{
		Retention: cfg.retention, VerifyEvery: cfg.verifyEvery, FirstVerify: 2 * time.Minute, VerifyBudget: cfg.verifyBudget,
		Policy: policy, PolicyStore: cat, PolicyGrace: cfg.grace,
		State: cat, Health: health, DataLock: dataLock, StateBase: urd.ArchiverState{
			MinRetentionDays: cfg.bounds.MinRetentionDays, MaxRetentionDays: cfg.bounds.MaxRetentionDays,
			PolicyGraceS: int(cfg.grace / time.Second), ExcludePrefixes: cfg.exclude,
			Version: svc.Version, RetentionDays: int(cfg.retention / (24 * time.Hour)),
			SegmentMaxMB: int(cfg.segBytes >> 20), SegmentMaxAgeS: int(cfg.segAge / time.Second),
			VerifyEveryS: int(cfg.verifyEvery / time.Second), StartedAt: time.Now().UTC(),
		}})

	r := &archiver.Archiver{A: a, Log: log, M: m, Health: health, Policy: policy,
		Cfg: archiver.Config{SegmentMaxBytes: cfg.segBytes, SegmentMaxAge: cfg.segAge, ExcludeAgents: cfg.exclude,
			MinFreeBytes: uint64(cfg.minFreeGB) << 30, MinFreePercent: cfg.minFreePct, WarnFreePercent: cfg.warnFreePct}}
	log.Info("archiwizator uruchomiony", "dir", cfg.dir, "retention", cfg.retention.String(),
		"min_retention_days", cfg.bounds.MinRetentionDays, "policy_grace", cfg.grace.String(),
		"segment_mb", cfg.segBytes>>20, "segment_age", cfg.segAge.String(), "verify_every", cfg.verifyEvery.String(),
		"exclude_agents", cfg.exclude, "min_free_gb", cfg.minFreeGB, "min_free_percent", cfg.minFreePct)
	for ctx.Err() == nil {
		if r.CheckDisk() != "" {
			r.Pause(ctx, 10*time.Second)
			continue
		}
		msgs, err := cons.Fetch(512, jetstream.FetchMaxWait(time.Second))
		if err != nil {
			log.Warn("pobranie z kolejki nieudane", "err", err)
			time.Sleep(time.Second)
			continue
		}
		for msg := range msgs.Messages() {
			if err := r.Add(ctx, msg); err != nil {
				log.Error("zapis do archiwum nieudany – paczki wrócą z kolejki", "err", err)
			}
		}
		if err := r.Tick(ctx); err != nil {
			log.Error("zamykanie segmentu lub godziny nieudane", "err", err)
		}
	}
	if err := r.Close(context.WithoutCancel(ctx)); err != nil {
		log.Error("zatwierdzenie ostatniego segmentu nieudane", "err", err)
	}
	return nil
}

func verify(log *slog.Logger) (bool, error) {
	ctx, stop := svc.Context()
	defer stop()
	cfg, err := load(log)
	if err != nil {
		return false, err
	}
	cat, err := openCatalog(ctx, log, cfg.dbURL)
	if err != nil {
		return false, err
	}
	defer cat.Close()
	// --full: całe archiwum (np. przed audytem); bez niego – budżet jak w usłudze.
	opt := urd.VerifyOptions{BudgetBytes: cfg.verifyBudget}
	if slices.Contains(os.Args[2:], "--full") {
		opt.BudgetBytes = 0
	}
	v := urd.New(cfg.dir, cat).Verify(ctx, opt)
	if _, err := cat.SaveVerification(ctx, v); err != nil {
		log.Warn("zapis wyniku nieudany", "err", err)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
	return v.OK, nil
}

func disable(log *slog.Logger) error {
	ctx, stop := svc.Context()
	defer stop()
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-archiver-disable")
	if err != nil {
		return err
	}
	defer nc.Close()
	if err := bus.DisableArchiver(ctx, js); err != nil {
		return err
	}
	log.Warn("archiwizacja nowych paczek WYŁĄCZONA (konsument usunięty); zatrzymaj usługę archiver – dane w archiwum zostają do końca retencji")
	return nil
}

// checkExport sprawdza paczkę eksportu (np. u audytora, bez dostępu do systemu).
func checkExport(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	c := urd.CheckExport(f)
	out, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(out))
	if c.OK {
		fmt.Fprintf(os.Stderr, "Paczka zgodna. Porównaj kotwicę (SHA-256 najnowszego manifestu) z wartością zapisaną niezależnie:\n%s\n", c.Latest)
	}
	return c.OK, nil
}
