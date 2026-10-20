// Command siem-api to backend panelu Hliðskjálf: API (logowanie, konta,
// audyt) i aplikacja React, po HTTPS. Dane w bazie Saga (PostgreSQL).
//
// Polecenia:
//
//	siem-api                                    uruchomienie serwera (domyślnie)
//	siem-api bootstrap-admin -username admin    pierwsze konto administratora
//	siem-api reset-password -username jan       nowe hasło startowe dla konta
//	siem-api reset-mfa -username jan            usunięcie drugiego składnika konta
//	                                            (zgubiony telefon i kody zapasowe)
//
// Polecenia administracyjne wypisują hasło startowe na ekran – uruchamia je
// administrator na serwerze (docker compose run --rm api …). Hasło trzeba
// zmienić przy pierwszym logowaniu.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // strefa czasu kotwicy (obraz bez tzdata)

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/alerts"
	"siem/internal/decode"
	"siem/internal/decodekv"
	"siem/internal/fleet"
	"siem/internal/identity"
	"siem/internal/reprocess"
	"siem/internal/svc"
	"siem/internal/urd"
	"siem/panel/internal/api"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/enroll"
	"siem/panel/internal/events"
	"siem/panel/internal/fleetsync"
	"siem/panel/internal/notify"
	"siem/panel/internal/status"
	"siem/panel/web"
)

func main() {
	log := svc.Logger("api")
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "bootstrap-admin":
		err = bootstrapAdmin(os.Args[2:])
	case "reset-password":
		err = resetPassword(os.Args[2:])
	case "reset-mfa":
		err = resetMFA(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "nieznane polecenie %q (dostępne: serve, bootstrap-admin, reset-password, reset-mfa)\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		log.Error("zakończono z błędem", "err", err)
		os.Exit(1)
	}
}

func openStore(ctx context.Context, log *slog.Logger) (*store.PG, error) {
	url := os.Getenv("SIEM_API_DB_URL")
	if url == "" {
		return nil, errors.New("brak SIEM_API_DB_URL (adres bazy Saga, postgres://…)")
	}
	var db *store.PG
	if err := svc.Retry(ctx, log, "połączenie z bazą Saga", func() error {
		var err error
		db, err = store.Open(ctx, url)
		return err
	}); err != nil {
		return nil, err
	}
	applied, err := db.Migrate(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, m := range applied {
		log.Info("zastosowano migrację bazy", "migration", m)
	}
	return db, nil
}

func serve(log *slog.Logger) error {
	ctx, stop := svc.Context()
	defer stop()

	db, err := openStore(ctx, log)
	if err != nil {
		return err
	}
	defer db.Close()

	cert, err := tls.LoadX509KeyPair(svc.Env("SIEM_TLS_CERT", "/certs/server.crt"), svc.Env("SIEM_TLS_KEY", "/certs/server.key"))
	if err != nil {
		return fmt.Errorf("certyfikat panelu: %w", err)
	}
	ui := web.FS()
	if ui == nil {
		log.Warn("frontend nie został zbudowany – panel pokaże stronę zastępczą (cd panel/web && npm ci && npm run build)")
	}

	// Bifröst: rejestracja agentów tokenem (wymaga CA agentów z siem-pki agents-ca).
	enrollment := &api.Enrollment{
		AgentExe:     svc.Env("SIEM_AGENT_EXE", "/agent-dist/vardr-agent.exe"),
		RootCA:       svc.Env("SIEM_ROOT_CA", "/certs/ca.crt"),
		PublicServer: os.Getenv("SIEM_PUBLIC_SERVER"),
	}
	agentsCA := svc.Env("SIEM_AGENTS_CA_CERT", "/certs/agents-ca.crt")
	if signer, err := enroll.LoadSigner(agentsCA, svc.Env("SIEM_AGENTS_CA_KEY", "/certs/agents-ca.key")); err == nil {
		enrollment.Signer = signer
		log.Info("rejestracja agentów tokenem włączona", "agents_ca", signer.CA.Subject.CommonName, "public_server", enrollment.PublicServer)
	} else {
		log.Warn("rejestracja agentów tokenem wyłączona – brak CA agentów", "err", err)
	}
	if enrollment.PublicServer == "" {
		log.Warn("brak SIEM_PUBLIC_SERVER – paczki instalacyjne nie będą zawierały adresu serwera")
	}

	// Certyfikat klienta jest opcjonalny: wymaga go tylko odnowienie
	// certyfikatu agenta (/enroll/v1/renew); przeglądarki logują się hasłem.
	clientCAs := x509.NewCertPool()
	for _, f := range []string{enrollment.RootCA, agentsCA} {
		if data, err := os.ReadFile(f); err == nil {
			clientCAs.AppendCertsFromPEM(data)
		}
	}
	apiServer := &api.Server{Store: db, Log: log, UI: ui, Enroll: enrollment}

	// Dekodery syslog (strefa nagłówków bez strefy jak w normalizatorze).
	syslogLoc, err := time.LoadLocation(svc.Env("SIEM_SYSLOG_TZ", "Europe/Warsaw"))
	if err != nil {
		return fmt.Errorf("SIEM_SYSLOG_TZ: %w", err)
	}
	decoders := &api.Decoders{Store: db, Loc: syslogLoc}
	apiServer.Decoders = decoders
	quarantine := &api.Quarantine{Store: db, Log: log}
	apiServer.Quarantine = quarantine
	identities := &api.Identities{Store: db}
	apiServer.Identities = identities
	apiServer.Backups = db
	// Drugi składnik logowania (TOTP): klucz szyfrujący sekrety z pliku
	// (deploy.sh tworzy certs/mfa.key); bez klucza – logowanie samym hasłem.
	if keyFile := svc.Env("SIEM_MFA_KEY_FILE", "/certs/mfa.key"); keyFile != "" {
		if data, err := os.ReadFile(keyFile); err != nil {
			log.Warn("brak klucza MFA – drugi składnik logowania wyłączony", "file", keyFile, "err", err)
		} else if key, err := auth.ParseMFAKey(string(data)); err != nil {
			return err
		} else {
			apiServer.MFA, apiServer.MFAKey = db, key
		}
	}
	if n, err := db.AbortRunningQuarantineJobs(ctx); err != nil {
		return err
	} else if n > 0 {
		log.Warn("zlecenia ponownego przetwarzania kwarantanny przerwane restartem panelu", "jobs", n)
	}

	// Mímir: wyszukiwarka zdarzeń (ClickHouse, konto tylko do odczytu).
	if chUser := os.Getenv("SIEM_CLICKHOUSE_USER"); chUser != "" {
		var searcher *events.Searcher
		if err := svc.Retry(ctx, log, "połączenie z ClickHouse (wyszukiwarka)", func() error {
			var err error
			searcher, err = events.Open(ctx, svc.Env("SIEM_CLICKHOUSE_ADDR", "clickhouse:9000"), chUser, os.Getenv("SIEM_CLICKHOUSE_PASSWORD"))
			return err
		}); err != nil {
			return err
		}
		apiServer.Events = searcher
		apiServer.RuleTester = searcher
		decoders.Samples = searcher
		quarantine.Source = searcher
		identities.People = searcher
		log.Info("wyszukiwarka zdarzeń włączona", "user", chUser)
	} else {
		log.Warn("brak SIEM_CLICKHOUSE_USER – wyszukiwarka zdarzeń wyłączona")
	}

	// Urd: stan archiwum NIS2 (schemat urd w Sadze zakłada archiwizator;
	// panel tylko czyta i zleca weryfikację).
	archive, err := urd.OpenPG(ctx, os.Getenv("SIEM_API_DB_URL"))
	if err != nil {
		return err
	}
	defer archive.Close()
	apiServer.Archive = archive
	apiServer.ExportDir = os.Getenv("SIEM_ARCHIVE_EXPORT_DIR")

	// Powiadomienia: kanały z panelu, kotwica archiwum raz na dobę i przekaźnik
	// alertów Grafany (wewnętrzny adres, tylko w sieci stosu, z tokenem).
	notifySvc := &notify.Service{Store: db, Log: log}
	relayToken := os.Getenv("SIEM_ALERT_RELAY_TOKEN")
	anchorHour, err := svc.EnvInt("SIEM_ANCHOR_HOUR", 7)
	if err != nil || anchorHour < 0 || anchorHour > 23 {
		return fmt.Errorf("SIEM_ANCHOR_HOUR: godzina 0–23")
	}
	loc, err := time.LoadLocation(svc.Env("SIEM_ANCHOR_TZ", "Europe/Warsaw"))
	if err != nil {
		return fmt.Errorf("SIEM_ANCHOR_TZ: %w", err)
	}
	anchor := &notify.Anchor{Svc: notifySvc, Archive: archive, Store: db, Log: log, Hour: anchorHour, Loc: loc}
	apiServer.Notify = &api.Notifications{Store: db, Svc: notifySvc, Anchor: anchor, RelayConfigured: relayToken != ""}
	go anchor.Run(ctx)

	// Gjallarhorn: alerty z detektora (schemat gjallarhorn) i wysyłka nowych
	// alertów z outboxa na kanały powiadomień.
	alertStore, err := alerts.Open(ctx, os.Getenv("SIEM_API_DB_URL"))
	if err != nil {
		return err
	}
	defer alertStore.Close()
	apiServer.GrafanaURL = strings.TrimRight(svc.Env("SIEM_GRAFANA_URL", ""), "/")
	if u := svc.Env("SIEM_PROMETHEUS_URL", ""); u != "" {
		apiServer.Status = &status.Prometheus{URL: u}
	}
	apiServer.Alerts = alertStore
	apiServer.RuleAdmin = alertStore
	panelLink := ""
	if ps := os.Getenv("SIEM_PUBLIC_SERVER"); ps != "" {
		panelLink = "https://" + ps + ":8444"
	}
	// Burza alertów: SIEM_ALERT_NOTIFY_PER_RULE osobnych powiadomień na regułę
	// w SIEM_ALERT_NOTIFY_WINDOW (domyślnie 5 w 10 min, 0 = bez limitu); reszta zbiorczo.
	perRule, err := svc.EnvInt("SIEM_ALERT_NOTIFY_PER_RULE", 5)
	if err != nil {
		return err
	}
	if perRule == 0 {
		perRule = -1
	}
	window, err := svc.EnvDuration("SIEM_ALERT_NOTIFY_WINDOW", 10*time.Minute)
	if err != nil {
		return err
	}
	ruleInfo := func(id string) (alerts.RuleInfo, bool) {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		r, err := alertStore.Rule(c, id)
		return r, err == nil
	}
	go (&notify.AlertSender{Store: alertStore, Svc: notifySvc, Log: log, PanelURL: panelLink, PerRule: perRule, Window: window,
		Rule: ruleInfo}).Run(ctx)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			if n, err := db.PruneNotifyLog(ctx, time.Now().Add(-90*24*time.Hour)); err != nil && ctx.Err() == nil {
				log.Warn("sprzątanie dziennika wysyłek nieudane", "err", err)
			} else if n > 0 {
				log.Info("usunięto stare wpisy dziennika wysyłek", "count", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	if relayToken != "" {
		relay := &http.Server{Addr: svc.Env("SIEM_API_INTERNAL_LISTEN", ":8081"), ReadHeaderTimeout: 10 * time.Second,
			Handler: notifySvc.GrafanaHandler(relayToken)}
		go func() {
			log.Info("przekaźnik alertów Grafany nasłuchuje (tylko sieć stosu)", "addr", relay.Addr)
			if err := relay.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("przekaźnik alertów zatrzymany", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			_ = relay.Close()
		}()
	} else {
		log.Warn("brak SIEM_ALERT_RELAY_TOKEN – alerty Grafany nie będą przekazywane na kanały powiadomień")
	}
	srv := &http.Server{
		Addr:    svc.Env("SIEM_API_LISTEN", ":8444"),
		Handler: apiServer.Handler(),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// Huginn: heartbeaty agentów z NATS (publikuje je siem-ingest).
	if natsURL := os.Getenv("SIEM_NATS_URL"); natsURL != "" {
		// Bez NATS panel i przekaźnik alertów Grafany mają działać dalej: połączenie
		// zestawia się w tle (etap 8: awaria NATS po restarcie VM wyłączała też
		// panel – i powiadomienie o awarii nie miało którędy wyjść).
		nc, err := nats.Connect(natsURL, nats.Name("siem-api"), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second),
			nats.RetryOnFailedConnect(true))
		if err != nil {
			return fmt.Errorf("NATS: %w", err)
		}
		defer nc.Close()
		js, err := jetstream.New(nc)
		if err != nil {
			return err
		}
		// Unieważnienia certyfikatów: zapis do NATS KV (czyta je siem-ingest),
		// przy starcie synchronizacja z bazą (np. po odtworzeniu NATS).
		enrollment.Revoke = func(ctx context.Context, serials []string, reason string) error {
			kv, err := fleet.EnsureRevoked(ctx, js)
			if err != nil {
				return err
			}
			for _, s := range serials {
				if _, err := kv.PutString(ctx, s, reason); err != nil {
					return err
				}
			}
			return nil
		}
		// Tożsamości: zmiana od razu do NATS KV, wyrównanie przy starcie i co 5 min.
		identities.Publish = func(ctx context.Context, c identity.Config) error {
			kv, err := identity.Ensure(ctx, js)
			if err != nil {
				return err
			}
			return identity.Publish(ctx, kv, c)
		}
		go func() {
			sync := func() error {
				c, err := identities.Config(ctx)
				if err != nil {
					return err
				}
				return identities.Publish(ctx, c)
			}
			if svc.Retry(ctx, log, "synchronizacja tożsamości", sync) != nil {
				return
			}
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := sync(); err != nil {
						log.Warn("synchronizacja tożsamości z NATS nieudana", "err", err)
					}
				}
			}
		}()
		// Kwarantanna: części zleceń do normalizatora (request-reply).
		quarantine.Request = func(ctx context.Context, data []byte) ([]byte, error) {
			m, err := nc.RequestWithContext(ctx, reprocess.Subject, data)
			if err != nil {
				return nil, err
			}
			return m.Data, nil
		}
		// Dekodery z panelu: zmiana od razu do NATS KV (czytają ją normalizatory),
		// a co 5 minut i przy starcie – wyrównanie magazynu do bazy.
		decoders.Publish = func(ctx context.Context, id string, c *decode.Custom) error {
			kv, err := decodekv.Ensure(ctx, js)
			if err != nil {
				return err
			}
			if c == nil {
				if err := kv.Delete(ctx, id); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
					return err
				}
				return nil
			}
			return decodekv.Put(ctx, kv, id, *c)
		}
		go func() {
			sync := func() error {
				all, err := decoders.All(ctx)
				if err != nil {
					return err
				}
				kv, err := decodekv.Ensure(ctx, js)
				if err != nil {
					return err
				}
				return decodekv.Sync(ctx, kv, all)
			}
			if svc.Retry(ctx, log, "synchronizacja dekoderów", sync) != nil {
				return
			}
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := sync(); err != nil {
						log.Warn("synchronizacja dekoderów z NATS nieudana", "err", err)
					}
				}
			}
		}()
		go func() {
			_ = svc.Retry(ctx, log, "synchronizacja unieważnień", func() error {
				serials, err := db.RevokedSerials(ctx, time.Now())
				if err != nil {
					return err
				}
				return enrollment.Revoke(ctx, serials, "unieważniony (synchronizacja z bazą)")
			})
		}()
		go func() {
			var cons jetstream.Consumer
			if err := svc.Retry(ctx, log, "strumień heartbeatów", func() error {
				var err error
				cons, err = fleet.Ensure(ctx, js)
				return err
			}); err != nil {
				return
			}
			log.Info("odbiór heartbeatów agentów uruchomiony")
			// Deinstalacja tokenem z panelu: certyfikaty agenta unieważnione
			// (klucz zostaje na dysku – bez certyfikatu jest bezużyteczny).
			retire := func(ctx context.Context, u store.TokenUse) error {
				reason := "deinstalacja tokenem " + u.TokenID
				serials, err := db.RevokeAgentCerts(ctx, u.AgentID, reason)
				if err != nil {
					return err
				}
				if len(serials) > 0 {
					if err := enrollment.Revoke(ctx, serials, reason); err != nil {
						return err
					}
				}
				return db.Audit(ctx, store.AuditEntry{Action: "agent_retired", Target: u.AgentID, Details: map[string]any{
					"reason": "deinstalacja tokenem", "token": u.TokenID, "by": u.User, "serials": serials}})
			}
			fleetsync.Run(ctx, log, cons, db, retire)
		}()
	} else {
		log.Warn("brak SIEM_NATS_URL – lista agentów nie będzie aktualizowana")
	}

	// Sprzątanie wygasłych sesji.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if n, err := db.DeleteExpiredSessions(ctx, time.Now()); err != nil {
					log.Warn("sprzątanie sesji nieudane", "err", err)
				} else if n > 0 {
					log.Info("usunięto wygasłe sesje", "count", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()

	log.Info("panel Hliðskjálf nasłuchuje", "addr", srv.Addr, "ui", ui != nil)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// bootstrapAdmin zakłada pierwsze konto administratora – tylko gdy w bazie
// nie ma jeszcze żadnego aktywnego administratora.
func bootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	username := fs.String("username", "admin", "login administratora")
	_ = fs.Parse(args)

	ctx := context.Background()
	db, err := openStore(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	defer db.Close()
	if n, err := db.CountActiveAdmins(ctx); err != nil {
		return err
	} else if n > 0 {
		return errors.New("w bazie jest już aktywny administrator – dodawaj konta w panelu albo użyj reset-password")
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		return err
	}
	u, err := db.CreateUser(ctx, store.User{Username: *username, DisplayName: "Administrator",
		Role: store.RoleAdmin, PasswordHash: hash, MustChangePassword: true})
	if err != nil {
		return err
	}
	_ = db.Audit(ctx, store.AuditEntry{Username: "(konsola)", Action: "user_created", Target: u.Username,
		Details: map[string]any{"role": u.Role, "via": "bootstrap-admin"}})
	printTemp(u.Username, temp)
	return nil
}

// resetPassword ustawia nowe hasło startowe (np. gdy administrator zapomniał
// hasła) i zamyka sesje konta.
func resetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	username := fs.String("username", "", "login konta")
	_ = fs.Parse(args)
	if *username == "" {
		return errors.New("podaj -username")
	}
	ctx := context.Background()
	db, err := openStore(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	defer db.Close()
	u, err := db.UserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("konto %s: %w", *username, err)
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		return err
	}
	if err := db.SetPassword(ctx, u.ID, hash, true); err != nil {
		return err
	}
	if err := db.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		return err
	}
	_ = db.Audit(ctx, store.AuditEntry{Username: "(konsola)", Action: "password_reset", Target: u.Username,
		Details: map[string]any{"via": "reset-password"}})
	printTemp(u.Username, temp)
	return nil
}

// resetMFA usuwa drugi składnik konta i zamyka jego sesje – awaryjnie, gdy
// jedyny administrator zgubił telefon i kody zapasowe (w panelu reset robi
// inny administrator). Przy wymogu MFA konto skonfiguruje aplikację od nowa
// przy najbliższym logowaniu.
func resetMFA(args []string) error {
	fs := flag.NewFlagSet("reset-mfa", flag.ExitOnError)
	username := fs.String("username", "", "login konta")
	_ = fs.Parse(args)
	if *username == "" {
		return errors.New("podaj -username")
	}
	ctx := context.Background()
	db, err := openStore(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	defer db.Close()
	u, err := db.UserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("konto %s: %w", *username, err)
	}
	if err := db.DisableMFA(ctx, u.ID); err != nil {
		return err
	}
	if err := db.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		return err
	}
	_ = db.Audit(ctx, store.AuditEntry{Username: "(konsola)", Action: "mfa_reset", Target: u.Username,
		Details: map[string]any{"via": "reset-mfa"}})
	fmt.Printf("\nKonto %s: drugi składnik usunięty, sesje zakończone. Przy logowaniu skonfiguruj aplikację od nowa.\n\n", u.Username)
	return nil
}

func printTemp(username, temp string) {
	fmt.Printf("\nKonto: %s\nHasło startowe: %s\n\nZaloguj się w panelu i ustaw własne hasło (wymagane przy pierwszym logowaniu).\n"+
		"To hasło nie jest nigdzie zapisane – nie da się go odczytać ponownie.\n\n", username, temp)
}
