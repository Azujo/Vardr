// Command siem-api to backend panelu Hliðskjálf: API (logowanie, konta,
// audyt) i aplikacja React, po HTTPS. Dane w bazie Saga (PostgreSQL).
//
// Polecenia:
//
//	siem-api                                    uruchomienie serwera (domyślnie)
//	siem-api bootstrap-admin -username admin    pierwsze konto administratora
//	siem-api reset-password -username jan       nowe hasło startowe dla konta
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
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/fleet"
	"siem/internal/svc"
	"siem/panel/internal/api"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
	"siem/panel/internal/enroll"
	"siem/panel/internal/events"
	"siem/panel/internal/fleetsync"
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
	default:
		fmt.Fprintf(os.Stderr, "nieznane polecenie %q (dostępne: serve, bootstrap-admin, reset-password)\n", cmd)
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
		AgentExe:     svc.Env("SIEM_AGENT_EXE", "/agent-dist/siem_agent.exe"),
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
		log.Info("wyszukiwarka zdarzeń włączona", "user", chUser)
	} else {
		log.Warn("brak SIEM_CLICKHOUSE_USER – wyszukiwarka zdarzeń wyłączona")
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
		nc, err := nats.Connect(natsURL, nats.Name("siem-api"), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
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
			fleetsync.Run(ctx, log, cons, db)
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

func printTemp(username, temp string) {
	fmt.Printf("\nKonto: %s\nHasło startowe: %s\n\nZaloguj się w panelu i ustaw własne hasło (wymagane przy pierwszym logowaniu).\n"+
		"To hasło nie jest nigdzie zapisane – nie da się go odczytać ponownie.\n\n", username, temp)
}
