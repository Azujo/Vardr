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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"siem/internal/api"
	"siem/internal/api/auth"
	"siem/internal/api/store"
	"siem/internal/server/svc"
	"siem/web"
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
		log.Warn("frontend nie został zbudowany – panel pokaże stronę zastępczą (cd web && npm ci && npm run build)")
	}
	srv := &http.Server{
		Addr:              svc.Env("SIEM_API_LISTEN", ":8444"),
		Handler:           (&api.Server{Store: db, Log: log, UI: ui}).Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
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
