// Command entrasim to symulator Microsoft Graph (logi Entra ID) dla
// laboratorium – konektor Vardra łączy się z nim tak jak z prawdziwym
// API (internal/entrasim). Generuje tło (zwykłe logowania użytkowników)
// i scenariusze ataków na żądanie:
//
//	entrasim -listen :8080 -tenant lab -client-id vardr -secret-file entra.secret
//	curl -X POST 'http://127.0.0.1:8099/sim/scenario?name=spray'
//
// Scenariusze: normal, spray, brute, success-after-failures, foreign,
// mfa-fatigue, admin-role (parametry user=, attacker=).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"siem/internal/entrasim"
)

func main() {
	listen := flag.String("listen", ":8080", "adres nasłuchu")
	tenant := flag.String("tenant", "lab", "identyfikator tenanta")
	clientID := flag.String("client-id", "vardr", "identyfikator aplikacji")
	secretFile := flag.String("secret-file", "", "plik z sekretem aplikacji (wymagany)")
	domain := flag.String("domain", "azujo.pl", "domena kont (UPN)")
	users := flag.String("users", "jkowalski,anowak,pwisniewski,kwojcik,mkaminska,heimdall-lab", "konta (przecinki)")
	latency := flag.Duration("latency", 3*time.Minute, "najdłuższe opóźnienie pojawienia się logu w API (jak w Entra)")
	throttle := flag.Int("throttle", 7, "co N-te zapytanie o logi – 429 Too Many Requests (0 = bez)")
	background := flag.Duration("background", 2*time.Minute, "odstęp zwykłych logowań w tle (0 = bez tła)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "entrasim: -secret-file:", err)
		os.Exit(1)
	}
	sim := entrasim.New(entrasim.Config{Tenant: *tenant, ClientID: *clientID, ClientSecret: strings.TrimSpace(string(secret)),
		Domain: *domain, Users: strings.Split(*users, ","), Latency: *latency, ThrottleN: *throttle})
	if *background > 0 {
		go func() {
			us := strings.Split(*users, ",")
			for {
				u := us[mrand.IntN(len(us))]
				sim.AddSignIn(entrasim.SignIn{User: u, IP: fmt.Sprintf("192.168.88.%d", 100+mrand.IntN(50)),
					Device: "DESKTOP-" + strings.ToUpper(u[:min(3, len(u))])})
				time.Sleep(*background)
			}
		}()
	}
	log.Info("symulator Microsoft Graph", "listen", *listen, "tenant", *tenant, "domain", *domain, "latency", latency.String())
	srv := &http.Server{Addr: *listen, Handler: sim, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "entrasim:", err)
		os.Exit(1)
	}
}
