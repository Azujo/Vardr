// SPDX-License-Identifier: AGPL-3.0-or-later

// Program vardr-mcp to serwer Model Context Protocol dla Vardra (wersja
// 1.4): klient AI (Claude Desktop, LM Studio, Ollama z klientem MCP…)
// uruchamia go na komputerze analityka, a on zamienia wywołania narzędzi
// na zapytania do API panelu z tokenem API rodzaju „ai”.
//
// vardr-mcp nie ma własnych uprawnień: wszystkie ograniczenia (profil
// tokenu, polityka AI – narzędzia, zakres danych, maskowanie – audyt
// i historia zapytań) egzekwuje serwer. Wszystkie narzędzia tylko czytają.
//
// Konfiguracja (zmienne środowiskowe, ustawiane w kliencie AI):
//
//	VARDR_URL         adres panelu, np. https://siem.firma.local:8444
//	VARDR_TOKEN       token API rodzaju AI (albo VARDR_TOKEN_FILE – plik z tokenem)
//	VARDR_CA_FILE     certyfikat CA serwera (PEM), gdy nie jest w systemie
//	VARDR_INSECURE=1  bez sprawdzania certyfikatu (tylko laboratorium)
//
// vardr-mcp setup – kreator: pyta o adres i token, sprawdza połączenie
// i dopisuje serwer do konfiguracji Claude Desktop (także po dwukliku).
// vardr-mcp check – sprawdza połączenie, token i politykę AI.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"siem/internal/mcp"
)

// version_ ustawiane przy budowaniu (-ldflags "-X main.version_=…").
var version_ = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(os.Args) > 1 && strings.TrimLeft(os.Args[1], "-") == "version" {
		fmt.Println("vardr-mcp", version_)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		os.Exit(setup(ctx, os.Args[2:], false))
	}
	// Dwuklik w Eksploratorze (konsola, bez konfiguracji) – kreator zamiast
	// serwera MCP, który czekałby w pustym oknie na JSON-RPC.
	if len(os.Args) == 1 && os.Getenv("VARDR_URL") == "" && isConsole(os.Stdin) {
		os.Exit(setup(ctx, nil, true))
	}
	c, err := clientFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vardr-mcp:", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "check":
			os.Exit(check(ctx, c))
		default:
			fmt.Fprintln(os.Stderr, "usage: vardr-mcp [setup|check|version]  (no arguments – MCP server on stdio)")
			os.Exit(2)
		}
	}
	if c.insecure {
		log.Warn("VARDR_INSECURE=1 – the server certificate is not verified (lab only)")
	}
	log.Info("vardr-mcp started", "version", version_, "server", c.base)
	info := mcp.Info{Name: "vardr-mcp", Title: "Vardr SIEM (read-only)", Version: version_}
	if err := mcp.Serve(ctx, os.Stdin, os.Stdout, &mcp.Server{C: c, Log: log}, info, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("vardr-mcp stopped", "err", err)
		os.Exit(1)
	}
}

func clientFromEnv() (*client, error) {
	token := strings.TrimSpace(os.Getenv("VARDR_TOKEN"))
	if f := os.Getenv("VARDR_TOKEN_FILE"); token == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("VARDR_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	return newClient(os.Getenv("VARDR_URL"), token, os.Getenv("VARDR_CA_FILE"), os.Getenv("VARDR_INSECURE") == "1")
}

func newClient(base, token, caFile string, insecure bool) (*client, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if !strings.HasPrefix(base, "https://") {
		return nil, errors.New("VARDR_URL must be the panel address starting with https://")
	}
	if !strings.HasPrefix(token, "vardr_") {
		return nil, errors.New("set VARDR_TOKEN (or VARDR_TOKEN_FILE) to an API token of kind AI from the panel (vardr_…)")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // tylko laboratorium, jawnie ustawione
	} else if f := caFile; f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("VARDR_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("VARDR_CA_FILE: no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	return &client{base: base, token: token, insecure: insecure,
		http: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

// check: połączenie, token i polityka AI – do sprawdzenia konfiguracji.
func check(ctx context.Context, c *client) int {
	var self struct {
		Name      string    `json:"name"`
		Kind      string    `json:"kind"`
		Profile   string    `json:"profile"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.Get(ctx, "/api/v1/api-tokens/self", nil, &self); err != nil {
		fmt.Fprintln(os.Stderr, "token:", err)
		return 1
	}
	fmt.Printf("token: %s (kind %s, profile %s, valid until %s)\n", self.Name, self.Kind, self.Profile, self.ExpiresAt.Format(time.DateOnly))
	if self.Kind != "ai" {
		fmt.Println("warning: this is not an AI token – the panel's AI policy (tools, limits, masking) does not apply to it")
	}
	pol, err := mcp.FetchPolicy(ctx, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "AI policy:", err)
		return 1
	}
	var masked []string
	for _, k := range []string{"users", "hosts", "ips", "emails"} {
		if pol.Policy.Mask[k] {
			masked = append(masked, k)
		}
	}
	mask := "off"
	if len(masked) > 0 {
		mask = strings.Join(masked, ", ")
	}
	fmt.Printf("AI access: enabled=%v, period ≤ %d h, ≤ %d rows, masking: %s\n", pol.Policy.Enabled, pol.Policy.MaxRangeHours,
		pol.Policy.MaxRows, mask)
	var names []string
	for _, t := range (&mcp.Server{C: c}).ToolsFor(pol) {
		names = append(names, t.Name)
	}
	fmt.Println("tools:", strings.Join(names, ", "))
	if !pol.Policy.Enabled {
		fmt.Println("AI access is disabled in the panel (Administration → AI access)")
		return 1
	}
	return 0
}
