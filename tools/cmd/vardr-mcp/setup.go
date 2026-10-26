// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// setup – kreator dla Claude Desktop: adres panelu i token, test połączenia
// (check), token i certyfikat CA do katalogu konfiguracji użytkownika,
// wpis „vardr” w claude_desktop_config.json (z kopią zapasową, bez ruszania
// reszty pliku). Nic nie zapisuje, gdy test się nie powiedzie.
func setup(ctx context.Context, args []string, pause bool) (code int) {
	if pause {
		defer func() {
			fmt.Print("\nPress Enter to close this window.")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}()
	}
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	urlFlag := flags.String("url", os.Getenv("VARDR_URL"), "panel address, e.g. https://siem.example.local:8444")
	caFlag := flags.String("ca", os.Getenv("VARDR_CA_FILE"), "server CA certificate (PEM); \"-\" = system certificate store")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	in := bufio.NewReader(os.Stdin)

	fmt.Println("vardr-mcp", version_, "– connecting Claude Desktop to Vardr")
	fmt.Println("You need an API token of kind AI (panel: Administration → API tokens → New token → AI).")
	fmt.Println()

	base := strings.TrimSpace(*urlFlag)
	if base == "" {
		base = prompt(in, "Panel address (e.g. https://siem.example.local:8444): ")
	}
	if base != "" && !strings.Contains(base, "://") {
		base = "https://" + base
	}
	token := strings.TrimSpace(os.Getenv("VARDR_TOKEN"))
	if token == "" {
		fmt.Print("API token (vardr_…, input is hidden): ")
		token = strings.TrimSpace(readSecret(in))
	}
	ca := strings.TrimSpace(*caFlag)
	if ca == "" {
		if found := findCA(); found != "" {
			if a := prompt(in, fmt.Sprintf("Server CA certificate [%s] (Enter = use it, \"-\" = system store, or another path): ", found)); a != "" {
				ca = a
			} else {
				ca = found
			}
		} else {
			ca = prompt(in, "Server CA certificate vardr-ca.crt (path; Enter = system store): ")
		}
	}
	if ca == "-" {
		ca = ""
	}
	ca = strings.Trim(ca, `"`)

	c, err := newClient(base, token, ca, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\n", err)
		return 2
	}
	fmt.Println("\nChecking the connection…")
	if check(ctx, c) != 0 {
		fmt.Fprintln(os.Stderr, "\nNothing was saved. Fix the problem above and run vardr-mcp setup again.")
		return 1
	}

	dir, err := vardrDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	env := map[string]string{"VARDR_URL": c.base, "VARDR_TOKEN_FILE": filepath.Join(dir, "token")}
	if err := os.WriteFile(env["VARDR_TOKEN_FILE"], []byte(token+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "token:", err)
		return 1
	}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err == nil {
			env["VARDR_CA_FILE"] = filepath.Join(dir, "vardr-ca.crt")
			err = os.WriteFile(env["VARDR_CA_FILE"], pem, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "CA certificate:", err)
			return 1
		}
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "program path:", err)
		return 1
	}
	fmt.Println("\nToken and certificate saved in", dir)

	entry := map[string]any{"command": exe, "env": env}
	ok := 0
	for _, p := range claudeConfigs() {
		backup, err := addToClaudeConfig(p, entry)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Claude Desktop:", err)
			continue
		}
		ok++
		fmt.Println("Claude Desktop configuration updated:", p)
		if backup != "" {
			fmt.Println("  previous version:", backup)
		}
	}
	if ok == 0 {
		return 1
	}
	fmt.Println()
	fmt.Println("Done. Quit Claude Desktop completely (also from the system tray), start it again")
	fmt.Println("and ask in a chat, e.g. „What open alerts do I have in Vardr?”.")
	fmt.Println("Keep vardr-mcp.exe where it is – after moving it, run setup again.")
	return 0
}

func prompt(in *bufio.Reader, q string) string {
	fmt.Print(q)
	return strings.TrimSpace(readLine(in))
}

func readLine(in *bufio.Reader) string {
	s, _ := in.ReadString('\n')
	// Potok z PowerShella zaczyna się od BOM-u.
	return strings.TrimPrefix(strings.TrimRight(s, "\r\n"), "\ufeff")
}

// findCA: vardr-ca.crt obok programu albo najnowszy pobrany do Pobranych.
func findCA() string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Downloads"))
	}
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(d, "vardr-ca*.crt"))
		sort.Slice(m, func(i, j int) bool { return modTime(m[i]).After(modTime(m[j])) })
		if len(m) > 0 {
			return m[0]
		}
	}
	return ""
}

func modTime(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// vardrDir: %APPDATA%\Vardr (Windows), ~/Library/Application Support/Vardr, ~/.config/Vardr.
func vardrDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d = filepath.Join(d, "Vardr")
	return d, os.MkdirAll(d, 0o700)
}

const claudeConfigName = "claude_desktop_config.json"

// claudeConfigs: istniejące pliki konfiguracji Claude Desktop (wersja
// klasyczna w %APPDATA%\Claude, instalacja ze sklepu/MSIX w %LOCALAPPDATA%);
// gdy żadnego nie ma – plik w miejscu klasycznym.
func claudeConfigs() []string {
	var cand []string
	if d, err := os.UserConfigDir(); err == nil {
		cand = append(cand, filepath.Join(d, "Claude", claudeConfigName))
	}
	if local := os.Getenv("LOCALAPPDATA"); runtime.GOOS == "windows" && local != "" {
		for _, pat := range []string{
			filepath.Join(local, "Claude-Data", "*", claudeConfigName),
			filepath.Join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", claudeConfigName),
		} {
			m, _ := filepath.Glob(pat)
			cand = append(cand, m...)
		}
	}
	var out []string
	for _, p := range cand {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 && len(cand) > 0 {
		out = cand[:1]
	}
	return out
}

// addToClaudeConfig ustawia mcpServers.vardr, zachowując resztę pliku
// (ustawienia aplikacji, inne serwery MCP). Niepoprawnego JSON-u nie
// nadpisuje. Zwraca ścieżkę kopii zapasowej (pusta dla nowego pliku).
func addToClaudeConfig(path string, entry any) (string, error) {
	doc := map[string]json.RawMessage{}
	old, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		old = nil
	case err != nil:
		return "", err
	case len(bytes.TrimSpace(old)) > 0:
		if err := json.Unmarshal(old, &doc); err != nil {
			return "", fmt.Errorf("%s is not valid JSON (%v) – nothing was changed; fix the file or remove it and run setup again", path, err)
		}
	}
	servers := map[string]json.RawMessage{}
	if raw, ok := doc["mcpServers"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return "", fmt.Errorf("%s: mcpServers is not an object – nothing was changed", path)
		}
	}
	var err2 error
	if servers["vardr"], err2 = marshal(entry); err2 != nil {
		return "", err2
	}
	if doc["mcpServers"], err2 = marshal(servers); err2 != nil {
		return "", err2
	}
	out, err := marshalIndent(doc)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	backup := ""
	if old != nil {
		backup = path + ".vardr-" + time.Now().Format("20060102-150405") + ".bak"
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", err
		}
	}
	tmp := path + ".vardr-tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return backup, nil
}

// marshal bez zamiany <, >, & na <… – plik czyta i edytuje człowiek.
func marshal(v any) (json.RawMessage, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b.Bytes()), nil
}

func marshalIndent(v any) ([]byte, error) {
	raw, err := marshal(v)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := json.Indent(&b, raw, "", "  "); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// isConsole: standardowe wejście to terminal (dwuklik, ręczne uruchomienie),
// a nie potok od klienta MCP.
func isConsole(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
