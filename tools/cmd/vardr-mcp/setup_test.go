// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddToClaudeConfig(t *testing.T) {
	entry := map[string]any{"command": `C:\Vardr\vardr-mcp.exe`, "env": map[string]string{"VARDR_URL": "https://siem:8444"}}
	dir := t.TempDir()

	// Nowy plik (także w nieistniejącym katalogu) – bez kopii zapasowej.
	p := filepath.Join(dir, "Claude", claudeConfigName)
	backup, err := addToClaudeConfig(p, entry)
	if err != nil || backup != "" {
		t.Fatalf("new file: backup=%q err=%v", backup, err)
	}

	// Istniejący: ustawienia aplikacji i inne serwery MCP zostają, stary wpis vardr jest zastępowany.
	p = filepath.Join(dir, "existing.json")
	orig := `{"preferences":{"sidebarMode":"epitaxy","a<b":"x&y"},"mcpServers":{"other":{"command":"x"},"vardr":{"command":"old"}}}`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err = addToClaudeConfig(p, entry)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(backup); string(b) != orig {
		t.Fatalf("backup = %q", b)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), `\u003c`) || strings.Contains(string(raw), `\u0026`) {
		t.Errorf("HTML-escaped output: %s", raw)
	}
	var got struct {
		Preferences map[string]string `json:"preferences"`
		MCPServers  map[string]struct {
			Command string `json:"command"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Preferences["sidebarMode"] != "epitaxy" || got.Preferences["a<b"] != "x&y" {
		t.Errorf("preferences lost: %v", got.Preferences)
	}
	if got.MCPServers["other"].Command != "x" || got.MCPServers["vardr"].Command != `C:\Vardr\vardr-mcp.exe` {
		t.Errorf("mcpServers = %+v", got.MCPServers)
	}

	// Niepoprawny JSON (blok wklejony bez klucza) – plik nietknięty, bez kopii.
	p = filepath.Join(dir, "broken.json")
	broken := `{"preferences":{} {"mcpServers":{}}}`
	if err := os.WriteFile(p, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := addToClaudeConfig(p, entry); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("broken file: err=%v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != broken {
		t.Errorf("broken file was changed: %s", b)
	}
	if m, _ := filepath.Glob(p + ".vardr-*"); len(m) != 0 {
		t.Errorf("unexpected files: %v", m)
	}
}
