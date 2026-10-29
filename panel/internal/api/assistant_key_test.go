// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Klucz API asystenta w bazie tylko zaszyfrowany; zapis otwartym tekstem
// (sprzed szyfrowania) szyfrowany przy pierwszym odczycie.
func TestAssistantKeyEncrypted(t *testing.T) {
	var srv *Server
	var kv map[string]string
	e, _ := newAIEnvWith(t, func(s *Server) {
		s.MFAKey = bytes.Repeat([]byte{7}, 32)
		kv = s.Settings.(*memSettings).kv
		kv[assistantKey] = `{"enabled":false,"model":"m","api_key":"stary-klucz"}`
		srv = s
	})
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	if code, out, _ := a.do("GET", "/api/v1/ai/assistant", nil); code != 200 || out["assistant"].(map[string]any)["has_api_key"] != true {
		t.Fatalf("odczyt: %d %v", code, out)
	}
	if strings.Contains(kv[assistantKey], "stary-klucz") || !strings.Contains(kv[assistantKey], `"api_key_enc"`) {
		t.Fatalf("stary zapis nie zaszyfrowany: %s", kv[assistantKey])
	}
	if got, err := srv.assistantSettings(context.Background()); err != nil || got.APIKey != "stary-klucz" || got.Model != "m" {
		t.Fatalf("odszyfrowanie: %v %+v", err, got)
	}

	set := map[string]any{"enabled": false, "model": "m2"}
	if code, out, _ := a.do("PUT", "/api/v1/ai/assistant", map[string]any{"assistant": set, "api_key": "nowy-klucz",
		"password": "bardzo-tajne-haslo-1"}); code != 200 {
		t.Fatalf("zapis: %d %v", code, out)
	}
	if strings.Contains(kv[assistantKey], "nowy-klucz") {
		t.Fatalf("klucz otwartym tekstem: %s", kv[assistantKey])
	}
	if got, _ := srv.assistantSettings(context.Background()); got.APIKey != "nowy-klucz" || got.Model != "m2" {
		t.Fatalf("po zapisie: %+v", got)
	}
	// Zmieniony klucz MFA: czytelny błąd zamiast śmieci.
	srv.MFAKey = bytes.Repeat([]byte{8}, 32)
	if _, err := srv.assistantSettings(context.Background()); err == nil || !strings.Contains(err.Error(), "enter it again") {
		t.Fatalf("inny klucz MFA: %v", err)
	}
}
