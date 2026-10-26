// SPDX-License-Identifier: AGPL-3.0-or-later

// Package perm to uprawnienia panelu: moduły z uporządkowanymi poziomami
// (wyższy obejmuje niższe) i profile – przypisanie poziomu do modułów.
// Profile wbudowane (administrator, analityk, obserwator) odpowiadają
// dawnym rolom; administrator ma zawsze wszystko, także moduły dodane
// w przyszłych wersjach.
package perm

import (
	"slices"

	"siem/internal/lang"
)

// Level to poziom uprawnienia w module.
type Level struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Module to obszar panelu z poziomami od najniższego.
type Module struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Help   string  `json:"help"`
	Levels []Level `json:"levels"`
}

var (
	read   = Level{"read", "odczyt"}
	write  = Level{"write", "zmiana"}
	test   = Level{"test", "test"}
	export = Level{"export", "eksport"}
)

// Modules: wszystkie moduły panelu (kolejność – macierz w panelu).
var Modules = []Module{
	{"alerts", "Alerty", "lista i szczegóły alertów; zmiana: obsługa (status, przypisanie, notatki)", []Level{read, {"write", "obsługa"}}},
	{"incidents", "Incydenty i zgłoszenia NIS2", "obsługa: zakładanie, alerty, notatki, zgłoszenia do CSIRT", []Level{read, {"write", "obsługa"}}},
	{"events", "Zdarzenia (Mímir)", "wyszukiwarka zdarzeń", []Level{read}},
	{"rules", "Reguły detekcji i MITRE", "test: test reguły na historii i kreator korelacji; zmiana: włączanie, próby, reguły z panelu", []Level{read, test, write}},
	{"agents", "Agenci i grupy (Huginn)", "zmiana: grupy, usuwanie agentów, tokeny deinstalacji", []Level{read, write}},
	{"deploy", "Wdrażanie agentów (Bifröst)", "tokeny rejestracji i instalatory MSI", []Level{read, write}},
	{"archive", "Archiwum NIS2 (Urd)", "eksport: paczki dla audytora; zmiana: polityka, weryfikacja, odtworzenie", []Level{read, export, write}},
	{"decoders", "Dekodery syslog", "test: próbki i test dekodera; zmiana: edycja", []Level{read, test, write}},
	{"quarantine", "Kwarantanna", "zmiana: ponowne przetwarzanie", []Level{read, {"write", "ponowne przetwarzanie"}}},
	{"identities", "Tożsamości", "domeny organizacji, aliasy kont", []Level{read, write}},
	{"system", "Stan systemu", "zdrowie usług (Himinbjörg)", []Level{read}},
	{"notify", "Powiadomienia", "kanały (Discord, Teams, webhook)", []Level{read, write}},
	{"backup", "Kopie zapasowe", "ustawienia, zlecenia i przywracanie", []Level{read, write}},
	{"users", "Użytkownicy i bezpieczeństwo", "konta, profile uprawnień, wymóg MFA; zmiana = administrator panelu", []Level{read, write}},
	{"audit", "Dziennik audytu", "", []Level{read}},
}

// Set to uprawnienia profilu: moduł → najwyższy przyznany poziom.
type Set map[string]string

func module(key string) *Module {
	for i := range Modules {
		if Modules[i].Key == key {
			return &Modules[i]
		}
	}
	return nil
}

func levelIndex(m *Module, level string) int {
	return slices.IndexFunc(m.Levels, func(l Level) bool { return l.Key == level })
}

// Has: profil ma w module co najmniej dany poziom.
func (s Set) Has(mod, level string) bool {
	m := module(mod)
	if m == nil {
		return false
	}
	need := levelIndex(m, level)
	got, ok := s[mod]
	if !ok || need < 0 {
		return false
	}
	return levelIndex(m, got) >= need
}

// Admin: profil administratora panelu (zarządza kontami i bezpieczeństwem) –
// wymóg MFA „administratorzy”, ochrona przed usunięciem ostatniego.
func (s Set) Admin() bool { return s.Has("users", "write") }

// Validate sprawdza moduły i poziomy (nieznane – błąd; brak modułu = brak dostępu).
func (s Set) Validate() error {
	for mod, level := range s {
		m := module(mod)
		if m == nil {
			return lang.Errorf("nieznany moduł %q", "unknown module %q", mod)
		}
		if levelIndex(m, level) < 0 {
			return lang.Errorf("moduł %s: nieznany poziom %q", "module %s: unknown level %q", mod, level)
		}
	}
	return nil
}

// Identyfikatory profili wbudowanych (dawne role; wartości users.role).
const (
	Admin   = "admin"
	Analyst = "analyst"
	Viewer  = "viewer"
)

// all: najwyższy poziom każdego modułu.
func all() Set {
	s := Set{}
	for _, m := range Modules {
		s[m.Key] = m.Levels[len(m.Levels)-1].Key
	}
	return s
}

// Builtin: profile wbudowane – nie do zmiany ani usunięcia (można je skopiować).
var Builtin = []struct {
	ID, Name, Description string
	Perms                 func() Set
}{
	{Admin, "Administrator", "pełny dostęp, także do kont, profili i ustawień bezpieczeństwa", all},
	{Analyst, "Analityk", "praca z alertami i danymi: obsługa alertów, testy reguł i dekoderów, bez administracji", func() Set {
		return Set{"alerts": "write", "incidents": "write", "events": "read", "rules": "test", "agents": "read", "archive": "read",
			"decoders": "test", "quarantine": "read", "identities": "read", "system": "read"}
	}},
	{Viewer, "Obserwator", "tylko odczyt alertów, zdarzeń, reguł i stanu systemu", func() Set {
		return Set{"alerts": "read", "incidents": "read", "events": "read", "rules": "read", "agents": "read", "archive": "read",
			"decoders": "read", "quarantine": "read", "identities": "read", "system": "read"}
	}},
}

// BuiltinSet zwraca uprawnienia profilu wbudowanego (nil – to nie wbudowany).
func BuiltinSet(id string) Set {
	for _, b := range Builtin {
		if b.ID == id {
			return b.Perms()
		}
	}
	return nil
}
