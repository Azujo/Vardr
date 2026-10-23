// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lang to język tekstów tworzonych poza panelem: usługi serwera
// piszą komunikaty widoczne w panelu w języku systemu (ustawienie
// administratora, widok public.system_language), a programy wiersza
// poleceń na Windows (agent, czytnik eksportu) – w języku Windows.
// Logi usług są po angielsku.
package lang

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Default: język bez ustawienia (dotychczasowe instalacje).
const Default = "pl"

// Pick zwraca tekst w języku lang (polski dla każdego innego niż en).
func Pick(lang, pl, en string) string {
	if lang == "en" {
		return en
	}
	return pl
}

// OS zwraca język programu wiersza poleceń: VARDR_LANG (pl, en), potem
// język interfejsu systemu (Windows) albo LANG/LC_ALL; polski tylko dla
// polskiego systemu, każdy inny – angielski.
func OS() string {
	if v := strings.ToLower(os.Getenv("VARDR_LANG")); v == "pl" || v == "en" {
		return v
	}
	if strings.HasPrefix(strings.ToLower(osLanguage()), "pl") {
		return "pl"
	}
	return "en"
}

func envLanguage() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// Error to błąd z komunikatem w dwóch językach (walidacja ustawień, reguł,
// dekoderów – panel pokazuje go w języku konta). Error() zwraca polski
// (dotychczasowe komunikaty), English() – angielski.
type Error struct {
	pl, en string
	err    error // opakowany (%w)
}

func (e *Error) Error() string   { return e.pl }
func (e *Error) English() string { return e.en }
func (e *Error) Unwrap() error   { return e.err }

// LogValue: w logach (slog) błąd po angielsku – logi usług są po angielsku.
func (e *Error) LogValue() slog.Value { return slog.StringValue(e.en) }

// Errorf tworzy Error. Argumenty-błędy wchodzą do wersji angielskiej
// swoim angielskim tekstem (English), więc opakowanie zachowuje oba języki.
func Errorf(pl, en string, args ...any) error {
	enArgs := make([]any, len(args))
	var wrapped error
	for i, a := range args {
		enArgs[i] = a
		if e, ok := a.(error); ok {
			enArgs[i] = englishErr{e}
			if wrapped == nil {
				wrapped = e
			}
		}
	}
	return &Error{pl: fmt.Errorf(pl, args...).Error(), en: fmt.Errorf(en, enArgs...).Error(), err: wrapped}
}

// englishErr: błąd podstawiany do wersji angielskiej (%v, %s, %w).
type englishErr struct{ err error }

func (e englishErr) Error() string { return English(e.err) }
func (e englishErr) Unwrap() error { return e.err }

// English zwraca angielski tekst błędu: z Error (także opakowanego przez
// fmt.Errorf – wtedy prefiks zostaje bez zmian), w pozostałych – Error().
func English(err error) string {
	if err == nil {
		return ""
	}
	var le *Error
	if !errors.As(err, &le) {
		return err.Error()
	}
	if le == err {
		return le.en
	}
	// fmt.Errorf("prefiks: %w", le) – zamiana polskiego tekstu w całości.
	return strings.Replace(err.Error(), le.pl, le.en, 1)
}

// Join łączy błędy (jak errors.Join) z zachowaniem wersji angielskiej.
func Join(errs ...error) error {
	var pl, en []string
	var first error
	for _, e := range errs {
		if e == nil {
			continue
		}
		if first == nil {
			first = e
		}
		pl, en = append(pl, e.Error()), append(en, English(e))
	}
	if first == nil {
		return nil
	}
	return &Error{pl: strings.Join(pl, "\n"), en: strings.Join(en, "\n"), err: errors.Join(errs...)}
}

var local = sync.OnceValue(OS)

// Local: język systemu operacyjnego (OS), ustalony raz na proces – programy
// na komputerach (agent, czytnik eksportu).
func Local() string { return local() }

// L: tekst w języku systemu operacyjnego (Local).
func L(pl, en string) string { return Pick(Local(), pl, en) }
