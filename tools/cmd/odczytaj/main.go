// SPDX-License-Identifier: AGPL-3.0-or-later

// Command odczytaj (odczytaj.exe) to czytnik eksportu archiwum NIS2 Vardra
// dla odbiorcy paczki – audytora, CSIRT, organu nadzoru. Nie wymaga
// Vardra ani instalacji:
//
//   - dwuklik na odczytaj.exe w rozpakowanym folderze paczki albo
//   - przeciągnięcie pliku .tar na odczytaj.exe (paczka zostanie rozpakowana obok)
//   - odczytaj [folder | paczka.tar] [-bez-pauzy] [-nie-otwieraj]
//
// Program sprawdza integralność paczki i zapisuje w podfolderze ODCZYT:
// RAPORT.txt (wynik sprawdzenia, opis eksportu, zdarzenia wymagające uwagi,
// statystyki) oraz zdarzenia/RRRR-MM-DD.txt – wszystkie zdarzenia dnia
// w kolejności czasu, z opisem i danymi zdarzenia. Język odczytu – według
// języka Windows (polski albo angielski; VARDR_LANG=pl|en). Niczego w paczce
// nie zmienia (ODCZYT nie jest częścią paczki i nie podlega sprawdzeniu).
package main

import (
	"archive/tar"
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	_ "time/tzdata" // czas polski także na komputerze bez bazy stref czasowych

	"siem/internal/lang"
	"siem/internal/urd"
)

// version ustawiana przy budowaniu (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	L = lang.OS()
	noPause := flag.Bool("bez-pauzy", false, tr("nie czekaj na Enter po zakończeniu", "do not wait for Enter at the end"))
	noOpen := flag.Bool("nie-otwieraj", false, tr("nie otwieraj raportu w Notatniku", "do not open the report in Notepad"))
	flag.Parse()

	fmt.Printf(tr("Vardr – odczyt eksportu archiwum NIS2 (wersja %s)\n\n", "Vardr – NIS2 archive export reader (version %s)\n\n"), version)
	code := 0
	report, ok, err := runFor(flag.Arg(0))
	switch {
	case err != nil:
		fmt.Println(tr("BŁĄD:", "ERROR:"), err)
		code = 2
	case ok:
		fmt.Println(tr("Wynik: ZGODNE – paczka nienaruszona, zdarzenia odczytane.", "Result: CONSISTENT – package intact, events read."))
	default:
		fmt.Println(tr("Wynik: NIEZGODNOŚCI – szczegóły w raporcie. Nie traktuj zdarzeń jako wiarygodnych bez wyjaśnienia.",
			"Result: INCONSISTENCIES – details in the report. Do not treat the events as reliable until this is explained."))
		code = 1
	}
	if report != "" {
		fmt.Println(tr("Raport:", "Report:"), report)
		if !*noOpen && runtime.GOOS == "windows" {
			_ = exec.Command("notepad.exe", report).Start()
		}
	}
	if !*noPause {
		fmt.Print(tr("\nNaciśnij Enter, aby zamknąć… ", "\nPress Enter to close… "))
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

// runFor ustala folder paczki: argument (folder albo .tar), folder programu
// albo bieżący – i tworzy odczyt.
func runFor(arg string) (report string, ok bool, err error) {
	dir := arg
	switch {
	case arg == "":
		dir, err = findPackage()
		if err != nil {
			return "", false, err
		}
	case strings.HasSuffix(strings.ToLower(arg), ".tar"):
		fmt.Println(tr("Rozpakowuję", "Extracting"), arg)
		dir, err = extract(arg)
		if err != nil {
			return "", false, err
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "export.json")); err != nil {
		return "", false, fmt.Errorf(tr("w folderze %s nie ma pliku export.json – to nie jest rozpakowana paczka eksportu",
			"folder %s has no export.json file – it is not an extracted export package"), dir)
	}
	fmt.Println(tr("Paczka:", "Package:"), dir)
	fmt.Println(tr("Sprawdzam integralność i odczytuję zdarzenia…", "Checking integrity and reading events…"))
	return Run(dir, time.Now())
}

// findPackage szuka paczki w folderze programu, potem w bieżącym.
func findPackage() (string, error) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "export.json")); err == nil {
			return c, nil
		}
	}
	return "", errors.New(tr("nie znaleziono paczki: uruchom program w rozpakowanym folderze paczki albo przeciągnij na niego plik .tar",
		"package not found: run the program in the extracted package folder or drag a .tar file onto it"))
}

// extract rozpakowuje paczkę obok pliku .tar (bezpiecznie – bez ścieżek
// wychodzących poza folder). Istniejący folder z paczką jest używany ponownie.
func extract(tarPath string) (string, error) {
	dir := strings.TrimSuffix(tarPath, filepath.Ext(tarPath))
	if _, err := os.Stat(filepath.Join(dir, "export.json")); err == nil {
		fmt.Println(tr("Folder już istnieje – używam rozpakowanej wcześniej paczki:", "The folder already exists – using the package extracted earlier:"), dir)
		return dir, nil
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tarR := tar.NewReader(f)
	for {
		h, err := tarR.Next()
		if errors.Is(err, io.EOF) {
			return dir, nil
		}
		if err != nil {
			return "", fmt.Errorf(tr("paczka nieczytelna: %w", "unreadable package: %w"), err)
		}
		// IsLocal odrzuca też to, czego nie łapały IsAbs i "..": ścieżki
		// względne do dysku (C:plik) i nazwy zarezerwowane Windows (NUL, COM1).
		name := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(name) {
			return "", fmt.Errorf(tr("niedozwolona ścieżka w paczce: %s", "path not allowed in the package: %s"), h.Name)
		}
		target := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err != nil {
				return "", err
			}
			_, err = io.Copy(out, tarR)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return "", err
			}
		}
	}
}

// Run sprawdza paczkę w folderze dir i zapisuje odczyt w dir/ODCZYT.
func Run(dir string, now time.Time) (report string, ok bool, err error) {
	check := urd.CheckExportDir(dir, L)
	info, err := readInfo(dir)
	if err != nil {
		return "", false, err
	}
	events, err := loadEvents(dir, info)
	if err != nil {
		return "", false, err
	}
	out := filepath.Join(dir, urd.ReadOutputDir)
	if err := os.RemoveAll(out); err != nil { // poprzedni odczyt (tylko nasze pliki)
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Join(out, "zdarzenia"), 0o755); err != nil {
		return "", false, err
	}
	days, err := writeDays(filepath.Join(out, "zdarzenia"), events)
	if err != nil {
		return "", false, err
	}
	report = filepath.Join(out, "RAPORT.txt")
	if err := writeReport(report, dir, info, check, events, days, now); err != nil {
		return "", false, err
	}
	return report, check.OK, nil
}
