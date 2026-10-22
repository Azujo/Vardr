// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/urd"
	"siem/internal/windesc"
)

// packageInfo to potrzebna część export.json.
type packageInfo struct {
	ExportID      int64     `json:"export_id"`
	RequestedBy   string    `json:"requested_by"`
	Reason        string    `json:"reason"`
	RequestedAt   time.Time `json:"requested_at"`
	CreatedAt     time.Time `json:"created_at"`
	ServerVersion string    `json:"server_version"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Agents        []string  `json:"agents"`
	Latest        struct {
		Seq    int64  `json:"seq"`
		SHA256 string `json:"sha256"`
	} `json:"latest_manifest"`
	Totals struct {
		Segments int   `json:"segments"`
		Records  int64 `json:"records"`
	} `json:"totals"`
	Readable struct {
		Files []string `json:"files"`
	} `json:"readable"`
}

func readInfo(dir string) (packageInfo, error) {
	var info packageInfo
	data, err := os.ReadFile(filepath.Join(dir, "export.json"))
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return info, fmt.Errorf("export.json nieczytelny: %w", err)
	}
	if len(info.Readable.Files) == 0 {
		return info, errors.New("paczka nie zawiera czytelnych zdarzeń (starszy format eksportu) – zleć eksport ponownie")
	}
	return info, nil
}

type event struct {
	t    time.Time
	r    urd.Readable
	data [][2]string
}

type loaded struct {
	events     []event
	unreadable int
}

// loadEvents czyta zdarzenia z zdarzenia/*.ndjson.gz i porządkuje je wg czasu.
func loadEvents(dir string, info packageInfo) (loaded, error) {
	var l loaded
	for _, name := range info.Readable.Files {
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return l, err
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return l, fmt.Errorf("%s: %w", name, err)
		}
		dec := json.NewDecoder(zr)
		for {
			var r urd.Readable
			if err := dec.Decode(&r); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				f.Close()
				return l, fmt.Errorf("%s: %w", name, err)
			}
			if r.Error != "" {
				l.unreadable++
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, r.Timestamp)
			if err != nil {
				t, _ = time.Parse(time.RFC3339Nano, r.Ingested)
			}
			l.events = append(l.events, event{t: t, r: r, data: eventData(r.Original)})
		}
		f.Close()
	}
	sort.SliceStable(l.events, func(i, j int) bool {
		if !l.events[i].t.Equal(l.events[j].t) {
			return l.events[i].t.Before(l.events[j].t)
		}
		return l.events[i].r.EventID < l.events[j].r.EventID
	})
	return l, nil
}

// eventData wyciąga z XML zdarzenia pary nazwa = wartość (EventData/Data,
// a dla UserData – elementy końcowe).
func eventData(raw string) [][2]string {
	var out [][2]string
	dec := xml.NewDecoder(strings.NewReader(raw))
	var stack []string
	var section string // EventData | UserData
	var dataName string
	var text strings.Builder
	unnamed := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
			if t.Name.Local == "EventData" || t.Name.Local == "UserData" {
				section = t.Name.Local
			}
			if section == "EventData" && t.Name.Local == "Data" {
				dataName = ""
				for _, a := range t.Attr {
					if a.Name.Local == "Name" {
						dataName = a.Value
					}
				}
				if dataName == "" {
					unnamed++
					dataName = "Dane " + strconv.Itoa(unnamed)
				}
			}
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			name := t.Name.Local
			value := strings.TrimSpace(text.String())
			switch {
			case section == "EventData" && name == "Data":
				out = append(out, [2]string{dataName, value})
			case section == "UserData" && value != "" && name != "UserData":
				out = append(out, [2]string{name, value})
			case name == section:
				section = ""
			}
			text.Reset()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

// ---- zapis plików tekstowych (UTF-8 z BOM, końce linii CRLF – Notatnik) ----

type txt struct {
	f *os.File
	w *bufio.Writer
}

func createTxt(path string) (*txt, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(f, 256<<10)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // BOM: Notatnik rozpozna UTF-8
	return &txt{f: f, w: w}, nil
}

func (t *txt) line(format string, args ...any) {
	fmt.Fprintf(t.w, format, args...)
	_, _ = t.w.WriteString("\r\n")
}

func (t *txt) close() error {
	if err := t.w.Flush(); err != nil {
		t.f.Close()
		return err
	}
	return t.f.Close()
}

var pl = func() *time.Location {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		return time.UTC
	}
	return loc
}()

const rule = "------------------------------------------------------------------------------"

func plTime(t time.Time) string { return t.In(pl).Format("2006-01-02 15:04:05") }

func outcome(o string) string {
	switch o {
	case "success":
		return "sukces"
	case "failure":
		return "porażka"
	}
	return o
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// isSyslog: zdarzenie spoza Windows – z kolektora syslog (urządzenia
// sieciowe, serwery) albo z konektora API (Entra ID); bez struktury XML.
func isSyslog(r urd.Readable) bool {
	return strings.HasPrefix(r.Channel, "syslog:") || strings.HasPrefix(r.Channel, "entra:")
}

// kindOf opisuje rodzaj zdarzenia syslog: zbiór danych i akcja z dekodera.
func kindOf(r urd.Readable) string {
	kind, _, _ := strings.Cut(r.Channel, ":")
	s := kind + "  " + orDash(r.Dataset)
	if r.Action != "" {
		s += "  " + r.Action
	}
	return s
}

// clip skraca tekst do n znaków (z informacją o reszcie).
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + fmt.Sprintf(" … (+%d znaków – pełna treść w event.original)", len(r)-n)
}

func describe(code uint32) string {
	if d := windesc.Describe(code); d != "" {
		return d
	}
	return "(opis niedostępny – zob. dokumentację Microsoft dla tego Event ID)"
}

func userOf(r urd.Readable) string {
	if r.UserDomain != "" && r.UserName != "" {
		return r.UserDomain + `\` + r.UserName
	}
	return orDash(r.UserName)
}

type dayFile struct {
	name  string
	count int
}

// writeDays zapisuje zdarzenia w plikach dziennych (data w czasie polskim).
func writeDays(dir string, l loaded) ([]dayFile, error) {
	var days []dayFile
	var cur *txt
	var curDay string
	part, partNo := 0, 1
	flush := func() error {
		if cur == nil {
			return nil
		}
		return cur.close()
	}
	for _, e := range l.events {
		day := e.t.In(pl).Format("2006-01-02")
		if day != curDay || part >= maxPerFile {
			if err := flush(); err != nil {
				return days, err
			}
			name := day + ".txt"
			if day == curDay {
				partNo++
				name = fmt.Sprintf("%s_czesc%d.txt", day, partNo)
			} else {
				partNo = 1
			}
			var err error
			cur, err = createTxt(filepath.Join(dir, name))
			if err != nil {
				return days, err
			}
			curDay, part = day, 0
			days = append(days, dayFile{name: name})
			cur.line("VARDR – zdarzenia z dnia %s (czas polski), plik %s", day, name)
			cur.line("Kolejność: według czasu zdarzenia. Pełny oryginalny zapis (XML) każdego zdarzenia: pliki")
			cur.line("zdarzenia/*.ndjson.gz w paczce, pole event.original (wyszukaj po identyfikatorze).")
			cur.line("")
		}
		part++
		days[len(days)-1].count++
		r := e.r
		cur.line("%s", rule)
		cur.line("%s (czas polski)   |   %s UTC", plTime(e.t), e.t.UTC().Format("2006-01-02 15:04:05"))
		head := fmt.Sprintf("%d  %s", r.Code, describe(r.Code))
		if isSyslog(r) {
			head = kindOf(r)
		} else if r.Code == 0 {
			head = "(zdarzenie bez rozpoznanego kodu)"
		}
		if r.Outcome != "" {
			head += "  [" + outcome(r.Outcome) + "]"
		}
		cur.line("%s", head)
		cur.line("  Komputer:       %s", orDash(r.HostName))
		cur.line("  Użytkownik:     %s", userOf(r))
		cur.line("  Adres IP:       %s", orDash(r.SourceIP))
		if r.ProcessName != "" {
			cur.line("  Proces:         %s", r.ProcessName)
		}
		if r.CommandLine != "" {
			cur.line("  Polecenie:      %s", r.CommandLine)
		}
		if isSyslog(r) {
			cur.line("  Nadawca:        %s   (%s, zbiór danych: %s)", orDash(r.Peer), r.Channel, orDash(r.Dataset))
		} else {
			cur.line("  Dziennik:       %s   (źródło: %s)", orDash(strings.TrimPrefix(r.Channel, "wineventlog:")), orDash(r.Provider))
		}
		cur.line("  Agent:          %s   przyjęto: %s (czas polski)", r.AgentID, plTimeStr(r.Ingested))
		cur.line("  Identyfikator:  %s", r.EventID)
		if r.Truncated {
			cur.line("  UWAGA: zdarzenie zostało przycięte przez agenta (bardzo długi zapis).")
		}
		if isSyslog(r) {
			// Syslog nie ma struktury XML – pokazujemy oryginalną wiadomość.
			cur.line("  Treść:          %s", clip(r.Original, 2000))
		}
		if len(e.data) > 0 {
			cur.line("  Dane zdarzenia:")
			width := 0
			for _, kv := range e.data {
				width = max(width, len([]rune(kv[0])))
			}
			for _, kv := range e.data {
				v := orDash(kv[1])
				if h := windesc.FieldHint(kv[0], kv[1]); h != "" {
					v += " (" + h + ")"
				}
				cur.line("    %s%s = %s", kv[0], strings.Repeat(" ", width-len([]rune(kv[0]))), v)
			}
		}
	}
	return days, flush()
}

func plTimeStr(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return orDash(s)
	}
	return plTime(t)
}

type counted struct {
	key   string
	count int
}

func top(m map[string]int, n int) []counted {
	out := make([]counted, 0, len(m))
	for k, v := range m {
		out = append(out, counted{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// writeReport zapisuje RAPORT.txt.
func writeReport(path, dir string, info packageInfo, check urd.ExportCheck, l loaded, days []dayFile, now time.Time) error {
	t, err := createTxt(path)
	if err != nil {
		return err
	}
	t.line("VARDR – ODCZYT EKSPORTU ARCHIWUM NIS2")
	t.line("========================================")
	t.line("Utworzono:      %s (czas polski), odczytaj.exe wersja %s", plTime(now), version)
	t.line("Folder paczki:  %s", dir)
	t.line("")

	t.line("1. WYNIK SPRAWDZENIA INTEGRALNOŚCI")
	t.line("%s", rule)
	if check.OK {
		t.line("   ZGODNE – żaden plik paczki nie został zmieniony, łańcuch manifestów jest ciągły,")
		t.line("   a zdarzenia w tym odczycie pochodzą z nienaruszonych oryginałów.")
	} else {
		t.line("   NIEZGODNOŚCI – paczka została zmieniona albo jest niekompletna. Zdarzeń poniżej")
		t.line("   nie należy traktować jako wiarygodnych do czasu wyjaśnienia:")
		for _, p := range check.Problems {
			t.line("     - %s", p)
		}
	}
	t.line("   Kotwica (SHA-256 najnowszego manifestu archiwum):")
	t.line("     %s", info.Latest.SHA256)
	t.line("   Porównaj ją z wartością przekazaną niezależnie (protokół przekazania, panel Vardra).")
	t.line("")

	t.line("2. O EKSPORCIE")
	t.line("%s", rule)
	t.line("   Numer eksportu:     %d", info.ExportID)
	t.line("   Zlecił:             %s, %s (czas polski)", info.RequestedBy, plTime(info.RequestedAt))
	t.line("   Powód:              %s", info.Reason)
	t.line("   Zakres (przyjęcie przez serwer): %s – %s (czas polski)", plTime(info.From), plTime(info.To))
	t.line("   Paczkę utworzono:   %s (czas polski), Vardr %s", plTime(info.CreatedAt), info.ServerVersion)
	if len(info.Agents) > 0 {
		t.line("   Tylko agenci:       %s", strings.Join(info.Agents, ", "))
		t.line("                       (zdarzenia innych agentów są tylko w segmentach – dowodzie)")
	}
	hosts, agents := map[string]int{}, map[string]int{}
	for _, e := range l.events {
		hosts[orDash(e.r.HostName)]++
		agents[e.r.AgentID]++
	}
	t.line("   Zawartość:          %d zdarzeń z %d komputerów (%d agentów), %d paczek agentów",
		len(l.events), len(hosts), len(agents), info.Totals.Records)
	if len(l.events) > 0 {
		t.line("   Czas zdarzeń:       %s – %s (czas polski)", plTime(l.events[0].t), plTime(l.events[len(l.events)-1].t))
	}
	if l.unreadable > 0 {
		t.line("   Nieczytelne paczki: %d (oryginały są w segments/, opis błędu w zdarzenia/*.ndjson.gz)", l.unreadable)
	}
	t.line("")

	t.line("3. ZDARZENIA WYMAGAJĄCE UWAGI")
	t.line("%s", rule)
	byCat := map[string][]event{}
	failedUsers, failedIPs := map[string]int{}, map[string]int{}
	for _, e := range l.events {
		if isSyslog(e.r) {
			// Kody urządzeń (np. logid FortiGate) to nie identyfikatory zdarzeń Windows.
			if e.r.Outcome == "failure" && strings.Contains(e.r.Action, "login") {
				failedUsers[userOf(e.r)+"  ("+orDash(e.r.HostName)+")"]++
				failedIPs[orDash(e.r.SourceIP)]++
			}
			continue
		}
		if a := windesc.Attention(e.r.Code); a != "" {
			byCat[a] = append(byCat[a], e)
		}
		if e.r.Code == 4625 || e.r.Code == 4771 {
			failedUsers[userOf(e.r)]++
			failedIPs[orDash(e.r.SourceIP)]++
		}
	}
	if len(byCat) == 0 {
		t.line("   Brak zdarzeń z listy wymagających uwagi.")
	}
	for _, cat := range []string{windesc.AttentionSecurity, windesc.AttentionSystem, windesc.AttentionLogon} {
		list := byCat[cat]
		if len(list) == 0 {
			continue
		}
		codes := map[string]int{}
		for _, e := range list {
			codes[fmt.Sprintf("%d  %s", e.r.Code, describe(e.r.Code))]++
		}
		t.line("   [%s] – %d zdarzeń", cat, len(list))
		for _, c := range top(codes, 50) {
			t.line("     %7d × %s", c.count, c.key)
		}
		if cat != windesc.AttentionLogon {
			t.line("     Lista (najwyżej 100 pierwszych):")
			for i, e := range list {
				if i == 100 {
					t.line("     … oraz %d kolejnych – zob. pliki dzienne", len(list)-100)
					break
				}
				detail := windesc.Detail(dataMap(e.data))
				if detail == "" {
					detail = userOf(e.r)
				}
				t.line("     %s  %-6d %-22s %s", plTime(e.t), e.r.Code, orDash(e.r.HostName), detail)
			}
		}
		t.line("")
	}
	if len(failedUsers) > 0 {
		t.line("   Nieudane logowania – najczęstsze konta:")
		for _, c := range top(failedUsers, 15) {
			t.line("     %7d × %s", c.count, c.key)
		}
		t.line("   Nieudane logowania – najczęstsze adresy źródłowe:")
		for _, c := range top(failedIPs, 15) {
			t.line("     %7d × %s", c.count, c.key)
		}
		t.line("")
	}

	t.line("4. STATYSTYKI")
	t.line("%s", rule)
	codes := map[string]int{}
	for _, e := range l.events {
		if isSyslog(e.r) {
			codes[kindOf(e.r)]++
			continue
		}
		codes[fmt.Sprintf("%-6d %s", e.r.Code, describe(e.r.Code))]++
	}
	t.line("   Rodzaje zdarzeń (najczęstsze):")
	for _, c := range top(codes, 30) {
		t.line("     %9d × %s", c.count, c.key)
	}
	t.line("   Komputery (najczęstsze):")
	for _, c := range top(hosts, 30) {
		t.line("     %9d × %s", c.count, c.key)
	}
	t.line("")

	t.line("5. PLIKI ODCZYTU")
	t.line("%s", rule)
	t.line("   Wszystkie zdarzenia w kolejności czasu, plik na każdy dzień (czas polski):")
	for _, d := range days {
		t.line("     ODCZYT\\zdarzenia\\%s   – %d zdarzeń", d.name, d.count)
	}
	t.line("")
	t.line("   Pola „komputer”, „użytkownik” itp. wylicza Vardr z oryginalnego zapisu. Rozstrzygający")
	t.line("   jest zawsze oryginał: zdarzenia/*.ndjson.gz, pole event.original (XML Windows), a jako")
	t.line("   dowód – segments/ i chain/ (opis w README.txt). Folder ODCZYT można usunąć i odtworzyć")
	t.line("   ponownie; nie jest częścią paczki i nie wpływa na wynik sprawdzenia.")
	return t.close()
}

// maxPerFile: zdarzeń w jednym pliku dziennym (ok. 50 MB – Notatnik otwiera
// go jeszcze sprawnie); większe dni są dzielone na części.
var maxPerFile = 50_000

func dataMap(pairs [][2]string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		m[kv[0]] = kv[1]
	}
	return m
}
