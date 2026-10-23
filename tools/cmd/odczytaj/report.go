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

	"siem/internal/lang"
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
		return info, fmt.Errorf(tr("export.json nieczytelny: %w", "export.json is unreadable: %w"), err)
	}
	if len(info.Readable.Files) == 0 {
		return info, errors.New(tr("paczka nie zawiera czytelnych zdarzeń (starszy format eksportu) – zleć eksport ponownie",
			"the package contains no readable events (older export format) – request the export again"))
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
					dataName = tr("Dane ", "Data ") + strconv.Itoa(unnamed)
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

// L: język odczytu (pl, en) – według języka Windows (main, lang.OS).
var L = "pl"

func tr(pl, en string) string { return lang.Pick(L, pl, en) }

// zone: strefa czasu raportu – czas polski (raport po polsku) albo czas
// lokalny komputera (po angielsku); zoneLabel – jej opis w raporcie.
func zone() *time.Location {
	if L == "en" {
		return time.Local
	}
	return warsaw
}

func zoneLabel() string { return tr("czas polski", "local time") }

var warsaw = func() *time.Location {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		return time.UTC
	}
	return loc
}()

const rule = "------------------------------------------------------------------------------"

func plTime(t time.Time) string { return t.In(zone()).Format("2006-01-02 15:04:05") }

func outcome(o string) string {
	switch o {
	case "success":
		return tr("sukces", "success")
	case "failure":
		return tr("porażka", "failure")
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
	return string(r[:n]) + fmt.Sprintf(tr(" … (+%d znaków – pełna treść w event.original)", " … (+%d characters – full content in event.original)"), len(r)-n)
}

func describe(code uint32) string {
	if d := windesc.Describe(code, L); d != "" {
		return d
	}
	return tr("(opis niedostępny – zob. dokumentację Microsoft dla tego Event ID)", "(no description – see the Microsoft documentation for this Event ID)")
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

// writeDays zapisuje zdarzenia w plikach dziennych (data w strefie raportu).
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
		day := e.t.In(zone()).Format("2006-01-02")
		if day != curDay || part >= maxPerFile {
			if err := flush(); err != nil {
				return days, err
			}
			name := day + ".txt"
			if day == curDay {
				partNo++
				name = fmt.Sprintf(tr("%s_czesc%d.txt", "%s_part%d.txt"), day, partNo)
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
			cur.line(tr("VARDR – zdarzenia z dnia %s (%s), plik %s", "VARDR – events of %s (%s), file %s"), day, zoneLabel(), name)
			cur.line("%s", tr("Kolejność: według czasu zdarzenia. Pełny oryginalny zapis (XML) każdego zdarzenia: pliki",
				"Order: by event time. The full original record (XML) of every event: files"))
			cur.line("%s", tr("zdarzenia/*.ndjson.gz w paczce, pole event.original (wyszukaj po identyfikatorze).",
				"zdarzenia/*.ndjson.gz in the package, field event.original (search by identifier)."))
			cur.line("")
		}
		part++
		days[len(days)-1].count++
		r := e.r
		cur.line("%s", rule)
		cur.line("%s (%s)   |   %s UTC", plTime(e.t), zoneLabel(), e.t.UTC().Format("2006-01-02 15:04:05"))
		head := fmt.Sprintf("%d  %s", r.Code, describe(r.Code))
		if isSyslog(r) {
			head = kindOf(r)
		} else if r.Code == 0 {
			head = tr("(zdarzenie bez rozpoznanego kodu)", "(event without a recognized code)")
		}
		if r.Outcome != "" {
			head += "  [" + outcome(r.Outcome) + "]"
		}
		cur.line("%s", head)
		cur.line(tr("  Komputer:       %s", "  Computer:       %s"), orDash(r.HostName))
		cur.line(tr("  Użytkownik:     %s", "  User:           %s"), userOf(r))
		cur.line(tr("  Adres IP:       %s", "  IP address:     %s"), orDash(r.SourceIP))
		if r.ProcessName != "" {
			cur.line(tr("  Proces:         %s", "  Process:        %s"), r.ProcessName)
		}
		if r.CommandLine != "" {
			cur.line(tr("  Polecenie:      %s", "  Command line:   %s"), r.CommandLine)
		}
		if isSyslog(r) {
			cur.line(tr("  Nadawca:        %s   (%s, zbiór danych: %s)", "  Sender:         %s   (%s, dataset: %s)"), orDash(r.Peer), r.Channel, orDash(r.Dataset))
		} else {
			cur.line(tr("  Dziennik:       %s   (źródło: %s)", "  Log:            %s   (source: %s)"), orDash(strings.TrimPrefix(r.Channel, "wineventlog:")), orDash(r.Provider))
		}
		cur.line(tr("  Agent:          %s   przyjęto: %s (%s)", "  Agent:          %s   ingested: %s (%s)"), r.AgentID, plTimeStr(r.Ingested), zoneLabel())
		cur.line(tr("  Identyfikator:  %s", "  Identifier:     %s"), r.EventID)
		if r.Truncated {
			cur.line("%s", tr("  UWAGA: zdarzenie zostało przycięte przez agenta (bardzo długi zapis).",
				"  NOTE: the event was truncated by the agent (very long record)."))
		}
		if isSyslog(r) {
			// Syslog nie ma struktury XML – pokazujemy oryginalną wiadomość.
			cur.line(tr("  Treść:          %s", "  Content:        %s"), clip(r.Original, 2000))
		}
		if len(e.data) > 0 {
			cur.line("%s", tr("  Dane zdarzenia:", "  Event data:"))
			width := 0
			for _, kv := range e.data {
				width = max(width, len([]rune(kv[0])))
			}
			for _, kv := range e.data {
				v := orDash(kv[1])
				if h := windesc.FieldHint(kv[0], kv[1], L); h != "" {
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
	z := zoneLabel()
	t.line("%s", tr("VARDR – ODCZYT EKSPORTU ARCHIWUM NIS2", "VARDR – NIS2 ARCHIVE EXPORT READOUT"))
	t.line("========================================")
	t.line(tr("Utworzono:      %s (%s), odczytaj.exe wersja %s", "Created:        %s (%s), odczytaj.exe version %s"), plTime(now), z, version)
	t.line(tr("Folder paczki:  %s", "Package folder: %s"), dir)
	t.line("")

	t.line("%s", tr("1. WYNIK SPRAWDZENIA INTEGRALNOŚCI", "1. INTEGRITY CHECK RESULT"))
	t.line("%s", rule)
	if check.OK {
		t.line("%s", tr("   ZGODNE – żaden plik paczki nie został zmieniony, łańcuch manifestów jest ciągły,",
			"   CONSISTENT – no file of the package was modified, the manifest chain is continuous,"))
		t.line("%s", tr("   a zdarzenia w tym odczycie pochodzą z nienaruszonych oryginałów.",
			"   and the events in this readout come from intact originals."))
	} else {
		t.line("%s", tr("   NIEZGODNOŚCI – paczka została zmieniona albo jest niekompletna. Zdarzeń poniżej",
			"   INCONSISTENCIES – the package was modified or is incomplete. The events below"))
		t.line("%s", tr("   nie należy traktować jako wiarygodnych do czasu wyjaśnienia:",
			"   must not be treated as reliable until this is explained:"))
		for _, p := range check.Problems {
			t.line("     - %s", p)
		}
	}
	t.line("%s", tr("   Kotwica (SHA-256 najnowszego manifestu archiwum):", "   Anchor (SHA-256 of the latest archive manifest):"))
	t.line("     %s", info.Latest.SHA256)
	t.line("%s", tr("   Porównaj ją z wartością przekazaną niezależnie (protokół przekazania, panel Vardra).",
		"   Compare it with a value provided independently (handover protocol, Vardr panel)."))
	t.line("")

	t.line("%s", tr("2. O EKSPORCIE", "2. ABOUT THE EXPORT"))
	t.line("%s", rule)
	t.line(tr("   Numer eksportu:     %d", "   Export number:      %d"), info.ExportID)
	t.line(tr("   Zlecił:             %s, %s (%s)", "   Requested by:       %s, %s (%s)"), info.RequestedBy, plTime(info.RequestedAt), z)
	t.line(tr("   Powód:              %s", "   Reason:             %s"), info.Reason)
	t.line(tr("   Zakres (przyjęcie przez serwer): %s – %s (%s)", "   Range (accepted by the server): %s – %s (%s)"), plTime(info.From), plTime(info.To), z)
	t.line(tr("   Paczkę utworzono:   %s (%s), Vardr %s", "   Package created:    %s (%s), Vardr %s"), plTime(info.CreatedAt), z, info.ServerVersion)
	if len(info.Agents) > 0 {
		t.line(tr("   Tylko agenci:       %s", "   Agents only:        %s"), strings.Join(info.Agents, ", "))
		t.line("%s", tr("                       (zdarzenia innych agentów są tylko w segmentach – dowodzie)",
			"                       (events of other agents are only in the segments – the evidence)"))
	}
	hosts, agents := map[string]int{}, map[string]int{}
	for _, e := range l.events {
		hosts[orDash(e.r.HostName)]++
		agents[e.r.AgentID]++
	}
	t.line(tr("   Zawartość:          %d zdarzeń z %d komputerów (%d agentów), %d paczek agentów",
		"   Contents:           %d events from %d computers (%d agents), %d agent batches"),
		len(l.events), len(hosts), len(agents), info.Totals.Records)
	if len(l.events) > 0 {
		t.line(tr("   Czas zdarzeń:       %s – %s (%s)", "   Event time:         %s – %s (%s)"), plTime(l.events[0].t), plTime(l.events[len(l.events)-1].t), z)
	}
	if l.unreadable > 0 {
		t.line(tr("   Nieczytelne paczki: %d (oryginały są w segments/, opis błędu w zdarzenia/*.ndjson.gz)",
			"   Unreadable batches: %d (originals are in segments/, error description in zdarzenia/*.ndjson.gz)"), l.unreadable)
	}
	t.line("")

	t.line("%s", tr("3. ZDARZENIA WYMAGAJĄCE UWAGI", "3. EVENTS REQUIRING ATTENTION"))
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
		t.line("%s", tr("   Brak zdarzeń z listy wymagających uwagi.", "   No events from the attention list."))
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
		t.line(tr("   [%s] – %d zdarzeń", "   [%s] – %d events"), windesc.AttentionLabel(cat, L), len(list))
		for _, c := range top(codes, 50) {
			t.line("     %7d × %s", c.count, c.key)
		}
		if cat != windesc.AttentionLogon {
			t.line("%s", tr("     Lista (najwyżej 100 pierwszych):", "     List (at most the first 100):"))
			for i, e := range list {
				if i == 100 {
					t.line(tr("     … oraz %d kolejnych – zob. pliki dzienne", "     … and %d more – see the daily files"), len(list)-100)
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
		t.line("%s", tr("   Nieudane logowania – najczęstsze konta:", "   Failed logons – most frequent accounts:"))
		for _, c := range top(failedUsers, 15) {
			t.line("     %7d × %s", c.count, c.key)
		}
		t.line("%s", tr("   Nieudane logowania – najczęstsze adresy źródłowe:", "   Failed logons – most frequent source addresses:"))
		for _, c := range top(failedIPs, 15) {
			t.line("     %7d × %s", c.count, c.key)
		}
		t.line("")
	}

	t.line("%s", tr("4. STATYSTYKI", "4. STATISTICS"))
	t.line("%s", rule)
	codes := map[string]int{}
	for _, e := range l.events {
		if isSyslog(e.r) {
			codes[kindOf(e.r)]++
			continue
		}
		codes[fmt.Sprintf("%-6d %s", e.r.Code, describe(e.r.Code))]++
	}
	t.line("%s", tr("   Rodzaje zdarzeń (najczęstsze):", "   Event types (most frequent):"))
	for _, c := range top(codes, 30) {
		t.line("     %9d × %s", c.count, c.key)
	}
	t.line("%s", tr("   Komputery (najczęstsze):", "   Computers (most frequent):"))
	for _, c := range top(hosts, 30) {
		t.line("     %9d × %s", c.count, c.key)
	}
	t.line("")

	t.line("%s", tr("5. PLIKI ODCZYTU", "5. READOUT FILES"))
	t.line("%s", rule)
	t.line(tr("   Wszystkie zdarzenia w kolejności czasu, plik na każdy dzień (%s):", "   All events in time order, one file per day (%s):"), z)
	for _, d := range days {
		t.line(tr("     ODCZYT\\zdarzenia\\%s   – %d zdarzeń", "     ODCZYT\\zdarzenia\\%s   – %d events"), d.name, d.count)
	}
	t.line("")
	for _, s := range strings.Split(tr(`   Pola „komputer”, „użytkownik” itp. wylicza Vardr z oryginalnego zapisu. Rozstrzygający
   jest zawsze oryginał: zdarzenia/*.ndjson.gz, pole event.original (XML Windows), a jako
   dowód – segments/ i chain/ (opis w README.txt). Folder ODCZYT można usunąć i odtworzyć
   ponownie; nie jest częścią paczki i nie wpływa na wynik sprawdzenia.`,
		`   Fields such as "computer" and "user" are computed by Vardr from the original record. The
   original is always decisive: zdarzenia/*.ndjson.gz, field event.original (Windows XML),
   and as evidence – segments/ and chain/ (described in README-EN.txt). The ODCZYT folder can
   be deleted and recreated; it is not part of the package and does not affect the check.`), "\n") {
		t.line("%s", s)
	}
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
