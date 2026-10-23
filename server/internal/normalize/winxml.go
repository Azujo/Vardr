// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// winEvent to pola zdarzenia Windows potrzebne do normalizacji
// (XML z EvtRender, EvtRenderEventXml).
type winEvent struct {
	Provider      string
	EventID       string
	Level         string
	Task          string
	Keywords      string
	SystemTime    string
	EventRecordID string
	Channel       string
	Computer      string
	UserID        string
	Data          []winData         // EventData/Data w kolejności wystąpienia
	UserData      map[string]string // liście elementów w UserData (nazwa → tekst)
}

type winData struct {
	Name, Value string
}

var errXMLEOF = errors.New("unexpected end of XML")

// parseWinEvent to lekki parser XML zdarzeń Windows (etap 1.5, W1).
// Zastępuje encoding/xml, który zajmował ponad połowę czasu normalizacji:
// przechodzi tekst raz, nie buduje drzewa i nie kopiuje wartości bez encji.
//
// Zachowuje się jak dotychczasowe xml.Unmarshal do struktury zdarzenia
// (sprawdza to test porównawczy): niezamknięte lub źle zagnieżdżone
// elementy, nieznane encje i ucięty tekst są błędem – takie zdarzenie
// trafia do kwarantanny. Przetwarzanie kończy się na końcu elementu
// głównego, jak w xml.Unmarshal.
func parseWinEvent(s string) (winEvent, error) {
	var w winEvent
	type frame struct {
		name     string // nazwa z prefiksem (do porównania ze znacznikiem końca)
		local    string
		hasChild bool
		pre      string // tekst elementu sprzed pierwszych elementów podrzędnych
	}
	stack := make([]frame, 0, 8)
	var text textAcc

	// Ścieżki obsługiwane przez parser (głębokość liczona od 1 = element główny).
	inSystem := func() bool { return len(stack) == 3 && stack[1].local == "System" }
	inEventData := func() bool { return len(stack) == 3 && stack[1].local == "EventData" }
	inUserData := func() bool { return len(stack) >= 3 && stack[1].local == "UserData" }

	end := func() error { // obsługa końca elementu ze szczytu stosu
		top := stack[len(stack)-1]
		value := func() string { // tekst bezpośrednio w elemencie, jak w encoding/xml
			if top.pre != "" {
				return top.pre + text.String()
			}
			return text.String()
		}
		switch {
		case inSystem():
			v := value()
			switch top.local {
			case "EventID":
				w.EventID = v
			case "Level":
				w.Level = v
			case "Task":
				w.Task = v
			case "Keywords":
				w.Keywords = v
			case "EventRecordID":
				w.EventRecordID = v
			case "Channel":
				w.Channel = v
			case "Computer":
				w.Computer = v
			}
		case inEventData() && top.local == "Data":
			w.Data[len(w.Data)-1].Value = value()
		case inUserData() && !top.hasChild:
			if w.UserData == nil {
				w.UserData = map[string]string{}
			}
			w.UserData[top.local] = strings.TrimSpace(text.String())
		}
		stack = stack[:len(stack)-1]
		text.Reset()
		return nil
	}

	i, n := 0, len(s)
	for i < n {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				j = n - i
			}
			if strings.Contains(s[i:i+j], "]]>") {
				return w, errors.New("]]> not allowed outside a CDATA section")
			}
			acc := &text
			if len(stack) == 0 {
				acc = &textAcc{} // tekst poza elementem głównym: tylko sprawdzenie poprawności
			}
			if err := acc.AddEscaped(s[i : i+j]); err != nil {
				return w, err
			}
			i += j
			continue
		}
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "<?"):
			if !strings.HasPrefix(rest, "<?xml ") {
				return w, errors.New("<?…?> instructions in an event are not supported")
			}
			k := strings.Index(rest, "?>")
			if k < 0 {
				return w, errXMLEOF
			}
			i += k + 2
		case strings.HasPrefix(rest, "<!--"):
			k := strings.Index(rest[4:], "-->")
			if k < 0 {
				return w, errXMLEOF
			}
			if body := rest[4 : 4+k]; strings.Contains(body, "--") || strings.HasSuffix(body, "-") {
				return w, errors.New("sekwencja -- niedozwolona w komentarzu XML")
			}
			i += 4 + k + 3
		case strings.HasPrefix(rest, "<![CDATA["):
			k := strings.Index(rest[9:], "]]>")
			if k < 0 {
				return w, errXMLEOF
			}
			if err := checkText(rest[9 : 9+k]); err != nil {
				return w, err
			}
			if len(stack) > 0 {
				_ = text.AddRaw(rest[9 : 9+k])
			}
			i += 9 + k + 3
		case strings.HasPrefix(rest, "<!"):
			// <!DOCTYPE>, <!ENTITY> itp. nie występują w zdarzeniach Windows –
			// odrzucamy je zamiast interpretować (bezpieczniej niż encoding/xml).
			return w, errors.New("<!…> declarations in an event are not supported")
		case strings.HasPrefix(rest, "</"):
			k := strings.IndexByte(rest, '>')
			if k < 0 {
				return w, errXMLEOF
			}
			name := strings.TrimRight(rest[2:k], " \t\r\n")
			if len(stack) == 0 {
				return w, fmt.Errorf("unexpected end tag </%s>", name)
			}
			if top := stack[len(stack)-1]; top.name != name {
				return w, fmt.Errorf("element <%s> closed by </%s>", top.name, name)
			}
			if err := end(); err != nil {
				return w, err
			}
			i += k + 1
			if len(stack) == 0 {
				return w, nil // koniec elementu głównego
			}
		default:
			// Znacznik początku: nazwa, atrybuty, opcjonalnie „/>”.
			j := i + 1
			for j < n && !isNameEnd(s[j]) {
				j++
			}
			name := s[i+1 : j]
			if name == "" || !validName(name) {
				return w, fmt.Errorf("invalid element name at position %d", i)
			}
			if len(stack) > 0 {
				parent := &stack[len(stack)-1]
				parent.hasChild = true
				parent.pre += text.String()
			}
			stack = append(stack, frame{name: name, local: localName(name)})
			text.Reset()
			local := stack[len(stack)-1].local
			if inEventData() && local == "Data" {
				w.Data = append(w.Data, winData{})
			}

			selfClosing := false
			for {
				for j < n && isSpace(s[j]) {
					j++
				}
				if j >= n {
					return w, errXMLEOF
				}
				if s[j] == '>' {
					j++
					break
				}
				if s[j] == '/' {
					if j+1 >= n {
						return w, errXMLEOF
					}
					if s[j+1] != '>' {
						return w, fmt.Errorf("invalid tag <%s>", name)
					}
					selfClosing = true
					j += 2
					break
				}
				// atrybut: nazwa = 'wartość' | "wartość"
				a := j
				for j < n && !isNameEnd(s[j]) && s[j] != '=' {
					j++
				}
				attr := s[a:j]
				if !validName(attr) {
					return w, fmt.Errorf("invalid attribute in <%s>", name)
				}
				for j < n && isSpace(s[j]) {
					j++
				}
				if j >= n {
					return w, errXMLEOF
				}
				if s[j] != '=' {
					return w, fmt.Errorf("attribute %s in <%s> without a value", attr, name)
				}
				j++
				for j < n && isSpace(s[j]) {
					j++
				}
				if j >= n {
					return w, errXMLEOF
				}
				q := s[j]
				if q != '\'' && q != '"' {
					return w, fmt.Errorf("value of attribute %s in <%s> without quotes", attr, name)
				}
				k := strings.IndexByte(s[j+1:], q)
				if k < 0 {
					return w, errXMLEOF
				}
				raw := s[j+1 : j+1+k]
				j += k + 2
				if strings.IndexByte(raw, '<') >= 0 {
					return w, fmt.Errorf("character < in the value of attribute %s", attr)
				}
				var val textAcc
				if err := val.AddEscaped(raw); err != nil {
					return w, err
				}
				switch a := localName(attr); {
				case inSystem():
					switch {
					case local == "Provider" && a == "Name":
						w.Provider = val.String()
					case local == "TimeCreated" && a == "SystemTime":
						w.SystemTime = val.String()
					case local == "Security" && a == "UserID":
						w.UserID = val.String()
					}
				case inEventData() && local == "Data" && a == "Name":
					w.Data[len(w.Data)-1].Name = val.String()
				}
			}
			i = j
			if selfClosing {
				if err := end(); err != nil {
					return w, err
				}
				if len(stack) == 0 {
					return w, nil
				}
			}
		}
	}
	return w, errXMLEOF
}

// ---- pomocnicze ----

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isNameEnd(c byte) bool { return isSpace(c) || c == '>' || c == '/' || c == '=' }

// localName usuwa prefiks przestrzeni nazw (jak encoding/xml: „a:b” → „b”,
// ale „:b” i „a:” pozostają bez zmian).
func localName(name string) string {
	if space, local, ok := strings.Cut(name, ":"); ok && space != "" && local != "" {
		return local
	}
	return name
}

// validName sprawdza nazwę elementu lub atrybutu: pierwszy znak to litera,
// _ lub :, kolejne także cyfry, . i - (jak encoding/xml). Dopuszczamy tylko
// ASCII – nazwy w zdarzeniach Windows są zawsze ASCII.
func validName(name string) bool {
	if strings.Count(name, ":") > 1 {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch r := name[i]; {
		case r == '_' || r == ':' || (r|0x20) >= 'a' && (r|0x20) <= 'z':
		case i > 0 && (r == '.' || r == '-' || r >= '0' && r <= '9'):
		default:
			return false
		}
	}
	return name != ""
}

// checkText odrzuca znaki niedozwolone w XML i niepoprawny UTF-8 (jak encoding/xml).
func checkText(s string) error {
	ascii := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			ascii = false
			continue
		}
		if c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D { // poza tabulacją, LF i CR
			return fmt.Errorf("niedozwolony znak 0x%02x w XML", c)
		}
	}
	if ascii {
		return nil
	}
	for _, r := range s {
		if r == utf8.RuneError || !isXMLChar(r) {
			return errors.New("invalid UTF-8 or a character not allowed in XML")
		}
	}
	return nil
}

// textAcc składa tekst elementu. Pojedynczy fragment bez encji i \r jest
// podciągiem wejścia (bez kopiowania); w pozostałych przypadkach tekst
// jest budowany w buforze.
type textAcc struct {
	s     string
	b     []byte
	inBuf bool
}

func (t *textAcc) Reset() { t.s, t.b, t.inBuf = "", t.b[:0], false }

func (t *textAcc) String() string {
	if t.inBuf {
		return string(t.b)
	}
	return t.s
}

func (t *textAcc) toBuf() {
	if !t.inBuf {
		t.b = append(t.b[:0], t.s...)
		t.inBuf = true
	}
}

// AddRaw dodaje tekst bez interpretacji encji (CDATA); \r\n i \r → \n jak w encoding/xml.
func (t *textAcc) AddRaw(seg string) error {
	if err := checkText(seg); err != nil {
		return err
	}
	if strings.IndexByte(seg, '\r') < 0 {
		if !t.inBuf && t.s == "" {
			t.s = seg
			return nil
		}
		t.toBuf()
		t.b = append(t.b, seg...)
		return nil
	}
	t.toBuf()
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c == '\r' {
			if i+1 < len(seg) && seg[i+1] == '\n' {
				continue
			}
			c = '\n'
		}
		t.b = append(t.b, c)
	}
	return nil
}

// AddEscaped dodaje tekst z encjami XML.
func (t *textAcc) AddEscaped(seg string) error {
	if strings.IndexByte(seg, '&') < 0 {
		return t.AddRaw(seg)
	}
	t.toBuf()
	for len(seg) > 0 {
		k := strings.IndexByte(seg, '&')
		if k < 0 {
			return t.AddRaw(seg)
		}
		if err := t.AddRaw(seg[:k]); err != nil {
			return err
		}
		t.toBuf()
		seg = seg[k:]
		semi := strings.IndexByte(seg, ';')
		if semi < 0 {
			return errors.New("unterminated XML entity")
		}
		ent := seg[1:semi]
		switch ent {
		case "lt":
			t.b = append(t.b, '<')
		case "gt":
			t.b = append(t.b, '>')
		case "amp":
			t.b = append(t.b, '&')
		case "apos":
			t.b = append(t.b, '\'')
		case "quot":
			t.b = append(t.b, '"')
		default:
			r, ok := charRef(ent)
			if !ok {
				return fmt.Errorf("nieznana encja XML &%s;", ent)
			}
			t.b = utf8.AppendRune(t.b, r)
		}
		seg = seg[semi+1:]
	}
	return nil
}

// charRef dekoduje odwołanie znakowe (#123 lub #x7B).
func charRef(ent string) (rune, bool) {
	if len(ent) < 2 || ent[0] != '#' {
		return 0, false
	}
	var v uint64
	var err error
	if ent[1] == 'x' {
		v, err = strconv.ParseUint(ent[2:], 16, 32)
	} else {
		v, err = strconv.ParseUint(ent[1:], 10, 32)
	}
	if err != nil || !isXMLChar(rune(v)) {
		return 0, false
	}
	return rune(v), true
}

// isXMLChar: znaki dozwolone w XML 1.0 (jak w encoding/xml).
func isXMLChar(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D ||
		r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD ||
		r >= 0x10000 && r <= 0x10FFFF
}
