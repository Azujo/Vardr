package normalize

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"siem/server/internal/loadgen"
)

// Przypadki brzegowe składni XML, które musi obsłużyć parser.
var edgeCases = []string{
	`<?xml version="1.0" encoding="UTF-8"?><Event><System><EventID>1</EventID></System></Event>`,
	`<Event><!-- komentarz --><System><EventID>2</EventID><Provider Name="Dwa &amp; &quot;cudzysłowy&quot;"/></System></Event>`,
	"<Event><System><EventID>\r\n3\r\n</EventID><Computer>A&#x42;&#67;</Computer></System></Event>",
	`<Event><EventData><Data Name='a'><![CDATA[<nie tag> & nie encja]]></Data><Data Name = "b" >x &lt; y</Data><Data/><Data Name='c'/></EventData></Event>`,
	`<e:Event xmlns:e='urn:x'><e:System><e:EventID>4</e:EventID><e:Provider e:Name='P'/></e:System></e:Event >`,
	`<Event><UserData><A xmlns='urn:a'><B> b </B><C><D>d</D></C><E/></A></UserData></Event>`,
	`<Event><System><EventID>5</EventID></System></Event>trailing garbage <<<`,
	`<Event><System><EventID>6</EventID><EventID>7</EventID></System><EventData><Data Name='x'>1</Data><Data Name='x'>2</Data></EventData></Event>`,
	`<Event><System><Security UserID='S-1-5-18'></Security></System><RenderingInfo><Message>m</Message></RenderingInfo></Event>`,
	`<Event><EventData><Data Name='a'>przed<b>w</b>po</Data></EventData></Event>`,
	// Błędne – oba parsery muszą je odrzucić.
	`<Event><System><EventID>1</EventID></System>`,
	`<Event><System><EventID>1</Level></System></Event>`,
	`<Event><System><EventID>&nieznana;</EventID></System></Event>`,
	`<Event><System><EventID a=b>1</EventID></System></Event>`,
	`<Event><System><EventID>1 &amp</EventID></System></Event>`,
	`</Event>`,
	``,
	`<Event`,
	`<Event a='1`,
}

func corpus() []string {
	out := []string{sys7045, app999, sec4625, sec1102, sysmon1}
	out = append(out, edgeCases...)
	now := time.Now().UTC()
	for i := range 3000 {
		_, raw := loadgen.RandomEvent("LOAD-0001", uint64(i+1), now)
		out = append(out, raw)
	}
	return out
}

// checkSame porównuje nowy parser ze wzorcem (encoding/xml).
func checkSame(t *testing.T, raw string) {
	t.Helper()
	want, werr := refParseWinEvent(raw)
	got, gerr := parseWinEvent(raw)
	switch {
	case werr != nil && gerr == nil:
		t.Fatalf("wzorzec odrzucił (%v), nowy parser przyjął:\n%q", werr, raw)
	case werr == nil && gerr != nil:
		t.Fatalf("wzorzec przyjął, nowy parser odrzucił (%v):\n%q", gerr, raw)
	case werr == nil && !reflect.DeepEqual(got, want):
		t.Fatalf("różne wyniki dla\n%q\n nowy:   %+v\n wzorzec: %+v", raw, got, want)
	}
}

func TestParserMatchesEncodingXML(t *testing.T) {
	for _, raw := range corpus() {
		checkSame(t, raw)
	}
}

// Ucięte zdarzenia (agent przycina zbyt duże) muszą być odrzucane tak samo.
func TestParserTruncatedEvents(t *testing.T) {
	for _, raw := range []string{sys7045, sec4625, sec1102, sysmon1} {
		for n := 0; n < len(raw); n++ {
			checkSame(t, raw[:n])
		}
	}
}

func FuzzParseWinEvent(f *testing.F) {
	for _, raw := range []string{sys7045, app999, sec4625, sec1102, sysmon1} {
		f.Add(raw)
	}
	for _, raw := range edgeCases {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if hasDirective(raw) || strings.Contains(raw, "<?") || nonASCIIMarkup(raw) {
			t.Skip() // <!…> i <?…?> są celowo odrzucane (nie występują w zdarzeniach); nazwy tylko ASCII
		}
		checkSame(t, raw)
	})
}

func BenchmarkParseWinEvent(b *testing.B) {
	now := time.Now().UTC()
	var evs []string
	for i := range 500 {
		_, raw := loadgen.RandomEvent("LOAD-0001", uint64(i+1), now)
		evs = append(evs, raw)
	}
	b.Run("nowy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			_, _ = parseWinEvent(evs[i%len(evs)])
		}
	})
	b.Run("encoding-xml", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			_, _ = refParseWinEvent(evs[i%len(evs)])
		}
	})
}

// hasDirective: czy tekst zawiera <! inne niż komentarz lub CDATA.
func hasDirective(s string) bool {
	for {
		k := strings.Index(s, "<!")
		if k < 0 {
			return false
		}
		s = s[k+2:]
		if !strings.HasPrefix(s, "--") && !strings.HasPrefix(s, "[CDATA[") {
			return true
		}
	}
}

// nonASCIIMarkup: czy wewnątrz znaczników (<…>) są znaki spoza ASCII.
// Nowy parser celowo przyjmuje tylko nazwy ASCII.
func nonASCIIMarkup(s string) bool {
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<':
			in = true
		case c == '>':
			in = false
		case in && c >= 0x80:
			return true
		}
	}
	return false
}
