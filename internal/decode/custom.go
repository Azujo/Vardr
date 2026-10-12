package decode

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Custom to dekoder zmieniony w panelu: własna definicja (nowy dekoder albo
// zastąpienie wbudowanego o tym samym id) i/lub wyłączenie. Pusta Source
// i Enabled = true – bez zmian (dekoder wbudowany).
type Custom struct {
	Source   string    `json:"source,omitempty"` // YAML
	Enabled  bool      `json:"enabled"`
	Revision int       `json:"revision"`
	By       string    `json:"by,omitempty"`
	At       time.Time `json:"at,omitzero"`
}

// Merge składa zestaw: wbudowane, zastąpione definicjami z panelu, bez
// wyłączonych, plus nowe dekodery z panelu. Definicja, która się nie
// kompiluje albo ma inny id niż klucz, jest pomijana (błąd w wyniku) –
// zostaje dekoder wbudowany, jeśli był.
func Merge(builtin []*Decoder, custom map[string]Custom, loc *time.Location) (*Set, []error) {
	var errs []error
	byID := map[string]*Decoder{}
	for _, d := range builtin {
		byID[d.ID] = d
	}
	for id, c := range custom {
		if c.Source != "" {
			d, err := Parse([]byte(c.Source), loc)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("dekoder %s: %w", id, err))
			case d.ID != id:
				errs = append(errs, fmt.Errorf("dekoder %s: id w definicji to %q", id, d.ID))
			default:
				byID[id] = d
			}
		}
		if !c.Enabled {
			delete(byID, id)
		}
	}
	list := make([]*Decoder, 0, len(byID))
	for _, d := range byID {
		list = append(list, d)
	}
	return NewSet(list), errs
}

// CheckSamples sprawdza, czy próbki z definicji pasują do dekodera i dają
// się zdekodować (adres nadawcy: pierwszy z warunków peer, jeśli są).
func (d *Decoder) CheckSamples(now time.Time) error {
	var peer netip.Addr
	for _, m := range append([]matcher{d.match}, d.any...) {
		if len(m.peers) > 0 {
			peer = m.peers[0].Addr()
			break
		}
	}
	for i, raw := range d.Samples {
		h := d.SampleHeader(raw, now)
		if !d.Matches(h, peer) {
			return fmt.Errorf("próbka %d nie pasuje do warunków match", i+1)
		}
		if _, err := d.Decode(h); err != nil {
			return fmt.Errorf("próbka %d: %w", i+1, err)
		}
	}
	return nil
}

// SampleSource: źródło, z którego pochodzą wiadomości dekodera – konektor API
// (gdy match.app wskazuje tylko źródła API, np. entra:signin) albo syslog.
func (d *Decoder) SampleSource() string {
	if len(d.Match.App) > 0 {
		for _, a := range d.Match.App {
			if !IsAPI(strings.ToLower(a)) {
				return "syslog:udp"
			}
		}
		return strings.ToLower(d.Match.App[0])
	}
	return "syslog:udp"
}

// SampleHeader: nagłówek próbki – dla dekoderów API rekord bez nagłówka.
func (d *Decoder) SampleHeader(raw string, now time.Time) Header {
	if src := d.SampleSource(); IsAPI(src) {
		return Header{Facility: -1, Severity: -1, Format: "api", App: src, Message: raw}
	}
	return ParseHeader(raw, d.loc, now)
}
