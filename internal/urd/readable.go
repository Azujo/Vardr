package urd

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"siem/internal/contract"
)

// readerScript to niezależny skrypt sprawdzający dołączany do paczki eksportu.
//
//go:embed narzedzia/odczytaj_segmenty.py
var readerScript []byte

// Readable to zdarzenie w czytelnej części eksportu (zdarzenia/*.ndjson.gz):
// pola zgodne z ECS (Elastic Common Schema), żeby paczkę dało się wczytać do
// innego systemu bez Heimdalla, oraz oryginalny XML Windows w event.original.
type Readable struct {
	Timestamp   string `json:"@timestamp,omitempty"`
	HostName    string `json:"host.name,omitempty"`
	Code        uint32 `json:"event.code,omitempty"`
	Dataset     string `json:"event.dataset,omitempty"`
	Provider    string `json:"event.provider,omitempty"`
	Action      string `json:"event.action,omitempty"`
	Outcome     string `json:"event.outcome,omitempty"`
	UserName    string `json:"user.name,omitempty"`
	UserDomain  string `json:"user.domain,omitempty"`
	Identity    string `json:"user.identity,omitempty"` // osoba (to samo konto w AD, Entra, na VPN)
	SourceIP    string `json:"source.ip,omitempty"`
	ProcessName string `json:"process.name,omitempty"`
	CommandLine string `json:"process.command_line,omitempty"`
	Channel     string `json:"winlog.channel,omitempty"`
	Peer        string `json:"log.source.address,omitempty"` // nadawca syslog (kolektor)
	AgentID     string `json:"agent.id"`
	Ingested    string `json:"event.ingested"`
	EventID     string `json:"heimdall.event_id"`
	BatchID     string `json:"heimdall.batch_id"`
	BatchSHA256 string `json:"heimdall.batch_sha256"`
	Truncated   bool   `json:"heimdall.truncated,omitempty"`
	TimeQuality string `json:"heimdall.time_quality,omitempty"`
	Error       string `json:"heimdall.error,omitempty"` // paczka nieczytelna
	Original    string `json:"event.original,omitempty"`
}

// Enricher uzupełnia pola znormalizowane (archiwizator podaje normalizator
// serwera); nil = tylko pola z paczki i oryginalny XML.
type Enricher func(ev contract.Event, agentID string, received time.Time, r *Readable)

// maxBatchBytes: limit rozpakowanej paczki agenta (ochrona przed „bombą”).
const maxBatchBytes = 256 << 20

// DecodeBatch rozpakowuje oryginalną paczkę agenta (gzip + JSON, załącznik A).
func DecodeBatch(payload []byte) (contract.Batch, error) {
	var b contract.Batch
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return b, err
	}
	data, err := io.ReadAll(io.LimitReader(zr, maxBatchBytes+1))
	if err != nil {
		return b, err
	}
	if len(data) > maxBatchBytes {
		return b, errors.New("paczka po rozpakowaniu przekracza limit")
	}
	return b, json.Unmarshal(data, &b)
}

// readableEvents zamienia paczkę z archiwum na zdarzenia czytelne.
func readableEvents(meta RecordMeta, payload []byte, enrich Enricher) []Readable {
	sum := SumHex(payload)
	b, err := DecodeBatch(payload)
	if err != nil {
		return []Readable{{AgentID: meta.Agent, Ingested: meta.ReceivedAt.UTC().Format(time.RFC3339Nano),
			BatchID: meta.Batch, BatchSHA256: sum, Error: "nieczytelna paczka: " + err.Error()}}
	}
	out := make([]Readable, 0, len(b.Events))
	for _, ev := range b.Events {
		r := Readable{AgentID: meta.Agent, Ingested: meta.ReceivedAt.UTC().Format(time.RFC3339Nano),
			EventID: ev.ID, BatchID: meta.Batch, BatchSHA256: sum, Channel: ev.Source, Truncated: ev.Truncated,
			Original: ev.Raw, Peer: ev.Peer}
		if enrich != nil {
			enrich(ev, meta.Agent, meta.ReceivedAt, &r)
		}
		out = append(out, r)
	}
	return out
}

// eventDigest to skrót zbioru zdarzeń (niezależny od kolejności): liczba
// i dwie sumy modulo 2^64 z SHA-256 każdego zdarzenia. Pozwala porównać
// czytelną część eksportu z oryginałami bez trzymania wszystkiego w pamięci.
type eventDigest struct {
	n, unreadable int64
	a, b          uint64
}

func (d *eventDigest) add(batchSHA, eventID, raw string) {
	h := sha256.New()
	h.Write([]byte(batchSHA))
	h.Write([]byte{0})
	h.Write([]byte(eventID))
	h.Write([]byte{0})
	h.Write([]byte(raw))
	s := h.Sum(nil)
	d.n++
	d.a += binary.BigEndian.Uint64(s[:8])
	d.b += binary.BigEndian.Uint64(s[8:16])
}

// csvHeader to kolumny pliku zdarzenia/zdarzenia.csv (dla arkusza kalkulacyjnego).
var csvHeader = []string{"czas_zdarzenia_utc", "komputer", "kod", "kanal", "akcja", "wynik", "uzytkownik", "domena",
	"ip_zrodlowe", "proces", "agent", "przyjeto_na_serwerze_utc", "id_zdarzenia", "zbior_danych", "nadawca_syslog", "osoba"}

// csvMaxRows: Excel otwiera najwyżej 1 048 576 wierszy.
const csvMaxRows = 1_000_000

type csvSink struct {
	w    *csv.Writer
	rows int
	full bool
}

func newCSVSink(w io.Writer) (*csvSink, error) {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil { // BOM – polskie znaki w Excelu
		return nil, err
	}
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	return &csvSink{w: cw}, cw.Write(csvHeader)
}

func (c *csvSink) add(r Readable) error {
	if r.Error != "" {
		return nil
	}
	if c.rows >= csvMaxRows {
		c.full = true
		return nil
	}
	c.rows++
	code := ""
	if r.Code != 0 {
		code = strconv.FormatUint(uint64(r.Code), 10)
	}
	return c.w.Write([]string{r.Timestamp, r.HostName, code, r.Channel, r.Action, r.Outcome, r.UserName, r.UserDomain,
		r.SourceIP, r.ProcessName, r.AgentID, r.Ingested, r.EventID, r.Dataset, r.Peer, r.Identity})
}

func (c *csvSink) close() error {
	c.w.Flush()
	return c.w.Error()
}

// readableName to plik czytelnych zdarzeń dla godziny archiwizacji.
func readableName(hour time.Time) string {
	return fmt.Sprintf("zdarzenia/%s.ndjson.gz", hour.UTC().Format("2006-01-02_15"))
}

// readableDigestOf liczy skrót zdarzeń z pliku zdarzenia/*.ndjson.gz.
func readableDigestOf(r io.Reader, d *eventDigest) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(zr)
	for {
		var ev Readable
		if err := dec.Decode(&ev); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if ev.Error != "" {
			d.unreadable++
			continue
		}
		d.add(ev.BatchSHA256, ev.EventID, ev.Original)
	}
}

// same porównuje zbiory zdarzeń (bez licznika nieczytelnych paczek).
func (d eventDigest) same(o eventDigest) bool { return d.n == o.n && d.a == o.a && d.b == o.b }

// merge dołącza drugi skrót (suma zbiorów – kolejność nie ma znaczenia).
func (d *eventDigest) merge(o eventDigest) {
	d.n += o.n
	d.unreadable += o.unreadable
	d.a += o.a
	d.b += o.b
}
