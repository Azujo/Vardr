//go:build windows

package winevt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"siem/internal/agent/source"
)

// ErrChannelNotFound oznacza, że kanał nie istnieje na tym hoście
// (np. Sysmon nie jest zainstalowany).
var ErrChannelNotFound = errors.New("kanał nie istnieje")

// ErrAccessDenied oznacza brak uprawnień do kanału (np. Security bez
// uprawnień administratora lub członkostwa w grupie Event Log Readers).
var ErrAccessDenied = errors.New("brak dostępu do kanału")

// Reader czyta jeden kanał Event Log przez subskrypcję typu pull.
type Reader struct {
	channel   string
	query     string
	startAt   string // "now" lub "oldest" – tylko gdy brak zapisanej pozycji
	pollEvery time.Duration
	log       *slog.Logger

	// OnGap (opcjonalne) dostaje opis luki w danych (zdarzenia nadpisane
	// w dzienniku, zanim agent je przeczytał) – np. do statusu agenta.
	OnGap func(msg string)

	lastDrained atomic.Int64 // UnixNano chwili, gdy subskrypcja była opróżniona
}

// NewReader tworzy czytnik kanału. Zapytanie powstaje z BuildQuery.
func NewReader(channel, query, startAt string, log *slog.Logger) *Reader {
	return &Reader{
		channel:   channel,
		query:     query,
		startAt:   startAt,
		pollEvery: time.Second,
		log:       log.With("channel", channel),
	}
}

func (r *Reader) Channel() string { return r.channel }

// LastDrained zwraca chwilę, w której czytnik ostatnio przeczytał wszystko,
// co było w subskrypcji (był na bieżąco z dziennikiem).
func (r *Reader) LastDrained() time.Time {
	if ns := r.lastDrained.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// gap zgłasza lukę w danych: log (także do Podglądu zdarzeń) i OnGap.
func (r *Reader) gap(msg string, attrs ...any) {
	r.log.Error(msg, append(attrs, "eventlog", true)...)
	if r.OnGap != nil {
		r.OnGap("kanał " + r.channel + ": " + msg)
	}
}

// checkResumeGap sprawdza przy wznowieniu, czy dziennik nie nadpisał
// rekordów po zapisanej pozycji (np. agent był długo wyłączony). Windows
// wznawia wtedy po cichu od najstarszego dostępnego rekordu.
func (r *Reader) checkResumeGap(pos source.Position) {
	if !pos.Valid {
		return
	}
	info, err := LogInfo(r.channel)
	if err != nil {
		r.log.Debug("odczyt stanu dziennika nieudany", "err", err)
		return
	}
	if info.Records > 0 && info.Oldest > pos.RecordID+1 {
		r.gap(fmt.Sprintf("LUKA W DANYCH: dziennik nadpisał rekordy %d–%d, zanim agent je przeczytał (np. długa przerwa w działaniu agenta)",
			pos.RecordID+1, info.Oldest-1), "after_record", pos.RecordID, "oldest_record", info.Oldest)
	}
}

// Run realizuje source.Source.
func (r *Reader) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	pos := start

	// Zdarzenie ręcznie resetowane, początkowo ustawione, żeby od razu
	// opróżnić zaległe zdarzenia.
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return pos, err
	}
	defer windows.CloseHandle(signal)

	sub, err := r.subscribe(signal, pos)
	if err != nil {
		return pos, err
	}
	defer func() { evtClose(sub) }()
	r.log.Info("subskrypcja kanału uruchomiona", "query", r.query, "after_record", pos.RecordID, "resume", pos.Valid)
	r.checkResumeGap(pos)

	handles := make([]evtHandle, 64)
	var buf []uint16

	for {
		// Czekamy na sygnał nowych zdarzeń. Timeout służy tylko do sprawdzania
		// kontekstu – EvtNext bez sygnału zwraca ERROR_INVALID_OPERATION.
		ev, err := windows.WaitForSingleObject(signal, uint32(r.pollEvery.Milliseconds()))
		if err := ctx.Err(); err != nil {
			return pos, err
		}
		if err != nil {
			return pos, fmt.Errorf("WaitForSingleObject: %w", err)
		}
		if ev == uint32(windows.WAIT_TIMEOUT) {
			// Brak sygnału = nic pasującego do odczytu: czytnik jest na bieżąco,
			// nawet jeśli dziennik rośnie o zdarzenia spoza filtra.
			r.lastDrained.Store(time.Now().UnixNano())
			continue
		}
		windows.ResetEvent(signal)

		for {
			n, err := evtNext(sub, handles)
			if err != nil {
				// ERROR_INVALID_OPERATION po opróżnieniu subskrypcji też
				// oznacza brak nowych zdarzeń (nie błąd czytnika).
				if errors.Is(err, errorNoMoreItems) || errors.Is(err, errorInvalidOperation) {
					r.lastDrained.Store(time.Now().UnixNano())
					break
				}
				if errors.Is(err, errorEvtQueryResultStale) {
					// Zdarzenia zostały nadpisane, zanim je przeczytaliśmy:
					// to realna luka w danych, którą trzeba zgłosić.
					r.gap("LUKA W DANYCH: zdarzenia nadpisane w dzienniku przed odczytem; wznawiam od najstarszego dostępnego", "after_record", pos.RecordID)
					evtClose(sub)
					sub = 0
					if sub, err = r.subscribe(signal, pos); err != nil {
						return pos, err
					}
					break
				}
				return pos, fmt.Errorf("EvtNext: %w", err)
			}

			for i := 0; i < n; i++ {
				h := handles[i]
				xml, err := evtRenderXML(h, &buf)
				evtClose(h)
				if err != nil {
					r.log.Warn("nie udało się wyrenderować zdarzenia", "err", err)
					continue
				}
				meta, err := parseMeta(xml)
				if err != nil {
					r.log.Warn("pomijam zdarzenie bez numeru rekordu", "err", err)
					continue
				}
				rec := source.Record{
					Channel: r.channel, RecordID: meta.RecordID, EventID: meta.EventID, HasEventID: meta.HasEventID,
					CreatedAt: meta.CreatedAt, Raw: xml, ReadAt: time.Now().UTC(),
				}
				select {
				case out <- rec:
					pos = source.Position{RecordID: meta.RecordID, Valid: true}
				case <-ctx.Done():
					for _, rest := range handles[i+1 : n] {
						evtClose(rest)
					}
					return pos, ctx.Err()
				}
			}
		}
	}
}

func (r *Reader) subscribe(signal windows.Handle, pos source.Position) (evtHandle, error) {
	var bookmark evtHandle
	var flags uint32
	switch {
	case pos.Valid:
		bm, err := evtCreateBookmark(bookmarkXML(r.channel, pos.RecordID))
		if err != nil {
			return 0, fmt.Errorf("EvtCreateBookmark: %w", err)
		}
		defer evtClose(bm)
		bookmark, flags = bm, evtSubscribeStartAfterBookmark
	case pos.Oldest || r.startAt == "oldest":
		flags = evtSubscribeStartAtOldestRecord
	default:
		flags = evtSubscribeToFutureEvents
	}

	sub, err := evtSubscribe(signal, r.channel, r.query, bookmark, flags)
	switch {
	case err == nil:
		return sub, nil
	case errors.Is(err, errorEvtChannelNotFound):
		return 0, fmt.Errorf("%w: %s", ErrChannelNotFound, r.channel)
	case errors.Is(err, errorAccessDenied):
		return 0, fmt.Errorf("%w: %s", ErrAccessDenied, r.channel)
	case errors.Is(err, errorEvtInvalidQuery):
		return 0, fmt.Errorf("niepoprawne zapytanie XPath %q: %w", r.query, err)
	default:
		return 0, fmt.Errorf("EvtSubscribe(%s): %w", r.channel, err)
	}
}

func bookmarkXML(channel string, recordID uint64) string {
	esc := strings.NewReplacer("&", "&amp;", "'", "&apos;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return fmt.Sprintf("<BookmarkList><Bookmark Channel='%s' RecordId='%d' IsCurrent='true'/></BookmarkList>",
		esc.Replace(channel), recordID)
}
