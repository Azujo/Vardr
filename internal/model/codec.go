// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"encoding/binary"
	"errors"
	"slices"
	"time"
)

// Format binarny paczki między normalizatorem a odbiorcami SIEM_EVENTS
// (writer, detektor). JSON był najdroższym krokiem writera (W7): każdy ciąg
// trzeba przeskanować pod kątem znaków ucieczki, a XML w Raw ma ich dużo.
// Pierwszy bajt (binaryMagic) odróżnia format od JSON ('{'), więc odbiorca
// czyta oba – wiadomości sprzed aktualizacji czekające w kolejce też.
const binaryMagic = 0xB1

// ErrBadBatch: treść nie jest poprawną paczką binarną.
var ErrBadBatch = errors.New("invalid binary batch")

// IsBinary: czy treść jest w formacie binarnym (nie JSON).
func IsBinary(data []byte) bool { return len(data) > 0 && data[0] == binaryMagic }

// AppendBatch dopisuje paczkę w formacie binarnym do dst.
func AppendBatch(dst []byte, b *Batch) []byte {
	dst = append(dst, binaryMagic)
	dst = appendString(dst, b.BatchID)
	dst = appendString(dst, b.AgentID)
	dst = binary.AppendUvarint(dst, uint64(len(b.Events)))
	var keys []string
	for i := range b.Events {
		e := &b.Events[i]
		dst = appendTime(dst, e.Timestamp)
		dst = appendTime(dst, e.Ingested)
		for _, s := range [...]string{e.ID, e.AgentID, e.Dataset, e.Provider, e.Action, e.Outcome, e.HostName, e.UserName,
			e.UserDomain, e.Identity, e.SourceIP, e.ProcessName, e.CommandLine, e.Message, e.Raw, e.Parser, e.TimeQuality} {
			dst = appendString(dst, s)
		}
		dst = binary.AppendUvarint(dst, uint64(e.Code))
		dst = binary.AppendUvarint(dst, uint64(e.ReplayID))
		dst = appendBool(dst, e.Truncated)
		dst = binary.AppendUvarint(dst, uint64(len(e.Fields)))
		keys = keys[:0]
		for k := range e.Fields {
			keys = append(keys, k)
		}
		slices.Sort(keys) // ta sama paczka – te same bajty
		for _, k := range keys {
			dst = appendString(dst, k)
			dst = appendString(dst, e.Fields[k])
		}
	}
	dst = binary.AppendUvarint(dst, uint64(len(b.Quarantine)))
	for i := range b.Quarantine {
		q := &b.Quarantine[i]
		dst = appendTime(dst, q.Ingested)
		for _, s := range [...]string{q.AgentID, q.EventID, q.Source, q.Reason, q.Raw, q.Peer} {
			dst = appendString(dst, s)
		}
		dst = appendBool(dst, q.Truncated)
	}
	return dst
}

// DecodeBatch czyta paczkę w formacie binarnym. Każda długość jest
// sprawdzana przed alokacją – uszkodzona wiadomość daje błąd, nie panikę.
func DecodeBatch(data []byte) (Batch, error) {
	var b Batch
	if !IsBinary(data) {
		return b, ErrBadBatch
	}
	r := reader{data: data[1:]}
	b.BatchID, b.AgentID = r.str(), r.str()
	if n := r.count(minEventBytes); n > 0 {
		b.Events = make([]Event, n)
		for i := range b.Events {
			e := &b.Events[i]
			e.Timestamp, e.Ingested = r.time(), r.time()
			for _, s := range [...]*string{&e.ID, &e.AgentID, &e.Dataset, &e.Provider, &e.Action, &e.Outcome, &e.HostName, &e.UserName,
				&e.UserDomain, &e.Identity, &e.SourceIP, &e.ProcessName, &e.CommandLine, &e.Message, &e.Raw, &e.Parser, &e.TimeQuality} {
				*s = r.str()
			}
			e.Code, e.ReplayID = r.u32(), r.u32()
			e.Truncated = r.bool()
			// Zawsze mapa, także pusta: JSON alertu ma „{}”, nie null.
			n := r.count(2)
			e.Fields = make(map[string]string, n)
			for range n {
				k := r.str()
				e.Fields[k] = r.str()
			}
			if r.bad {
				return Batch{}, ErrBadBatch
			}
		}
	}
	if n := r.count(minQuarantineBytes); n > 0 {
		b.Quarantine = make([]Quarantined, n)
		for i := range b.Quarantine {
			q := &b.Quarantine[i]
			q.Ingested = r.time()
			for _, s := range [...]*string{&q.AgentID, &q.EventID, &q.Source, &q.Reason, &q.Raw, &q.Peer} {
				*s = r.str()
			}
			q.Truncated = r.bool()
		}
	}
	if r.bad || len(r.data) != 0 {
		return Batch{}, ErrBadBatch
	}
	return b, nil
}

// Najmniejszy zapis elementu: czasy, puste ciągi, liczby, flagi. Liczba
// elementów ponad to, co mieści się w danych, to uszkodzona paczka.
const (
	minEventBytes      = 2*2 + 17 + 2 + 1 + 1
	minQuarantineBytes = 2 + 6 + 1
)

func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

func appendBool(dst []byte, v bool) []byte {
	if v {
		return append(dst, 1)
	}
	return append(dst, 0)
}

// appendTime: sekundy i nanosekundy (także czas zerowy, poza zakresem UnixNano).
func appendTime(dst []byte, t time.Time) []byte {
	dst = binary.AppendVarint(dst, t.Unix())
	return binary.AppendUvarint(dst, uint64(t.Nanosecond()))
}

type reader struct {
	data []byte
	bad  bool
}

func (r *reader) fail() {
	r.bad, r.data = true, nil
}

func (r *reader) uvarint() uint64 {
	v, n := binary.Uvarint(r.data)
	if n <= 0 {
		r.fail()
		return 0
	}
	r.data = r.data[n:]
	return v
}

func (r *reader) str() string {
	n := r.uvarint()
	if n > uint64(len(r.data)) {
		r.fail()
		return ""
	}
	s := string(r.data[:n])
	r.data = r.data[n:]
	return s
}

func (r *reader) count(minBytes int) int {
	n := r.uvarint()
	if n > uint64(len(r.data)/minBytes) {
		r.fail()
		return 0
	}
	return int(n)
}

func (r *reader) u32() uint32 {
	v := r.uvarint()
	if v > 1<<32-1 {
		r.fail()
	}
	return uint32(v)
}

func (r *reader) bool() bool {
	if len(r.data) == 0 || r.data[0] > 1 {
		r.fail()
		return false
	}
	v := r.data[0] == 1
	r.data = r.data[1:]
	return v
}

func (r *reader) time() time.Time {
	sec, n := binary.Varint(r.data)
	if n <= 0 {
		r.fail()
		return time.Time{}
	}
	r.data = r.data[n:]
	ns := r.uvarint()
	if ns >= 1e9 {
		r.fail()
		return time.Time{}
	}
	return time.Unix(sec, int64(ns)).UTC()
}
