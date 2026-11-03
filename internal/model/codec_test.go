// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// filled ustawia każde pole struktury na wartość niezerową – nowe pole
// w Event albo Quarantined bez obsługi w formacie binarnym oblewa test.
func filled(t *testing.T, v any) {
	t.Helper()
	rv := reflect.ValueOf(v).Elem()
	for i := range rv.NumField() {
		f := rv.Field(i)
		switch f.Interface().(type) {
		case string:
			f.SetString(rv.Type().Field(i).Name + " ąć\"<x>\x00")
		case uint32:
			f.SetUint(uint64(i + 1))
		case bool:
			f.SetBool(true)
		case time.Time:
			f.Set(reflect.ValueOf(time.Date(2026, 11, 3, 8, i, 1, 123456789, time.UTC)))
		case map[string]string:
			f.Set(reflect.ValueOf(map[string]string{"a": "1", "winlog.channel": "Security", "pusty": ""}))
		default:
			t.Fatalf("pole %s: typ %s bez obsługi w teście", rv.Type().Field(i).Name, f.Type())
		}
	}
}

func sameJSON(t *testing.T, a, b any) {
	t.Helper()
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("różnica:\n%s\n%s", ja, jb)
	}
}

func TestBatchRoundTrip(t *testing.T) {
	var e Event
	var q Quarantined
	filled(t, &e)
	filled(t, &q)
	in := Batch{BatchID: "b1", AgentID: "agt-1", Events: []Event{e, {ID: "pusty", Fields: map[string]string{}}}, Quarantine: []Quarantined{q}}
	data := AppendBatch(nil, &in)
	if !IsBinary(data) {
		t.Fatal("brak znacznika formatu")
	}
	out, err := DecodeBatch(data)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, in, out)
	if out.Events[0].Timestamp.Location() != time.UTC {
		t.Fatalf("strefa: %v", out.Events[0].Timestamp.Location())
	}

	// Czas zerowy i brak pól: odbiorcy dostają pustą mapę (nie null w JSON alertu).
	out, err = DecodeBatch(AppendBatch(nil, &Batch{Events: []Event{{ID: "x"}}}))
	if err != nil || !out.Events[0].Timestamp.IsZero() || out.Events[0].Fields == nil {
		t.Fatalf("%+v %v", out.Events[0], err)
	}
	// Pusta paczka.
	if out, err = DecodeBatch(AppendBatch(nil, &Batch{BatchID: "b"})); err != nil || out.BatchID != "b" || out.Events != nil {
		t.Fatalf("%+v %v", out, err)
	}
	// Te same dane – te same bajty (kolejność mapy).
	if string(AppendBatch(nil, &in)) != string(data) {
		t.Fatal("zapis niedeterministyczny")
	}
}

func TestDecodeBatchCorrupt(t *testing.T) {
	var e Event
	filled(t, &e)
	data := AppendBatch(nil, &Batch{BatchID: "b", Events: []Event{e}, Quarantine: []Quarantined{{AgentID: "a"}}})
	for i := range data {
		if _, err := DecodeBatch(data[:i]); err == nil {
			t.Fatalf("przyjęto paczkę uciętą do %d B", i)
		}
	}
	if _, err := DecodeBatch(append(data[:len(data):len(data)], 0)); err == nil {
		t.Fatal("przyjęto paczkę z nadmiarowym bajtem")
	}
	if _, err := DecodeBatch([]byte(`{"batch_id":"x"}`)); err == nil {
		t.Fatal("przyjęto JSON")
	}
	// Ogromna liczba zdarzeń w nagłówku nie może wywołać alokacji.
	huge := append([]byte{binaryMagic, 0, 0}, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f)
	if _, err := DecodeBatch(huge); err == nil {
		t.Fatal("przyjęto ogromną liczbę zdarzeń")
	}
}

// FuzzDecodeBatch: dowolne bajty nie powodują paniki, a poprawna paczka po
// ponownym zapisie czyta się tak samo.
func FuzzDecodeBatch(f *testing.F) {
	var e Event
	e.ID, e.Fields = "x", map[string]string{"a": "b"}
	f.Add(AppendBatch(nil, &Batch{BatchID: "b", Events: []Event{e}, Quarantine: []Quarantined{{AgentID: "a"}}}))
	f.Add([]byte{binaryMagic})
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := DecodeBatch(data)
		if err != nil {
			return
		}
		again, err := DecodeBatch(AppendBatch(nil, &b))
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, b, again)
	})
}
