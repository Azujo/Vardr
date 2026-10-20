// Package decodekv dostarcza dekodery syslog zmienione w panelu do
// normalizatorów przez magazyn klucz-wartość NATS (klucz = id dekodera,
// wartość = decode.Custom w JSON). Panel zapisuje (źródłem prawdy jest baza
// Saga – przy starcie panel wyrównuje magazyn do bazy), normalizatory
// obserwują i podmieniają zestaw dekoderów bez restartu i bez dostępu do bazy.
package decodekv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/decode"
)

// Bucket to nazwa magazynu.
const Bucket = "SIEM_DECODERS"

// Ensure tworzy (lub otwiera) magazyn.
func Ensure(ctx context.Context, js jetstream.JetStream) (jetstream.KeyValue, error) {
	return js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       Bucket,
		Description:  "Dekodery syslog zmienione w panelu Vardr",
		History:      1,
		Storage:      jetstream.FileStorage,
		MaxValueSize: 256 << 10,
		MaxBytes:     16 << 20, // rezerwacja w max_file_store (setki dekoderów)
	})
}

// Put zapisuje dekoder.
func Put(ctx context.Context, kv jetstream.KeyValue, id string, c decode.Custom) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = kv.Put(ctx, id, b)
	return err
}

// Sync wyrównuje magazyn do stanu z bazy: zapisuje wpisy różne od
// zapisanych (bez zmian – bez zapisu, więc normalizatory nie przeładowują
// dekoderów co synchronizację), usuwa klucze, których w bazie nie ma.
func Sync(ctx context.Context, kv jetstream.KeyValue, all map[string]decode.Custom) error {
	for id, c := range all {
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if e, err := kv.Get(ctx, id); err == nil && bytes.Equal(e.Value(), b) {
			continue
		}
		if _, err := kv.Put(ctx, id, b); err != nil {
			return err
		}
	}
	keys, err := kv.ListKeys(ctx)
	if err != nil {
		return err
	}
	for k := range keys.Keys() {
		if _, ok := all[k]; !ok {
			if err := kv.Delete(ctx, k); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
				return err
			}
		}
	}
	return nil
}

// Watch obserwuje magazyn i po każdej zmianie (oraz po wczytaniu stanu
// początkowego) wywołuje apply z kompletem wpisów. Kończy się z ctx.
func Watch(ctx context.Context, kv jetstream.KeyValue, log *slog.Logger, apply func(map[string]decode.Custom)) error {
	w, err := kv.WatchAll(ctx)
	if err != nil {
		return err
	}
	defer w.Stop()
	cur := map[string]decode.Custom{}
	initial := true
	// Seria zmian (np. synchronizacja przy starcie panelu) – jedno przeładowanie.
	var pending <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pending:
			pending = nil
			apply(clone(cur))
		case e, ok := <-w.Updates():
			if !ok {
				return errors.New("obserwacja dekoderów zakończona")
			}
			if e == nil {
				if initial {
					initial = false
					apply(clone(cur))
				}
				continue
			}
			if e.Operation() == jetstream.KeyValuePut {
				var c decode.Custom
				if err := json.Unmarshal(e.Value(), &c); err != nil {
					log.Error("nieczytelny wpis dekodera w NATS – pominięty", "id", e.Key(), "err", err)
					continue
				}
				cur[e.Key()] = c
			} else {
				delete(cur, e.Key())
			}
			if !initial && pending == nil {
				pending = time.After(500 * time.Millisecond)
			}
		}
	}
}

func clone(m map[string]decode.Custom) map[string]decode.Custom {
	out := make(map[string]decode.Custom, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
