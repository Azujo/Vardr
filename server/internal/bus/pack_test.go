// SPDX-License-Identifier: AGPL-3.0-or-later

package bus

import (
	"encoding/json"
	"testing"

	"siem/internal/model"
)

func packTestBatch() *model.Batch {
	return &model.Batch{Events: []model.Event{{
		ID:     "e1",
		Fields: map[string]string{"CommandLine": "cmd /c whoami"},
	}}}
}

func TestUnpackEventsBinary(t *testing.T) {
	data, err := PackEvents(packTestBatch(), 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := UnpackEvents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 || b.Events[0].Fields["CommandLine"] != "cmd /c whoami" {
		t.Fatalf("%+v", b)
	}
}

// Wiadomości zapisane przez poprzednią wersję czekają w kolejce po aktualizacji.
func TestUnpackEventsJSON(t *testing.T) {
	raw, err := json.Marshal(packTestBatch())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Gzip(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := UnpackEvents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 || b.Events[0].ID != "e1" {
		t.Fatalf("%+v", b)
	}
}

func TestUnpackEventsGarbage(t *testing.T) {
	if _, err := UnpackEvents([]byte("nie gzip")); err == nil {
		t.Fatal("brak błędu")
	}
}
