// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"encoding/json"
	"strings"
	"testing"
)

// Zdarzenia z eksportów sprzed zmiany nazwy na Vardr (pola heimdall.*)
// czytają się tak samo jak obecne (vardr.*).
func TestReadableLegacyFields(t *testing.T) {
	var old, cur Readable
	if err := json.Unmarshal([]byte(`{"agent.id":"a","heimdall.event_id":"e1","heimdall.batch_sha256":"abc","heimdall.truncated":true}`), &old); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"agent.id":"a","vardr.event_id":"e1","vardr.batch_sha256":"abc","vardr.truncated":true}`), &cur); err != nil {
		t.Fatal(err)
	}
	if old != cur || old.EventID != "e1" || !old.Truncated {
		t.Fatalf("dawne pola: %+v, obecne: %+v", old, cur)
	}
	data, _ := json.Marshal(cur)
	if !strings.Contains(string(data), `"vardr.event_id":"e1"`) {
		t.Fatalf("zapis: %s", data)
	}
}
