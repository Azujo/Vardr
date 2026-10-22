// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"strings"
	"testing"
	"time"

	"siem/internal/alerts"
)

func TestHeartbeatCheck(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	beats := []alerts.AgentBeat{
		{ID: "agt-dc", Host: "dc01", Group: "DC", LastSeen: now.Add(-20 * time.Minute), AlertAfter: 15 * time.Minute},
		{ID: "agt-srv", Host: "srv01", Group: "Serwery", LastSeen: now.Add(-time.Minute), AlertAfter: 15 * time.Minute},
		{ID: "agt-pc", Host: "pc01", Group: "Stacje", LastSeen: now.Add(-48 * time.Hour)}, // grupa bez alarmu
	}
	hits, back := HeartbeatCheck(beats, now)
	if len(hits) != 1 || hits[0].AgentID != "agt-dc" || !strings.HasPrefix(hits[0].GroupKey, HeartbeatKey("agt-dc")) ||
		hits[0].Engine != "system" || !strings.Contains(hits[0].Summary, "próg 15 min") {
		t.Fatalf("alerty: %+v", hits)
	}
	if len(back) != 1 || back[0].ID != "agt-srv" {
		t.Fatalf("agenci z łącznością: %+v", back)
	}
	// Ta sama przerwa w kolejnym sprawdzeniu – ten sam identyfikator (jeden alert).
	again, _ := HeartbeatCheck(beats, now.Add(time.Hour))
	if again[0].EventID != hits[0].EventID {
		t.Fatalf("przerwa dała nowy identyfikator: %s / %s", again[0].EventID, hits[0].EventID)
	}
}
