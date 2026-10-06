package winevt

import (
	"testing"
	"time"
)

func TestBuildQuery(t *testing.T) {
	q, agentSide := BuildQuery([]uint32{4625, 4624, 4722, 4723, 4724, 4725, 4726, 1102, 4624})
	want := "*[System[(EventID=1102 or (EventID>=4624 and EventID<=4625) or (EventID>=4722 and EventID<=4726))]]"
	if q != want || agentSide {
		t.Fatalf("BuildQuery = %q (agentSide=%v)\nwant %q", q, agentSide, want)
	}

	if q, agentSide := BuildQuery(nil); q != "*" || agentSide {
		t.Fatalf("pusta lista: %q %v", q, agentSide)
	}

	var many []uint32
	for i := uint32(0); i <= MaxQueryTerms; i++ {
		many = append(many, 1000+i*2) // bez sąsiadów, więc każdy to osobny warunek
	}
	if q, agentSide := BuildQuery(many); q != "*" || !agentSide {
		t.Fatalf("zbyt długa lista powinna przejść na filtr agenta: %q %v", q, agentSide)
	}
}

func TestParseIDs(t *testing.T) {
	xml := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
		`<Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID>` +
		`<TimeCreated SystemTime='2026-10-06T10:29:01.4570000Z'/>` +
		`<EventRecordID>98765</EventRecordID><Channel>System</Channel></System></Event>`
	m, err := parseMeta(xml)
	if err != nil || m.RecordID != 98765 || m.EventID != 7036 || !m.HasEventID {
		t.Fatalf("parseMeta = %+v %v", m, err)
	}
	if want := time.Date(2026, 10, 6, 10, 29, 1, 457000000, time.UTC); !m.CreatedAt.Equal(want) {
		t.Fatalf("CreatedAt = %v, want %v", m.CreatedAt, want)
	}
	if _, err := parseMeta("<Event/>"); err == nil {
		t.Fatal("brak EventRecordID powinien dawać błąd")
	}
}
