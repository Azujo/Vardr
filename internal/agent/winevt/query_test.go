package winevt

import "testing"

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
		`<EventRecordID>98765</EventRecordID><Channel>System</Channel></System></Event>`
	rec, ev, has, err := parseIDs(xml)
	if err != nil || rec != 98765 || ev != 7036 || !has {
		t.Fatalf("parseIDs = %d %d %v %v", rec, ev, has, err)
	}
	if _, _, _, err := parseIDs("<Event/>"); err == nil {
		t.Fatal("brak EventRecordID powinien dawać błąd")
	}
}
