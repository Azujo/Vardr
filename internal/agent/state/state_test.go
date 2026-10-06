package state

import "testing"

func TestLoadMissingAndRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())

	st, err := s.Load()
	if err != nil || len(st.Channels) != 0 {
		t.Fatalf("pusty stan: %v, %v", st, err)
	}

	st.Channels["Security"] = ChannelState{RecordID: 42, Generation: 1}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	st.Channels["Security"] = ChannelState{RecordID: 43, Generation: 1}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Channels["Security"] != (ChannelState{RecordID: 43, Generation: 1}) {
		t.Fatalf("odczytany stan: %+v", got)
	}
}
