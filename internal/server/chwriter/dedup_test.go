package chwriter

import (
	"net"
	"testing"
)

func TestSeenEvictsOldest(t *testing.T) {
	s := NewSeen(2)
	s.Add("a")
	s.Add("b")
	s.Add("a") // bez zmian
	s.Add("c") // usuwa "a"
	if s.Has("a") || !s.Has("b") || !s.Has("c") || s.Len() != 2 {
		t.Fatalf("a=%v b=%v c=%v len=%d", s.Has("a"), s.Has("b"), s.Has("c"), s.Len())
	}
}

func TestIPv6(t *testing.T) {
	if got := ipv6("10.0.5.23"); !got.Equal(net.ParseIP("::ffff:10.0.5.23")) {
		t.Fatal(got)
	}
	if got := ipv6(""); !got.Equal(net.IPv6zero) {
		t.Fatal(got)
	}
	if got := ipv6("fe80::1"); !got.Equal(net.ParseIP("fe80::1")) {
		t.Fatal(got)
	}
}
