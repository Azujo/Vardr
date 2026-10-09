package syslog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
)

func freeAddr(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func collect(t *testing.T, out <-chan source.Record, n int) []source.Record {
	t.Helper()
	var got []source.Record
	timeout := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case r := <-out:
			got = append(got, r)
		case <-timeout:
			t.Fatalf("odebrano %d z %d wiadomości: %+v", len(got), n, got)
		}
	}
	return got
}

func TestSyslogUDPAndTCP(t *testing.T) {
	udp, tcp := freeAddr(t, "udp"), freeAddr(t, "tcp")
	s := &Source{Cfg: Config{UDP: udp, TCP: tcp, MaxMessage: 60}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position)
	go func() {
		pos, _ := s.Run(ctx, source.Position{}, out)
		done <- pos
	}()
	time.Sleep(200 * time.Millisecond)

	uc, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(uc, "<134>Oct  9 12:00:00 fw01 date=2026-10-09 type=traffic\n")
	m2 := "<30>1 2026-10-09T12:00:01Z router1 system - - - " + strings.Repeat("x", 100)
	fmt.Fprint(uc, m2)
	uc.Close()
	got := collect(t, out, 2)
	if got[0].Source != "syslog:udp" || got[0].Peer != "127.0.0.1" || !strings.HasPrefix(got[0].Raw, "<134>Oct") ||
		strings.HasSuffix(got[0].Raw, "\n") {
		t.Fatalf("UDP: %+v", got[0])
	}
	if len(got[1].Raw) != 60 || s.Stats.Truncated.Load() != 1 || !got[1].Truncated || got[1].OriginalSize != len(m2) || got[0].Truncated {
		t.Fatalf("przycięcie do 60 bajtów: %d %q %v %d", len(got[1].Raw), got[1].Raw, got[1].Truncated, got[1].OriginalSize)
	}
	if got[1].RecordID <= got[0].RecordID || got[0].Channel != "syslog" {
		t.Fatalf("numeracja: %d %d", got[0].RecordID, got[1].RecordID)
	}

	tc, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	m1 := "<134>1 2026-10-09T12:00:02Z fw01 - - - - pierwsza"
	fmt.Fprintf(tc, "%d %s", len(m1), m1)                               // octet counting
	fmt.Fprint(tc, "<134>Oct  9 12:00:03 fw01 druga\r\n<134>trzecia\n") // koniec linii
	long := "<134>" + strings.Repeat("y", 200)
	fmt.Fprintf(tc, "%d %s", len(long), long) // ramka ponad limit – przycięta, ze znacznikiem
	tc.Close()
	got = collect(t, out, 4)
	if got[0].Raw != m1 || got[1].Raw != "<134>Oct  9 12:00:03 fw01 druga" || got[2].Raw != "<134>trzecia" || got[0].Source != "syslog:tcp" {
		t.Fatalf("TCP: %q %q %q", got[0].Raw, got[1].Raw, got[2].Raw)
	}
	if len(got[3].Raw) != 60 || !got[3].Truncated || got[3].OriginalSize != 205 {
		t.Fatalf("ramka TCP ponad limit: %d %v %d", len(got[3].Raw), got[3].Truncated, got[3].OriginalSize)
	}

	// Strumień samych cyfr (bez spacji) – rozłączenie zamiast rosnącego bufora.
	tc, err = net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tc.Write([]byte(strings.Repeat("9", 4096)))
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("połączenie z błędną ramką powinno zostać zamknięte: %v", err)
	}
	tc.Close()
	cancel()
	if pos := <-done; !pos.Valid || pos.RecordID != got[3].RecordID {
		t.Fatalf("pozycja po zatrzymaniu: %+v", pos)
	}
}

func TestSyslogAllowList(t *testing.T) {
	udp := freeAddr(t, "udp")
	s := &Source{Cfg: Config{UDP: udp, Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 10)
	go func() { _, _ = s.Run(ctx, source.Position{}, out) }()
	time.Sleep(200 * time.Millisecond)
	uc, _ := net.Dial("udp", udp)
	fmt.Fprint(uc, "<134>nie z dozwolonej sieci")
	uc.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats.Denied.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats.Denied.Load() != 1 || len(out) != 0 {
		t.Fatalf("lista dozwolonych: odrzucone %d, przyjęte %d", s.Stats.Denied.Load(), len(out))
	}
}

// Numery rekordów po restarcie nie wracają do wcześniejszych (identyfikatory zdarzeń unikalne).
func TestSyslogRecordIDsAfterRestart(t *testing.T) {
	future := uint64(time.Now().Add(time.Hour).UnixMicro())
	udp := freeAddr(t, "udp")
	s := &Source{Cfg: Config{UDP: udp}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 10)
	go func() { _, _ = s.Run(ctx, source.Position{RecordID: future, Valid: true}, out) }()
	time.Sleep(200 * time.Millisecond)
	uc, _ := net.Dial("udp", udp)
	fmt.Fprint(uc, "<134>po restarcie")
	uc.Close()
	if r := collect(t, out, 1)[0]; r.RecordID != future+1 {
		t.Fatalf("numer po zapisanej pozycji: %d, oczekiwano %d", r.RecordID, future+1)
	}
	_ = io.EOF
}
