// Package syslog to źródło logów kolektora: odbiór syslog przez UDP i TCP
// (RFC 3164 i RFC 5424; w TCP ramkowanie „octet counting” z RFC 6587 albo
// koniec linii). Wiadomość trafia do paczki bez zmian (parsowanie na
// serwerze – dekodery), z adresem nadawcy w polu Peer.
package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"siem/agent/internal/source"
)

// Config to ustawienia odbioru.
type Config struct {
	UDP        string         // adres nasłuchu UDP, np. ":514" (puste = wyłączony)
	TCP        string         // adres nasłuchu TCP (puste = wyłączony)
	MaxMessage int            // największa wiadomość w bajtach (dłuższe są przycinane)
	Allow      []netip.Prefix // dozwoloni nadawcy (puste = wszyscy)
	MaxConns   int            // najwięcej równoczesnych połączeń TCP
	IdleTCP    time.Duration  // rozłączenie nieaktywnego połączenia TCP
}

// Stats to liczniki odbioru.
type Stats struct {
	Received  atomic.Uint64
	Denied    atomic.Uint64 // nadawca spoza listy dozwolonych
	Truncated atomic.Uint64
	Refused   atomic.Uint64 // połączenia TCP ponad limit
}

// Source odbiera syslog. Kanał w stanie agenta: „syslog”.
type Source struct {
	Cfg   Config
	Log   *slog.Logger
	Stats Stats
	now   func() time.Time
}

// Channel: nazwa kanału w stanie agenta i w identyfikatorach zdarzeń.
func (s *Source) Channel() string { return "syslog" }

func (s *Source) allowed(addr netip.Addr) bool {
	if len(s.Cfg.Allow) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range s.Cfg.Allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Run nasłuchuje do anulowania ctx. Numery rekordów zaczynają się od chwili
// startu (mikrosekundy) – po restarcie identyfikatory zdarzeń się nie
// powtarzają, nawet gdy stan nie zdążył się zapisać.
func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	if s.now == nil {
		s.now = time.Now
	}
	if s.Cfg.MaxMessage <= 0 {
		s.Cfg.MaxMessage = 64 << 10
	}
	if s.Cfg.MaxConns <= 0 {
		s.Cfg.MaxConns = 200
	}
	if s.Cfg.IdleTCP <= 0 {
		s.Cfg.IdleTCP = 10 * time.Minute
	}
	var seq atomic.Uint64
	first := uint64(s.now().UnixMicro())
	if start.Valid && start.RecordID >= first {
		first = start.RecordID + 1
	}
	seq.Store(first - 1)
	var last atomic.Uint64
	last.Store(start.RecordID)

	emit := func(msg []byte, peer netip.Addr, proto string) bool {
		if !s.allowed(peer) {
			s.Stats.Denied.Add(1)
			return true
		}
		m := strings.TrimRight(string(msg), "\r\n\x00")
		if m == "" {
			return true
		}
		if len(m) > s.Cfg.MaxMessage {
			m = truncate(m, s.Cfg.MaxMessage)
			s.Stats.Truncated.Add(1)
		}
		id := seq.Add(1)
		rec := source.Record{Channel: s.Channel(), RecordID: id, Raw: m, ReadAt: s.now().UTC(),
			Source: "syslog:" + proto, Peer: peer.Unmap().String()}
		select {
		case out <- rec:
			s.Stats.Received.Add(1)
			last.Store(id)
			return true
		case <-ctx.Done():
			return false
		}
	}

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	if s.Cfg.UDP != "" {
		pc, err := net.ListenPacket("udp", s.Cfg.UDP)
		if err != nil {
			return start, fmt.Errorf("syslog UDP %s: %w", s.Cfg.UDP, err)
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(8 << 20) // zapas na krótkie szczyty
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- s.serveUDP(ctx, pc, emit)
		}()
		s.Log.Info("syslog: nasłuch UDP", "addr", pc.LocalAddr().String())
	}
	if s.Cfg.TCP != "" {
		ln, err := net.Listen("tcp", s.Cfg.TCP)
		if err != nil {
			return start, fmt.Errorf("syslog TCP %s: %w", s.Cfg.TCP, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- s.serveTCP(ctx, ln, emit)
		}()
		s.Log.Info("syslog: nasłuch TCP", "addr", ln.Addr().String())
	}
	if s.Cfg.UDP == "" && s.Cfg.TCP == "" {
		return start, errors.New("syslog: brak adresu nasłuchu (udp albo tcp)")
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	wg.Wait()
	pos := source.Position{RecordID: last.Load(), Valid: last.Load() > 0}
	if ctx.Err() != nil {
		return pos, nil
	}
	return pos, err
}

func (s *Source) serveUDP(ctx context.Context, pc net.PacketConn, emit func([]byte, netip.Addr, string) bool) error {
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("syslog UDP: %w", err)
		}
		ap, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(ap.IP)
		if !emit(buf[:n], ip, "udp") {
			return nil
		}
	}
}

func (s *Source) serveTCP(ctx context.Context, ln net.Listener, emit func([]byte, netip.Addr, string) bool) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var conns sync.WaitGroup
	defer conns.Wait()
	slots := make(chan struct{}, s.Cfg.MaxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("syslog TCP: %w", err)
		}
		ip := netip.Addr{}
		if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			ip, _ = netip.AddrFromSlice(ta.IP)
		}
		if !s.allowed(ip) {
			s.Stats.Denied.Add(1)
			_ = c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Stats.Refused.Add(1)
			_ = c.Close()
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer func() { <-slots }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stop()
			s.readStream(c, ip, emit)
		}()
	}
}

// readStream czyta wiadomości z połączenia TCP: „octet counting” (długość,
// spacja, wiadomość) albo wiadomości zakończone znakiem nowej linii.
func (s *Source) readStream(c net.Conn, ip netip.Addr, emit func([]byte, netip.Addr, string) bool) {
	r := bufio.NewReaderSize(c, 64<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.Cfg.IdleTCP))
		b, err := r.Peek(1)
		if err != nil {
			return
		}
		var msg []byte
		if b[0] >= '1' && b[0] <= '9' {
			n, err := readLength(r)
			if err != nil || n > 1<<20 {
				return // zła ramka – rozłączamy
			}
			keep := min(n, s.Cfg.MaxMessage+1)
			msg = make([]byte, keep)
			if _, err := io.ReadFull(r, msg); err != nil {
				return
			}
			if n > keep {
				if _, err := r.Discard(n - keep); err != nil {
					return
				}
			}
		} else {
			line, err := r.ReadSlice('\n')
			if errors.Is(err, bufio.ErrBufferFull) {
				// Linia dłuższa niż bufor – reszta do końca linii odrzucona.
				msg = append([]byte(nil), line...)
				for errors.Is(err, bufio.ErrBufferFull) {
					_, err = r.ReadSlice('\n')
				}
			} else if err != nil && len(line) == 0 {
				return
			} else {
				msg = append([]byte(nil), line...)
			}
		}
		if !emit(msg, ip, "tcp") {
			return
		}
	}
}

func readLength(r *bufio.Reader) (int, error) {
	s, err := r.ReadString(' ')
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("zła długość ramki %q", s)
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 { // nie przecinamy znaku UTF-8
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] >= 0xC0 {
		s = s[:len(s)-1]
	}
	return s
}
