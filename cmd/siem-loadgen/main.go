// Command siem-loadgen symuluje wielu agentów wysyłających zdarzenia Windows
// do siem-ingest (etap 1.5, ustalenie K4). Każdy symulowany agent ma własny
// certyfikat (wystawiany w pamięci przez laboratoryjne CA), własne
// połączenie TLS i bufor udający dziennik Windows: gdy serwer nie nadąża,
// zdarzenia czekają w buforze, a po jego przepełnieniu przepadają – tak jak
// nadpisane wpisy dziennika.
//
// Przykład (100 agentów po 20 zdarzeń/s przez 5 minut):
//
//	siem-loadgen -url https://192.168.88.98:8443/v1/ingest -agents 100 -eps 20 -duration 5m
//
// Zdarzenia mają agent_id z prefiksem -prefix (domyślnie agt-load), żeby
// dało się je odróżnić od prawdziwych i usunąć z bazy.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"siem/internal/contract"
	"siem/internal/loadgen"
)

type options struct {
	url        string
	pkiDir     string
	prefix     string
	agents     int
	eps        float64
	duration   time.Duration
	ramp       time.Duration
	batch      int
	flush      time.Duration
	maxBacklog int
	timeout    time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.url, "url", "https://localhost:8443/v1/ingest", "adres endpointu ingest")
	flag.StringVar(&o.pkiDir, "pki", "certs", "katalog z ca.crt i ca.key (laboratoryjne CA)")
	flag.StringVar(&o.prefix, "prefix", "agt-load", "prefiks identyfikatorów agentów")
	flag.IntVar(&o.agents, "agents", 100, "liczba symulowanych agentów")
	flag.Float64Var(&o.eps, "eps", 5, "zdarzeń na sekundę na agenta")
	flag.DurationVar(&o.duration, "duration", 2*time.Minute, "czas generowania zdarzeń")
	flag.DurationVar(&o.ramp, "ramp", 20*time.Second, "czas rozruchu (agenci startują równomiernie)")
	flag.IntVar(&o.batch, "batch", 500, "maks. zdarzeń w paczce (jak agent)")
	flag.DurationVar(&o.flush, "flush", 2*time.Second, "maks. czas zbierania paczki (jak agent)")
	flag.IntVar(&o.maxBacklog, "backlog", 50000, "pojemność bufora agenta (symulacja dziennika Windows)")
	flag.DurationVar(&o.timeout, "timeout", 30*time.Second, "limit czasu żądania")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	ca, caKey, err := loadCA(o.pkiDir)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	// Generacja z czasu startu: każde uruchomienie ma nowe identyfikatory
	// zdarzeń (inaczej writer pominąłby je jako duplikaty).
	gen := uint32(time.Now().Unix() % 1_000_000)
	fmt.Printf("Agenci: %d × %.1f zdarzeń/s = %.0f zdarzeń/s, czas %v (rozruch %v), cel %s, generacja g%d\n",
		o.agents, o.eps, float64(o.agents)*o.eps, o.duration, o.ramp, o.url, gen)

	sims := make([]*agent, o.agents)
	for i := range sims {
		id := fmt.Sprintf("%s-%04d", o.prefix, i+1)
		cert, err := issue(ca, caKey, id)
		if err != nil {
			return err
		}
		sims[i] = &agent{id: id, host: fmt.Sprintf("LOAD-%04d", i+1), gen: gen, o: &o,
			client: &http.Client{Timeout: o.timeout, Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
				MaxIdleConnsPerHost: 1,
				DisableCompression:  true,
			}}}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	genEnd := start.Add(o.ramp + o.duration)

	var wg sync.WaitGroup
	for i, a := range sims {
		wg.Add(1)
		delay := time.Duration(int64(o.ramp) * int64(i) / int64(max(1, o.agents)))
		go func() {
			defer wg.Done()
			a.run(ctx, start.Add(delay), genEnd)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	prev := stats.snapshot()
	prevAt := start
	for {
		select {
		case <-tick.C:
			now := time.Now()
			cur := stats.snapshot()
			report(now.Sub(start), cur, prev, now.Sub(prevAt), sims)
			prev, prevAt = cur, now
		case <-done:
			summary(time.Since(start), sims)
			return nil
		case <-ctx.Done():
			<-done
			summary(time.Since(start), sims)
			return nil
		}
	}
}

// ---- symulowany agent ----

type agent struct {
	id, host string
	gen      uint32
	o        *options
	client   *http.Client

	backlog []contract.Event
	record  uint64
	owed    float64 // ułamek zdarzenia „należny” z poprzedniego kroku
	pending atomic.Int64
}

func (a *agent) run(ctx context.Context, startAt, genEnd time.Time) {
	if !sleep(ctx, time.Until(startAt)) {
		return
	}
	last, lastFlush := time.Now(), time.Now()
	for {
		now := time.Now()
		if now.Before(genEnd) {
			a.produce(now.Sub(last).Seconds())
		}
		last = now
		a.pending.Store(int64(len(a.backlog)))

		if len(a.backlog) == 0 {
			if !now.Before(genEnd) {
				return // wszystko wygenerowane i wysłane
			}
			if !sleep(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		if len(a.backlog) < a.o.batch && now.Sub(lastFlush) < a.o.flush && now.Before(genEnd) {
			if !sleep(ctx, 100*time.Millisecond+time.Duration(mrand.Int64N(int64(100*time.Millisecond)))) {
				return
			}
			continue
		}

		n := min(len(a.backlog), a.o.batch)
		wait, ok := a.send(ctx, a.backlog[:n])
		if ctx.Err() != nil {
			return
		}
		if ok {
			a.backlog = slices.Delete(a.backlog, 0, n)
			lastFlush = time.Now()
			continue
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

// produce dokłada zdarzenia należne za dt sekund; nadmiar ponad pojemność
// bufora przepada (jak nadpisany dziennik Windows).
func (a *agent) produce(dt float64) {
	a.owed += a.o.eps * dt
	n := int(a.owed)
	a.owed -= float64(n)
	now := time.Now().UTC()
	for range n {
		a.record++
		ch, raw := loadgen.RandomEvent(a.host, a.record, now)
		a.backlog = append(a.backlog, contract.Event{
			ID: contract.EventID(a.id, ch, a.gen, a.record), Source: "wineventlog:" + ch, ReadAt: now, Raw: raw,
		})
	}
	stats.generated.Add(int64(n))
	if over := len(a.backlog) - a.o.maxBacklog; over > 0 {
		a.backlog = slices.Delete(a.backlog, 0, over)
		stats.lost.Add(int64(over))
	}
}

// send wysyła paczkę; przy niepowodzeniu zwraca czas oczekiwania.
func (a *agent) send(ctx context.Context, events []contract.Event) (time.Duration, bool) {
	body, err := encode(contract.Batch{Schema: contract.SchemaBatchV1, BatchID: contract.NewBatchID(),
		AgentID: a.id, SentAt: time.Now().UTC(), Events: events})
	if err != nil {
		panic(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.o.url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	t0 := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			stats.netErrors.Add(1)
			stats.setLastError(err.Error())
		}
		return jitter(2 * time.Second), false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	lat := time.Since(t0)
	stats.bytes.Add(int64(len(body)))

	switch resp.StatusCode {
	case http.StatusOK:
		stats.latency.observe(lat)
		stats.batches.Add(1)
		stats.accepted.Add(int64(len(events)))
		return 0, true
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		if resp.StatusCode == http.StatusTooManyRequests {
			stats.status429.Add(1)
		} else {
			stats.status503.Add(1)
		}
		ra := 2 * time.Second
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			ra = time.Duration(s) * time.Second
		}
		return jitter(ra), false
	default:
		stats.otherErrors.Add(1)
		stats.setLastError("HTTP " + resp.Status)
		return jitter(5 * time.Second), false
	}
}

func encode(b contract.Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jitter: d plus losowe 0–50% (jak agent).
func jitter(d time.Duration) time.Duration {
	return d + time.Duration(mrand.Int64N(int64(d/2)+1))
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// ---- certyfikaty ----

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	read := func(name string) (*pem.Block, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: niepoprawny PEM", name)
		}
		return blk, nil
	}
	cb, err := read("ca.crt")
	if err != nil {
		return nil, nil, err
	}
	kb, err := read("ca.key")
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, errors.Join(errors.New("ca.key"), err)
	}
	return cert, key, nil
}

// issue wystawia w pamięci krótko żyjący certyfikat klienta (CN = agent).
func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, agentID string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"SIEM Load Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ---- statystyki ----

type counters struct {
	generated, accepted, batches, bytes, lost    atomic.Int64
	status429, status503, netErrors, otherErrors atomic.Int64
	latency                                      histogram
	mu                                           sync.Mutex
	lastError                                    string
}

var stats counters

func (c *counters) setLastError(s string) {
	c.mu.Lock()
	c.lastError = s
	c.mu.Unlock()
}

type snapshot struct {
	generated, accepted, batches, bytes, lost, s429, s503, net, other int64
}

func (c *counters) snapshot() snapshot {
	return snapshot{c.generated.Load(), c.accepted.Load(), c.batches.Load(), c.bytes.Load(), c.lost.Load(),
		c.status429.Load(), c.status503.Load(), c.netErrors.Load(), c.otherErrors.Load()}
}

func backlog(sims []*agent) int64 {
	var n int64
	for _, a := range sims {
		n += a.pending.Load()
	}
	return n
}

func report(elapsed time.Duration, cur, prev snapshot, dt time.Duration, sims []*agent) {
	s := dt.Seconds()
	fmt.Printf("[%6s] wygenerowane %7.0f/s  przyjęte %7.0f/s  paczki %5.1f/s  %6.2f MB/s  429 %4.1f/s  503 %4.1f/s  błędy %d  bufor agentów %d  utracone %d  opóźnienie p50 %v p99 %v\n",
		elapsed.Round(time.Second), float64(cur.generated-prev.generated)/s, float64(cur.accepted-prev.accepted)/s,
		float64(cur.batches-prev.batches)/s, float64(cur.bytes-prev.bytes)/s/1e6,
		float64(cur.s429-prev.s429)/s, float64(cur.s503-prev.s503)/s, cur.net+cur.other,
		backlog(sims), cur.lost, stats.latency.quantile(0.5), stats.latency.quantile(0.99))
}

func summary(elapsed time.Duration, sims []*agent) {
	c := stats.snapshot()
	fmt.Println("\n=== Podsumowanie ===")
	fmt.Printf("czas: %v\n", elapsed.Round(time.Second))
	fmt.Printf("zdarzenia: wygenerowane %d, przyjęte %d, niewysłane (bufor) %d, utracone (przepełnienie bufora) %d\n",
		c.generated, c.accepted, backlog(sims), c.lost)
	fmt.Printf("średnio przyjęte: %.0f zdarzeń/s, %d paczek, %.1f MB skompresowanych\n",
		float64(c.accepted)/elapsed.Seconds(), c.batches, float64(c.bytes)/1e6)
	fmt.Printf("odmowy: 429 = %d, 503 = %d; błędy sieci %d, inne %d\n", c.s429, c.s503, c.net, c.other)
	fmt.Printf("opóźnienie odpowiedzi: p50 %v, p90 %v, p99 %v, max %v\n",
		stats.latency.quantile(0.5), stats.latency.quantile(0.9), stats.latency.quantile(0.99), stats.latency.max())
	stats.mu.Lock()
	if stats.lastError != "" {
		fmt.Printf("ostatni błąd: %s\n", stats.lastError)
	}
	stats.mu.Unlock()
}

// histogram z kubełkami co ~10% (1 ms – ok. 100 s), bez blokad.
type histogram struct {
	buckets [128]atomic.Int64
	maxNs   atomic.Int64
}

func bucketOf(d time.Duration) int {
	ms := float64(d) / float64(time.Millisecond)
	i := 0
	for edge := 1.0; ms > edge && i < 127; edge *= 1.1 {
		i++
	}
	return i
}

func (h *histogram) observe(d time.Duration) {
	h.buckets[bucketOf(d)].Add(1)
	for {
		m := h.maxNs.Load()
		if int64(d) <= m || h.maxNs.CompareAndSwap(m, int64(d)) {
			return
		}
	}
}

func (h *histogram) quantile(q float64) time.Duration {
	var total int64
	for i := range h.buckets {
		total += h.buckets[i].Load()
	}
	if total == 0 {
		return 0
	}
	target := int64(q * float64(total))
	var acc int64
	edge := 1.0
	for i := range h.buckets {
		acc += h.buckets[i].Load()
		if acc > target {
			return time.Duration(edge * float64(time.Millisecond)).Round(time.Millisecond)
		}
		edge *= 1.1
	}
	return h.max()
}

func (h *histogram) max() time.Duration { return time.Duration(h.maxNs.Load()).Round(time.Millisecond) }
