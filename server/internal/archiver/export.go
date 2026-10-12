package archiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"siem/internal/contract"
	"siem/internal/urd"
	"siem/server/internal/normalize"
)

// ExportStore to zlecenia eksportu w spisie (implementuje urd.PG).
type ExportStore interface {
	ClaimExport(ctx context.Context) (urd.ExportJob, bool, error)
	FinishExport(ctx context.Context, j urd.ExportJob) error
	FailInterruptedExports(ctx context.Context) (int64, error)
	ExpireExports(ctx context.Context, before time.Time) ([]string, error)
}

// Exporter wykonuje zlecenia eksportu dla audytora złożone w panelu.
type Exporter struct {
	A            *urd.Archive
	Store        ExportStore
	Dir          string        // katalog paczek (czyta go panel)
	Keep         time.Duration // po tym czasie paczka jest usuwana
	MinFreeBytes uint64        // zapas miejsca po zapisaniu paczki
	Version      string
	// ToolsDir: programy dołączane do każdej paczki (np. odczytaj.exe);
	// "" albo brak katalogu = bez programów (skrypt w Pythonie jest zawsze).
	ToolsDir string
	Log      *slog.Logger
	// Lock: wspólny z usuwaniem danych po retencji – eksport nie może
	// czytać segmentów, które właśnie znikają.
	Lock *sync.Mutex
}

// Run sprawdza zlecenia co 15 s i co godzinę usuwa stare paczki.
func (e *Exporter) Run(ctx context.Context) {
	for _, pattern := range []string{"urd-ndjson-*", "urd-csv-*", "*.tar.tmp"} {
		left, _ := filepath.Glob(filepath.Join(e.Dir, pattern))
		for _, f := range left {
			_ = os.Remove(f) // pozostałości po przerwanym eksporcie
		}
	}
	if n, err := e.Store.FailInterruptedExports(ctx); err != nil {
		e.Log.Warn("oznaczanie przerwanych eksportów nieudane", "err", err)
	} else if n > 0 {
		e.Log.Warn("eksporty przerwane restartem oznaczone jako nieudane", "count", n)
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	var lastExpire time.Time
	for {
		if time.Since(lastExpire) >= time.Hour {
			lastExpire = time.Now()
			e.expire(ctx)
		}
		for ctx.Err() == nil {
			j, ok, err := e.Store.ClaimExport(ctx)
			if err != nil {
				e.Log.Warn("odczyt zleceń eksportu nieudany", "err", err)
				break
			}
			if !ok {
				break
			}
			e.Log.Info("eksport dla audytora: start", "id", j.ID, "by", j.RequestedBy,
				"from", j.From.UTC().Format(time.RFC3339), "to", j.To.UTC().Format(time.RFC3339))
			j = e.runJob(ctx, j)
			if err := e.Store.FinishExport(context.WithoutCancel(ctx), j); err != nil {
				e.Log.Error("zapis wyniku eksportu nieudany", "id", j.ID, "err", err)
			}
			if j.Status == urd.ExportDone {
				e.Log.Info("eksport dla audytora: gotowy", "id", j.ID, "file", j.FileName, "bytes", j.Bytes, "sha256", j.SHA256)
			} else {
				e.Log.Error("eksport dla audytora nieudany", "id", j.ID, "err", j.Error)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (e *Exporter) runJob(ctx context.Context, j urd.ExportJob) urd.ExportJob {
	fail := func(err error) urd.ExportJob {
		j.Status, j.Error = urd.ExportFailed, err.Error()
		return j
	}
	if st, err := os.Stat(e.Dir); err != nil || !st.IsDir() {
		return fail(fmt.Errorf("katalog eksportów %s niedostępny", e.Dir))
	}
	e.Lock.Lock()
	defer e.Lock.Unlock()
	plan, err := e.A.PlanExport(ctx, j.From, j.To)
	if err != nil {
		return fail(err)
	}
	// Paczka: oryginały + czytelne zdarzenia (NDJSON gzip ≈ oryginały, CSV ≈ 2×)
	// + pliki robocze – szacunkowo 4× rozmiar oryginałów.
	if free, _, err := diskUsageFn(e.Dir); err == nil && free < 4*uint64(plan.Bytes)+e.MinFreeBytes+64<<20 {
		return fail(fmt.Errorf("za mało miejsca na paczkę: potrzeba %.1f GB, wolne %.1f GB",
			float64(4*plan.Bytes)/(1<<30), float64(free)/(1<<30)))
	}

	name := urd.ExportName(j)
	full := filepath.Join(e.Dir, name)
	f, err := os.OpenFile(full+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fail(err)
	}
	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h)}
	j, err = e.A.WriteExport(ctx, j, plan, cw, urd.ExportOptions{Version: e.Version, TempDir: e.Dir, Enrich: NormalizerEnricher,
		Tools: e.tools()})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(full+".tmp", full)
	}
	if err != nil {
		_ = os.Remove(full + ".tmp")
		return fail(err)
	}
	_ = os.Chmod(full, 0o440)
	j.Status, j.FileName, j.Bytes, j.SHA256 = urd.ExportDone, name, cw.n, hex.EncodeToString(h.Sum(nil))
	return j
}

func (e *Exporter) expire(ctx context.Context) {
	names, err := e.Store.ExpireExports(ctx, time.Now().Add(-e.Keep))
	if err != nil {
		e.Log.Warn("usuwanie starych eksportów nieudane", "err", err)
		return
	}
	for _, n := range names {
		if !urd.ValidExportName(n) {
			continue
		}
		full := filepath.Join(e.Dir, n)
		_ = os.Chmod(full, 0o640)
		if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
			e.Log.Warn("usunięcie paczki eksportu nieudane", "file", n, "err", err)
		}
	}
	if len(names) > 0 {
		e.Log.Info("usunięto stare paczki eksportu", "count", len(names), "keep", e.Keep.String())
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

// NormalizerEnricher uzupełnia czytelne zdarzenia eksportu polami
// z normalizatora serwera (te same, co w bazie zdarzeń).
func NormalizerEnricher(ev contract.Event, agentID string, received time.Time, r *urd.Readable) {
	e, err := normalize.Event(ev, agentID, received)
	if err != nil {
		return
	}
	r.Timestamp = e.Timestamp.UTC().Format(time.RFC3339Nano)
	r.HostName, r.Code, r.Dataset, r.Provider = e.HostName, e.Code, e.Dataset, e.Provider
	r.Action, r.Outcome, r.UserName, r.UserDomain = e.Action, e.Outcome, e.UserName, e.UserDomain
	r.SourceIP, r.ProcessName, r.CommandLine, r.TimeQuality = e.SourceIP, e.ProcessName, e.CommandLine, e.TimeQuality
	r.Identity = e.Identity
}

// tools zwraca programy do dołączenia (pliki z katalogu ToolsDir).
func (e *Exporter) tools() map[string]string {
	if e.ToolsDir == "" {
		return nil
	}
	entries, err := os.ReadDir(e.ToolsDir)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, en := range entries {
		if en.Type().IsRegular() && !strings.HasPrefix(en.Name(), ".") {
			out[en.Name()] = filepath.Join(e.ToolsDir, en.Name())
		}
	}
	return out
}
