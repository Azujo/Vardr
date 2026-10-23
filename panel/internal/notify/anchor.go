// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"siem/internal/lang"
	"siem/internal/urd"
)

// ArchiveSource to stan archiwum potrzebny do kotwicy (implementuje urd.PG).
type ArchiveSource interface {
	Overview(ctx context.Context) (urd.Overview, error)
	RecentManifests(ctx context.Context, limit int) ([]urd.ManifestRecord, error)
}

// AnchorStore to czas ostatniej wysłanej kotwicy (implementuje store.PG).
type AnchorStore interface {
	LastAnchorAt(ctx context.Context) (*time.Time, error)
}

// Anchor raz na dobę wysyła hash najnowszego manifestu archiwum poza system.
// Kopia u odbiorcy (Discord, skrzynka) jest niezależnym dowodem: kto
// przepisze łańcuch w archiwum i w bazie, nie zmieni wysłanych wiadomości.
type Anchor struct {
	Svc     *Service
	Archive ArchiveSource
	Store   AnchorStore
	Log     *slog.Logger
	Hour    int            // godzina wysyłki (czas lokalny Loc)
	Loc     *time.Location // strefa godziny wysyłki
}

// ErrNoManifest: archiwum nie ma jeszcze manifestu.
var ErrNoManifest = lang.Errorf("archiwum nie ma jeszcze żadnego manifestu", "the archive has no manifest yet")

// Message buduje wiadomość z kotwicą.
func (a *Anchor) Message(ctx context.Context, now time.Time) (Message, error) {
	ms, err := a.Archive.RecentManifests(ctx, 1)
	if err != nil {
		return Message{}, err
	}
	if len(ms) == 0 {
		return Message{}, ErrNoManifest
	}
	m := ms[0]
	o, err := a.Archive.Overview(ctx)
	if err != nil {
		return Message{}, err
	}
	loc := a.loc()
	lang := a.Svc.Language(ctx)
	verif := pick(lang, "jeszcze nie było", "none yet")
	sev := SevInfo
	if v := o.LastVerification; v != nil {
		if v.OK {
			verif = pick(lang, "zgodne, ", "compliant, ") + v.FinishedAt.In(loc).Format("2006-01-02 15:04")
		} else {
			verif = fmt.Sprintf(pick(lang, "NIEZGODNOŚCI (%d), %s", "MISMATCHES (%d), %s"), len(v.Problems), v.FinishedAt.In(loc).Format("2006-01-02 15:04"))
			sev = SevCritical
		}
	}
	seq := m.Seq
	return Message{
		Event:    EventAnchor,
		Severity: sev,
		Title:    pick(lang, "Kotwica archiwum Urd – ", "Urd archive anchor – ") + now.In(loc).Format("2006-01-02"),
		Text: pick(lang, "Hash najnowszego manifestu łańcucha archiwum NIS2. Zachowaj tę wiadomość: jeśli ktoś przepisze "+
			"archiwum i jego spis, ten hash przestanie się zgadzać z łańcuchem (sprawdzenie: panel → Urd → Manifesty "+
			"albo kotwica w eksporcie dla audytora).", "Hash of the latest manifest in the NIS2 archive chain. Keep this message: if "+
			"someone rewrites the archive and its catalog, this hash will no longer match the chain (check: panel → Urd → Manifests "+
			"or the anchor in the export for auditors)."),
		Fields: []Field{
			{Name: "Manifest", Value: fmt.Sprintf(pick(lang, "#%d – godzina %s", "#%d – hour %s"), m.Seq, m.Hour.In(loc).Format("2006-01-02 15:04")), Inline: true},
			{Name: pick(lang, "Łańcuch", "Chain"), Value: fmt.Sprintf(pick(lang, "%d manifestów, %d h z danymi w retencji",
				"%d manifests, %d h with data in retention"), o.Summary.ManifestsTotal, o.Summary.Manifests), Inline: true},
			{Name: pick(lang, "Ostatnia weryfikacja", "Last verification"), Value: verif},
			{Name: pick(lang, "SHA-256 manifestu", "Manifest SHA-256"), Value: "`" + m.SHA256 + "`"},
		},
		At:           now,
		AnchorSeq:    &seq,
		AnchorSHA256: m.SHA256,
	}, nil
}

func (a *Anchor) loc() *time.Location {
	if a.Loc != nil {
		return a.Loc
	}
	return time.Local
}

// due mówi, czy dziś (czas lokalny) należy już wysłać kotwicę.
func (a *Anchor) due(now time.Time, last *time.Time) bool {
	l := now.In(a.loc())
	slot := time.Date(l.Year(), l.Month(), l.Day(), a.Hour, 0, 0, 0, a.loc())
	if l.Before(slot) {
		return false
	}
	return last == nil || last.Before(slot)
}

// Run co 5 minut sprawdza, czy pora wysłać kotwicę.
func (a *Anchor) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	warned := false
	for {
		if err := a.tick(ctx); err != nil && ctx.Err() == nil {
			if !warned {
				a.Log.Warn("archive anchor not sent", "err", err)
				warned = true
			}
		} else {
			warned = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Anchor) tick(ctx context.Context) error {
	now := a.Svc.now()
	last, err := a.Store.LastAnchorAt(ctx)
	if err != nil {
		return err
	}
	if !a.due(now, last) {
		return nil
	}
	if ok, err := a.Svc.HasSubscribers(ctx, EventAnchor); err != nil || !ok {
		return err
	}
	m, err := a.Message(ctx, now)
	if errors.Is(err, ErrNoManifest) || errors.Is(err, urd.ErrNotConfigured) {
		return nil
	}
	if err != nil {
		return err
	}
	n, err := a.Svc.Send(ctx, m)
	if err == nil {
		a.Log.Info("archive anchor sent", "seq", *m.AnchorSeq, "sha256", m.AnchorSHA256, "channels", n)
	}
	return err
}
