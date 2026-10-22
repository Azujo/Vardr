// SPDX-License-Identifier: AGPL-3.0-or-later

package status

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrackerSnapshotAndRender(t *testing.T) {
	tr := NewTracker("0.2.0", "agt-1", "https://siem:8443/v1/ingest", map[string]any{"priority": "below_normal"})
	tr.ChannelState("Microsoft-Windows-Sysmon/Operational", ChannelNotFound, "kanał nie istnieje")
	tr.ChannelRead("Security", 1234, time.Now().UTC(), 1500*time.Millisecond)
	tr.SendFailed("connection refused")
	tr.AddProbe(func(s *Status) { s.Counters.Accepted = 42 })

	s := tr.Snapshot()
	if len(s.Channels) != 2 || s.Channels[0].Name != "Microsoft-Windows-Sysmon/Operational" {
		t.Fatalf("kanały: %+v", s.Channels)
	}
	if s.Server.Healthy || s.Counters.Accepted != 42 || s.Process.Goroutines == 0 {
		t.Fatalf("migawka: %+v", s)
	}

	var out bytes.Buffer
	Render(&out, s, time.Now())
	for _, want := range []string{"BRAK KANAŁU", "kanał nie istnieje", "rekord 1234", "PROBLEM", "connection refused", "przyjęte przez serwer 42"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("brak %q w:\n%s", want, out.String())
		}
	}

	tr.SendOK()
	out.Reset()
	Render(&out, tr.Snapshot(), time.Now().Add(time.Minute))
	if !strings.Contains(out.String(), "NIEAKTUALNY") || !strings.Contains(out.String(), "OK – ostatnia") {
		t.Errorf("po odzyskaniu łączności i starym zapisie:\n%s", out.String())
	}
}

func TestRunWritesFile(t *testing.T) {
	dir := t.TempDir()
	tr := NewTracker("0.2.0", "agt-1", "u", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx, dir, time.Hour); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	s, err := Read(filepath.Join(dir, FileName))
	if err != nil || s.AgentID != "agt-1" {
		t.Fatalf("odczyt statusu: %+v, %v", s, err)
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *Tracker
	tr.ChannelRead("x", 1, time.Now(), 0)
	tr.SendOK()
	tr.SendFailed("x")
	tr.ChannelState("x", ChannelOK, "")
	tr.AddProbe(func(*Status) {})
}
