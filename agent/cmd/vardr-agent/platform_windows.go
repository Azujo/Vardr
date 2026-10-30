// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"siem/agent/internal/config"
	"siem/agent/internal/iis"
	"siem/agent/internal/logwatch"
	"siem/agent/internal/secure"
	"siem/agent/internal/source"
	"siem/agent/internal/state"
	"siem/agent/internal/status"
	"siem/agent/internal/sysmon"
	"siem/agent/internal/timesync"
	"siem/agent/internal/update"
	"siem/agent/internal/winevt"
	"siem/internal/contract"
	"siem/internal/lang"
)

// Część agenta zależna od Windows: Event Log, IIS, uprawnienia (ACL), kopia
// stanu w rejestrze, ochrona usługi i aktualizacje przez MSI.

// autoUpdate: automatyczne aktualizacje instalatorem MSI.
const autoUpdate = true

// updateOffer: instalator MSI z konfiguracji grupy.
func updateOffer(c *contract.AgentConfig) *contract.AgentUpdate {
	if c == nil {
		return nil
	}
	return c.Update
}

func platformUpdater(*update.Updater) {}

func isPrivileged() bool { return secure.IsPrivileged() }

func restrictDir(dir string) error { return secure.RestrictDir(dir) }

// programWarning: opis zagrożenia, gdy plik programu może podmienić zwykły
// użytkownik (pusty – w porządku).
func programWarning() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if ok, why := secure.ServiceBinarySafe(exe); !ok {
		return why
	}
	return ""
}

// stateBackup: kopia stanu w rejestrze (znacznik wcześniejszego działania).
func stateBackup(privileged bool, dir string) (state.Backup, string) {
	b := state.NewRegistryBackup(privileged, dir)
	return b, b.Location()
}

func serviceRunning() bool {
	st, err := queryService()
	return err == nil && st.State == svc.Running
}

// systemProbes: usługa czasu Windows i stan Sysmona co 5 min.
func systemProbes(ctx context.Context, tracker *status.Tracker) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		tracker.SetTimeService(timesync.ServiceState())
		tracker.SetSysmon(sysmon.Check())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pipelineSources: kanały Event Log (z filtrem po stronie agenta, gdy lista
// Event ID nie mieści się w XPath), logi IIS i ostrzeżenie przed nadpisaniem
// niewysłanych zdarzeń w dzienniku (K3).
func platformSources(cfg *config.Config, tracker *status.Tracker, log *slog.Logger) pipelineSources {
	var p pipelineSources
	var watched []logwatch.Channel
	p.filters = map[string]map[uint32]bool{}
	for _, ch := range cfg.Channels {
		q, agentSide := winevt.BuildQuery(ch.EventIDs)
		if agentSide {
			allowed := map[uint32]bool{}
			for _, id := range ch.EventIDs {
				allowed[id] = true
			}
			p.filters[ch.Name] = allowed
			log.Warn("Event ID list too long for XPath – agent-side filter", "channel", ch.Name, "ids", len(ch.EventIDs))
		}
		reader := winevt.NewReader(ch.Name, q, cfg.StartAt, log)
		reader.OnGap = tracker.Warn
		p.sources = append(p.sources, reader)
		watched = append(watched, logwatch.Channel{
			Name:        ch.Name,
			LastDrained: reader.LastDrained,
			LastRead:    lastRead(tracker, ch.Name),
		})
	}
	p.sources = append(p.sources, iisSources(cfg.IIS, tracker, log)...)
	p.watch = func(ctx context.Context) {
		w := &logwatch.Watcher{Info: winevt.LogInfo, Channels: watched, Log: log, Warn: tracker.Warn,
			Interval: time.Minute, WarnAt: 0.5, AlarmAt: 0.8}
		w.Run(ctx)
	}
	return p
}

// protectFiles zawęża uprawnienia katalogu stanu i klucza prywatnego.
// Zwraca ostrzeżenia do pokazania w statusie.
func protectFiles(cfg *config.Config, log *slog.Logger) []string {
	if !secure.IsPrivileged() {
		w := lang.L("agent działa bez uprawnień administratora – uprawnienia katalogu stanu i klucza nie zostały zawężone",
			"the agent runs without administrator rights – permissions of the state directory and the key were not restricted")
		log.Warn("the agent runs without administrator rights – permissions of the state directory and the key were not restricted")
		return []string{w}
	}
	var warns []string
	if err := secure.RestrictDir(cfg.StateDir); err != nil {
		warns = append(warns, errText(err))
		log.Error("securing agent files failed", "err", err)
	}
	if err := secure.RestrictFile(cfg.Server.KeyFile); err != nil {
		warns = append(warns, errText(err))
		log.Error("securing agent files failed", "err", err)
	}
	return warns
}

// retryDelay: brakujący kanał (np. Sysmon niezainstalowany) i brak uprawnień
// sprawdzamy rzadko; inne błędy szybciej.
func retryDelay(err error) time.Duration {
	if errors.Is(err, winevt.ErrChannelNotFound) || errors.Is(err, winevt.ErrAccessDenied) {
		return 5 * time.Minute
	}
	return 10 * time.Second
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, winevt.ErrChannelNotFound):
		return status.ChannelNotFound
	case errors.Is(err, winevt.ErrAccessDenied):
		return status.ChannelAccessDenied
	default:
		return status.ChannelError
	}
}

func processCPUTime() time.Duration {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return 0
	}
	// Filetime dla czasów procesu to liczba interwałów 100 ns.
	return time.Duration((filetimeTicks(k) + filetimeTicks(u)) * 100)
}

func filetimeTicks(f windows.Filetime) int64 {
	return int64(f.HighDateTime)<<32 | int64(f.LowDateTime)
}

// iisSources: po jednym źródle na katalog witryny IIS (włączone w agent.yaml
// albo w grupie). Nowa witryna – od ponownego uruchomienia odczytu (zmiana
// konfiguracji albo restart usługi).
func iisSources(c config.IISConfig, tracker *status.Tracker, log *slog.Logger) []source.Source {
	if !c.Enabled {
		return nil
	}
	dir := c.LogDir
	if dir == "" {
		dir = iis.DefaultDir
	}
	sites, err := iis.Sites(dir)
	if err == nil && len(sites) == 0 {
		err = fmt.Errorf("no W3C log files (u_ex*.log) in %s", dir)
	}
	if err != nil {
		log.Warn("IIS logs enabled, but not available", "err", err)
		tracker.Warn(lang.L("logi IIS włączone, ale niedostępne: ", "IIS logs enabled, but not available: ") + err.Error())
		return nil
	}
	host, _ := os.Hostname()
	out := make([]source.Source, 0, len(sites))
	for _, d := range sites {
		out = append(out, &iis.Source{Dir: d, Host: strings.ToLower(host), Log: log})
	}
	log.Info("IIS logs", "dir", dir, "sites", len(sites))
	return out
}
