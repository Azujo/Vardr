// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package limits

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Unit: jednostka systemd agenta Linux.
const Unit = "vardr-agent.service"

// Controller nakłada limity agenta Linux. Pod systemd – właściwości jednostki
// zmieniane w trakcie pracy (systemctl set-property --runtime): waga CPU i I/O
// zamiast priorytetu (nice dotyczy pojedynczego wątku, a agent ma ich wiele),
// CPUQuota i MemoryMax w cgroup usługi. W konsoli (vardr-agent run) – tylko
// miękki limit pamięci Go.
type Controller struct {
	mu   sync.Mutex
	last string // ostatnio ustawione właściwości
}

// Apply tworzy kontroler i nakłada limity.
func Apply(l Limits) (*Controller, error) {
	c := &Controller{}
	if err := c.Update(l); err != nil {
		return nil, err
	}
	return c, nil
}

// UnderSystemd: proces uruchomiony przez systemd (zmienna INVOCATION_ID).
func UnderSystemd() bool { return os.Getenv("INVOCATION_ID") != "" }

// Update zmienia limity działającego procesu.
func (c *Controller) Update(l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	applySoftMemory(l.MemorySoftMB)
	if !UnderSystemd() {
		return nil
	}
	props := Properties(l, runtime.NumCPU())
	key := strings.Join(props, " ")
	if key == c.last {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", append([]string{"set-property", "--runtime", Unit}, props...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl set-property: %v: %s", err, strings.TrimSpace(string(out)))
	}
	c.last = key
	return nil
}

// Close: limity zostają do końca procesu (właściwości --runtime znikają
// przy restarcie systemu).
func (c *Controller) Close() {}
