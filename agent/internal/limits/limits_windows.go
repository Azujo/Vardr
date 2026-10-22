// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package limits

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobObjectCPURateControlEnable  = 0x1
	jobObjectCPURateControlHardCap = 0x4
)

// jobObjectCPURateControlInformation odpowiada JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
// (ControlFlags + unia, z której używamy CpuRate).
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	CPURate      uint32 // w setnych procenta całego komputera (1–10000)
}

// Controller utrzymuje Job Object agenta i pozwala zmieniać limity w trakcie
// pracy (np. po zmianie polityki w panelu) bez restartu.
type Controller struct {
	mu        sync.Mutex
	job       windows.Handle
	cpuCapped bool // czy limit CPU był kiedykolwiek włączony
}

// Apply tworzy kontroler przy pierwszym wywołaniu i nakłada limity.
func Apply(l Limits) (*Controller, error) {
	c := &Controller{}
	if err := c.Update(l); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Update zmienia limity działającego procesu.
func (c *Controller) Update(l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.setPriority(l.Priority); err != nil {
		return fmt.Errorf("priorytet: %w", err)
	}
	applySoftMemory(l.MemorySoftMB)

	needJob := l.CPUMaxPercent > 0 || l.MemoryHardMB > 0
	if !needJob && c.job == 0 {
		return nil
	}
	if c.job == 0 {
		job, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return fmt.Errorf("CreateJobObject: %w", err)
		}
		if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
			windows.CloseHandle(job)
			return fmt.Errorf("AssignProcessToJobObject: %w", err)
		}
		c.job = job
	}
	if err := c.setCPU(l.CPUMaxPercent); err != nil {
		return fmt.Errorf("limit CPU: %w", err)
	}
	if err := c.setMemory(l.MemoryHardMB); err != nil {
		return fmt.Errorf("limit pamięci: %w", err)
	}
	return nil
}

func (c *Controller) setPriority(p string) error {
	class := map[string]uint32{
		PriorityNormal:      windows.NORMAL_PRIORITY_CLASS,
		PriorityBelowNormal: windows.BELOW_NORMAL_PRIORITY_CLASS,
		PriorityBackground:  windows.IDLE_PRIORITY_CLASS,
	}[p]
	return windows.SetPriorityClass(windows.CurrentProcess(), class)
}

func (c *Controller) setCPU(percent float64) error {
	// Windows odrzuca wyłączanie limitu, który nigdy nie był włączony.
	if percent <= 0 && !c.cpuCapped {
		return nil
	}
	info := jobObjectCPURateControlInformation{}
	if percent > 0 {
		rate := uint32(percent*100 + 0.5)
		if rate < 1 {
			rate = 1
		}
		info.ControlFlags = jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap
		info.CPURate = rate
	}
	if _, err := windows.SetInformationJobObject(c.job, windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	c.cpuCapped = percent > 0
	return nil
}

func (c *Controller) setMemory(mb int) error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(c.job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return err
	}
	if mb > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(mb) << 20
	} else {
		info.BasicLimitInformation.LimitFlags &^= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = 0
	}
	_, err := windows.SetInformationJobObject(c.job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	return err
}

// Close zwalnia uchwyt Job Object. Limity pozostają aktywne do końca procesu.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.job != 0 {
		windows.CloseHandle(c.job)
		c.job = 0
	}
}
