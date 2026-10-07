//go:build windows

package limits

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Test nakłada limity na proces testowy i sprawdza, że Windows je przyjął.
func TestApplyAndUpdateOnCurrentProcess(t *testing.T) {
	c, err := Apply(Limits{Priority: PriorityBelowNormal, CPUMaxPercent: 50, MemorySoftMB: 200, MemoryHardMB: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	prio, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil || prio != windows.BELOW_NORMAL_PRIORITY_CLASS {
		t.Fatalf("priorytet = %#x, %v", prio, err)
	}
	var info jobObjectCPURateControlInformation
	if err := windows.QueryInformationJobObject(c.job, windows.JobObjectCpuRateControlInformation,
		uintptrOf(&info), sizeOf(info), nil); err != nil {
		t.Fatal(err)
	}
	if info.CPURate != 5000 || info.ControlFlags&jobObjectCPURateControlHardCap == 0 {
		t.Fatalf("limit CPU w Windows: %+v", info)
	}

	// Zmiana w trakcie pracy: zdjęcie limitu CPU, powrót do normalnego priorytetu.
	if err := c.Update(Limits{Priority: PriorityNormal}); err != nil {
		t.Fatal(err)
	}
	if err := windows.QueryInformationJobObject(c.job, windows.JobObjectCpuRateControlInformation,
		uintptrOf(&info), sizeOf(info), nil); err != nil {
		t.Fatal(err)
	}
	if info.ControlFlags != 0 {
		t.Fatalf("limit CPU nie został zdjęty: %+v", info)
	}
}

func uintptrOf(p *jobObjectCPURateControlInformation) uintptr { return uintptr(unsafe.Pointer(p)) }

func sizeOf(v jobObjectCPURateControlInformation) uint32 { return uint32(unsafe.Sizeof(v)) }

// Domyślny profil: tylko twardy limit pamięci, bez limitu CPU.
// (Regresja: wcześniej próba „wyłączenia” nigdy niewłączonego limitu CPU
// kończyła się błędem „Parametr jest niepoprawny”.)
func TestApplyMemoryOnlyWithoutCPUCap(t *testing.T) {
	c, err := Apply(Limits{Priority: PriorityBelowNormal, MemorySoftMB: 150, MemoryHardMB: 400})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(c.job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		t.Fatal(err)
	}
	if info.ProcessMemoryLimit != 400<<20 || info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY == 0 {
		t.Fatalf("limit pamięci w Windows: %d, flagi %#x", info.ProcessMemoryLimit, info.BasicLimitInformation.LimitFlags)
	}
}

func TestBackgroundPriorityIsIdleClass(t *testing.T) {
	c, err := Apply(Limits{Priority: PriorityBackground})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if prio, _ := windows.GetPriorityClass(windows.CurrentProcess()); prio != windows.IDLE_PRIORITY_CLASS {
		t.Fatalf("priorytet = %#x, oczekiwano IDLE", prio)
	}
	if err := c.Update(Limits{Priority: PriorityNormal}); err != nil {
		t.Fatal(err)
	}
	if prio, _ := windows.GetPriorityClass(windows.CurrentProcess()); prio != windows.NORMAL_PRIORITY_CLASS {
		t.Fatalf("powrót do normal: %#x", prio)
	}
}
