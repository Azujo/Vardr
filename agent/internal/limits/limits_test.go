package limits

import "testing"

func TestValidate(t *testing.T) {
	ok := []Limits{
		{Priority: PriorityBelowNormal},
		{Priority: PriorityBackground, CPUMaxPercent: 5, MemorySoftMB: 100, MemoryHardMB: 200},
		{Priority: PriorityNormal, CPUMaxPercent: 0.5},
	}
	for _, l := range ok {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	bad := []Limits{
		{Priority: "turbo"},
		{Priority: PriorityNormal, CPUMaxPercent: 120},
		{Priority: PriorityNormal, CPUMaxPercent: 0.001},
		{Priority: PriorityNormal, MemorySoftMB: 8},
		{Priority: PriorityNormal, MemoryHardMB: 32},
		{Priority: PriorityNormal, MemorySoftMB: 100, MemoryHardMB: 120}, // bezpiecznik za blisko punktu pracy
	}
	for _, l := range bad {
		if err := l.Validate(); err == nil {
			t.Errorf("%+v: oczekiwano błędu", l)
		}
	}
}
