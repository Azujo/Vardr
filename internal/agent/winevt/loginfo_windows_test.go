//go:build windows

package winevt

import "testing"

// System i Application są czytelne bez uprawnień administratora.
func TestLogInfoRealChannels(t *testing.T) {
	for _, ch := range []string{"System", "Application"} {
		info, err := LogInfo(ch)
		if err != nil {
			t.Fatalf("%s: %v", ch, err)
		}
		t.Logf("%s: %+v (najnowszy %d, pojemność ok. %d)", ch, info, info.Newest(), info.Capacity())
		if info.Records == 0 || info.Oldest == 0 || info.MaxSize < 1<<20 || info.FileSize == 0 {
			t.Errorf("%s: nieprawdopodobne wartości %+v", ch, info)
		}
	}
	if _, err := LogInfo("Kanał-Który-Nie-Istnieje"); err == nil {
		t.Error("nieistniejący kanał powinien dać błąd")
	}
}
