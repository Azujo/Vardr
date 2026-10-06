//go:build windows

package state

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestRegistryBackupRoundTrip(t *testing.T) {
	r := NewRegistryBackup(false, t.TempDir()) // HKCU – bez uprawnień administratora
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, r.path) })

	if _, exists, err := r.Load(); err != nil || exists {
		t.Fatalf("nowa kopia nie powinna istnieć: %v %v", exists, err)
	}
	if err := r.Save(State{Channels: map[string]ChannelState{"System": {RecordID: 99}}}); err != nil {
		t.Fatal(err)
	}
	st, exists, err := r.Load()
	if err != nil || !exists || st.Channels["System"].RecordID != 99 {
		t.Fatalf("odczyt kopii: %+v %v %v", st, exists, err)
	}
}
