//go:build windows

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// RegistryBackup przechowuje kopię stanu w rejestrze:
// <root>\SOFTWARE\SiemAgent\Instances\<skrót ścieżki katalogu stanu>.
// Usługa (SYSTEM) używa HKLM – zapis wymaga administratora; agent
// uruchomiony w konsoli bez uprawnień używa HKCU.
type RegistryBackup struct {
	root registry.Key
	path string
	dir  string
}

// NewRegistryBackup tworzy kopię dla katalogu stanu.
func NewRegistryBackup(machine bool, stateDir string) *RegistryBackup {
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		abs = stateDir
	}
	sum := sha256.Sum256([]byte(strings.ToLower(abs)))
	root := registry.CURRENT_USER
	if machine {
		root = registry.LOCAL_MACHINE
	}
	return &RegistryBackup{root: root, dir: abs,
		path: `SOFTWARE\SiemAgent\Instances\` + hex.EncodeToString(sum[:8])}
}

// Location opisuje miejsce kopii (do logów).
func (r *RegistryBackup) Location() string {
	if r.root == registry.LOCAL_MACHINE {
		return `HKLM\` + r.path
	}
	return `HKCU\` + r.path
}

func (r *RegistryBackup) Load() (State, bool, error) {
	k, err := registry.OpenKey(r.root, r.path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return empty(), false, nil
	}
	if err != nil {
		return empty(), false, err
	}
	defer k.Close()
	raw, _, err := k.GetStringValue("state")
	if errors.Is(err, registry.ErrNotExist) || raw == "" {
		return empty(), true, nil
	}
	if err != nil {
		return empty(), true, err
	}
	st := empty()
	if err := json.Unmarshal([]byte(raw), &st); err != nil || st.Channels == nil {
		return empty(), true, nil // uszkodzona kopia = brak pozycji, ale znacznik jest
	}
	return st, true, nil
}

func (r *RegistryBackup) Save(st State) error {
	k, _, err := registry.CreateKey(r.root, r.path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := k.SetStringValue("state_dir", r.dir); err != nil {
		return err
	}
	if err := k.SetStringValue("updated_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return k.SetStringValue("state", string(data))
}
