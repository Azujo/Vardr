package contract

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Ochrona agenta (roadmapa, sekcja 7 – „utrudnić i wykryć”): usługa
// z zawężonymi uprawnieniami, zatrzymanie i deinstalacja tylko tokenem
// z panelu, raport prób sabotażu w heartbeacie.

// UninstallToken to skrót jednorazowego tokenu deinstalacji agenta, który
// panel przekazuje w konfiguracji. Token zna tylko administrator, który go
// wygenerował; na komputerze jest wyłącznie skrót.
type UninstallToken struct {
	ID        string    `json:"id"`   // pierwsze 12 znaków skrótu – w raportach agenta
	Hash      string    `json:"hash"` // UninstallHash
	ExpiresAt time.Time `json:"expires_at"`
}

// MaxUninstallTokens ogranicza liczbę tokenów w konfiguracji agenta.
const MaxUninstallTokens = 5

// tokenAlphabet: 32 znaki bez łatwych do pomylenia 0/O i 1/I.
const tokenAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewUninstallToken losuje token (100 bitów) w postaci XXXXX-XXXXX-XXXXX-XXXXX.
func NewUninstallToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var s strings.Builder
	for i, c := range b {
		if i > 0 && i%5 == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(tokenAlphabet[int(c)%len(tokenAlphabet)]) // 256 % 32 == 0 – bez obciążenia
	}
	return s.String(), nil
}

// NormalizeUninstallToken: wielkie litery, bez spacji i myślników.
func NormalizeUninstallToken(t string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, t)
}

// UninstallHash to skrót tokenu związany z agentem (token jednego agenta
// nie pasuje do innego).
func UninstallHash(agentID, token string) string {
	sum := sha256.Sum256([]byte("heimdall-uninstall-v1\x00" + agentID + "\x00" + NormalizeUninstallToken(token)))
	return hex.EncodeToString(sum[:])
}

// UninstallTokenID to identyfikator tokenu widoczny w raportach i panelu.
func UninstallTokenID(hash string) string {
	if len(hash) < 12 {
		return hash
	}
	return hash[:12]
}

func validateTokens(ts []UninstallToken) error {
	if len(ts) > MaxUninstallTokens {
		return fmt.Errorf("za dużo tokenów deinstalacji (maks. %d)", MaxUninstallTokens)
	}
	for _, t := range ts {
		if _, err := hex.DecodeString(t.Hash); err != nil || len(t.Hash) != 64 || t.ID != UninstallTokenID(t.Hash) {
			return errors.New("niepoprawny skrót tokenu deinstalacji")
		}
	}
	return nil
}

// Rodzaje zdarzeń ochrony agenta (TamperRecord.Kind).
const (
	TamperStop          = "stop"            // usługa zatrzymana bez tokenu
	TamperUncleanExit   = "unclean_exit"    // proces zakończony bez zatrzymania usługi (zabity, awaria)
	TamperACL           = "acl_restored"    // ktoś zmienił uprawnienia usługi – przywrócone
	TamperConfig        = "config_restored" // ktoś zmienił typ uruchamiania albo ścieżkę programu usługi – przywrócone
	TamperBadToken      = "bad_token"       // nieudana próba zatrzymania/deinstalacji (zły token)
	TamperStopToken     = "stop_token"      // zatrzymanie tokenem (prace serwisowe)
	TamperUninstallTok  = "uninstall_token" // deinstalacja tokenem
	TamperUpgrade       = "upgrade"         // aktualizacja (MSI albo siem_agent upgrade)
	TamperProtectionOff = "protection_off"  // grupa wyłączyła ochronę – uprawnienia usługi zwykłe
)

// TamperKind opisuje rodzaj zdarzenia: poziom alertu ("" = bez alertu,
// tylko wpis w panelu) i opis.
type TamperKind struct {
	Level string
	Title string
}

// TamperKinds: znane rodzaje zdarzeń ochrony.
var TamperKinds = map[string]TamperKind{
	TamperStop:          {"high", "Usługa agenta zatrzymana bez tokenu"},
	TamperUncleanExit:   {"medium", "Proces agenta zakończony bez zatrzymania usługi (zabity albo awaria)"},
	TamperACL:           {"high", "Zmieniono uprawnienia usługi agenta (przywrócone)"},
	TamperConfig:        {"high", "Zmieniono konfigurację usługi agenta – typ uruchamiania albo program (przywrócona)"},
	TamperBadToken:      {"medium", "Nieudana próba zatrzymania albo deinstalacji agenta (bez ważnego tokenu)"},
	TamperStopToken:     {"", "Zatrzymanie agenta tokenem"},
	TamperUninstallTok:  {"", "Deinstalacja agenta tokenem"},
	TamperUpgrade:       {"", "Aktualizacja agenta"},
	TamperProtectionOff: {"", "Ochrona agenta wyłączona w grupie"},
}

// TamperRecord to zdarzenie ochrony agenta. Agent trzyma je w dzienniku
// w katalogu stanu i wysyła ostatnie w heartbeacie (status.protection.events),
// więc zdarzenie z chwili zatrzymania dociera także po ponownym starcie.
type TamperRecord struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Detail  string    `json:"detail,omitempty"`
	User    string    `json:"user,omitempty"`     // konto, z którego wydano polecenie (jeśli znane)
	TokenID string    `json:"token_id,omitempty"` // użyty token deinstalacji
}

// ProtectionStatus to stan ochrony w statusie agenta (status.json, heartbeat).
type ProtectionStatus struct {
	Enabled bool           `json:"enabled"`
	Service string         `json:"service"` // protected | open | error
	Error   string         `json:"error,omitempty"`
	Tokens  int            `json:"tokens"` // ważne tokeny deinstalacji znane agentowi
	Events  []TamperRecord `json:"events,omitempty"`
}
