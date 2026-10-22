// SPDX-License-Identifier: AGPL-3.0-or-later

// Package backupcfg to ustawienia kopii zapasowych Vardra wspólne dla
// panelu (zapis ustawień) i usługi kopii siem-backup (wykonanie):
// harmonogram, zawartość, retencja, miejsce docelowe i sekrety.
//
// Sekrety (hasło, klucz prywatny SSH, klucz S3) panel szyfruje kluczem
// publicznym usługi kopii (NaCl sealed box, X25519). Klucz prywatny jest
// tylko w katalogu stanu usługi kopii – ani panel, ani baza Saga nie mogą
// odczytać sekretu po zapisie.
package backupcfg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Config to ustawienia kopii (JSON w Sadze, tabela backup_config).
type Config struct {
	Enabled  bool      `json:"enabled"`
	Schedule Schedule  `json:"schedule"`
	Include  Include   `json:"include"`
	Local    Retention `json:"local"`
	Remote   Retention `json:"remote"`
	Target   Target    `json:"target"`
}

// Schedule: co ile godzin (Kind=hours), codziennie albo co tydzień o godzinie.
type Schedule struct {
	Kind       string `json:"kind"` // hours | daily | weekly
	EveryHours int    `json:"every_hours,omitempty"`
	Hour       int    `json:"hour"`
	Minute     int    `json:"minute"`
	Weekday    int    `json:"weekday,omitempty"` // 1 = poniedziałek … 7 = niedziela
}

// Include: co trafia do kopii.
type Include struct {
	Saga    bool `json:"saga"`    // baza Saga: konta, agenci, certyfikaty, alerty, spis archiwum, polityka
	Config  bool `json:"config"`  // certs/ (z kluczem CA agentów) i .env
	Archive bool `json:"archive"` // przyrosty archiwum NIS2 (tylko do miejsca docelowego)
	Grafana bool `json:"grafana"` // dane Grafany (pulpity i ustawienia zmienione w interfejsie)
}

// Retention: kopia jest usuwana, gdy jest starsza niż KeepDays dni albo
// spoza KeepCount najnowszych (0 = bez tego warunku). Najnowsza kopia
// zostaje zawsze.
type Retention struct {
	KeepDays  int `json:"keep_days"`
	KeepCount int `json:"keep_count"`
}

// Metody wysyłki poza serwer.
const (
	MethodNone = "none"
	MethodSFTP = "sftp"
	MethodSMB  = "smb"
	MethodS3   = "s3"
)

// Sposoby logowania SFTP.
const (
	AuthServerKey  = "server_key"  // klucz wygenerowany przez usługę kopii (zalecane)
	AuthPrivateKey = "private_key" // klucz prywatny wklejony w panelu
	AuthPassword   = "password"
)

// Target to miejsce docelowe kopii poza serwerem.
type Target struct {
	Method string `json:"method"`
	Host   string `json:"host,omitempty"`   // SFTP, SMB
	Port   int    `json:"port,omitempty"`   // SFTP (22), SMB (445)
	User   string `json:"user,omitempty"`   // SFTP, SMB
	Auth   string `json:"auth,omitempty"`   // SFTP
	Share  string `json:"share,omitempty"`  // SMB: nazwa udziału
	Domain string `json:"domain,omitempty"` // SMB
	Path   string `json:"path,omitempty"`   // katalog: SFTP – od / bezwzględny, inaczej od katalogu domowego; SMB – w udziale; S3 – w kubełku

	Endpoint  string `json:"endpoint,omitempty"` // S3: adres (pusty – AWS)
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
}

// Nazwy sekretów (tabela backup_secrets).
const (
	SecretPassword   = "password"    // SFTP, SMB
	SecretPrivateKey = "private_key" // SFTP (klucz wklejony)
	SecretS3Key      = "s3_secret"   // S3: secret access key
)

// Secrets to sekrety potrzebne przy danych ustawieniach.
func (t Target) Secrets() []string {
	switch t.Method {
	case MethodSFTP:
		switch t.Auth {
		case AuthPassword:
			return []string{SecretPassword}
		case AuthPrivateKey:
			return []string{SecretPrivateKey}
		}
	case MethodSMB:
		return []string{SecretPassword}
	case MethodS3:
		return []string{SecretS3Key}
	}
	return nil
}

// Default to ustawienia nowej instalacji (jak dotychczasowy backup.sh:
// codziennie 02:15, baza i konfiguracja, 14 dni lokalnie, 90 zdalnie).
func Default() Config {
	return Config{
		Enabled:  true,
		Schedule: Schedule{Kind: "daily", Hour: 2, Minute: 15},
		Include:  Include{Saga: true, Config: true, Archive: true},
		Local:    Retention{KeepDays: 14},
		Remote:   Retention{KeepDays: 90},
		Target:   Target{Method: MethodNone},
	}
}

var (
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)
	userRe   = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{1,128}$`)
	shareRe  = regexp.MustCompile(`^[A-Za-z0-9._$ -]{1,80}$`)
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRe = regexp.MustCompile(`^[a-z0-9-]{0,40}$`)
	keyIDRe  = regexp.MustCompile(`^[A-Za-z0-9/+=._-]{1,128}$`)
)

// Validate sprawdza ustawienia (komunikaty dla panelu).
func (c *Config) Validate() error {
	s := &c.Schedule
	switch s.Kind {
	case "hours":
		if !oneOf(s.EveryHours, 1, 2, 3, 4, 6, 8, 12) {
			return errors.New("harmonogram: co 1, 2, 3, 4, 6, 8 albo 12 godzin")
		}
	case "daily":
	case "weekly":
		if s.Weekday < 1 || s.Weekday > 7 {
			return errors.New("harmonogram: dzień tygodnia 1–7")
		}
	default:
		return errors.New("harmonogram: co kilka godzin, codziennie albo co tydzień")
	}
	if s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 {
		return errors.New("harmonogram: godzina 0–23, minuta 0–59")
	}
	if !c.Include.Saga && !c.Include.Config && !c.Include.Archive && !c.Include.Grafana {
		return errors.New("zawartość: wybierz co najmniej jeden element")
	}
	for _, r := range []struct {
		name string
		r    Retention
	}{{"lokalnie", c.Local}, {"w miejscu docelowym", c.Remote}} {
		if r.r.KeepDays < 1 || r.r.KeepDays > 3650 || r.r.KeepCount < 0 || r.r.KeepCount > 1000 {
			return fmt.Errorf("retencja %s: 1–3650 dni, 0–1000 kopii (0 – bez limitu liczby)", r.name)
		}
	}
	t := &c.Target
	t.Host, t.User, t.Path = strings.TrimSpace(t.Host), strings.TrimSpace(t.User), strings.TrimRight(strings.TrimSpace(t.Path), "/")
	if strings.Contains(t.Path, "..") || strings.ContainsAny(t.Path, "\x00\n\r:") {
		return errors.New("miejsce docelowe: niepoprawny katalog")
	}
	host := func() error {
		if net.ParseIP(t.Host) == nil && !hostRe.MatchString(t.Host) {
			return errors.New("miejsce docelowe: podaj adres serwera (nazwa albo IP)")
		}
		if t.Port < 0 || t.Port > 65535 {
			return errors.New("miejsce docelowe: port 1–65535")
		}
		if !userRe.MatchString(t.User) {
			return errors.New("miejsce docelowe: podaj użytkownika")
		}
		return nil
	}
	switch t.Method {
	case MethodNone:
		*t = Target{Method: MethodNone}
	case MethodSFTP:
		if err := host(); err != nil {
			return err
		}
		if t.Auth != AuthServerKey && t.Auth != AuthPrivateKey && t.Auth != AuthPassword {
			return errors.New("SFTP: wybierz sposób logowania")
		}
		if t.Path == "" {
			return errors.New("SFTP: podaj katalog na serwerze kopii")
		}
		t.Share, t.Domain, t.Endpoint, t.Region, t.Bucket, t.AccessKey = "", "", "", "", "", ""
	case MethodSMB:
		if err := host(); err != nil {
			return err
		}
		if !shareRe.MatchString(t.Share) {
			return errors.New("SMB: podaj nazwę udziału")
		}
		if t.Domain != "" && !userRe.MatchString(t.Domain) {
			return errors.New("SMB: niepoprawna domena")
		}
		t.Auth, t.Endpoint, t.Region, t.Bucket, t.AccessKey = "", "", "", "", ""
		t.Path = strings.TrimLeft(t.Path, "/") // katalog w udziale
	case MethodS3:
		if t.Endpoint != "" && !strings.HasPrefix(t.Endpoint, "https://") && !strings.HasPrefix(t.Endpoint, "http://") {
			return errors.New("S3: adres zaczyna się od https:// (pusty – AWS)")
		}
		if !bucketRe.MatchString(t.Bucket) {
			return errors.New("S3: niepoprawna nazwa kubełka")
		}
		if !regionRe.MatchString(t.Region) {
			return errors.New("S3: niepoprawny region")
		}
		if !keyIDRe.MatchString(t.AccessKey) {
			return errors.New("S3: podaj identyfikator klucza dostępu")
		}
		t.Host, t.Port, t.User, t.Auth, t.Share, t.Domain = "", 0, "", "", "", ""
		t.Path = strings.TrimLeft(t.Path, "/") // prefiks w kubełku
	default:
		return errors.New("miejsce docelowe: tylko lokalnie, SFTP, SMB albo S3")
	}
	if c.Include.Archive && t.Method == MethodNone && !c.Include.Saga && !c.Include.Config && !c.Include.Grafana {
		return errors.New("zawartość: archiwum NIS2 jest wysyłane tylko do miejsca docelowego – ustaw je albo wybierz coś jeszcze")
	}
	return nil
}

func oneOf(v int, list ...int) bool {
	for _, x := range list {
		if v == x {
			return true
		}
	}
	return false
}

// LastSlot zwraca ostatni termin z harmonogramu nie późniejszy niż now
// (czas lokalny loc).
func (s Schedule) LastSlot(now time.Time, loc *time.Location) time.Time {
	n := now.In(loc)
	day := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	switch s.Kind {
	case "hours":
		every := max(s.EveryHours, 1)
		slot := time.Date(n.Year(), n.Month(), n.Day(), n.Hour()-n.Hour()%every, s.Minute, 0, 0, loc)
		for slot.After(n) {
			slot = slot.Add(-time.Duration(every) * time.Hour)
		}
		return slot
	case "weekly":
		wd := (int(n.Weekday())+6)%7 + 1 // 1 = poniedziałek
		slot := time.Date(n.Year(), n.Month(), n.Day()-(wd-s.Weekday), s.Hour, s.Minute, 0, 0, loc)
		if slot.After(n) {
			slot = slot.AddDate(0, 0, -7)
		}
		return slot
	}
	slot := day.Add(time.Duration(s.Hour)*time.Hour + time.Duration(s.Minute)*time.Minute)
	if slot.After(n) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}

// Due mówi, czy kopia z harmonogramu jest należna: ostatni termin minął
// po since (ostatnia kopia z harmonogramu albo zapis ustawień – zmiana
// ustawień nie uruchamia od razu zaległej kopii).
func (c Config) Due(since, now time.Time, loc *time.Location) bool {
	return c.Enabled && c.Schedule.LastSlot(now, loc).After(since)
}

// ---- sekrety ----

// NewBoxKey tworzy parę kluczy usługi kopii.
func NewBoxKey() (public, private *[32]byte, err error) { return box.GenerateKey(rand.Reader) }

// KeyID: krótki identyfikator klucza publicznego (sekret zaszyfrowany innym
// kluczem trzeba wpisać ponownie).
func KeyID(public *[32]byte) string {
	h := sha256.Sum256(public[:])
	return hex.EncodeToString(h[:6])
}

// EncodeKey / DecodeKey: klucz publiczny w bazie (base64).
func EncodeKey(k *[32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func DecodeKey(s string) (*[32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("niepoprawny klucz usługi kopii")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}

// Seal szyfruje sekret kluczem publicznym usługi kopii.
func Seal(secret string, public *[32]byte) ([]byte, error) {
	return box.SealAnonymous(nil, []byte(secret), public, rand.Reader)
}

// Open odszyfrowuje sekret (tylko usługa kopii – ma klucz prywatny).
func Open(sealed []byte, public, private *[32]byte) (string, error) {
	b, ok := box.OpenAnonymous(nil, sealed, public, private)
	if !ok {
		return "", errors.New("sekret zaszyfrowany innym kluczem – wpisz go ponownie w panelu")
	}
	return string(b), nil
}
