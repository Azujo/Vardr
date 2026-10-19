package backupcfg

import (
	"testing"
	"time"
)

func TestLastSlotAndDue(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	now := at("2026-10-21 11:30") // środa
	for _, c := range []struct {
		s    Schedule
		want string
	}{
		{Schedule{Kind: "daily", Hour: 2, Minute: 15}, "2026-10-21 02:15"},
		{Schedule{Kind: "daily", Hour: 23, Minute: 0}, "2026-10-20 23:00"},
		{Schedule{Kind: "hours", EveryHours: 6, Minute: 10}, "2026-10-21 06:10"},
		{Schedule{Kind: "hours", EveryHours: 1, Minute: 45}, "2026-10-21 10:45"},
		{Schedule{Kind: "weekly", Weekday: 3, Hour: 4}, "2026-10-21 04:00"},  // środa
		{Schedule{Kind: "weekly", Weekday: 5, Hour: 4}, "2026-10-16 04:00"},  // piątek – poprzedni tydzień
		{Schedule{Kind: "weekly", Weekday: 3, Hour: 12}, "2026-10-14 12:00"}, // środa, ale później niż teraz
	} {
		if got := c.s.LastSlot(now, loc); !got.Equal(at(c.want)) {
			t.Errorf("%+v: %s, oczekiwano %s", c.s, got.In(loc).Format("2006-01-02 15:04"), c.want)
		}
	}
	cfg := Default()
	if !cfg.Due(at("2026-10-20 02:20"), now, loc) || cfg.Due(at("2026-10-21 02:16"), now, loc) {
		t.Fatal("Due: kopia z 20.10 – należna dziś o 02:15; z dziś po 02:15 – nie")
	}
	cfg.Enabled = false
	if cfg.Due(time.Time{}, now, loc) {
		t.Fatal("wyłączone kopie nie są należne")
	}
}

func TestValidate(t *testing.T) {
	ok := Default()
	ok.Target = Target{Method: MethodSFTP, Host: "192.168.88.180", User: "heimdall", Auth: AuthServerKey, Path: "/mnt/tank/heimdall/"}
	if err := ok.Validate(); err != nil || ok.Target.Path != "/mnt/tank/heimdall" {
		t.Fatalf("poprawne SFTP: %v %q", err, ok.Target.Path)
	}
	for name, mod := range map[string]func(*Config){
		"pusta zawartość":       func(c *Config) { c.Include = Include{} },
		"zły harmonogram":       func(c *Config) { c.Schedule = Schedule{Kind: "hours", EveryHours: 5} },
		"retencja 0 dni":        func(c *Config) { c.Local.KeepDays = 0 },
		"SFTP bez hosta":        func(c *Config) { c.Target.Host = "" },
		"ścieżka z ..":          func(c *Config) { c.Target.Path = "a/../b" },
		"S3 bez kubełka":        func(c *Config) { c.Target = Target{Method: MethodS3, AccessKey: "AK"} },
		"SMB bez udziału":       func(c *Config) { c.Target = Target{Method: MethodSMB, Host: "nas", User: "u"} },
		"nieznana metoda":       func(c *Config) { c.Target.Method = "ftp" },
		"host z wstrzyknięciem": func(c *Config) { c.Target.Host = "a;rm -rf" },
	} {
		c := ok
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: brak błędu", name)
		}
	}
	if s := (Target{Method: MethodSFTP, Auth: AuthPassword}).Secrets(); len(s) != 1 || s[0] != SecretPassword {
		t.Fatalf("sekrety SFTP z hasłem: %v", s)
	}
}

func TestSealOpen(t *testing.T) {
	pub, priv, err := NewBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal("tajne hasło", pub)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(sealed, pub, priv); err != nil || got != "tajne hasło" {
		t.Fatalf("Open: %q %v", got, err)
	}
	pub2, priv2, _ := NewBoxKey()
	if _, err := Open(sealed, pub2, priv2); err == nil {
		t.Fatal("inny klucz nie może odszyfrować")
	}
	k, err := DecodeKey(EncodeKey(pub))
	if err != nil || *k != *pub || len(KeyID(pub)) != 12 {
		t.Fatal("kodowanie klucza")
	}
}
