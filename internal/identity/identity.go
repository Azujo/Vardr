// Package identity wyznacza tożsamość osoby (user.identity) z konta
// w zdarzeniu (etap 7a): to samo konto w AD („AZUJO\jkowalski”), w Entra ID
// („jkowalski@azujo.pl”) i na VPN („jkowalski”) daje jeden klucz, więc reguły
// i wyszukiwarka łączą zdarzenia jednej osoby z różnych źródeł.
//
// Klucz: nazwa konta bez domeny, małymi literami. Konta spoza domen
// organizacji (lokalne konta komputerów, goście z innych firm) zostają
// osobnymi tożsamościami z domeną; konta techniczne (komputery, usługi
// systemowe) tożsamości nie mają. Aliasy z panelu przypisują inne nazwy
// do osoby (np. login VPN „j.kowalski” → „jkowalski”).
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/nats-io/nats.go/jetstream"
)

// Config to ustawienia z panelu.
type Config struct {
	// Domains: domeny organizacji – nazwy NetBIOS i DNS (np. azujo,
	// azujo.centrala, azujo.pl). Puste = każda domena należy do organizacji.
	Domains []string `json:"domains,omitempty"`
	// Aliases: nazwa konta (klucz, pełne DOMENA\konto albo UPN; małe litery)
	// → tożsamość osoby.
	Aliases map[string]string `json:"aliases,omitempty"`
}

// Resolver wyznacza tożsamość według konfiguracji.
type Resolver struct {
	domains map[string]bool
	aliases map[string]string
}

// New buduje Resolver (nazwy domen i aliasów bez wielkości liter).
func New(c Config) *Resolver {
	r := &Resolver{domains: map[string]bool{}, aliases: map[string]string{}}
	for _, d := range c.Domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			r.domains[d] = true
		}
	}
	for a, id := range c.Aliases {
		if a, id = Normalize(a), Normalize(id); a != "" && id != "" {
			r.aliases[a] = id
		}
	}
	return r
}

// Normalize: nazwa małymi literami, bez otaczających spacji.
func Normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// technical: konta systemowe Windows (bez osoby) – także nazwy z polskiego
// Windows („USŁUGA LOKALNA”, „ANONIMOWE LOGOWANIE”).
var technical = map[string]bool{"-": true, "system": true, "local service": true, "network service": true,
	"anonymous logon": true, "defaultaccount": true, "wdagutilityaccount": true, "font driver host": true,
	"window manager": true, "local system": true, "usługa lokalna": true, "usługa sieciowa": true,
	"anonimowe logowanie": true, "system lokalny": true}

// technicalDomains: „domeny” kont wbudowanych (NT AUTHORITY, po polsku ZARZĄDZANIE NT).
var technicalDomains = map[string]bool{"nt authority": true, "zarządzanie nt": true, "window manager": true,
	"menedżer okien": true, "font driver host": true, "nt service": true, "iis apppool": true,
	"virtual users": true, "użytkownicy wirtualni": true}

// Resolve zwraca tożsamość dla konta (user, domena). Domena może być też
// w nazwie: „DOMENA\konto” albo „konto@domena”. "" – konto bez osoby.
func (r *Resolver) Resolve(user, domain string) string {
	u := Normalize(user)
	if u == "" || technical[u] || strings.HasSuffix(u, "$") {
		return ""
	}
	full := u
	dom := Normalize(domain)
	if d, name, ok := strings.Cut(u, `\`); ok {
		dom, u = d, name
	} else if i := strings.LastIndexByte(u, '@'); i > 0 {
		u, dom = u[:i], u[i+1:]
	} else if dom != "" && dom != "-" {
		full = dom + `\` + u
	}
	// Surowy SID (konto bez nazwy, np. wirtualne konto usługi) – bez osoby.
	if u == "" || technical[u] || strings.HasSuffix(u, "$") || strings.HasPrefix(u, "dwm-") || strings.HasPrefix(u, "umfd-") ||
		strings.HasPrefix(u, "s-1-") {
		return ""
	}
	if technicalDomains[dom] {
		return ""
	}
	// Alias: najpierw pełna nazwa (DOMENA\konto, UPN), potem samo konto.
	if id, ok := r.aliases[full]; ok {
		return id
	}
	key := u
	if dom != "" && dom != "-" && len(r.domains) > 0 && !r.domains[dom] {
		// Konto spoza organizacji: osobna tożsamość z domeną.
		if strings.Contains(full, "@") {
			key = u + "@" + dom
		} else {
			key = dom + `\` + u
		}
	}
	if id, ok := r.aliases[key]; ok {
		return id
	}
	return key
}

// current to konfiguracja używana przez normalizator (podmieniana z panelu).
var current atomic.Pointer[Resolver]

func init() { current.Store(New(Config{})) }

// Current zwraca bieżący Resolver.
func Current() *Resolver { return current.Load() }

// Set podmienia konfigurację.
func Set(c Config) { current.Store(New(c)) }

// Bucket to magazyn NATS KV z konfiguracją (klucz Key, wartość Config w JSON).
const (
	Bucket = "SIEM_IDENTITY"
	Key    = "config"
)

// Ensure tworzy (lub otwiera) magazyn.
func Ensure(ctx context.Context, js jetstream.JetStream) (jetstream.KeyValue, error) {
	return js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       Bucket,
		Description:  "Tożsamości osób (domeny organizacji, aliasy kont) z panelu Heimdall",
		History:      1,
		Storage:      jetstream.FileStorage,
		MaxValueSize: 4 << 20,
		MaxBytes:     16 << 20,
	})
}

// Publish zapisuje konfigurację (bez zmian – bez zapisu).
func Publish(ctx context.Context, kv jetstream.KeyValue, c Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if e, err := kv.Get(ctx, Key); err == nil && string(e.Value()) == string(b) {
		return nil
	}
	_, err = kv.Put(ctx, Key, b)
	return err
}

// Watch obserwuje konfigurację i podmienia ją (Set) do zakończenia ctx.
func Watch(ctx context.Context, kv jetstream.KeyValue, log *slog.Logger) error {
	w, err := kv.Watch(ctx, Key)
	if err != nil {
		return err
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-w.Updates():
			if !ok {
				return errors.New("obserwacja tożsamości zakończona")
			}
			if e == nil {
				continue
			}
			var c Config
			if e.Operation() == jetstream.KeyValuePut {
				if err := json.Unmarshal(e.Value(), &c); err != nil {
					log.Error("nieczytelna konfiguracja tożsamości w NATS – pominięta", "err", err)
					continue
				}
			}
			Set(c)
			log.Info("tożsamości wczytane", "domains", len(c.Domains), "aliases", len(c.Aliases))
		}
	}
}
