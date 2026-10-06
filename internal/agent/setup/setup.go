// Package setup zawiera logikę instalatora agenta niezależną od systemu:
// adres serwera, generowanie konfiguracji, zmianę adresu w istniejącym
// pliku i operacje na zmiennej PATH.
package setup

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"siem/internal/contract"
)

// DefaultPort to port endpointu przyjmującego serwera.
const DefaultPort = "8443"

// ServerURL zamienia to, co wpisał administrator ("192.168.88.98",
// "siem.firma.pl:9443", pełny URL), na adres endpointu agenta.
func ServerURL(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("nie podano adresu serwera")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("niepoprawny adres serwera %q: %w", input, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("adres serwera musi używać https (jest %q)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("brak nazwy hosta w adresie %q", input)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), DefaultPort)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = contract.IngestPath
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// Channel to kanał Event Log z listą Event ID w konfiguracji.
type Channel struct {
	Name     string
	EventIDs []uint32
}

var (
	securityAll     = []uint32{4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4702, 4719, 1102}
	securityServers = []uint32{4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4728, 4729, 4732, 4733, 4756, 4757}
	securityDC      = []uint32{4768, 4769, 4771, 4776}
	commonChannels  = []Channel{
		{"System", []uint32{7036, 7040, 7045}},
		{"Microsoft-Windows-PowerShell/Operational", []uint32{4104}},
		{"Microsoft-Windows-Sysmon/Operational", []uint32{1, 3, 11, 13, 22}},
	}
)

// Profiles to profile zbieranych zdarzeń z załącznika B roadmapy.
var Profiles = map[string]string{
	"workstation": "stacja robocza",
	"server":      "serwer (+ zarządzanie kontami i grupami)",
	"dc":          "kontroler domeny (+ Kerberos i NTLM)",
}

// ProfileChannels zwraca kanały dla profilu.
func ProfileChannels(profile string) ([]Channel, error) {
	ids := append([]uint32{}, securityAll...)
	switch profile {
	case "workstation":
	case "server":
		ids = append(ids, securityServers...)
	case "dc":
		ids = append(ids, securityServers...)
		ids = append(ids, securityDC...)
	default:
		names := make([]string, 0, len(Profiles))
		for n := range Profiles {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("nieznany profil %q (dostępne: %s)", profile, strings.Join(names, ", "))
	}
	return append([]Channel{{"Security", ids}}, commonChannels...), nil
}

// Options to parametry generowanej konfiguracji.
type Options struct {
	ServerURL string
	Profile   string
	StartAt   string // now | oldest
}

// GenerateConfig tworzy treść agent.yaml dla instalacji w ProgramData.
// Certyfikaty leżą w podkatalogu certs obok pliku konfiguracji.
func GenerateConfig(o Options) (string, error) {
	if _, err := ServerURL(o.ServerURL); err != nil {
		return "", err
	}
	chans, err := ProfileChannels(o.Profile)
	if err != nil {
		return "", err
	}
	if o.StartAt == "" {
		o.StartAt = "now"
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Konfiguracja agenta SIEM – utworzona przez "siem_agent install".
# Zmiana adresu serwera: siem_agent set-server <adres>
# Pozostałe opcje i opis: configs/agent.example.yaml w repozytorium projektu.

server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key

# Skąd zacząć przy pierwszym uruchomieniu: now (nowe zdarzenia) | oldest.
start_at: %s

# Profil: %s (%s).
channels:
`, o.ServerURL, o.StartAt, o.Profile, Profiles[o.Profile])
	for _, ch := range chans {
		fmt.Fprintf(&b, "  - name: %s\n    event_ids: [%s]\n", ch.Name, joinIDs(ch.EventIDs))
	}
	return b.String(), nil
}

func joinIDs(ids []uint32) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprint(id)
	}
	return strings.Join(parts, ", ")
}

// SetServerURL zmienia server.url w istniejącej konfiguracji, zachowując
// komentarze i pozostałe ustawienia.
func SetServerURL(data []byte, serverURL string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("konfiguracja nie jest mapą YAML")
	}
	root := doc.Content[0]
	server := mapValue(root, "server")
	if server == nil {
		server = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "server"}, server)
	}
	if server.Kind != yaml.MappingNode {
		return nil, errors.New("sekcja server nie jest mapą")
	}
	if u := mapValue(server, "url"); u != nil {
		u.Value, u.Tag, u.Style = serverURL, "!!str", 0
	} else {
		server.Content = append([]*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "url"}, {Kind: yaml.ScalarNode, Value: serverURL},
		}, server.Content...)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// AddToPath dopisuje katalog do wartości PATH, jeśli go tam nie ma.
func AddToPath(path, dir string) (string, bool) {
	for _, p := range splitPath(path) {
		if samePath(p, dir) {
			return path, false
		}
	}
	if path == "" {
		return dir, true
	}
	return strings.TrimRight(path, ";") + ";" + dir, true
}

// RemoveFromPath usuwa katalog z wartości PATH.
func RemoveFromPath(path, dir string) (string, bool) {
	var keep []string
	changed := false
	for _, p := range splitPath(path) {
		if samePath(p, dir) {
			changed = true
			continue
		}
		keep = append(keep, p)
	}
	return strings.Join(keep, ";"), changed
}

func splitPath(path string) []string {
	var out []string
	for _, p := range strings.Split(path, ";") {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func samePath(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), `\/`)) }
	return norm(a) == norm(b)
}
