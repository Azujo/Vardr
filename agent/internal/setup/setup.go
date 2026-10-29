// SPDX-License-Identifier: AGPL-3.0-or-later

// Package setup zawiera logikę instalatora agenta niezależną od systemu:
// adres serwera, generowanie konfiguracji, zmianę adresu w istniejącym
// pliku i operacje na zmiennej PATH.
package setup

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"siem/internal/contract"
	"siem/internal/lang"
)

// DefaultPort to port endpointu przyjmującego serwera.
const DefaultPort = "8443"

// ServerURL zamienia to, co wpisał administrator ("192.168.88.98",
// "siem.firma.pl:9443", pełny URL), na adres endpointu agenta.
func ServerURL(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", lang.Errorf("nie podano adresu serwera", "no server address given")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", lang.Errorf("niepoprawny adres serwera %q: %w", "invalid server address %q: %w", input, err)
	}
	if u.Scheme != "https" {
		return "", lang.Errorf("adres serwera musi używać https (jest %q)", "the server address must use https (got %q)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", lang.Errorf("brak nazwy hosta w adresie %q", "no host name in address %q", input)
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

// Channel to kanał Event Log z listą Event ID (profile – internal/contract,
// wspólne z narzędziami serwera, np. importerem reguł Sigma).
type Channel = contract.Channel

// Profiles to profile zbieranych zdarzeń (contract.Profiles).
var Profiles = contract.Profiles

// ProfileChannels zwraca kanały dla profilu.
func ProfileChannels(profile string) ([]Channel, error) { return contract.ProfileChannels(profile) }

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
	header := `# Konfiguracja agenta SIEM – utworzona przez "vardr-agent install".
# Zmiana adresu serwera: vardr-agent set-server <adres>
# Pozostałe opcje i opis: agent/configs/agent.example.yaml w repozytorium projektu.
`
	startAt, profile := "# Skąd zacząć przy pierwszym uruchomieniu: now (nowe zdarzenia) | oldest.", "# Profil: %s (%s)."
	profileDesc := Profiles[o.Profile]
	if lang.Local() == "en" {
		header = `# SIEM agent configuration – created by "vardr-agent install".
# Changing the server address: vardr-agent set-server <address>
# Other options and descriptions: agent/configs/agent.example.yaml in the project repository.
`
		startAt, profile = "# Where to start on the first run: now (new events) | oldest.", "# Profile: %s (%s)."
		profileDesc = contract.ProfilesEn[o.Profile]
	}
	fmt.Fprintf(&b, header+`
server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key

`+startAt+`
start_at: %s

`+profile+`
channels:
`, o.ServerURL, o.StartAt, o.Profile, profileDesc)
	for _, ch := range chans {
		fmt.Fprintf(&b, "  - name: %s\n    event_ids: [%s]\n", ch.Name, joinIDs(ch.EventIDs))
	}
	return b.String(), nil
}

// GenerateLinuxConfig tworzy treść agent.yaml agenta Linux (/etc/vardr-agent).
// Źródło: dziennik systemd; profil grupy (kanały Event Log) go nie dotyczy.
func GenerateLinuxConfig(o Options) (string, error) {
	if _, err := ServerURL(o.ServerURL); err != nil {
		return "", err
	}
	if o.StartAt == "" {
		o.StartAt = "now"
	}
	text := `# Konfiguracja agenta Vardr (Linux) – utworzona przez "vardr-agent install".
# Zmiana adresu serwera: vardr-agent set-server <adres>
# Pozostałe opcje i opis: agent/configs/agent.example.yaml w repozytorium projektu.

server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key

# Skąd zacząć przy pierwszym uruchomieniu: now (nowe wpisy) | oldest (cały dziennik).
start_at: %s

# Dziennik systemd: uwierzytelnianie (auth, authpriv – SSH, sudo, su, PAM,
# zmiany kont) i wpisy o priorytecie warning lub wyższym. Dodatkowe jednostki
# albo programy w całości: units / identifiers.
journald:
  enabled: true
  # units: [nginx.service]
  # identifiers: [cron]

# Linux Audit (auditd): uruchamiane programy, zmiany plików i konfiguracji
# audytu według reguł audytu (zalecane: vardr-agent audit-rules). Bez auditd
# agent czeka na plik dziennika.
auditd:
  enabled: true
  # exclude: [CRED_ACQ, CRED_DISP, CRED_REFR, USER_ACCT, USER_START, USER_END, LOGIN, SERVICE_START, SERVICE_STOP, BPF, NETFILTER_CFG]
# Pliki logów aplikacji (wiersz po wierszu, z rotacją). app – nazwa programu
# dla dekoderów (domyślnie nazwa pliku); wzorce rozwijane przy starcie.
# files:
#   - path: /var/log/nginx/*.log
#     app: nginx
`
	if lang.Local() == "en" {
		text = `# Vardr agent configuration (Linux) – created by "vardr-agent install".
# Changing the server address: vardr-agent set-server <address>
# Other options and descriptions: agent/configs/agent.example.yaml in the project repository.

server:
  url: %s
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key

# Where to start on the first run: now (new entries) | oldest (the whole journal).
start_at: %s

# systemd journal: authentication (auth, authpriv – SSH, sudo, su, PAM, account
# changes) and entries with priority warning or higher. Additional units or
# programs in full: units / identifiers.
journald:
  enabled: true
  # units: [nginx.service]
  # identifiers: [cron]

# Linux Audit (auditd): started programs, changes of files and of the audit
# configuration according to the audit rules (recommended: vardr-agent
# audit-rules). Without auditd the agent waits for the log file.
auditd:
  enabled: true
  # exclude: [CRED_ACQ, CRED_DISP, CRED_REFR, USER_ACCT, USER_START, USER_END, LOGIN, SERVICE_START, SERVICE_STOP, BPF, NETFILTER_CFG]
# Application log files (line by line, with rotation). app – program name
# for decoders (default: the file name); patterns expanded at start.
# files:
#   - path: /var/log/nginx/*.log
#     app: nginx
`
	}
	return fmt.Sprintf(text, o.ServerURL, o.StartAt), nil
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
		return nil, lang.Errorf("konfiguracja nie jest mapą YAML", "the configuration is not a YAML map")
	}
	root := doc.Content[0]
	server := mapValue(root, "server")
	if server == nil {
		server = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "server"}, server)
	}
	if server.Kind != yaml.MappingNode {
		return nil, lang.Errorf("sekcja server nie jest mapą", "the server section is not a map")
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
