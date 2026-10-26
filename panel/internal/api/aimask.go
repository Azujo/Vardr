// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"siem/panel/internal/api/store"
)

// Maskowanie danych osobowych w odpowiedziach dla tokenów AI (polityka AI,
// wersja 1.4): loginy, komputery, adresy IP i e-mail zamieniane na stałe
// pseudonimy (USER-7F3A12BC). Ta sama wartość ma zawsze ten sam pseudonim
// (HMAC z kluczem instalacji), więc model widzi, że to ta sama osoba
// w różnych zdarzeniach, ale nie wie, kto to. Pseudonimy zapisuje baza –
// analityk odkrywa je w panelu (uprawnienie, audyt).
//
// Dwa przejścia po JSON-ie odpowiedzi: najpierw wartości pól o znanych
// nazwach (user, host_name, fields.TargetUserName…), potem tekst wolny
// (opis alertu, treść zdarzenia, surowy XML): zastąpienie wartości
// znalezionych w polach oraz adresów IP i e-mail rozpoznanych wzorcem.
// Ograniczenie: nazwa, której nie ma w żadnym polu odpowiedzi, a występuje
// tylko w tekście wolnym, nie zostanie rozpoznana – stąd zalecenie modelu
// lokalnego dla danych wrażliwych.

var pseudonymPattern = regexp.MustCompile(`^(USER|HOST|IP|EMAIL)-[0-9A-F]{8}$`)

const (
	maskUser  = "USER"
	maskHost  = "HOST"
	maskIP    = "IP"
	maskEmail = "EMAIL"
)

// maskKeys: nazwy pól (małymi literami) i rodzaj danych.
var maskKeys = map[string]string{
	"user": maskUser, "user_name": maskUser, "username": maskUser, "user_identity": maskUser, "identity": maskUser,
	"user.name": maskUser, "user.identity": maskUser, "targetusername": maskUser, "subjectusername": maskUser,
	"accountname": maskUser, "samaccountname": maskUser, "userprincipalname": maskUser, "upn": maskUser,
	"host": maskHost, "host_name": maskHost, "hostname": maskHost, "host.name": maskHost, "computer": maskHost,
	"workstationname": maskHost, "workstation": maskHost,
	"ip": maskIP, "source_ip": maskIP, "source.ip": maskIP, "ipaddress": maskIP, "remote_ip": maskIP, "client_ip": maskIP,
	"src_ip": maskIP, "dst_ip": maskIP, "destination.ip": maskIP,
}

var (
	ipv4Re  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// skipValues: wartości, których nie maskujemy (puste, techniczne).
var skipValues = map[string]bool{"": true, "-": true, "n/a": true, "system": true, "local service": true, "network service": true,
	"anonymous logon": true, "127.0.0.1": true, "::1": true, "0.0.0.0": true}

type masker struct {
	key   []byte
	mask  AIMask
	found map[string]store.Pseudonym // pseudonim → wpis (do zapisu)
	known map[string]string          // wartość (małe litery) → pseudonim (tekst wolny)
}

func newMasker(key []byte, m AIMask) *masker {
	return &masker{key: key, mask: m, found: map[string]store.Pseudonym{}, known: map[string]string{}}
}

func (m *masker) enabled(kind string) bool {
	switch kind {
	case maskUser:
		return m.mask.Users
	case maskHost:
		return m.mask.Hosts
	case maskIP:
		return m.mask.IPs
	case maskEmail:
		return m.mask.Emails
	}
	return false
}

// pseudo: pseudonim wartości (i zapamiętanie jej do tekstu wolnego).
func (m *masker) pseudo(kind, value string) string {
	v := strings.TrimSpace(value)
	low := strings.ToLower(v)
	if skipValues[low] || strings.HasPrefix(v, kind+"-") && pseudonymPattern.MatchString(v) {
		return value
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(kind + "\x00" + low))
	p := kind + "-" + strings.ToUpper(hex.EncodeToString(mac.Sum(nil))[:8])
	if _, ok := m.found[p]; !ok {
		m.found[p] = store.Pseudonym{Pseudonym: p, Kind: kind, Value: v}
	}
	m.known[low] = p
	// Login z domeną: także sama nazwa (AZUJO\jan, jan@firma.pl → jan) –
	// tak bywa zapisany w tekście.
	if kind == maskUser {
		short := low
		if i := strings.LastIndex(short, `\`); i >= 0 {
			short = short[i+1:]
		}
		if i := strings.Index(short, "@"); i > 0 {
			short = short[:i]
		}
		if short != low && len(short) >= 3 {
			if _, ok := m.known[short]; !ok {
				m.known[short] = p
			}
		}
	}
	return p
}

// kindOf: rodzaj danych pola (obj – obiekt, w którym jest pole; wynik
// ryzyka ma „display”/„entity” zależne od „type”).
func kindOf(key string, obj map[string]any) string {
	k := strings.ToLower(key)
	if kind, ok := maskKeys[k]; ok {
		return kind
	}
	if k == "display" || k == "entity" {
		switch obj["type"] {
		case "user":
			return maskUser
		case "host":
			return maskHost
		}
	}
	return ""
}

// collect: przejście 1 – wartości pól o znanych nazwach.
func (m *masker) collect(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				if kind := kindOf(k, x); kind != "" && m.enabled(kind) {
					m.pseudo(kind, s)
				}
				continue
			}
			m.collect(val)
		}
	case []any:
		for _, e := range x {
			m.collect(e)
		}
	}
}

// replacer: wyrażenie dla tekstu wolnego ze znanych wartości (dłuższe
// najpierw, granice słów).
func (m *masker) replacer() *regexp.Regexp {
	var vals []string
	for v := range m.known {
		if len(v) >= 3 {
			vals = append(vals, regexp.QuoteMeta(v))
		}
	}
	if len(vals) == 0 {
		return nil
	}
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	re, err := regexp.Compile(`(?i)(^|[^\pL\pN_.@-])(` + strings.Join(vals, "|") + `)($|[^\pL\pN_])`)
	if err != nil {
		return nil
	}
	return re
}

func (m *masker) text(s string, re *regexp.Regexp) string {
	if re != nil {
		// Dwa razy: sąsiednie trafienia dzielą znak graniczny.
		for range 2 {
			s = re.ReplaceAllStringFunc(s, func(match string) string {
				sub := re.FindStringSubmatch(match)
				return sub[1] + m.known[strings.ToLower(sub[2])] + sub[3]
			})
		}
	}
	if m.mask.Emails {
		s = emailRe.ReplaceAllStringFunc(s, func(e string) string {
			if p, ok := m.known[strings.ToLower(e)]; ok {
				return p
			}
			return m.pseudo(maskEmail, e)
		})
	}
	if m.mask.IPs {
		s = ipv4Re.ReplaceAllStringFunc(s, func(ip string) string { return m.pseudo(maskIP, ip) })
	}
	return s
}

// apply: przejście 2 – pola o znanych nazwach na pseudonimy, tekst wolny
// przez replacer i wzorce.
func (m *masker) apply(v any, re *regexp.Regexp) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				if kind := kindOf(k, x); kind != "" && m.enabled(kind) {
					x[k] = m.pseudo(kind, s)
				} else {
					x[k] = m.text(s, re)
				}
				continue
			}
			x[k] = m.apply(val, re)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = m.apply(e, re)
		}
		return x
	case string:
		return m.text(x, re)
	}
	return v
}

// maskJSON maskuje odpowiedź JSON; zwraca nową treść i nowe pseudonimy.
func maskJSON(body []byte, key []byte, mask AIMask) ([]byte, []store.Pseudonym, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, nil, err
	}
	m := newMasker(key, mask)
	m.collect(v)
	v = m.apply(v, m.replacer())
	out, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	ps := make([]store.Pseudonym, 0, len(m.found))
	for _, p := range m.found {
		ps = append(ps, p)
	}
	return out, ps, nil
}

// bufferWriter zbiera odpowiedź handlera do zamaskowania przed wysłaniem.
type bufferWriter struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (b *bufferWriter) Header() http.Header         { return b.header }
func (b *bufferWriter) WriteHeader(code int)        { b.status = code }
func (b *bufferWriter) Write(p []byte) (int, error) { return b.buf.Write(p) }

// serveMasked wykonuje handler, maskuje odpowiedź JSON i wysyła ją.
// Odpowiedź, której nie da się zamaskować, nie wychodzi (błąd 500) –
// lepiej nic niż dane bez maskowania.
func (s *Server) serveMasked(w http.ResponseWriter, r *http.Request, pol AIPolicy, h http.HandlerFunc) {
	bw := &bufferWriter{header: http.Header{}}
	h(bw, r)
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	key, err := s.aiKey(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !strings.HasPrefix(bw.header.Get("Content-Type"), "application/json") {
		s.internalError(w, r, errors.New("AI masking: non-JSON response withheld"))
		return
	}
	out, ps, err := maskJSON(bw.buf.Bytes(), key, pol.Mask)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if s.AI != nil && len(ps) > 0 {
		if err := s.AI.SavePseudonyms(context.WithoutCancel(r.Context()), ps, s.now()); err != nil {
			s.Log.Warn("saving AI pseudonyms failed", "err", err)
		}
	}
	var res any
	if err := json.Unmarshal(out, &res); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, status, res)
}

// aiKey: klucz pseudonimów (losowy, w ustawieniach panelu – ten sam po
// restarcie, więc pseudonimy są stałe).
func (s *Server) aiKey(ctx context.Context) ([]byte, error) {
	s.aiKeyMu.Lock()
	defer s.aiKeyMu.Unlock()
	if s.aiKeyVal != nil {
		return s.aiKeyVal, nil
	}
	if s.Settings == nil {
		return nil, errors.New("AI masking needs panel settings")
	}
	raw, err := s.Settings.Setting(ctx, "ai_pseudonym_key")
	if errors.Is(err, store.ErrNotFound) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw = hex.EncodeToString(b)
		if err := s.Settings.SetSetting(ctx, "ai_pseudonym_key", raw, "system", s.now()); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) < 16 {
		return nil, errors.New("invalid AI pseudonym key")
	}
	s.aiKeyVal = key
	return key, nil
}

// aiKeyState: pola Server dla klucza pseudonimów.
type aiKeyState struct {
	aiKeyMu  sync.Mutex
	aiKeyVal []byte
}
