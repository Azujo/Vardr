// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api to backend panelu Hliðskjálf (siem-api): logowanie i sesje,
// konta i role, dziennik audytu oraz serwowanie aplikacji React.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"siem/internal/contract"
	"siem/internal/lang"
	"siem/internal/throttle"
	"siem/panel/internal/api/store"
	"siem/panel/internal/syslang"
)

// Store to operacje na bazie Saga używane przez API (implementuje store.PG).
type Store interface {
	Ping(ctx context.Context) error
	CreateUser(ctx context.Context, u store.User) (store.User, error)
	UserByUsername(ctx context.Context, username string) (store.User, error)
	UserByID(ctx context.Context, id int64) (store.User, error)
	ListUsers(ctx context.Context) ([]store.User, error)
	UpdateUser(ctx context.Context, id int64, p store.UserPatch) (store.User, error)
	SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error
	RecordLoginFailure(ctx context.Context, id int64, lockAfter int, lockFor time.Duration) (*time.Time, error)
	RecordLoginSuccess(ctx context.Context, id int64) error
	CountActiveAdmins(ctx context.Context) (int, error)
	CreateSession(ctx context.Context, s store.Session) error
	SessionWithUser(ctx context.Context, id string, now time.Time) (store.Session, store.User, error)
	TouchSession(ctx context.Context, id string, seen, expires time.Time) error
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID int64, exceptID string) error
	Audit(ctx context.Context, e store.AuditEntry) error
	ListAudit(ctx context.Context, limit int, beforeID int64) ([]store.AuditEntry, error)
	ListAgents(ctx context.Context) ([]store.Agent, error)
	AgentByID(ctx context.Context, id string) (store.Agent, error)
	DeleteAgent(ctx context.Context, id string) error
	CreateEnrollToken(ctx context.Context, t store.EnrollToken) (store.EnrollToken, error)
	ListEnrollTokens(ctx context.Context) ([]store.EnrollToken, error)
	RevokeEnrollToken(ctx context.Context, id int64) (store.EnrollToken, error)
	UseEnrollToken(ctx context.Context, tokenHash string, now time.Time) (store.EnrollToken, error)
	EnrollTokenByHash(ctx context.Context, tokenHash string, now time.Time) (store.EnrollToken, error)
	AgentIDTaken(ctx context.Context, agentID string) (bool, error)
	RecordAgentCert(ctx context.Context, c store.AgentCert) error
	AgentCertBySerial(ctx context.Context, serial string) (store.AgentCert, error)
	RevokeAgentCerts(ctx context.Context, agentID, reason string) ([]string, error)
	OrphanAgentCerts(ctx context.Context, now time.Time) ([]store.AgentCert, error)
	ListGroups(ctx context.Context) ([]store.AgentGroup, error)
	GroupByID(ctx context.Context, id int64) (store.AgentGroup, error)
	CreateGroup(ctx context.Context, g store.AgentGroup) (store.AgentGroup, error)
	UpdateGroup(ctx context.Context, g store.AgentGroup) (store.AgentGroup, error)
	DeleteGroup(ctx context.Context, id int64) error
	AssignAgent(ctx context.Context, agentID string, groupID int64) error
	GroupForAgent(ctx context.Context, agentID string) (store.AgentGroup, error)
	AgentGroupIDs(ctx context.Context) (map[string]int64, error)
	CreateUninstallToken(ctx context.Context, agentID, hash, reason, by string, expires time.Time) (store.UninstallToken, error)
	UninstallTokens(ctx context.Context, agentID string, now time.Time) ([]store.UninstallToken, error)
	ActiveUninstallTokens(ctx context.Context, agentID string) ([]contract.UninstallToken, error)
	RevokeUninstallToken(ctx context.Context, agentID string, id int64, by string) (bool, error)
}

// Server to handler HTTP panelu.
type Server struct {
	Store Store
	Log   *slog.Logger
	// UI to zbudowana aplikacja (web/dist); nil = strona zastępcza.
	UI fs.FS
	// Enroll (opcjonalne) – rejestracja agentów tokenem.
	Enroll *Enrollment
	// updCache: wersja i suma instalatora dla automatycznych aktualizacji.
	updCache agentUpdateCache
	// Events (opcjonalne) – wyszukiwarka zdarzeń (Mímir).
	Events EventSearcher
	// Archive (opcjonalne) – stan archiwum NIS2 (Urd).
	Archive ArchiveReader
	// ExportDir: katalog paczek eksportu (tylko odczyt); "" = bez pobierania.
	ExportDir string
	// Notify (opcjonalne) – kanały powiadomień (Discord, webhook).
	Notify *Notifications
	// Alerts (opcjonalne) – alerty i reguły detekcji (Gjallarhorn).
	Alerts AlertStore
	// RuleAdmin (opcjonalne) – wersje reguł i ich włączanie z panelu.
	RuleAdmin RuleAdmin
	// Exceptions (opcjonalne) – wyjątki reguł (fałszywe alarmy).
	Exceptions ExceptionStore
	// RuleTester (opcjonalne) – test reguły na zdarzeniach w ClickHouse.
	RuleTester RuleTester
	// Status (opcjonalne) – stan systemu z metryk Prometheusa.
	Status StatusReporter
	// GrafanaURL (opcjonalne) – adres Grafany dla przeglądarki (linki
	// w Himinbjörgu); pusty – panel bierze adres serwera z portem 3000.
	GrafanaURL string
	// Decoders (opcjonalne) – dekodery syslog i ich edytor.
	Decoders *Decoders
	// Quarantine (opcjonalne) – kwarantanna i jej ponowne przetwarzanie.
	Quarantine *Quarantine
	// Identities (opcjonalne) – tożsamości osób (domeny, aliasy kont).
	Identities *Identities
	// Backups (opcjonalne): ustawienia i zlecenia kopii zapasowych (siem-backup).
	Backups BackupStore
	// MFA (opcjonalne) z kluczem MFAKey (32 bajty – szyfrowanie sekretów
	// TOTP): drugi składnik logowania i polityka jego wymagania.
	MFA    MFAStore
	MFAKey []byte
	mfa    mfaState
	// Profiles (opcjonalne): profile uprawnień; bez nich – tylko wbudowane.
	Profiles     ProfileStore
	profileCache profileCache
	// LDAP (opcjonalne, wymaga MFAKey): logowanie kontem domenowym (LDAPS).
	LDAP LDAPStore
	// OIDC (opcjonalne, wymaga MFAKey): logowanie przez Entra ID (OIDC, wersja 1.6.1).
	OIDC OIDCStore
	// APITokens (opcjonalne): tokeny API dla programów; TokenRatePerMin –
	// limit zapytań jednego tokenu na minutę (0 – domyślny).
	APITokens       APITokenStore
	TokenRatePerMin int
	// TokenLogDays: retencja historii zapytań tokenów (0 – 30 dni; sprząta
	// siem-api). Kolejka historii – RunTokenLog.
	TokenLogDays    int
	tokenLog        chan store.APIRequest
	tokenLogDropped atomic.Int64
	// Risk (opcjonalne): scoring ryzyka osób i komputerów (wyniki z detektora).
	Risk RiskStore
	// AI (opcjonalne): historia zapytań tokenów AI i pseudonimy maskowania
	// (polityka AI – ai.go, w ustawieniach panelu).
	AI      AIStore
	aiCache aiPolicyCache
	// MCPExe: program vardr-mcp.exe do pobrania (domyślnie /agent-dist/vardr-mcp.exe).
	MCPExe string
	// mux: drzewo tras – dla wewnętrznych zapytań narzędzi MCP (mcp_handlers.go).
	mux *http.ServeMux
	// assistantBusy: równoczesne pytania do asystenta AI (limit z ustawień).
	assistantBusy assistantSem
	aiKeyState
	// Incidents (opcjonalne): incydenty i zgłoszenia NIS2.
	Incidents IncidentStore
	ldap      ldapState
	sso       oidcState
	// Settings (opcjonalne): ustawienia panelu; SysLang – język systemu
	// (powiadomienia, szkice zgłoszeń) odczytywany z nich.
	Settings SettingStore
	SysLang  *syslang.Cache

	// Sesje: wygasają po IdleTimeout bez aktywności, najpóźniej po MaxAge.
	IdleTimeout, MaxAge time.Duration
	// Blokada konta po LockAfter kolejnych nieudanych logowaniach na LockFor.
	LockAfter int
	LockFor   time.Duration

	now     func() time.Time
	limitMu sync.Mutex
	limits  map[string]*throttle.Limiter // ograniczenie prób logowania na adres IP
}

// Domyślne wartości (gdy pola Server są zerowe).
const (
	defaultIdle      = time.Hour
	defaultMaxAge    = 8 * time.Hour
	defaultLockAfter = 10
	defaultLockFor   = 15 * time.Minute

	cookieName = "__Host-vardr" // __Host-: tylko HTTPS, bez Domain, Path=/
	csrfHeader = "X-CSRF-Token"
)

// Handler buduje drzewo tras.
func (s *Server) Handler() http.Handler {
	if s.now == nil {
		s.now = time.Now
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = defaultIdle
	}
	if s.MaxAge == 0 {
		s.MaxAge = defaultMaxAge
	}
	if s.LockAfter == 0 {
		s.LockAfter = defaultLockAfter
	}
	if s.LockFor == 0 {
		s.LockFor = defaultLockFor
	}
	s.limits = map[string]*throttle.Limiter{}
	if s.APITokens != nil && s.tokenLog == nil {
		s.tokenLog = make(chan store.APIRequest, tokenLogBuffer)
	}

	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		if rt.need == public {
			mux.HandleFunc(rt.pattern, rt.h)
		} else {
			mux.Handle(rt.pattern, s.authed(rt.need, rt.flags, rt.h))
		}
	}

	// Dla agentów (bez sesji panelu): rejestracja tokenem i odnowienie certyfikatu.
	mux.HandleFunc("POST /enroll/v1/register", s.enrollRegister)
	mux.HandleFunc("POST /enroll/v1/renew", s.enrollRenew)
	mux.HandleFunc("GET "+contract.AgentConfigPath, s.agentConfig)
	mux.HandleFunc("GET "+contract.AgentMSIPath, s.agentMSI)
	mux.HandleFunc("GET "+contract.AgentLinuxPath+"{arch}", s.agentLinux)
	mux.HandleFunc("/enroll/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego zasobu")
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego zasobu API")
	})
	mux.Handle("/", s.ui())
	s.mux = mux
	return s.recover(securityHeaders(mux))
}

// ---- odpowiedzi JSON ----

type apiError struct {
	Error   string `json:"error"`   // kod dla aplikacji
	Message string `json:"message"` // opis dla człowieka
	// MessageEn: opis po angielsku, gdy błąd go ma (lang.Error – walidacja
	// ustawień, reguł, dekoderów); panel w innym języku niż polski bierze go
	// zamiast ogólnego tłumaczenia kodu.
	MessageEn string `json:"message_en,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, apiError{Error: errCode, Message: msg})
}

// failed: wynik „ok: false” (test reguły, dekodera, połączenia) z opisem
// błędu – także po angielsku, gdy błąd go ma (error_en).
func failed(err error) map[string]any {
	m := map[string]any{"ok": false, "error": err.Error()}
	if en := lang.English(err); en != err.Error() {
		m["error_en"] = en
	}
	return m
}

// writeErr: błąd z opisem z err (z wersją angielską, gdy err ją ma).
func writeErr(w http.ResponseWriter, code int, errCode string, err error) {
	msg, en := err.Error(), lang.English(err)
	if en == msg {
		en = ""
	}
	writeJSON(w, code, apiError{Error: errCode, Message: msg, MessageEn: en})
}

// readJSON dekoduje treść żądania (maks. 64 KB, bez nieznanych pól).
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", lang.Errorf("niepoprawne dane żądania: %w", "invalid request data: %w", err))
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("request handling error", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "błąd serwera – szczegóły w logu siem-api")
}

// ---- middleware ----

// securityHeaders dodaje nagłówki ochronne do każdej odpowiedzi.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic while handling a request", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal", "błąd serwera")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP to adres klienta. Panel nie stoi za proxy, więc nie ufamy
// nagłówkom X-Forwarded-For (łatwe do podrobienia).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// allow ogranicza liczbę prób dla klucza (np. „login:adres IP”): perMin na
// minutę z zapasem burst.
func (s *Server) allow(key string, perMin, burst float64) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	l, ok := s.limits[key]
	if !ok {
		if len(s.limits) > 10000 { // ochrona pamięci przed wieloma adresami
			clear(s.limits)
		}
		l = throttle.New(perMin/60, burst)
		s.limits[key] = l
	}
	return l.Allow(1)
}

// ---- strona aplikacji ----

const placeholderPage = `<!doctype html><html lang="pl"><meta charset="utf-8"><title>Vardr</title>
<body style="font-family:sans-serif;max-width:40rem;margin:4rem auto">
<h1>Vardr – panel nie został zbudowany</h1>
<p>API działa, ale brak plików aplikacji. Zbuduj frontend: <code>cd panel/web &amp;&amp; npm ci &amp;&amp; npm run build</code>,
a potem ponownie zbuduj <code>siem-api</code>.</p></body></html>`

// ui serwuje aplikację; nieznane ścieżki (np. /agents) dostają index.html,
// bo trasy obsługuje React.
func (s *Server) ui() http.Handler {
	if s.UI == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholderPage))
		})
	}
	files := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := s.UI.Open(p); err == nil {
				st, _ := f.Stat()
				f.Close()
				if st != nil && !st.IsDir() {
					if strings.HasPrefix(p, "assets/") { // nazwy z hashem treści
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					files.ServeHTTP(w, r)
					return
				}
			}
		}
		index, err := fs.ReadFile(s.UI, "index.html")
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholderPage))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "database": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

// audit zapisuje wpis; błąd zapisu nie przerywa operacji, ale trafia do logu.
func (s *Server) audit(r *http.Request, actor *store.User, action, target string, details map[string]any) {
	e := store.AuditEntry{Action: action, Target: target, IP: clientIP(r), Details: details}
	if actor != nil {
		e.Username = actor.Username
		if actor.ID != 0 { // 0 – token API (aktor api:<nazwa>, bez konta)
			id := actor.ID
			e.UserID = &id
		}
	}
	if t := current(r).token; t != nil {
		e.Details = maps.Clone(details)
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		e.Details["api_token_id"] = t.ID
	}
	if err := s.Store.Audit(context.WithoutCancel(r.Context()), e); err != nil {
		s.Log.Error("writing the audit entry failed", "action", action, "err", err)
	}
}

var errLastAdmin = errors.New("nie można odebrać uprawnień ostatniemu aktywnemu administratorowi")
