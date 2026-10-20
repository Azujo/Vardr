// Package api to backend panelu Hliðskjálf (siem-api): logowanie i sesje,
// konta i role, dziennik audytu oraz serwowanie aplikacji React.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"siem/internal/contract"
	"siem/internal/throttle"
	"siem/panel/internal/api/store"
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/mfa", s.loginMFA)
	mux.HandleFunc("POST /api/v1/auth/mfa/enroll", s.loginEnroll)
	mux.HandleFunc("POST /api/v1/auth/mfa/enroll/confirm", s.loginEnrollConfirm)
	mux.Handle("GET /api/v1/account/mfa", s.authed(roleViewer, 0, s.accountMFA))
	mux.Handle("POST /api/v1/account/mfa/setup", s.authed(roleViewer, 0, s.accountMFASetup))
	mux.Handle("POST /api/v1/account/mfa/confirm", s.authed(roleViewer, 0, s.accountMFAConfirm))
	mux.Handle("POST /api/v1/account/mfa/disable", s.authed(roleViewer, 0, s.accountMFADisable))
	mux.Handle("POST /api/v1/account/mfa/recovery", s.authed(roleViewer, 0, s.accountMFARecovery))
	mux.Handle("POST /api/v1/users/{id}/mfa/reset", s.authed(roleAdmin, 0, s.resetUserMFA))
	mux.Handle("GET /api/v1/settings/security", s.authed(roleAdmin, 0, s.securitySettings))
	mux.Handle("PUT /api/v1/settings/security", s.authed(roleAdmin, 0, s.setSecuritySettings))
	mux.Handle("GET /api/v1/auth/session", s.authed(roleViewer, allowPasswordChange, s.session))
	mux.Handle("POST /api/v1/auth/logout", s.authed(roleViewer, allowPasswordChange, s.logout))
	mux.Handle("POST /api/v1/auth/password", s.authed(roleViewer, allowPasswordChange, s.changePassword))

	mux.Handle("GET /api/v1/users", s.authed(roleAdmin, 0, s.listUsers))
	mux.Handle("POST /api/v1/users", s.authed(roleAdmin, 0, s.createUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.authed(roleAdmin, 0, s.updateUser))
	mux.Handle("POST /api/v1/users/{id}/reset-password", s.authed(roleAdmin, 0, s.resetPassword))
	mux.Handle("GET /api/v1/audit", s.authed(roleAdmin, 0, s.listAudit))

	mux.Handle("GET /api/v1/agents", s.authed(roleViewer, 0, s.listAgents))
	mux.Handle("GET /api/v1/agents/orphan-certs", s.authed(roleAdmin, 0, s.orphanCerts))
	mux.Handle("GET /api/v1/agents/{id}", s.authed(roleViewer, 0, s.getAgent))
	mux.Handle("DELETE /api/v1/agents/{id}", s.authed(roleAdmin, 0, s.deleteAgent))
	mux.Handle("POST /api/v1/agents/{id}/revoke", s.authed(roleAdmin, 0, s.revokeAgent))
	mux.Handle("PUT /api/v1/agents/{id}/group", s.authed(roleAdmin, 0, s.setAgentGroup))
	mux.Handle("GET /api/v1/agents/{id}/uninstall-tokens", s.authed(roleAdmin, 0, s.listUninstallTokens))
	mux.Handle("POST /api/v1/agents/{id}/uninstall-tokens", s.authed(roleAdmin, 0, s.createUninstallToken))
	mux.Handle("POST /api/v1/agents/{id}/uninstall-tokens/{tid}/revoke", s.authed(roleAdmin, 0, s.revokeUninstallToken))

	mux.Handle("GET /api/v1/groups", s.authed(roleViewer, 0, s.listGroups))
	mux.Handle("POST /api/v1/groups", s.authed(roleAdmin, 0, s.createGroup))
	mux.Handle("PATCH /api/v1/groups/{id}", s.authed(roleAdmin, 0, s.updateGroup))
	mux.Handle("DELETE /api/v1/groups/{id}", s.authed(roleAdmin, 0, s.deleteGroup))

	mux.Handle("GET /api/v1/events", s.authed(roleViewer, 0, s.searchEvents))
	mux.Handle("GET /api/v1/events/histogram", s.authed(roleViewer, 0, s.eventsHistogram))
	mux.Handle("GET /api/v1/events/fields", s.authed(roleViewer, 0, s.eventFields))
	mux.Handle("GET /api/v1/events/{id}", s.authed(roleViewer, 0, s.getEvent))

	mux.Handle("GET /api/v1/archive", s.authed(roleViewer, 0, s.archiveOverview))
	mux.Handle("POST /api/v1/archive/verify", s.authed(roleAdmin, 0, s.archiveVerify))
	mux.Handle("POST /api/v1/archive/recoveries", s.authed(roleAdmin, 0, s.requestRecovery))
	mux.Handle("GET /api/v1/archive/exports", s.authed(roleAdmin, 0, s.listExports))
	mux.Handle("POST /api/v1/archive/exports", s.authed(roleAdmin, 0, s.createExport))
	mux.Handle("GET /api/v1/archive/exports/{id}/download", s.authed(roleAdmin, 0, s.downloadExport))
	mux.Handle("GET /api/v1/archive/policy", s.authed(roleViewer, 0, s.archivePolicy))
	mux.Handle("POST /api/v1/archive/policy", s.authed(roleAdmin, 0, s.changeArchivePolicy))
	mux.Handle("POST /api/v1/archive/policy/changes/{id}/cancel", s.authed(roleAdmin, 0, s.cancelArchivePolicyChange))
	mux.Handle("GET /api/v1/archive/replays", s.authed(roleAdmin, 0, s.listReplays))
	mux.Handle("POST /api/v1/archive/replays", s.authed(roleAdmin, 0, s.createReplay))

	mux.Handle("GET /api/v1/alerts", s.authed(roleViewer, 0, s.listAlerts))
	mux.Handle("GET /api/v1/alerts/summary", s.authed(roleViewer, 0, s.alertsSummary))
	mux.Handle("GET /api/v1/alerts/{id}", s.authed(roleViewer, 0, s.getAlert))
	mux.Handle("POST /api/v1/alerts/{id}/status", s.authed(roleAnalyst, 0, s.setAlertStatus))
	mux.Handle("POST /api/v1/alerts/bulk-status", s.authed(roleAnalyst, 0, s.bulkAlertStatus))
	mux.Handle("POST /api/v1/alerts/{id}/assign", s.authed(roleAnalyst, 0, s.assignAlert))
	mux.Handle("POST /api/v1/alerts/{id}/notes", s.authed(roleAnalyst, 0, s.addAlertNote))
	mux.Handle("GET /api/v1/alert-assignees", s.authed(roleViewer, 0, s.listAssignees))
	mux.Handle("GET /api/v1/rules", s.authed(roleViewer, 0, s.listRules))
	mux.Handle("GET /api/v1/attack/dictionary", s.authed(roleViewer, 0, s.attackDictionary))
	mux.Handle("GET /api/v1/attack/coverage", s.authed(roleViewer, 0, s.attackCoverage))
	mux.Handle("GET /api/v1/attack/navigator", s.authed(roleViewer, 0, s.attackNavigator))
	mux.Handle("GET /api/v1/system", s.authed(roleViewer, 0, s.systemStatus))
	mux.Handle("POST /api/v1/rules/test", s.authed(roleAnalyst, 0, s.testRule))
	mux.Handle("GET /api/v1/rules/{id}/versions", s.authed(roleViewer, 0, s.ruleVersions))
	mux.Handle("POST /api/v1/rules/{id}/enabled", s.authed(roleAdmin, 0, s.setRuleEnabled))
	mux.Handle("POST /api/v1/rules/bulk", s.authed(roleAdmin, 0, s.bulkRules))
	mux.Handle("GET /api/v1/rules/trial", s.authed(roleViewer, 0, s.trialRules))
	mux.Handle("POST /api/v1/rules/wizard/events", s.authed(roleAnalyst, 0, s.wizardEvents))
	mux.Handle("GET /api/v1/panel-rules/{id}", s.authed(roleViewer, 0, s.getPanelRule))
	mux.Handle("PUT /api/v1/panel-rules/{id}", s.authed(roleAdmin, 0, s.savePanelRule))
	mux.Handle("POST /api/v1/panel-rules/{id}/delete", s.authed(roleAdmin, 0, s.deletePanelRule))

	mux.Handle("GET /api/v1/decoders", s.authed(roleViewer, 0, s.listDecoders))
	mux.Handle("GET /api/v1/decoders/samples", s.authed(roleAnalyst, 0, s.decoderSamples))
	mux.Handle("POST /api/v1/decoders/test", s.authed(roleAnalyst, 0, s.testDecoder))
	mux.Handle("GET /api/v1/decoders/{id}/versions", s.authed(roleViewer, 0, s.decoderVersions))
	mux.Handle("PUT /api/v1/decoders/{id}", s.authed(roleAdmin, 0, s.saveDecoder))
	mux.Handle("POST /api/v1/decoders/{id}/enabled", s.authed(roleAdmin, 0, s.setDecoderEnabled))
	mux.Handle("POST /api/v1/decoders/{id}/revert", s.authed(roleAdmin, 0, s.revertDecoder))

	mux.Handle("GET /api/v1/identities", s.authed(roleViewer, 0, s.getIdentities))
	mux.Handle("GET /api/v1/identities/people", s.authed(roleViewer, 0, s.listPeople))
	mux.Handle("GET /api/v1/identities/resolve", s.authed(roleViewer, 0, s.resolveIdentity))
	mux.Handle("GET /api/v1/identities/domains-seen", s.authed(roleViewer, 0, s.domainsSeen))
	mux.Handle("PUT /api/v1/identities/domains", s.authed(roleAdmin, 0, s.setIdentityDomains))
	mux.Handle("PUT /api/v1/identities/shared", s.authed(roleAdmin, 0, s.setIdentityShared))
	mux.Handle("GET /api/v1/backup", s.authed(roleAdmin, 0, s.getBackup))
	mux.Handle("PUT /api/v1/backup", s.authed(roleAdmin, 0, s.saveBackup))
	mux.Handle("POST /api/v1/backup/requests", s.authed(roleAdmin, 0, s.addBackupRequest))
	mux.Handle("POST /api/v1/backup/restore", s.authed(roleAdmin, 0, s.restoreBackup))
	mux.Handle("POST /api/v1/identities/aliases", s.authed(roleAdmin, 0, s.setIdentityAlias))
	mux.Handle("POST /api/v1/identities/aliases/delete", s.authed(roleAdmin, 0, s.deleteIdentityAlias))

	mux.Handle("GET /api/v1/quarantine", s.authed(roleViewer, 0, s.listQuarantine))
	mux.Handle("POST /api/v1/quarantine/reprocess", s.authed(roleAdmin, 0, s.reprocessQuarantine))

	mux.Handle("GET /api/v1/notify/channels", s.authed(roleAdmin, 0, s.listChannels))
	mux.Handle("POST /api/v1/notify/channels", s.authed(roleAdmin, 0, s.createChannel))
	mux.Handle("PATCH /api/v1/notify/channels/{id}", s.authed(roleAdmin, 0, s.updateChannel))
	mux.Handle("POST /api/v1/notify/channels/{id}/delete", s.authed(roleAdmin, 0, s.deleteChannel))
	mux.Handle("POST /api/v1/notify/channels/{id}/test", s.authed(roleAdmin, 0, s.testChannel))
	mux.Handle("POST /api/v1/notify/anchor", s.authed(roleAdmin, 0, s.sendAnchor))

	mux.Handle("GET /api/v1/enroll-tokens", s.authed(roleAdmin, 0, s.listTokens))
	mux.Handle("POST /api/v1/enroll-tokens", s.authed(roleAdmin, 0, s.createToken))
	mux.Handle("POST /api/v1/enroll-tokens/{id}/revoke", s.authed(roleAdmin, 0, s.revokeToken))
	mux.Handle("POST /api/v1/enroll-tokens/package", s.authed(roleAdmin, 0, s.tokenPackage))
	mux.Handle("POST /api/v1/enroll-tokens/msi", s.authed(roleAdmin, 0, s.tokenMSI))
	mux.Handle("GET /api/v1/agent-update.msi", s.authed(roleAdmin, 0, s.agentUpdateMSI))

	// Dla agentów (bez sesji panelu): rejestracja tokenem i odnowienie certyfikatu.
	mux.HandleFunc("POST /enroll/v1/register", s.enrollRegister)
	mux.HandleFunc("POST /enroll/v1/renew", s.enrollRenew)
	mux.HandleFunc("GET "+contract.AgentConfigPath, s.agentConfig)
	mux.HandleFunc("/enroll/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego zasobu")
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego zasobu API")
	})
	mux.Handle("/", s.ui())
	return s.recover(securityHeaders(mux))
}

// ---- odpowiedzi JSON ----

type apiError struct {
	Error   string `json:"error"`   // kod dla aplikacji
	Message string `json:"message"` // opis dla człowieka
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

// readJSON dekoduje treść żądania (maks. 64 KB, bez nieznanych pól).
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "niepoprawne dane żądania: "+err.Error())
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("błąd obsługi żądania", "method", r.Method, "path", r.URL.Path, "err", err)
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
				s.Log.Error("panika w obsłudze żądania", "path", r.URL.Path, "panic", v)
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
		id := actor.ID
		e.UserID, e.Username = &id, actor.Username
	}
	if err := s.Store.Audit(context.WithoutCancel(r.Context()), e); err != nil {
		s.Log.Error("zapis audytu nieudany", "action", action, "err", err)
	}
}

var errLastAdmin = errors.New("nie można odebrać uprawnień ostatniemu aktywnemu administratorowi")
