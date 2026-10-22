// SPDX-License-Identifier: AGPL-3.0-or-later

// Package entrasim to symulator Microsoft Graph dla logów Entra ID (etap 7):
// token aplikacji (OAuth2 client credentials), auditLogs/signIns
// i auditLogs/directoryAudits z filtrem czasu, stronicowaniem
// (@odata.nextLink), opóźnieniem pojawiania się logów i ograniczaniem
// zapytań (429 + Retry-After) – jak prawdziwe API. Rekordy mają kształt
// zasobów Graph v1.0 (signIn, directoryAudit), więc konektor i dekodery
// działają bez zmian na prawdziwym tenancie.
//
// Scenariusze (POST /sim/scenario?name=…): normal, spray, brute,
// success-after-failures, foreign, mfa-fatigue, admin-role.
package entrasim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config to ustawienia symulatora.
type Config struct {
	Tenant       string
	ClientID     string
	ClientSecret string
	Domain       string        // domena UPN użytkowników, np. azujo.pl
	Users        []string      // konta (bez domeny)
	Latency      time.Duration // najdłuższe opóźnienie pojawienia się rekordu w API
	ThrottleN    int           // co N-te zapytanie o dane – 429 (0 = bez)
}

// Sim to symulator (http.Handler).
type Sim struct {
	cfg     Config
	mu      sync.Mutex
	signIns []rec
	audits  []rec
	tokens  map[string]time.Time
	reqs    int
	Now     func() time.Time
}

type rec struct {
	at      time.Time // createdDateTime / activityDateTime
	visible time.Time // od kiedy widoczny w API
	data    map[string]any
}

// New tworzy symulator.
func New(c Config) *Sim {
	if c.Domain == "" {
		c.Domain = "azujo.pl"
	}
	if len(c.Users) == 0 {
		c.Users = []string{"jkowalski", "anowak", "pwisniewski", "kwojcik", "mkaminska", "heimdall-lab"}
	}
	return &Sim{cfg: c, tokens: map[string]time.Time{}, Now: time.Now}
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (s *Sim) upn(u string) string {
	if strings.Contains(u, "@") {
		return u
	}
	return u + "@" + s.cfg.Domain
}

// SignIn opisuje logowanie do dodania.
type SignIn struct {
	User      string
	IP        string
	Country   string
	City      string
	ErrorCode int
	App       string
	ClientApp string // Browser, IMAP4, Exchange ActiveSync…
	At        time.Time
	Device    string
}

var failureReasons = map[int]string{
	0:      "",
	50126:  "Error validating credentials due to invalid username or password.",
	50053:  "The account is locked, you've tried to sign in too many times with an incorrect user ID or password.",
	50074:  "Strong Authentication is required.",
	500121: "Authentication failed during strong authentication request.",
	50076:  "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access.",
	50034:  "The user account does not exist in the directory.",
}

// AddSignIn dodaje logowanie (widoczne w API po losowym opóźnieniu).
func (s *Sim) AddSignIn(x SignIn) {
	if x.At.IsZero() {
		x.At = s.Now()
	}
	if x.App == "" {
		x.App = "Office 365 Exchange Online"
	}
	if x.ClientApp == "" {
		x.ClientApp = "Browser"
	}
	if x.Country == "" {
		x.Country, x.City = "PL", "Warszawa"
	}
	upn := s.upn(x.User)
	name, _, _ := strings.Cut(upn, "@")
	status := map[string]any{"errorCode": x.ErrorCode, "failureReason": failureReasons[x.ErrorCode], "additionalDetails": nil}
	risk := "none"
	if x.Country != "PL" {
		risk = "low"
	}
	d := map[string]any{
		"id":                      newID(),
		"createdDateTime":         x.At.UTC().Format("2006-01-02T15:04:05Z"),
		"userDisplayName":         name,
		"userPrincipalName":       upn,
		"userId":                  newID(),
		"appId":                   newID(),
		"appDisplayName":          x.App,
		"ipAddress":               x.IP,
		"clientAppUsed":           x.ClientApp,
		"correlationId":           newID(),
		"conditionalAccessStatus": "notApplied",
		"isInteractive":           x.ClientApp == "Browser",
		"riskDetail":              "none",
		"riskLevelAggregated":     risk,
		"riskLevelDuringSignIn":   risk,
		"riskState":               "none",
		"riskEventTypes_v2":       []string{},
		"resourceDisplayName":     x.App,
		"resourceId":              newID(),
		"status":                  status,
		"deviceDetail": map[string]any{"deviceId": "", "displayName": x.Device, "operatingSystem": "Windows10",
			"browser": "Edge 129.0.0", "isCompliant": x.Device != "", "isManaged": x.Device != "", "trustType": ""},
		"location": map[string]any{"city": x.City, "state": "", "countryOrRegion": x.Country,
			"geoCoordinates": map[string]any{"altitude": nil, "latitude": 52.2297, "longitude": 21.0122}},
		"appliedConditionalAccessPolicies": []any{},
	}
	s.add(&s.signIns, x.At, d)
}

// Audit opisuje zmianę w katalogu.
type Audit struct {
	Activity  string // np. Add member to role
	Category  string // RoleManagement, UserManagement…
	Initiator string // konto wykonujące
	Target    string // konto, którego dotyczy
	Role      string // dla ról: nazwa roli
	Result    string // success | failure
	At        time.Time
}

// AddAudit dodaje wpis zmian w katalogu.
func (s *Sim) AddAudit(x Audit) {
	if x.At.IsZero() {
		x.At = s.Now()
	}
	if x.Result == "" {
		x.Result = "success"
	}
	props := []any{}
	if x.Role != "" {
		props = append(props, map[string]any{"displayName": "Role.DisplayName", "oldValue": nil, "newValue": `"` + x.Role + `"`})
	}
	d := map[string]any{
		"id":                  "Directory_" + newID(),
		"category":            x.Category,
		"correlationId":       newID(),
		"result":              x.Result,
		"resultReason":        "",
		"activityDisplayName": x.Activity,
		"activityDateTime":    x.At.UTC().Format("2006-01-02T15:04:05.0000000Z"),
		"loggedByService":     "Core Directory",
		"operationType":       "Assign",
		"initiatedBy": map[string]any{"app": nil, "user": map[string]any{"id": newID(), "displayName": nil,
			"userPrincipalName": s.upn(x.Initiator), "ipAddress": "", "userType": nil}},
		"targetResources": []any{map[string]any{"id": newID(), "displayName": nil, "type": "User",
			"userPrincipalName": s.upn(x.Target), "modifiedProperties": props}},
		"additionalDetails": []any{},
	}
	s.add(&s.audits, x.At, d)
}

func (s *Sim) add(list *[]rec, at time.Time, d map[string]any) {
	delay := time.Duration(0)
	if s.cfg.Latency > 0 {
		delay = time.Duration(mrand.Int64N(int64(s.cfg.Latency)))
	}
	s.mu.Lock()
	*list = append(*list, rec{at: at, visible: at.Add(delay), data: d})
	s.mu.Unlock()
}

// Counts zwraca liczbę rekordów (logowania, zmiany).
func (s *Sim) Counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.signIns), len(s.audits)
}

// Scenario dodaje rekordy scenariusza; zwraca ich liczbę.
func (s *Sim) Scenario(name, user, attacker string) (int, error) {
	now := s.Now()
	users := s.cfg.Users
	if user == "" {
		user = users[0]
	}
	if attacker == "" {
		attacker = fmt.Sprintf("185.220.101.%d", 2+mrand.IntN(250))
	}
	n := 0
	at := func(i int) time.Time { return now.Add(time.Duration(i-40) * 3 * time.Second) }
	switch name {
	case "normal":
		for i, u := range users {
			s.AddSignIn(SignIn{User: u, IP: fmt.Sprintf("192.168.88.%d", 100+i), Device: "DESKTOP-" + strings.ToUpper(u[:3]), At: at(i)})
			n++
		}
	case "spray":
		// Jedno hasło na wiele kont z jednego adresu (często IMAP/stare protokoły), konto nieistniejące też.
		for i, u := range append(append([]string{}, users...), "administrator", "test", "backup") {
			code := 50126
			if u == "test" || u == "backup" {
				code = 50034
			}
			s.AddSignIn(SignIn{User: u, IP: attacker, Country: "NL", City: "Amsterdam", ErrorCode: code, ClientApp: "IMAP4", At: at(i)})
			n++
		}
	case "brute":
		for i := range 12 {
			code := 50126
			if i >= 10 {
				code = 50053 // konto zablokowane
			}
			s.AddSignIn(SignIn{User: user, IP: attacker, Country: "DE", City: "Frankfurt", ErrorCode: code, At: at(i)})
			n++
		}
	case "success-after-failures":
		for i := range 8 {
			s.AddSignIn(SignIn{User: user, IP: attacker, Country: "RO", City: "Bukareszt", ErrorCode: 50126, At: at(i)})
			n++
		}
		s.AddSignIn(SignIn{User: user, IP: attacker, Country: "RO", City: "Bukareszt", ErrorCode: 0, At: at(9)})
		n++
	case "foreign":
		s.AddSignIn(SignIn{User: user, IP: "192.168.88.126", Device: "DESKTOP-3P8VS81", At: at(0)})
		s.AddSignIn(SignIn{User: user, IP: attacker, Country: "NG", City: "Lagos", At: at(5)})
		n += 2
	case "mfa-fatigue":
		for i := range 10 {
			s.AddSignIn(SignIn{User: user, IP: attacker, Country: "US", City: "Ashburn", ErrorCode: 500121, At: at(i)})
			n++
		}
	case "admin-role":
		s.AddAudit(Audit{Activity: "Add member to role", Category: "RoleManagement", Initiator: users[len(users)-1], Target: user,
			Role: "Global Administrator", At: at(0)})
		n++
	default:
		return 0, fmt.Errorf("nieznany scenariusz %q (normal, spray, brute, success-after-failures, foreign, mfa-fatigue, admin-role)", name)
	}
	return n, nil
}

// ServeHTTP obsługuje API: token, logi, sterowanie symulatorem.
func (s *Sim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		s.token(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1.0/auditLogs/signIns":
		s.list(w, r, &s.signIns, "createdDateTime")
	case r.Method == http.MethodGet && r.URL.Path == "/v1.0/auditLogs/directoryAudits":
		s.list(w, r, &s.audits, "activityDateTime")
	case r.Method == http.MethodPost && r.URL.Path == "/sim/scenario":
		q := r.URL.Query()
		n, err := s.Scenario(q.Get("name"), q.Get("user"), q.Get("attacker"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		si, au := s.Counts()
		writeJSON(w, http.StatusOK, map[string]any{"added": n, "sign_ins": si, "audits": au})
	case r.Method == http.MethodGet && r.URL.Path == "/sim/stats":
		si, au := s.Counts()
		writeJSON(w, http.StatusOK, map[string]any{"sign_ins": si, "audits": au})
	default:
		graphErr(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func graphErr(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

func (s *Sim) token(w http.ResponseWriter, r *http.Request) {
	tenant := strings.Trim(strings.TrimSuffix(r.URL.Path, "/oauth2/v2.0/token"), "/")
	_ = r.ParseForm()
	if tenant != s.cfg.Tenant || r.Form.Get("client_id") != s.cfg.ClientID || r.Form.Get("client_secret") != s.cfg.ClientSecret ||
		r.Form.Get("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided."})
		return
	}
	tok := newID() + newID()
	s.mu.Lock()
	s.tokens[tok] = s.Now().Add(time.Hour)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": tok})
}

func (s *Sim) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, found := s.tokens[tok]
	return ok && found && s.Now().Before(exp)
}

// list: $filter „pole ge czas [and pole le czas]”, $top, $skiptoken; od najnowszych.
func (s *Sim) list(w http.ResponseWriter, r *http.Request, src *[]rec, field string) {
	if !s.authorized(r) {
		graphErr(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or invalid.")
		return
	}
	s.mu.Lock()
	s.reqs++
	throttle := s.cfg.ThrottleN > 0 && s.reqs%s.cfg.ThrottleN == 0
	s.mu.Unlock()
	if throttle {
		w.Header().Set("Retry-After", "1")
		graphErr(w, http.StatusTooManyRequests, "TooManyRequests", "Too many requests.")
		return
	}
	q := r.URL.Query()
	from, to, err := parseFilter(q.Get("$filter"), field)
	if err != nil {
		graphErr(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	top := 100
	if v, err := strconv.Atoi(q.Get("$top")); err == nil && v > 0 && v <= 1000 {
		top = v
	}
	skip, _ := strconv.Atoi(q.Get("$skiptoken"))
	now := s.Now()
	s.mu.Lock()
	var sel []rec
	for _, x := range *src {
		if x.visible.After(now) || x.at.Before(from) || (!to.IsZero() && x.at.After(to)) {
			continue
		}
		sel = append(sel, x)
	}
	s.mu.Unlock()
	sort.SliceStable(sel, func(i, j int) bool { return sel[i].at.After(sel[j].at) })
	resp := map[string]any{"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/" + strings.TrimPrefix(r.URL.Path, "/v1.0/auditLogs/")}
	end := min(skip+top, len(sel))
	if skip > len(sel) {
		skip = len(sel)
	}
	vals := make([]any, 0, end-skip)
	for _, x := range sel[skip:end] {
		vals = append(vals, x.data)
	}
	resp["value"] = vals
	if end < len(sel) {
		nq := url.Values{}
		nq.Set("$filter", q.Get("$filter"))
		nq.Set("$top", strconv.Itoa(top))
		nq.Set("$skiptoken", strconv.Itoa(end))
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		resp["@odata.nextLink"] = scheme + "://" + r.Host + r.URL.Path + "?" + nq.Encode()
	}
	writeJSON(w, http.StatusOK, resp)
}

func parseFilter(f, field string) (from, to time.Time, err error) {
	if f == "" {
		return time.Time{}, time.Time{}, nil
	}
	for _, part := range strings.Split(f, " and ") {
		fs := strings.Fields(part)
		if len(fs) != 3 || fs[0] != field || (fs[1] != "ge" && fs[1] != "le") {
			return from, to, fmt.Errorf("Invalid filter clause: %q", part)
		}
		t, err := time.Parse(time.RFC3339Nano, fs[2])
		if err != nil {
			return from, to, fmt.Errorf("Invalid date: %q", fs[2])
		}
		if fs[1] == "ge" {
			from = t
		} else {
			to = t
		}
	}
	return from, to, nil
}
