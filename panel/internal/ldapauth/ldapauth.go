// Package ldapauth to logowanie do panelu kontem domenowym (Active
// Directory) przez LDAPS: sprawdzenie hasła, członkostwo w grupach (także
// zagnieżdżone – tokenGroups) i profil uprawnień według powiązań grupa →
// profil w ustalonej kolejności. Grupy rozpoznawane po SID – zmiana nazwy
// grupy w AD nie zmienia uprawnień, a grupa o tej samej nazwie w innym
// miejscu ich nie przejmuje.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config to ustawienia logowania domenowego (panel → Logowanie domenowe).
type Config struct {
	Enabled bool     `json:"enabled"`
	URLs    []string `json:"urls"`   // ldaps://dc01.firma.pl:636 (kolejne – zapasowe)
	CAPEM   string   `json:"ca_pem"` // certyfikat CA kontrolerów (PEM); pusty – systemowe
	// TLSServerName: nazwa w certyfikacie kontrolera, gdy adres to IP albo
	// nazwa spoza certyfikatu; pusta – nazwa z adresu.
	TLSServerName string    `json:"tls_server_name"`
	BindDN        string    `json:"bind_dn"`        // konto usługowe (DN albo UPN), tylko odczyt
	BindPassword  string    `json:"-"`              // hasło konta usługowego (zapis zaszyfrowany)
	BaseDN        string    `json:"base_dn"`        // gdzie szukać kont, np. DC=firma,DC=pl
	GroupsBaseDN  string    `json:"groups_base_dn"` // OU z grupami panelu (kreator)
	Mappings      []Mapping `json:"mappings"`       // grupa → profil; pierwsza pasująca wygrywa
}

// Mapping to powiązanie grupy AD z profilem uprawnień panelu.
type Mapping struct {
	SID     string `json:"sid"`
	Name    string `json:"name"` // nazwa w chwili wyboru (tylko do wyświetlenia)
	DN      string `json:"dn"`
	Profile string `json:"profile"`
}

// Account to konto domenowe po sprawdzeniu.
type Account struct {
	DN          string   `json:"dn"`
	SID         string   `json:"sid"`
	Login       string   `json:"login"` // sAMAccountName
	UPN         string   `json:"upn"`
	DisplayName string   `json:"display_name"`
	Disabled    bool     `json:"disabled"`
	GroupSIDs   []string `json:"-"`
}

// Group to grupa z OU kreatora.
type Group struct {
	SID         string `json:"sid"`
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Members     int    `json:"members"`
}

var (
	// ErrBadCredentials: zły login albo hasło (także konto wyłączone w AD).
	ErrBadCredentials = errors.New("nieprawidłowy login lub hasło konta domenowego")
	// ErrNotFound: brak takiego konta w AD.
	ErrNotFound = errors.New("nie ma takiego konta w domenie")
)

const timeout = 10 * time.Second

// loginPattern: login domenowy (jan.kowalski, FIRMA\jan, jan@firma.pl).
var loginPattern = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{1,128}$`)

// Validate sprawdza ustawienia (adresy tylko ldaps://, certyfikat CA, DN).
func (c *Config) Validate() error {
	if len(c.URLs) == 0 {
		return errors.New("podaj adres kontrolera domeny (ldaps://…)")
	}
	for _, u := range c.URLs {
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "ldaps" || p.Hostname() == "" {
			return fmt.Errorf("adres %q: tylko ldaps://nazwa-kontrolera[:636] (bez szyfrowania hasła szłyby otwartym tekstem)", u)
		}
	}
	if strings.TrimSpace(c.CAPEM) != "" {
		if _, err := c.pool(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.BindDN) == "" || strings.TrimSpace(c.BaseDN) == "" {
		return errors.New("podaj konto usługowe i bazę wyszukiwania kont")
	}
	if _, err := ldap.ParseDN(c.BaseDN); err != nil {
		return fmt.Errorf("baza kont: %v", err)
	}
	if c.GroupsBaseDN != "" {
		if _, err := ldap.ParseDN(c.GroupsBaseDN); err != nil {
			return fmt.Errorf("OU grup: %v", err)
		}
	}
	return nil
}

func (c *Config) pool() (*x509.CertPool, error) {
	if strings.TrimSpace(c.CAPEM) == "" {
		return x509.SystemCertPool()
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, errors.New("certyfikat CA: nieczytelny PEM (-----BEGIN CERTIFICATE-----…)")
	}
	return p, nil
}

// dial łączy się z pierwszym dostępnym kontrolerem (LDAPS z weryfikacją
// certyfikatu i nazwy).
func (c *Config) dial(ctx context.Context) (*ldap.Conn, error) {
	pool, err := c.pool()
	if err != nil {
		return nil, err
	}
	var errs []string
	for _, u := range c.URLs {
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "ldaps" {
			errs = append(errs, u+": nie ldaps://")
			continue
		}
		d := &net.Dialer{Timeout: timeout}
		name := p.Hostname()
		if c.TLSServerName != "" {
			name = c.TLSServerName
		}
		conn, err := ldap.DialURL(u, ldap.DialWithDialer(d),
			ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}))
		if err != nil {
			errs = append(errs, u+": "+err.Error())
			continue
		}
		conn.SetTimeout(timeout)
		if ctx.Err() != nil {
			conn.Close()
			return nil, ctx.Err()
		}
		return conn, nil
	}
	return nil, fmt.Errorf("kontroler domeny niedostępny: %s", strings.Join(errs, "; "))
}

// service: połączenie zalogowane kontem usługowym.
func (c *Config) service(ctx context.Context) (*ldap.Conn, error) {
	if c.BindPassword == "" {
		return nil, errors.New("brak hasła konta usługowego")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("logowanie kontem usługowym: %v", err)
	}
	return conn, nil
}

// NormalizeLogin: login bez domeny NetBIOS (FIRMA\jan → jan).
func NormalizeLogin(login string) string {
	login = strings.TrimSpace(login)
	if i := strings.LastIndex(login, `\`); i >= 0 {
		login = login[i+1:]
	}
	return login
}

const userAttrs = "distinguishedName,objectSid,sAMAccountName,userPrincipalName,displayName,userAccountControl"

// Lookup szuka konta (bez hasła) – podgląd w kreatorze i odświeżanie.
func (c *Config) Lookup(ctx context.Context, login string) (*Account, error) {
	conn, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return c.lookup(conn, login)
}

func (c *Config) lookup(conn *ldap.Conn, login string) (*Account, error) {
	login = NormalizeLogin(login)
	if !loginPattern.MatchString(login) {
		return nil, ErrNotFound
	}
	attr := "sAMAccountName"
	if strings.Contains(login, "@") {
		attr = "userPrincipalName"
	}
	return c.find(conn, fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(%s=%s))", attr, ldap.EscapeFilter(login)))
}

// LookupSID szuka konta po SID (odświeżanie członkostwa zalogowanych).
func (c *Config) LookupSID(ctx context.Context, sid string) (*Account, error) {
	raw, err := sidBytes(sid)
	if err != nil {
		return nil, err
	}
	conn, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var esc strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&esc, `\%02x`, b)
	}
	return c.find(conn, "(&(objectCategory=person)(objectClass=user)(objectSid="+esc.String()+"))")
}

func (c *Config) find(conn *ldap.Conn, filter string) (*Account, error) {
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(timeout/time.Second), false,
		filter, strings.Split(userAttrs, ","), nil))
	if err != nil {
		return nil, fmt.Errorf("wyszukiwanie konta: %v", err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrNotFound
	}
	e := res.Entries[0]
	uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
	a := &Account{DN: e.DN, SID: sidString(e.GetRawAttributeValue("objectSid")), Login: e.GetAttributeValue("sAMAccountName"),
		UPN: e.GetAttributeValue("userPrincipalName"), DisplayName: e.GetAttributeValue("displayName"), Disabled: uac&2 != 0}
	// tokenGroups: wszystkie grupy zabezpieczeń konta (także zagnieżdżone) –
	// atrybut liczony, tylko przy wyszukiwaniu bazowym na obiekcie konta.
	tg, err := conn.Search(ldap.NewSearchRequest(e.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(timeout/time.Second), false,
		"(objectClass=*)", []string{"tokenGroups"}, nil))
	if err != nil {
		return nil, fmt.Errorf("grupy konta: %v", err)
	}
	if len(tg.Entries) == 1 {
		for _, raw := range tg.Entries[0].GetRawAttributeValues("tokenGroups") {
			if s := sidString(raw); s != "" {
				a.GroupSIDs = append(a.GroupSIDs, s)
			}
		}
	}
	return a, nil
}

// Authenticate sprawdza login i hasło w AD i zwraca konto z grupami.
func (c *Config) Authenticate(ctx context.Context, login, password string) (*Account, error) {
	// Puste hasło w LDAP to logowanie anonimowe (bind się udaje) – nigdy.
	if password == "" {
		return nil, ErrBadCredentials
	}
	conn, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	a, err := c.lookup(conn, login)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := c.verify(ctx, a.DN, password); err != nil {
		return nil, err
	}
	if a.Disabled {
		return nil, ErrBadCredentials
	}
	return a, nil
}

// VerifyPassword sprawdza hasło konta o danym DN (ponowne podanie hasła).
func (c *Config) VerifyPassword(ctx context.Context, dn, password string) error {
	if password == "" {
		return ErrBadCredentials
	}
	return c.verify(ctx, dn, password)
}

func (c *Config) verify(ctx context.Context, dn, password string) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return ErrBadCredentials
		}
		return fmt.Errorf("sprawdzenie hasła: %v", err)
	}
	return nil
}

// Groups zwraca grupy z OU kreatora (najwyżej 1000).
func (c *Config) Groups(ctx context.Context) ([]Group, error) {
	if c.GroupsBaseDN == "" {
		return nil, errors.New("podaj OU z grupami")
	}
	conn, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000,
		int(timeout/time.Second), false, "(objectClass=group)", []string{"cn", "objectSid", "description", "member"}, nil), 200)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("grupy w %s: %v", c.GroupsBaseDN, err)
	}
	out := []Group{}
	for _, e := range res.Entries {
		out = append(out, Group{SID: sidString(e.GetRawAttributeValue("objectSid")), DN: e.DN, Name: e.GetAttributeValue("cn"),
			Description: e.GetAttributeValue("description"), Members: len(e.GetAttributeValues("member"))})
	}
	return out, nil
}

// Test: połączenie i logowanie kontem usługowym, sprawdzenie bazy kont.
func (c *Config) Test(ctx context.Context) error {
	conn, err := c.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(timeout/time.Second), false,
		"(objectClass=*)", []string{"distinguishedName"}, nil)); err != nil {
		return fmt.Errorf("baza kont %s: %v", c.BaseDN, err)
	}
	return nil
}

// ProfileFor: profil pierwszego powiązania, którego grupa jest wśród grup konta.
func (c *Config) ProfileFor(groupSIDs []string) (Mapping, bool) {
	has := map[string]bool{}
	for _, s := range groupSIDs {
		has[s] = true
	}
	for _, m := range c.Mappings {
		if has[m.SID] {
			return m, true
		}
	}
	return Mapping{}, false
}

// sidString: binarny SID → S-1-5-21-….
func sidString(b []byte) string {
	if len(b) < 8 || int(b[1])*4+8 != len(b) {
		return ""
	}
	auth := uint64(0)
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	var s strings.Builder
	fmt.Fprintf(&s, "S-%d-%d", b[0], auth)
	for i := 0; i < int(b[1]); i++ {
		fmt.Fprintf(&s, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s.String()
}

// sidBytes: S-1-5-21-… → binarny SID.
func sidBytes(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" || len(parts)-3 > 15 {
		return nil, fmt.Errorf("niepoprawny SID %q", s)
	}
	rev, err1 := strconv.ParseUint(parts[1], 10, 8)
	auth, err2 := strconv.ParseUint(parts[2], 10, 48)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("niepoprawny SID %q", s)
	}
	b := []byte{byte(rev), byte(len(parts) - 3)}
	for i := 5; i >= 0; i-- {
		b = append(b, byte(auth>>(8*i)))
	}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("niepoprawny SID %q", s)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return b, nil
}
