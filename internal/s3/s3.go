// SPDX-License-Identifier: AGPL-3.0-or-later

// Package s3 to minimalny klient S3 (podpis AWS Signature V4) dla kopii
// archiwum Urd z blokadą obiektów (Object Lock): zapis obiektu z blokadą,
// odczyt nagłówków obiektu i konfiguracji blokady kubełka. Działa z AWS S3
// i zgodnymi magazynami (Wasabi, Backblaze B2, MinIO, Ceph RGW).
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Tryby blokady obiektów.
const (
	ModeCompliance = "COMPLIANCE" // nikt (także administrator konta) nie skróci blokady
	ModeGovernance = "GOVERNANCE" // uprawnienie s3:BypassGovernanceRetention pozwala ją zdjąć
)

// Client to klient jednego kubełka.
type Client struct {
	Endpoint  string // np. https://s3.eu-central-1.amazonaws.com
	Region    string // np. eu-central-1 (MinIO: us-east-1)
	Bucket    string
	AccessKey string
	SecretKey string
	// PathStyle: adres https://host/bucket/klucz zamiast https://bucket.host/klucz
	// (MinIO, Ceph i większość magazynów poza AWS).
	PathStyle bool
	HTTP      *http.Client
	now       func() time.Time
}

// Lock to blokada zapisywanego obiektu.
type Lock struct {
	Mode        string
	RetainUntil time.Time
}

// Object to nagłówki obiektu.
type Object struct {
	Size        int64
	LockMode    string
	RetainUntil time.Time
}

// ErrNotFound: brak obiektu.
var ErrNotFound = errors.New("s3: object not found")

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// url zwraca adres obiektu (key "" – kubełek) i nagłówek Host.
func (c *Client) url(key string, query url.Values) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(c.Endpoint, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("s3: invalid endpoint %q", c.Endpoint)
	}
	raw, p := "/"+escapePath(key), "/"+key
	if c.PathStyle {
		raw, p = "/"+c.Bucket+raw, "/"+c.Bucket+p
	} else {
		u.Host = c.Bucket + "." + u.Host
	}
	u.Path, u.RawPath = p, raw
	u.RawQuery = canonicalQuery(query)
	return u, nil
}

// escapePath koduje klucz według reguł S3 (ukośniki zostają).
func escapePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = uriEncode(p)
	}
	return strings.Join(parts, "/")
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sign dodaje nagłówek Authorization (AWS Signature V4). Podpisywane są
// Host, nagłówki x-amz-*, Content-MD5 i Range.
func (c *Client) sign(req *http.Request, payloadHash string) {
	t := c.clock().UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	headers := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-md5" || lk == "range" {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery,
		canonHeaders.String(), signed, payloadHash}, "\n")
	scope := day + "/" + c.Region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	key := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	key = hmacSHA256(key, c.Region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

func (c *Client) do(ctx context.Context, method, key string, query url.Values, body []byte, hdr map[string]string) (*http.Response, error) {
	u, err := c.url(key, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host
	req.ContentLength = int64(len(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c.sign(req, sha256Hex(body))
	return c.client().Do(req)
}

// apiError odczytuje komunikat błędu S3 (XML <Error><Code>…</Code><Message>…).
func apiError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(body, &e) == nil && e.Code != "" {
		return fmt.Errorf("s3: HTTP %d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	return fmt.Errorf("s3: HTTP %d", resp.StatusCode)
}

// Put zapisuje obiekt; z blokadą (lock != nil) w podanym trybie do
// RetainUntil. Kubełek musi mieć włączone Object Lock (i wersjonowanie).
func (c *Client) Put(ctx context.Context, key string, body []byte, lock *Lock) error {
	sum := md5.Sum(body)
	hdr := map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(sum[:]),
		"Content-Type": "application/octet-stream"}
	if lock != nil {
		hdr["x-amz-object-lock-mode"] = lock.Mode
		hdr["x-amz-object-lock-retain-until-date"] = lock.RetainUntil.UTC().Format("2006-01-02T15:04:05Z")
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, body, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Head zwraca rozmiar i blokadę obiektu (ErrNotFound – brak).
func (c *Client) Head(ctx context.Context, key string) (Object, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, nil, nil)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Object{}, ErrNotFound
	default:
		return Object{}, fmt.Errorf("s3: HTTP %d", resp.StatusCode)
	}
	o := Object{Size: resp.ContentLength, LockMode: resp.Header.Get("x-amz-object-lock-mode")}
	if v := resp.Header.Get("x-amz-object-lock-retain-until-date"); v != "" {
		o.RetainUntil, _ = time.Parse(time.RFC3339, v)
	}
	return o, nil
}

// LockConfig zwraca domyślną konfigurację blokady kubełka: czy Object Lock
// jest włączone oraz domyślny tryb ("" – brak reguły domyślnej).
func (c *Client) LockConfig(ctx context.Context) (enabled bool, mode string, err error) {
	resp, err := c.do(ctx, http.MethodGet, "", url.Values{"object-lock": {""}}, nil, nil)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, "", nil // ObjectLockConfigurationNotFoundError
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", apiError(resp)
	}
	var cfg struct {
		Enabled string `xml:"ObjectLockEnabled"`
		Mode    string `xml:"Rule>DefaultRetention>Mode"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return false, "", fmt.Errorf("s3: object lock configuration: %w", err)
	}
	return cfg.Enabled == "Enabled", cfg.Mode, nil
}
