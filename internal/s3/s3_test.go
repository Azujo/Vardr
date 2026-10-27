// SPDX-License-Identifier: AGPL-3.0-or-later

package s3

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Przykład z dokumentacji AWS (Signature V4, GET obiektu z nagłówkiem Range).
func TestSignAWSExample(t *testing.T) {
	c := &Client{Endpoint: "https://s3.amazonaws.com", Region: "us-east-1", Bucket: "examplebucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}
	u, err := c.url("test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Range", "bytes=0-9")
	c.sign(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("podpis:\n%s\nchcę:\n%s", got, want)
	}
}

func TestPutHeadLock(t *testing.T) {
	objects := map[string][]byte{}
	headers := map[string]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=ak/") {
			w.WriteHeader(403)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/kubel/" && r.URL.RawQuery == "object-lock=":
			io.WriteString(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
		case r.Method == "PUT":
			body, _ := io.ReadAll(r.Body)
			sum := md5.Sum(body)
			if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(sum[:]) {
				w.WriteHeader(400)
				io.WriteString(w, `<Error><Code>BadDigest</Code><Message>md5</Message></Error>`)
				return
			}
			objects[r.URL.Path] = body
			headers[r.URL.Path] = r.Header.Clone()
		case r.Method == "HEAD":
			b, ok := objects[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Header().Set("x-amz-object-lock-mode", headers[r.URL.Path].Get("x-amz-object-lock-mode"))
			w.Header().Set("x-amz-object-lock-retain-until-date", headers[r.URL.Path].Get("x-amz-object-lock-retain-until-date"))
		default:
			w.WriteHeader(405)
		}
	}))
	defer srv.Close()
	c := &Client{Endpoint: srv.URL, Region: "us-east-1", Bucket: "kubel", AccessKey: "ak", SecretKey: "sk", PathStyle: true}
	ctx := context.Background()

	if on, mode, err := c.LockConfig(ctx); err != nil || !on || mode != ModeCompliance {
		t.Fatalf("konfiguracja blokady: %v %q %v", on, mode, err)
	}
	until := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	if err := c.Put(ctx, "urd/2026/10/27/10/seg 1.zst", []byte("dane"), &Lock{Mode: ModeCompliance, RetainUntil: until}); err != nil {
		t.Fatal(err)
	}
	if _, ok := objects["/kubel/urd/2026/10/27/10/seg 1.zst"]; !ok {
		t.Fatalf("klucz: %v", objects)
	}
	o, err := c.Head(ctx, "urd/2026/10/27/10/seg 1.zst")
	if err != nil || o.Size != 4 || o.LockMode != ModeCompliance || !o.RetainUntil.Equal(until) {
		t.Fatalf("nagłówki: %+v %v", o, err)
	}
	if _, err := c.Head(ctx, "brak"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("brak obiektu: %v", err)
	}
	bad := *c
	bad.AccessKey = "zly"
	if err := bad.Put(ctx, "x", []byte("y"), nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("odmowa: %v", err)
	}
}
