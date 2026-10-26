// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"siem/internal/mcp"
)

// client to klient API panelu z tokenem.
type client struct {
	base     string
	token    string
	insecure bool
	http     *http.Client
}

// Get: zapytanie GET do API panelu (mcp.Caller).
func (c *client) Get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vardr-mcp/"+version_)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connection to the panel failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	return mcp.DecodeResponse(resp.StatusCode, body, out)
}
