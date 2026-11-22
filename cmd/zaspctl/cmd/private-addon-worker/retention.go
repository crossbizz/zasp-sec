package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

type retentionReceipt struct {
	Mode    string    `json:"mode"`
	State   string    `json:"state"`
	Grant   string    `json:"grant_id"`
	Expires time.Time `json:"expires_at"`
}

// The socket carries the original signed short-lived grant. The storage
// process independently pins its key, Environment and archive digest.
func retainViaSocket(ctx context.Context, socket, token string, g grant, body []byte) (*retentionReceipt, error) {
	if !filepath.IsAbs(socket) || g.RetainUntil == 0 {
		return nil, errors.New("retention unavailable")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 28 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "PUT", "http://localhost/v1/uploads/"+g.ID, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/zip")
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("retention unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("retention unavailable")
	}
	var receipt retentionReceipt
	d := json.NewDecoder(io.LimitReader(resp.Body, 2048))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(&struct{}{}) != io.EOF || receipt.Mode != "encrypted_24h" || receipt.State != "retained" || receipt.Grant != g.ID || !receipt.Expires.Equal(time.Unix(g.RetainUntil, 0)) {
		return nil, errors.New("retention receipt invalid")
	}
	return &receipt, nil
}
