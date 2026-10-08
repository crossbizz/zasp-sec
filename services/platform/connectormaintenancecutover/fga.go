package connectormaintenancecutover

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"

	sdk "github.com/openfga/go-sdk"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

//go:embed model.json
var productModel []byte

type nativeEvidence struct {
	proc
	old, new   *fga.OpenFgaClient
	expected   fga.ClientWriteAuthorizationModelRequest
	model      string
	transports []*http.Transport
}
type cappedTransport struct {
	inner *http.Transport
	model string
}
type cappedBody struct {
	io.ReadCloser
	n int
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.n <= 0 {
		return 0, ErrRefused
	}
	if len(p) > b.n {
		p = p[:b.n]
	}
	n, e := b.ReadCloser.Read(p)
	b.n -= n
	return n, e
}
func (t cappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	v, e := t.inner.RoundTrip(r)
	if e != nil || v == nil {
		return v, e
	}
	if v.ContentLength > 1<<20 {
		v.Body.Close()
		return nil, ErrRefused
	}
	data, e := io.ReadAll(io.LimitReader(v.Body, (1<<20)+1))
	closed := v.Body.Close()
	if e != nil || closed != nil || len(data) > 1<<20 || r.Context().Err() != nil {
		return nil, ErrRefused
	}
	if v.StatusCode == http.StatusOK && wholeRawModel(data, productModel, t.model) != nil {
		return nil, ErrRefused
	}
	v.Body = io.NopCloser(bytes.NewReader(data))
	return v, nil
}

func tokenFile(path string) (string, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 8 || before.Size() > 8192 {
		return "", ErrRefused
	}
	s, ok := before.Sys().(*syscall.Stat_t)
	if !ok || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) {
		return "", ErrRefused
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", ErrRefused
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !sameTokenMetadata(before, opened) {
		return "", ErrRefused
	}
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	defer clear(b)
	after, e2 := f.Stat()
	last, e3 := os.Lstat(path)
	if e != nil || e2 != nil || e3 != nil || len(b) > 8192 || !sameTokenMetadata(before, after) || !sameTokenMetadata(before, last) {
		return "", ErrRefused
	}
	v := strings.TrimSpace(string(b))
	if len(v) < 8 || strings.ContainsAny(v, "\r\n\t ") {
		return "", ErrRefused
	}
	return v, nil
}
func newEvidence(endpoint, store, model, oldPath, newPath string) (*nativeEvidence, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" || store == "" || model == "" || oldPath == newPath {
		return nil, ErrRefused
	}
	old, e := tokenFile(oldPath)
	if e != nil {
		return nil, ErrRefused
	}
	next, e := tokenFile(newPath)
	if e != nil || old == next {
		return nil, ErrRefused
	}
	out := &nativeEvidence{model: model}
	if json.Unmarshal(productModel, &out.expected) != nil {
		return nil, ErrRefused
	}
	for _, token := range []string{old, next} {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.MaxConnsPerHost = 2
		out.transports = append(out.transports, t)
		client, e := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: endpoint, StoreId: store, AuthorizationModelId: model, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: cappedTransport{t, model}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
		if e != nil {
			out.close()
			return nil, ErrRefused
		}
		if out.old == nil {
			out.old = client
		} else {
			out.new = client
		}
	}
	return out, nil
}
func (n *nativeEvidence) close() {
	for _, t := range n.transports {
		t.CloseIdleConnections()
	}
}
func (n *nativeEvidence) whole(ctx context.Context, c *fga.OpenFgaClient) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, e := c.ReadAuthorizationModel(bounded).Execute()
	if e != nil || v == nil || bounded.Err() != nil {
		return ErrRefused
	}
	m := v.GetAuthorizationModel()
	if m.GetId() != n.model || m.GetSchemaVersion() != n.expected.SchemaVersion || !reflect.DeepEqual(m.TypeDefinitions, n.expected.TypeDefinitions) || !reflect.DeepEqual(m.Conditions, n.expected.Conditions) {
		return ErrRefused
	}
	return nil
}
func (n *nativeEvidence) oldModel(c context.Context) error { return n.whole(c, n.old) }
func (n *nativeEvidence) newModel(c context.Context) error { return n.whole(c, n.new) }
func (n *nativeEvidence) oldUnauthorized(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, e := n.old.ReadAuthorizationModel(bounded).Execute()
	var auth sdk.FgaApiAuthenticationError
	if e == nil || !errors.As(e, &auth) || auth.ResponseStatusCode() != 401 || bounded.Err() != nil {
		return ErrRefused
	}
	return nil
}

// atime may advance on read; all security and content identity fields remain fixed.
func sameTokenMetadata(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, other := b.Sys().(*syscall.Stat_t)
	return ok && other && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim && x.Nlink == 1 && x.Uid == uint32(os.Geteuid())
}
