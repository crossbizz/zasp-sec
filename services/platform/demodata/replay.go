package demodata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// HTTPSource is what a provider's API answers, as a route table. The replay
// transport serves it in process: the collector's HTTP client is given the
// transport, so no request leaves the process and no port is opened.
type HTTPSource struct {
	// Platform is the SaaS platform key (provider "saas" only).
	Platform string `json:"platform,omitempty"`
	// Host is the tenant host of a SaaS platform with one host per tenant.
	Host string `json:"host,omitempty"`
	// Endpoint is the provider endpoint the collector is configured with:
	// the Kubernetes API server, the Okta issuer, the Salesforce instance or
	// the Dataverse environment host.
	Endpoint string `json:"endpoint,omitempty"`
	// Azure says the Microsoft collection also reads Azure (AI Foundry).
	Azure  bool    `json:"azure,omitempty"`
	Routes []Route `json:"routes"`
}

// Route answers the requests of one method, host and path. A route with
// Query answers only requests whose query holds those values; the route with
// the most matching Query members wins.
type Route struct {
	Method string            `json:"method,omitempty"`
	Host   string            `json:"host,omitempty"`
	Path   string            `json:"path"`
	Query  map[string]string `json:"query,omitempty"`
	// BodyContains selects among POST routes of one path (GraphQL queries).
	BodyContains string `json:"body_contains,omitempty"`
	Status       int    `json:"status,omitempty"`
	// Body is the response document.
	Body json.RawMessage `json:"body,omitempty"`
	// Earlier is the response of the previous collection (see HasEarlier).
	Earlier json.RawMessage `json:"earlier,omitempty"`
	// Items is a list the route pages through the way the provider does;
	// Paging names the provider's convention.
	Items  []json.RawMessage `json:"items,omitempty"`
	Paging string            `json:"paging,omitempty"`
	// ItemsKey is the member of the response that holds the page's items
	// (paging "github" and "kubernetes").
	ItemsKey string `json:"items_key,omitempty"`
}

func (source HTTPSource) validate() error {
	if len(source.Routes) == 0 {
		return errors.New("an http source needs routes")
	}
	for _, route := range source.Routes {
		switch {
		case !strings.HasPrefix(route.Path, "/"):
			return fmt.Errorf("route %q: path", route.Path)
		case route.Method != "" && route.Method != http.MethodGet && route.Method != http.MethodPost:
			return fmt.Errorf("route %q: method", route.Path)
		case route.Paging != "" && route.Paging != "github" && route.Paging != "kubernetes" && route.Paging != "okta":
			return fmt.Errorf("route %q: paging", route.Path)
		case (route.Paging != "") == (len(route.Body) != 0):
			return fmt.Errorf("route %q: a route has either a body or a paged list", route.Path)
		case route.Paging == "" && route.Earlier != nil && !json.Valid(route.Earlier), len(route.Body) != 0 && !json.Valid(route.Body):
			return fmt.Errorf("route %q: body", route.Path)
		}
	}
	return nil
}

// replay is the in-process stand-in for a provider's API.
type replay struct {
	routes  []Route
	earlier bool
	// misses collects the requests no route answered, for the dataset test.
	misses map[string]bool
}

func newReplay(source *HTTPSource, earlier bool) *replay {
	return &replay{routes: source.Routes, earlier: earlier, misses: map[string]bool{}}
}

func (transport *replay) match(method, host, path string, query url.Values, body []byte) (Route, bool) {
	best, bestScore := Route{}, -1
	for _, route := range transport.routes {
		wantMethod := route.Method
		if wantMethod == "" {
			wantMethod = http.MethodGet
		}
		if wantMethod != method || route.Path != path || route.Host != "" && route.Host != host {
			continue
		}
		if route.BodyContains != "" && !bytes.Contains(body, []byte(route.BodyContains)) {
			continue
		}
		score, matched := 0, true
		for name, value := range route.Query {
			if query.Get(name) != value {
				matched = false
				break
			}
			score++
		}
		if route.Host != "" {
			score++
		}
		if route.BodyContains != "" {
			score++
		}
		if matched && score > bestScore {
			best, bestScore = route, score
		}
	}
	return best, bestScore >= 0
}

// answer returns the status, the headers and the body of one request.
func (transport *replay) answer(method, host, path string, query url.Values, body []byte) (int, http.Header, []byte) {
	headers := http.Header{"Content-Type": {"application/json"}}
	route, found := transport.match(method, host, path, query, body)
	if !found {
		transport.misses[method+" "+host+path] = true
		return http.StatusNotFound, headers, []byte(`{"error":"not found","message":"not found"}`)
	}
	status := route.Status
	if status == 0 {
		status = http.StatusOK
	}
	switch route.Paging {
	case "":
		document := route.Body
		if transport.earlier && route.Earlier != nil {
			document = route.Earlier
		}
		return status, headers, document
	case "github":
		// ?page=N&per_page=M answers {"total_count":T,"<key>":[...]}.
		page, size := positive(query.Get("page"), 1), positive(query.Get("per_page"), 30)
		items := slice(route.Items, (page-1)*size, size)
		encoded, _ := json.Marshal(map[string]any{"total_count": len(route.Items), route.ItemsKey: items})
		return status, headers, encoded
	case "kubernetes":
		// ?limit=N&continue=T answers a list with metadata.continue.
		start, size := positive(query.Get("continue"), 0), positive(query.Get("limit"), 500)
		items := slice(route.Items, start, size)
		metadata := map[string]any{"resourceVersion": "1"}
		if start+size < len(route.Items) {
			metadata["continue"] = strconv.Itoa(start + size)
		}
		encoded, _ := json.Marshal(map[string]any{"metadata": metadata, "items": items})
		return status, headers, encoded
	default:
		// okta: ?limit=N&after=T answers an array and a Link header.
		start, size := positive(query.Get("after"), 0), positive(query.Get("limit"), 200)
		items := slice(route.Items, start, size)
		if start+size < len(route.Items) {
			next := url.Values{}
			for name, values := range query {
				next[name] = values
			}
			next.Set("after", strconv.Itoa(start+size))
			headers.Set("Link", "<https://"+host+path+"?"+next.Encode()+`>; rel="next"`)
		}
		encoded, _ := json.Marshal(items)
		return status, headers, encoded
	}
}

func positive(text string, fallback int) int {
	value, err := strconv.Atoi(text)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func slice(items []json.RawMessage, start, size int) []json.RawMessage {
	if start > len(items) {
		start = len(items)
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	page := items[start:end]
	if page == nil {
		page = []json.RawMessage{}
	}
	return page
}

// RoundTrip answers the collector's request from the route table.
func (transport *replay) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, errors.New("demo replay: the collector must use https")
	}
	var body []byte
	if request.Body != nil {
		read, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		_ = request.Body.Close()
		if err != nil {
			return nil, err
		}
		body = read
	}
	status, headers, document := transport.answer(request.Method, request.URL.Hostname(), request.URL.Path, request.URL.Query(), body)
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: headers, Body: io.NopCloser(bytes.NewReader(document)), ContentLength: int64(len(document)), Request: request,
	}, nil
}
