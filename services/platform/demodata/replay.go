package demodata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HTTPSource is what a provider's API answers, as a route table. The replay
// transport serves it in process: the collector's HTTP client is given the
// transport, so no request leaves the process and no port is opened.
type HTTPSource struct {
	// Platform is the SaaS platform key (provider "saas" only).
	Platform string `json:"platform,omitempty"`
	// Endpoint is the provider endpoint the collector is configured with:
	// the Kubernetes API server, the Okta issuer, the Salesforce instance or
	// the Dataverse environment.
	Endpoint string `json:"endpoint,omitempty"`
	// Azure says the Microsoft collection also reads Azure (AI Foundry).
	Azure  bool    `json:"azure,omitempty"`
	Routes []Route `json:"routes"`
}

// Route answers the requests of one method, host and path. A route with
// Query answers only requests whose query holds those values; the route with
// the most matching members wins.
type Route struct {
	Method string            `json:"method,omitempty"`
	Host   string            `json:"host,omitempty"`
	Path   string            `json:"path"`
	Query  map[string]string `json:"query,omitempty"`
	// QueryContains answers only requests whose query value holds the text
	// (a SOQL statement names its object, for instance).
	QueryContains map[string]string `json:"query_contains,omitempty"`
	// BodyContains selects among POST routes of one path (GraphQL queries).
	BodyContains string `json:"body_contains,omitempty"`
	Status       int    `json:"status,omitempty"`
	// Body is the response document. The text {{hours_ago:N}} inside it is
	// replaced by the time N hours before the collection (RFC 3339, UTC),
	// so that "last seen" values stay recent whenever the demo is seeded.
	Body json.RawMessage `json:"body,omitempty"`
	// Earlier is the response of the previous collection (see HasEarlier).
	Earlier json.RawMessage `json:"earlier,omitempty"`
	// Items is a list the route pages through the way the provider does;
	// Paging names the provider's convention ("github", "kubernetes",
	// "okta"). Envelope holds the other members of a page's document.
	Items    []json.RawMessage `json:"items,omitempty"`
	Paging   string            `json:"paging,omitempty"`
	ItemsKey string            `json:"items_key,omitempty"`
	Envelope map[string]any    `json:"envelope,omitempty"`
	// EarlierItems is Items at the previous collection.
	EarlierItems []json.RawMessage `json:"earlier_items,omitempty"`
	// File is the text of a repository file. The route answers with the
	// GitHub contents document of it (base64), so that a fixture can hold
	// the file as it reads.
	File *string `json:"file,omitempty"`
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
		case kinds(route.Paging != "", len(route.Body) != 0, route.File != nil) != 1:
			return fmt.Errorf("route %q: a route has a body, a paged list or a file", route.Path)
		case route.Paging == "" && (route.Items != nil || route.EarlierItems != nil || route.Envelope != nil || route.ItemsKey != ""):
			return fmt.Errorf("route %q: items, items_key and envelope belong to a paged route", route.Path)
		}
	}
	return nil
}

// trace, when a test sets it, receives every request the replay answers.
var trace func(string)

var hoursAgoPattern = regexp.MustCompile(`\{\{hours_ago:([0-9]{1,5})\}\}`)

// replay is the in-process stand-in for a provider's API.
type replay struct {
	routes  []Route
	earlier bool
	now     time.Time
	// misses collects the requests no route answered.
	misses map[string]bool
}

func newReplay(source *HTTPSource, target Target) *replay {
	return &replay{routes: source.Routes, earlier: target.Earlier, now: target.ObservedAt, misses: map[string]bool{}}
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
		for name, text := range route.QueryContains {
			if !strings.Contains(query.Get(name), text) {
				matched = false
				break
			}
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

func (transport *replay) dated(document []byte) []byte {
	return hoursAgoPattern.ReplaceAllFunc(document, func(match []byte) []byte {
		hours, _ := strconv.Atoi(string(hoursAgoPattern.FindSubmatch(match)[1]))
		return []byte(transport.now.Add(-time.Duration(hours) * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339))
	})
}

// answer returns the status, the headers and the body of one request.
func (transport *replay) answer(method, host, path string, query url.Values, body []byte) (int, http.Header, []byte) {
	headers := http.Header{"Content-Type": {"application/json"}}
	route, found := transport.match(method, host, path, query, body)
	if trace != nil {
		trace(fmt.Sprintf("%s %s%s?%s answered=%t", method, host, path, query.Encode(), found))
	}
	if !found {
		transport.misses[method+" "+host+path] = true
		return http.StatusNotFound, headers, []byte(`{"error":"not found","message":"not found"}`)
	}
	status := route.Status
	if status == 0 {
		status = http.StatusOK
	}
	items := route.Items
	if transport.earlier && route.EarlierItems != nil {
		items = route.EarlierItems
	}
	page := func(key string, listed []json.RawMessage, more map[string]any) []byte {
		document := map[string]any{}
		for name, value := range route.Envelope {
			document[name] = value
		}
		for name, value := range more {
			document[name] = value
		}
		document[key] = listed
		encoded, _ := json.Marshal(document)
		return transport.dated(encoded)
	}
	switch route.Paging {
	case "":
		document := route.Body
		if transport.earlier && route.Earlier != nil {
			document = route.Earlier
		}
		if route.File != nil {
			// GitHub sends the content in base64 lines of sixty characters.
			encoded, wrapped := base64.StdEncoding.EncodeToString([]byte(*route.File)), strings.Builder{}
			for len(encoded) > 60 {
				wrapped.WriteString(encoded[:60] + "\n")
				encoded = encoded[60:]
			}
			wrapped.WriteString(encoded + "\n")
			name := path[strings.LastIndex(path, "/")+1:]
			document, _ = json.Marshal(map[string]any{"type": "file", "encoding": "base64", "size": len(*route.File), "name": name, "path": name, "sha": "0000000000000000000000000000000000000000", "content": wrapped.String()})
		}
		return status, headers, transport.dated(document)
	case "github":
		// ?page=N&per_page=M answers {"total_count":T,"<key>":[...]}.
		number, size := positive(query.Get("page"), 1), positive(query.Get("per_page"), 30)
		return status, headers, page(route.ItemsKey, slice(items, (number-1)*size, size), map[string]any{"total_count": len(items)})
	case "kubernetes":
		// ?limit=N&continue=T answers a list with metadata.continue.
		start, size := positive(query.Get("continue"), 0), positive(query.Get("limit"), 500)
		metadata := map[string]any{"continue": ""}
		if start+size < len(items) {
			metadata["continue"] = strconv.Itoa(start + size)
		}
		return status, headers, page("items", slice(items, start, size), map[string]any{"metadata": metadata})
	default:
		// okta: ?limit=N&after=T answers an array and a Link header.
		start, size := positive(query.Get("after"), 0), positive(query.Get("limit"), 200)
		if start+size < len(items) {
			// Okta's next link carries the cursor and the page size only.
			next := url.Values{"limit": {strconv.Itoa(size)}}
			next.Set("after", strconv.Itoa(start+size))
			headers.Set("Link", "<https://"+host+path+"?"+next.Encode()+`>; rel="next"`)
		}
		encoded, _ := json.Marshal(slice(items, start, size))
		return status, headers, transport.dated(encoded)
	}
}

func kinds(flags ...bool) int {
	count := 0
	for _, flag := range flags {
		if flag {
			count++
		}
	}
	return count
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
	return append([]json.RawMessage{}, items[start:end]...)
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
