package apiserver

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Diagnostics report only fixed operation labels, status codes and error types.
// They never log proof envelopes, tuple bodies, credentials or query arguments.
type discoveryProjectionSQLDiagnostic struct{ t *testing.T }
type discoveryProjectionSQLLabel struct{}

func (d discoveryProjectionSQLDiagnostic) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	label := "other"
	switch data.SQL {
	case `SELECT zasp_authorization79.snapshot($1)`:
		label = "snapshot"
	case `SELECT zasp_authorization79.stage($1,$2,$3,$4,$5,$6::jsonb)`:
		label = "stage"
	case `SELECT zasp_authorization79.ack($1,$2,$3,$4,$5,$6::jsonb)`:
		label = "ack"
	case `SELECT zasp_authorization79.blocked($1,$2)`:
		label = "blocked"
	}
	return context.WithValue(ctx, discoveryProjectionSQLLabel{}, label)
}

func (d discoveryProjectionSQLDiagnostic) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err == nil {
		return
	}
	code := "non-postgres"
	var native *pgconn.PgError
	if errors.As(data.Err, &native) {
		code = native.Code
	}
	d.t.Logf("discovery projection SQL operation=%v code=%s error_type=%T context_expired=%t", ctx.Value(discoveryProjectionSQLLabel{}), code, data.Err, ctx.Err() != nil)
}

type discoveryProjectionHTTPDiagnostic struct {
	t    *testing.T
	next http.RoundTripper
}

func (d discoveryProjectionHTTPDiagnostic) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := d.next.RoundTrip(r)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	if err != nil || status < 200 || status >= 300 {
		d.t.Logf("discovery projection HTTP status=%d error_type=%T context_expired=%t", status, err, r.Context().Err() != nil)
	}
	return response, err
}
