package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const browserSessionCookie = "__Host-zasp_session"

var (
	ErrInvalidProductSecurity = errors.New("invalid product security configuration")
	ErrAuthenticationRequired = errors.New("authentication required")
)

type CredentialKind uint8

const (
	CredentialBrowserSession CredentialKind = iota + 1
	CredentialBearerToken
)

type Credential struct {
	Kind  CredentialKind
	Value string
}

type RequestIdentity struct {
	PrincipalID        domain.ProductID
	Scope              domain.Scope
	Permissions        []string
	CSRFToken          string
	CredentialKind     CredentialKind
	FreshAuthenticated bool
}

type Authenticator func(context.Context, Credential) (RequestIdentity, error)

type ProductSecurity struct {
	PublicOrigin          string
	MaximumBodyBytes      int64
	Authenticate          Authenticator
	GenerateCorrelationID func() string
}

type identityContextKey struct{}
type correlationContextKey struct{}
type browserSecurityContextKey struct{}
type browserSecurityContext struct{ publicOrigin string }

func NewProductMiddleware(security ProductSecurity, next http.Handler) (http.Handler, error) {
	if next == nil || security.Authenticate == nil || security.GenerateCorrelationID == nil || security.MaximumBodyBytes < 1 {
		return nil, ErrInvalidProductSecurity
	}
	origin, err := url.Parse(security.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, ErrInvalidProductSecurity
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		correlationID := security.GenerateCorrelationID()
		if _, err := domain.ParseProductID(correlationID); err != nil {
			writeProductError(writer, http.StatusInternalServerError, "operation_rejected", "Operation rejected", fallbackCorrelationID)
			return
		}
		writer.Header().Set("X-Correlation-ID", correlationID)
		request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, correlationID))
		request.Header.Del("X-Zasp-Organization-ID")
		request.Header.Del("X-Zasp-Principal-ID")

		defer func() {
			if recover() != nil {
				writeProductError(writer, http.StatusInternalServerError, "operation_rejected", "Operation rejected", correlationID)
			}
		}()

		if err := validateBody(request, security.MaximumBodyBytes); err != nil {
			if errors.Is(err, errUnsupportedMediaType) {
				writeProductError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content type rejected", correlationID)
			} else {
				writeProductError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large", correlationID)
			}
			return
		}

		if request.URL.Path == "/api/v1/session/start" && request.Method == http.MethodGet {
			next.ServeHTTP(writer, request)
			return
		}
		if request.URL.Path == "/api/v1/session/callback" && request.Method == http.MethodPost {
			if request.Header.Get("Origin") != security.PublicOrigin {
				writeProductError(writer, http.StatusForbidden, "request_forbidden", "Request forbidden", correlationID)
				return
			}
			next.ServeHTTP(writer, request)
			return
		}

		credential, browser, valid := requestCredential(request)
		if !valid {
			writeProductError(writer, http.StatusUnauthorized, "authentication_required", "Authentication required", correlationID)
			return
		}
		identity, err := security.Authenticate(request.Context(), credential)
		if err != nil || !validRequestIdentity(identity, browser) {
			writeProductError(writer, http.StatusUnauthorized, "authentication_required", "Authentication required", correlationID)
			return
		}
		identity.CredentialKind = credential.Kind
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: security.PublicOrigin}))
		next.ServeHTTP(writer, request)
	}), nil
}

func IdentityFromRequest(request *http.Request) (RequestIdentity, bool) {
	if request == nil {
		return RequestIdentity{}, false
	}
	identity, ok := request.Context().Value(identityContextKey{}).(RequestIdentity)
	return identity, ok && validRequestIdentity(identity, false)
}

func correlationIDFromContext(ctx context.Context) string {
	if ctx != nil {
		if value, ok := ctx.Value(correlationContextKey{}).(string); ok {
			if _, err := domain.ParseProductID(value); err == nil {
				return value
			}
		}
	}
	return fallbackCorrelationID
}

func requestCredential(request *http.Request) (Credential, bool, bool) {
	cookie, cookieErr := request.Cookie(browserSessionCookie)
	authorization := request.Header.Get("Authorization")
	hasCookie := cookieErr == nil && cookie.Value != ""
	hasBearer := strings.HasPrefix(authorization, "Bearer ") && len(authorization) > len("Bearer ")
	if hasCookie == hasBearer {
		return Credential{}, false, false
	}
	if hasCookie {
		return Credential{Kind: CredentialBrowserSession, Value: cookie.Value}, true, true
	}
	return Credential{Kind: CredentialBearerToken, Value: strings.TrimPrefix(authorization, "Bearer ")}, false, true
}

func validRequestIdentity(identity RequestIdentity, requireCSRF bool) bool {
	if identity.PrincipalID.IsZero() || identity.Scope.Validate() != nil || !validPermissions(identity.Permissions) {
		return false
	}
	if requireCSRF && (len(identity.CSRFToken) < 32 || len(identity.CSRFToken) > 256) {
		return false
	}
	return true
}

func validPermissions(values []string) bool {
	if len(values) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		switch value {
		case "view", "manage_findings", "manage_workflows":
		default:
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

var errUnsupportedMediaType = errors.New("unsupported media type")
var errBodyTooLarge = errors.New("body too large")

func validateBody(request *http.Request, maximum int64) error {
	if request.Body == nil || request.ContentLength == 0 {
		return nil
	}
	if request.Header.Get("Content-Type") != "application/json" {
		return errUnsupportedMediaType
	}
	limited := io.LimitReader(request.Body, maximum+1)
	payload, err := io.ReadAll(limited)
	if err != nil || int64(len(payload)) > maximum {
		return errBodyTooLarge
	}
	request.Body = io.NopCloser(bytes.NewReader(payload))
	request.ContentLength = int64(len(payload))
	return nil
}

func writeProductError(writer http.ResponseWriter, status int, code string, message string, correlationID string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code": code, "message": message, "correlation_id": correlationID, "retryable": false,
	})
}
