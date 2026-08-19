package health

import (
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
)

const (
	LivenessPath  = "/healthz"
	ReadinessPath = "/readyz"
	VersionPath   = "/version"
	MetricsPath   = "/metrics"

	jsonContentType    = "application/json; charset=utf-8"
	metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
)

var ErrInvalidConfig = errors.New("invalid health handler configuration")

type Config struct {
	Service string
	Version string
	Metrics func() string
}

type Handler struct {
	service string
	version string
	ready   atomic.Bool
	metrics func() string
}

func New(config Config) (*Handler, error) {
	if !validService(config.Service) || !validVersion(config.Version) {
		return nil, ErrInvalidConfig
	}
	return &Handler{service: config.Service, version: config.Version, metrics: config.Metrics}, nil
}

func (handler *Handler) SetReady(ready bool) {
	handler.ready.Store(ready)
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setCommonHeaders(response)
	if request.URL.RawPath != "" || request.URL.RawQuery != "" {
		writeEmpty(response, http.StatusNotFound)
		return
	}

	path := request.URL.Path
	if path != LivenessPath && path != ReadinessPath && path != VersionPath && path != MetricsPath {
		writeEmpty(response, http.StatusNotFound)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		writeEmpty(response, http.StatusMethodNotAllowed)
		return
	}

	status, contentType, body := handler.response(path)
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(status)
	if request.Method == http.MethodGet {
		_, _ = response.Write([]byte(body))
	}
}

func (handler *Handler) response(path string) (int, string, string) {
	switch path {
	case LivenessPath:
		return http.StatusOK, jsonContentType, "{\"status\":\"live\"}\n"
	case ReadinessPath:
		if handler.ready.Load() {
			return http.StatusOK, jsonContentType, "{\"status\":\"ready\"}\n"
		}
		return http.StatusServiceUnavailable, jsonContentType, "{\"status\":\"not_ready\"}\n"
	case VersionPath:
		return http.StatusOK, jsonContentType,
			"{\"service\":\"" + handler.service + "\",\"version\":\"" + handler.version + "\"}\n"
	default:
		ready := "0"
		if handler.ready.Load() {
			ready = "1"
		}
		body :=
			"# HELP agentsec_up Process liveness.\n" +
				"# TYPE agentsec_up gauge\n" +
				"agentsec_up{service=\"" + handler.service + "\"} 1\n" +
				"# HELP agentsec_ready Service readiness.\n" +
				"# TYPE agentsec_ready gauge\n" +
				"agentsec_ready{service=\"" + handler.service + "\"} " + ready + "\n" +
				"# HELP agentsec_build_info Build information.\n" +
				"# TYPE agentsec_build_info gauge\n" +
				"agentsec_build_info{service=\"" + handler.service + "\",version=\"" + handler.version + "\"} 1\n"
		return http.StatusOK, metricsContentType, body + handler.additionalMetrics()
	}
}

func (handler *Handler) additionalMetrics() (value string) {
	if handler.metrics == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			value = ""
		}
	}()
	value = handler.metrics()
	if len(value) > 64*1024 || value != "" && value[len(value)-1] != '\n' {
		return ""
	}
	for _, character := range []byte(value) {
		if character != '\n' && (character < 0x20 || character > 0x7e) {
			return ""
		}
	}
	return value
}

func setCommonHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeEmpty(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func validService(service string) bool {
	if len(service) == 0 || len(service) > 64 || service[0] == '-' || service[len(service)-1] == '-' {
		return false
	}
	previousHyphen := false
	for index := 0; index < len(service); index++ {
		character := service[index]
		if character == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		if !asciiLowerAlphanumeric(character) {
			return false
		}
		previousHyphen = false
	}
	return true
}

func validVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for index := 0; index < len(version); index++ {
		character := version[index]
		if asciiAlphanumeric(character) {
			continue
		}
		if index == 0 || character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}

func asciiLowerAlphanumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func asciiAlphanumeric(character byte) bool {
	return asciiLowerAlphanumeric(character) || character >= 'A' && character <= 'Z'
}
