package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

const projectedServiceAccountTokenPath = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"

var (
	productionRegionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
	productionAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	productionBucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	productionRolePattern    = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	productionKMSPattern     = regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type productionIngestConfig struct {
	DatabaseURL         string
	Region              string
	RoleARN             string
	TokenFile           string
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	MaximumBytes        int64
	OperationTimeout    time.Duration
	ShutdownTimeout     time.Duration
}

type productionIngestRepository interface {
	runtimeevent.ProductionIngestRepository
	sensor.PrivateHeartbeatAuthority
}

func newProductionIngestRouter(repository productionIngestRepository, artifacts runtimeevent.RawArtifactAuthority, maximumBytes int64, clock func() time.Time) (http.Handler, error) {
	if invalidRuntimeValue(repository) || invalidRuntimeValue(artifacts) {
		return nil, errRuntimeUnavailable
	}
	ingest, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: maximumBytes, Clock: clock})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	heartbeat, err := sensor.NewPrivateHeartbeatHandler(repository)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	mux := http.NewServeMux()
	mux.Handle(sensor.PrivateHeartbeatPath, heartbeat)
	mux.Handle("/internal/v1/runtime/events", ingest)
	mux.Handle("/", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		http.Error(response, "not found", http.StatusNotFound)
	}))
	return mux, nil
}

func loadProductionIngestConfig(getenv func(string) string) (productionIngestConfig, error) {
	if getenv == nil {
		return productionIngestConfig{}, errRuntimeUnavailable
	}
	maximumBytes, maximumBytesErr := strconv.ParseInt(getenv("ZASP_EVENT_INGEST_MAX_BYTES"), 10, 64)
	operationTimeout, operationTimeoutErr := time.ParseDuration(getenv("ZASP_EVENT_INGEST_OPERATION_TIMEOUT"))
	shutdownTimeout, shutdownTimeoutErr := time.ParseDuration(getenv("ZASP_EVENT_INGEST_SHUTDOWN_TIMEOUT"))
	config := productionIngestConfig{
		DatabaseURL:         getenv("ZASP_DATABASE_URL"),
		Region:              getenv("ZASP_AWS_REGION"),
		RoleARN:             getenv("ZASP_EVENT_INGEST_ROLE_ARN"),
		TokenFile:           getenv("ZASP_EVENT_INGEST_WEB_IDENTITY_TOKEN_FILE"),
		Bucket:              getenv("ZASP_RUNTIME_RAW_BUCKET"),
		ExpectedBucketOwner: getenv("ZASP_RUNTIME_RAW_BUCKET_OWNER"),
		KMSKeyARN:           getenv("ZASP_RUNTIME_RAW_KMS_KEY_ARN"),
		MaximumBytes:        maximumBytes,
		OperationTimeout:    operationTimeout,
		ShutdownTimeout:     shutdownTimeout,
	}
	if maximumBytesErr != nil || operationTimeoutErr != nil || shutdownTimeoutErr != nil || !validProductionIngestConfig(config) {
		return productionIngestConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validProductionIngestConfig(config productionIngestConfig) bool {
	database, databaseErr := url.Parse(config.DatabaseURL)
	role := productionRolePattern.FindStringSubmatch(config.RoleARN)
	kms := productionKMSPattern.FindStringSubmatch(config.KMSKeyARN)
	return databaseErr == nil && database.String() == config.DatabaseURL && (database.Scheme == "postgres" || database.Scheme == "postgresql") && database.User != nil && database.Hostname() != "" && database.Path != "" && database.Fragment == "" && database.RawQuery == "sslmode=verify-full" &&
		productionRegionPattern.MatchString(config.Region) && len(role) == 2 && len(kms) == 3 && role[1] == config.ExpectedBucketOwner && kms[1] == config.Region && kms[2] == config.ExpectedBucketOwner &&
		config.TokenFile == projectedServiceAccountTokenPath && productionBucketPattern.MatchString(config.Bucket) && productionAccountPattern.MatchString(config.ExpectedBucketOwner) &&
		config.MaximumBytes >= 1<<20 && config.MaximumBytes <= 64<<20 && config.OperationTimeout >= time.Second && config.OperationTimeout <= 30*time.Second && config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= time.Minute
}

type readinessGatedIngestHandler struct {
	ready func(context.Context) error
	next  http.Handler
}

func (handler readinessGatedIngestHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler.ready == nil || invalidRuntimeValue(handler.next) || invalidRuntimeValue(request) || invalidRuntimeValue(request.Context()) || handler.ready(request.Context()) != nil {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(response).Encode(map[string]string{"error": "service_unavailable"})
		return
	}
	handler.next.ServeHTTP(response, request)
}
