package awsclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/zasp-ai/zasp-sec/services/platform/config"
)

const (
	endpointKey        = "AWS_ENDPOINT_URL"
	s3EndpointKey      = "AWS_ENDPOINT_URL_S3"
	localStackEndpoint = "http://localstack.zasp-local.svc.cluster.local:4566"
	localRegion        = "us-east-1"
)

var ErrConfiguration = errors.New("aws client configuration rejected")

type Mode string

const (
	ModeProduction Mode = "production"
	ModeLocal      Mode = "local"
	ModeCI         Mode = "ci"
)

type Options struct {
	Mode        Mode
	Region      config.AWSRegion
	Lookup      func(string) (string, bool)
	Credentials aws.CredentialsProvider
	HTTPClient  aws.HTTPClient
}

type Clients struct {
	sqsClient            *sqs.Client
	s3Client             *s3.Client
	kmsClient            *kms.Client
	secretsManagerClient *secretsmanager.Client
	openSearchClient     *opensearch.Client
	ownedTransport       *http.Transport
	closeOnce            sync.Once
}

func New(options Options) (*Clients, error) {
	region := options.Region.String()
	if region == "" {
		return nil, ErrConfiguration
	}

	base := aws.Config{
		Region: region,
		Retryer: func() aws.Retryer {
			return aws.NopRetryer{}
		},
	}
	var endpoint string
	var s3Endpoint string
	var ownedTransport *http.Transport

	switch options.Mode {
	case ModeProduction:
		if options.Lookup != nil || interfaceNil(options.Credentials) || interfaceNil(options.HTTPClient) {
			return nil, ErrConfiguration
		}
		base.Credentials = options.Credentials
		base.HTTPClient = options.HTTPClient
	case ModeLocal, ModeCI:
		if region != localRegion || options.Lookup == nil || options.Credentials != nil || options.HTTPClient != nil {
			return nil, ErrConfiguration
		}
		var endpointOK bool
		var s3EndpointOK bool
		endpoint, endpointOK = options.Lookup(endpointKey)
		s3Endpoint, s3EndpointOK = options.Lookup(s3EndpointKey)
		if !endpointOK || !s3EndpointOK || endpoint == "" || endpoint != s3Endpoint || !validEndpoint(options.Mode, endpoint) {
			return nil, ErrConfiguration
		}
		base.Credentials = aws.CredentialsProviderFunc(syntheticCredentials)
		ownedTransport = newOwnedTransport()
		base.HTTPClient = &http.Client{
			Transport: ownedTransport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	default:
		return nil, ErrConfiguration
	}

	clients := &Clients{ownedTransport: ownedTransport}
	clients.sqsClient = sqs.NewFromConfig(base, func(value *sqs.Options) {
		if endpoint != "" {
			value.BaseEndpoint = &endpoint
		}
	})
	clients.s3Client = s3.NewFromConfig(base, func(value *s3.Options) {
		if s3Endpoint != "" {
			value.BaseEndpoint = &s3Endpoint
			value.UsePathStyle = true
		}
	})
	clients.kmsClient = kms.NewFromConfig(base, func(value *kms.Options) {
		if endpoint != "" {
			value.BaseEndpoint = &endpoint
		}
	})
	clients.secretsManagerClient = secretsmanager.NewFromConfig(base, func(value *secretsmanager.Options) {
		if endpoint != "" {
			value.BaseEndpoint = &endpoint
		}
	})
	clients.openSearchClient = opensearch.NewFromConfig(base, func(value *opensearch.Options) {
		if endpoint != "" {
			value.BaseEndpoint = &endpoint
		}
	})
	return clients, nil
}

func syntheticCredentials(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		Source:          "zasp-localstack-client-factory",
	}, nil
}

func validEndpoint(mode Mode, value string) bool {
	if strings.Contains(value, "%") || strings.HasSuffix(value, "/") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.String() != value || parsed.Scheme != "http" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	if mode == ModeLocal {
		return value == localStackEndpoint
	}
	if parsed.Hostname() != "127.0.0.1" {
		return false
	}
	port := parsed.Port()
	if port == "" || port == "80" || port[0] == '0' || len(port) > 5 {
		return false
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return false
		}
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535 && net.ParseIP(parsed.Hostname()).String() == "127.0.0.1"
}

func newOwnedTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (clients *Clients) SQS() *sqs.Client {
	return clients.sqsClient
}

func (clients *Clients) S3() *s3.Client {
	return clients.s3Client
}

func (clients *Clients) KMS() *kms.Client {
	return clients.kmsClient
}

func (clients *Clients) SecretsManager() *secretsmanager.Client {
	return clients.secretsManagerClient
}

func (clients *Clients) OpenSearch() *opensearch.Client {
	return clients.openSearchClient
}

func (clients *Clients) Close() {
	if clients == nil {
		return
	}
	clients.closeOnce.Do(func() {
		if clients.ownedTransport != nil {
			clients.ownedTransport.CloseIdleConnections()
		}
	})
}
