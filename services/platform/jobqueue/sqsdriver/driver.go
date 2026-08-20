package sqsdriver

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

const (
	maximumVisibilitySeconds = int32(43_200)
	maximumReceiveCount      = 1_000
)

var (
	ErrConfiguration = errors.New("sqs driver configuration rejected")
	ErrInput         = errors.New("sqs driver input rejected")
	queueHostPattern = regexp.MustCompile(`^sqs\.[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]\.amazonaws\.com(?:\.cn)?$`)
	accountPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	queueNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
)

type Config struct {
	QueueURL                 string
	ReceiveWaitSeconds       int32
	VisibilityTimeoutSeconds int32
	MaximumReceiveCount      int
}

type Client interface {
	SendMessageBatch(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error)
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
	ChangeMessageVisibilityBatch(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error)
}

type Driver struct {
	client      Client
	config      Config
	lifecycleMu sync.Mutex
	inflight    sync.WaitGroup
	draining    bool
}

func New(client Client, config Config) (*Driver, error) {
	if nilInterface(client) || !validQueueURL(config.QueueURL) || config.ReceiveWaitSeconds < 0 || config.ReceiveWaitSeconds > 20 || config.VisibilityTimeoutSeconds < 1 || config.VisibilityTimeoutSeconds > maximumVisibilitySeconds || config.MaximumReceiveCount < 1 || config.MaximumReceiveCount > maximumReceiveCount {
		return nil, ErrConfiguration
	}
	return &Driver{client: client, config: config}, nil
}

func validQueueURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.String() != raw || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || !queueHostPattern.MatchString(parsed.Hostname()) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	return len(parts) == 2 && accountPattern.MatchString(parts[0]) && queueNamePattern.MatchString(parts[1])
}

func nilInterface(value any) bool {
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
