package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zasp-ai/zasp-sec/services/platform/awsclient"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
)

type auditExportCredentialTransport func(*http.Request) (*http.Response, error)

type auditExportSTSExchange func(context.Context) (*sts.AssumeRoleWithWebIdentityOutput, error)

func (exchange auditExportSTSExchange) AssumeRoleWithWebIdentity(ctx context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return exchange(ctx)
}

func TestAuditExportCredentialsRejectInvalidSTSResults(t *testing.T) {
	for _, scenario := range []string{"empty-access", "empty-secret", "empty-session", "missing-expiry", "expired", "cancelled", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(strings.Repeat("owned-token-", 8)), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exchange := auditExportSTSExchange(func(bounded context.Context) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				credentials := &ststypes.Credentials{AccessKeyId: aws.String("owned-access"), SecretAccessKey: aws.String("owned-secret"), SessionToken: aws.String("owned-session"), Expiration: aws.Time(time.Now().Add(time.Hour))}
				switch scenario {
				case "empty-access":
					credentials.AccessKeyId = aws.String("")
				case "empty-secret":
					credentials.SecretAccessKey = aws.String("")
				case "empty-session":
					credentials.SessionToken = aws.String("")
				case "missing-expiry":
					credentials.Expiration = nil
				case "expired":
					credentials.Expiration = aws.Time(time.Now().Add(-time.Minute))
				case "cancelled":
					cancel()
				case "deadline":
					<-bounded.Done()
				}
				return &sts.AssumeRoleWithWebIdentityOutput{Credentials: credentials}, nil
			})
			provider := &connectorWebIdentityProvider{client: exchange, roleARN: "arn:aws:iam::123456789012:role/zasp-audit-export-reader", tokenFile: path, timeout: 10 * time.Millisecond, sessionName: "zasp-api-audit-read"}
			credentials, err := provider.Retrieve(ctx)
			if err == nil || credentials != (aws.Credentials{}) {
				t.Fatal("invalid or cancelled STS exchange exposed credentials")
			}
		})
	}
}

func TestAuditExportCredentialsRejectInvalidTokenAuthority(t *testing.T) {
	for _, scenario := range []string{"relative", "unclean", "overlong", "nul", "newline", "short", "oversize", "whitespace", "malformed", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			token := strings.Repeat("owned-token-", 8)
			switch scenario {
			case "short":
				token = "short"
			case "oversize":
				token = strings.Repeat("a", 16385)
			case "whitespace":
				token += "\n"
			case "malformed":
				token += "!"
			}
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "relative":
				path = "token"
			case "unclean":
				path = filepath.Dir(path) + "/../token"
			case "overlong":
				path = "/" + strings.Repeat("a", 4096)
			case "nul":
				path += "\x00"
			case "newline":
				path += "\n"
			case "missing":
				path += "-missing"
			}
			calls := 0
			exchange := auditExportSTSExchange(func(context.Context) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				calls++
				return nil, errors.New("unexpected credential exchange")
			})
			provider := &connectorWebIdentityProvider{client: exchange, roleARN: "arn:aws:iam::123456789012:role/zasp-audit-export-reader", tokenFile: path, timeout: time.Second, sessionName: "zasp-api-audit-read"}
			credentials, err := provider.Retrieve(context.Background())
			if err != errRuntimeUnavailable || credentials != (aws.Credentials{}) || calls != 0 {
				t.Fatal("invalid token authority reached STS or exposed credentials")
			}
		})
	}
}

func (transport auditExportCredentialTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestAuditExportCredentialExchangeSignsPinnedS3Reads(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "http://invalid-ambient.example")
	t.Setenv("AWS_PROFILE", "invalid-ambient-profile")
	token := strings.Repeat("owned-token-", 8)
	path := filepath.Join(t.TempDir(), "projected-token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	role := "arn:aws:iam::123456789012:role/zasp-audit-export-reader"
	stsCalls, s3Calls := 0, 0
	expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	transport := auditExportCredentialTransport(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		body := "owned"
		switch request.URL.Host {
		case "sts.us-east-1.amazonaws.com":
			stsCalls++
			wire, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			form, err := url.ParseQuery(string(wire))
			deadline, bounded := request.Context().Deadline()
			if err != nil || form.Get("Action") != "AssumeRoleWithWebIdentity" || form.Get("RoleArn") != role || form.Get("RoleSessionName") != "zasp-api-audit-read" || form.Get("WebIdentityToken") != token || form.Get("DurationSeconds") != "900" || request.Header.Get("Authorization") != "" || !bounded || time.Until(deadline) > time.Second {
				return nil, errors.New("STS authority or deadline mismatch")
			}
			body = fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAOWNED000000000001</AccessKeyId><SecretAccessKey>owned-test-secret-not-real</SecretAccessKey><SessionToken>owned-session-token-not-real</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>owned-request</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`, expiry)
			header.Set("Content-Type", "text/xml")
		case "audit-exports-owned.s3.us-east-1.amazonaws.com":
			s3Calls++
			if request.Method != http.MethodGet || request.URL.Path != "/exports/owned" || request.URL.Query().Get("versionId") != "owned-version" || request.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || request.Header.Get("X-Amz-Security-Token") != "owned-session-token-not-real" || !strings.Contains(request.Header.Get("Authorization"), "Credential=ASIAOWNED000000000001/") || !strings.Contains(request.Header.Get("Authorization"), "/us-east-1/s3/aws4_request") {
				return nil, errors.New("S3 credential or immutable authority mismatch")
			}
			header.Set("X-Amz-Version-Id", "owned-version")
		default:
			return nil, errors.New("unexpected provider authority")
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
	})
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	base := aws.Config{Region: "us-east-1", HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &connectorWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: role, tokenFile: path, timeout: time.Second, sessionName: "zasp-api-audit-read"}
	cache := aws.NewCredentialsCache(provider)
	region, _ := platformconfig.ParseAWSRegion("us-east-1")
	clients, err := awsclient.New(awsclient.Options{Mode: awsclient.ModeProduction, Region: region, Credentials: cache, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()
	for range 2 {
		value, err := clients.S3().GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("audit-exports-owned"), Key: aws.String("exports/owned"), VersionId: aws.String("owned-version"), ExpectedBucketOwner: aws.String("123456789012")})
		if err != nil {
			t.Fatal("owned credential exchange/read failed", err)
		}
		body, readErr := io.ReadAll(value.Body)
		closeErr := value.Body.Close()
		if readErr != nil || closeErr != nil || string(body) != "owned" || aws.ToString(value.VersionId) != "owned-version" {
			t.Fatal("pinned read response changed")
		}
	}
	if stsCalls != 1 || s3Calls != 2 {
		t.Fatal("cache did not preserve explicit credentials", stsCalls, s3Calls)
	}
	// The owned private-provider path is not accepted by production configuration.
	config := fixtureAuditExportRuntimeConfig(t)
	config.AuditExports.TokenFile = path
	if entries, owner, err := newAuditExportStorageClients(config); err == nil || entries != nil || owner != nil {
		t.Fatal("production factory accepted a temporary token path")
	}
}
