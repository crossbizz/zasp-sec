package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type sdkContractTransport struct {
	mode       string
	methods    []string
	secretEcho bool
}

func (tr *sdkContractTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(req.Body, 65537))
	}
	operation := req.Header.Get("X-Amz-Target")
	if operation == "" {
		operation = req.Method + " " + req.URL.Host + req.URL.Path + "?" + req.URL.RawQuery
		if strings.Contains(string(body), "GetCallerIdentity") {
			operation = "STS.GetCallerIdentity"
		}
	}
	tr.methods = append(tr.methods, operation)
	if tr.mode == "unreachable" {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("DO_NOT_REFLECT_PROVIDER_VALUE")}
	}
	status := 200
	content := "application/xml"
	answer := ""
	switch {
	case operation == "STS.GetCallerIdentity":
		arn := "arn:aws:sts::123456789012:assumed-role/zasp-preflight-inspector/check"
		if tr.mode == "wrong-role" {
			arn = "arn:aws:sts::123456789012:assumed-role/foreign/check"
		}
		answer = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>` + arn + `</Arn><UserId>fixture</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
	case req.Method == "HEAD":
		answer = ""
	case strings.Contains(req.URL.RawQuery, "versioning"):
		answer = `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`
	case strings.Contains(req.URL.RawQuery, "encryption"):
		answer = `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`
	case strings.HasSuffix(operation, "DescribeKey"):
		content = "application/x-amz-json-1.1"
		answer = `{"KeyMetadata":{"AWSAccountId":"123456789012","Arn":"arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111","KeyId":"11111111-1111-4111-8111-111111111111","Enabled":true,"KeyManager":"CUSTOMER","KeyState":"Enabled","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","Origin":"AWS_KMS"}}`
	case strings.HasSuffix(operation, "GetSecretValue"):
		content = "application/x-amz-json-1.1"
		answer = `{"ARN":"arn:aws:secretsmanager:us-west-2:123456789012:secret:zasp/preflight-Abc123","Name":"zasp/preflight","VersionId":"11111111-1111-4111-8111-111111111111","VersionStages":["AWSCURRENT"],"SecretString":"DO_NOT_REFLECT_PROVIDER_VALUE"}`
	case strings.HasSuffix(operation, "GetQueueAttributes"):
		content = "application/x-amz-json-1.0"
		attrs := map[string]string{"QueueArn": "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs", "KmsMasterKeyId": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", "RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-dlq","maxReceiveCount":"5"}`}
		if strings.Contains(string(body), "agentsec-discovery-dlq") {
			attrs["QueueArn"] = "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-dlq"
			delete(attrs, "RedrivePolicy")
		}
		encoded, _ := json.Marshal(map[string]any{"Attributes": attrs})
		answer = string(encoded)
	default:
		status = 400
		answer = "unrecognized operation"
	}
	if tr.mode == "denied" {
		status = 403
		answer = `{"__type":"AccessDeniedException","message":"DO_NOT_REFLECT_PROVIDER_VALUE"}`
	}
	if tr.mode == "malformed" {
		answer = "{invalid"
	}
	if tr.mode == "wrong-key" && strings.Contains(req.URL.RawQuery, "encryption") {
		answer = strings.ReplaceAll(answer, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	}
	headers := http.Header{"Content-Type": []string{content}, "X-Amz-Bucket-Region": []string{"us-west-2"}}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(answer)), Request: req}, nil
}
func sdkContractConfig(t *testing.T) Config {
	t.Helper()
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-key-only")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret-only")
	key := "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"
	return Config{Schema: "agentsec-preflight-config-v1", Deployment: Deployment{AccountID: "123456789012", Region: "us-west-2", Partition: "aws", Profile: "canonical61-temporal78-authorization79-80-worker-v1", ReleaseVersion: "test"}, Scope: Scope{OrganizationID: "pid_00000000-0000-4000-8000-000000000001", WorkspaceID: "pid_00000000-0000-4000-8000-000000000002", EnvironmentID: "pid_00000000-0000-4000-8000-000000000003"}, Credentials: CredentialConfig{Kind: "operator_environment", ExpectedRoleARN: "arn:aws:iam::123456789012:role/zasp-preflight-inspector"}, Features: Features{AttackLab: "enabled", SensorMode: "required"}, AWS: AWSConfig{Buckets: []Bucket{{Name: "zasp-preflight-fixture", Owner: "123456789012", Region: "us-west-2", KMSKeyARN: key, Class: "evidence"}}, Secrets: []Secret{{LogicalName: "connector", ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:zasp/preflight-Abc123"}}, Queues: []Queue{{URL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", ARN: "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs", DeadLetterURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-dlq", DeadLetterARN: "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-dlq", MaximumReceiveCount: 5, KMSKeyARN: key, Purpose: "consumer"}}}}
}
func TestConnectedSDKReadOnlyContract(t *testing.T) {
	for _, mode := range []string{"observed", "wrong-role", "denied", "malformed", "wrong-key", "raw-only", "unreachable"} {
		t.Run(mode, func(t *testing.T) {
			config := sdkContractConfig(t)
			if mode == "raw-only" {
				config.AWS.Buckets[0].Class = "runtime-raw"
			}
			tr := &sdkContractTransport{mode: mode}
			r := &Runner{config: config, http: &http.Client{Transport: tr, Timeout: time.Second}}
			report, err := r.Run(context.Background(), "before-install")
			if err == nil || report.Ready || report.ProductionEndToEndVerified || len(report.Checks) != 8 {
				t.Fatal("incomplete original roster became readiness or missing bounded report")
			}
			seen := map[string]Observation{}
			for _, c := range report.Checks {
				for _, o := range c.Observations {
					seen[o.Name] = o
				}
			}
			if len(tr.methods) == 0 {
				t.Fatal("configured SDK probes did not reach actual provider protocol boundary")
			}
			for _, op := range tr.methods {
				if strings.Contains(op, "Put") || strings.Contains(op, "Delete") || strings.Contains(op, "SendMessage") || strings.Contains(op, "ReceiveMessage") || strings.Contains(op, "GenerateDataKey") {
					t.Fatal("preflight issued mutation")
				}
			}
			if mode == "observed" || mode == "raw-only" {
				for _, name := range []string{"iam_role", "s3_evidence", "kms", "secrets", "queues", "dead_letter_queue"} {
					if mode == "raw-only" && name == "s3_evidence" {
						if seen[name].Status != "unobserved" {
							t.Fatal("raw bucket metadata stood in for missing required evidence bucket")
						}
						continue
					}
					if seen[name].Status != "pass" || seen[name].ObservedAt == nil || seen[name].IdentityKind != "operator" {
						t.Fatal("actual read observation absent or falsely attributed to workload")
					}
				}
			} else {
				name := "iam_role"
				if mode == "wrong-key" {
					name = "s3_evidence"
				}
				if seen[name].Status == "pass" {
					t.Fatal("mismatched, denied or malformed provider fact accepted")
				}
			}

			if mode != "observed" && mode != "raw-only" {
				name, operation, outcome, target := "iam_role", "sts:GetCallerIdentity", "binding_mismatch", any(config.Credentials.ExpectedRoleARN)
				switch mode {
				case "denied":
					outcome = "denied"
				case "malformed":
					outcome = "malformed"
				case "unreachable":
					outcome = "unreachable"
				case "wrong-key":
					name = "s3_evidence"
					operation = "s3:GetBucketEncryption"
					target = config.AWS.Buckets[0]
				}
				failures := seen[name].Failures
				encoded, _ := json.Marshal(target)
				sum := sha256.Sum256(encoded)
				if len(failures) != 1 || failures[0].Operation != operation || failures[0].Hint == "" || failures[0].Outcome != outcome || failures[0].TargetDigest != hex.EncodeToString(sum[:]) {
					t.Fatal("failed SDK observation omitted exact action, single target or closed outcome")
				}
			}
			for _, name := range []string{"irsa_trust", "irsa_binding", "queue_permissions", "opensearch_reachable", "neon_pool_reachable", "stytch_session_reachable", "kernel_supported"} {
				if seen[name].Status != "unobserved" {
					t.Fatal("unexercised original requirement was promoted")
				}
			}
			raw, _ := json.Marshal(report)
			if strings.Contains(string(raw), "DO_NOT_REFLECT_PROVIDER_VALUE") || strings.Contains(string(raw), "fixture-secret-only") {
				t.Fatal("secret or dependency error reflected in report")
			}
		})
	}
}
