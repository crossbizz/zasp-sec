package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// WorkloadIdentityProfile binds the issuer and subject to a single customer
// role or workload identity provider. Its canonical digest survives JWT rotation.
type WorkloadIdentityProfile struct {
	Issuer           string `json:"issuer"`
	Subject          string `json:"subject"`
	TokenAudience    string `json:"token_audience"`
	STSPrivateIP     string `json:"sts_private_ip"`
	RoleARN          string `json:"role_arn,omitempty"`
	WorkloadProvider string `json:"workload_provider,omitempty"`
}

func (p WorkloadIdentityProfile) CredentialDigest() string {
	encoded, _ := json.Marshal(p)
	return digest(string(encoded))
}

var (
	modelRoleARN           = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]{1,128})$`)
	googleWorkloadProvider = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
)

type federatedSession struct {
	aws     aws.Credentials
	bearer  string
	expires time.Time
}

type privateFederation struct {
	profile                     WorkloadIdentityProfile
	region, tokenFile, endpoint string
	client                      *http.Client
	mu                          sync.Mutex
	sourceHash                  string
	cached                      federatedSession
}

func newPrivateFederation(mode, region, tokenFile string, profile WorkloadIdentityProfile) (*privateFederation, error) {
	issuer, err := url.Parse(profile.Issuer)
	if err != nil || issuer.Scheme != "https" || !hostName.MatchString(issuer.Hostname()) || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || profile.Subject == "" || len(profile.Subject) > 256 || profile.TokenAudience == "" || len(profile.TokenAudience) > 512 || tokenFile == "" {
		return nil, ErrInvalidConfiguration
	}
	var host, path string
	switch mode {
	case ModeBedrock:
		if awsResidency(region) == "" || !modelRoleARN.MatchString(profile.RoleARN) || profile.WorkloadProvider != "" || profile.TokenAudience != "sts.amazonaws.com" {
			return nil, ErrInvalidConfiguration
		}
		host, path = "sts."+region+".amazonaws.com", "/"
	case ModeVertex:
		if vertexResidency(region) == "" || !googleWorkloadProvider.MatchString(profile.WorkloadProvider) || profile.RoleARN != "" {
			return nil, ErrInvalidConfiguration
		}
		host, path = "sts."+region+".rep.googleapis.com", "/v1/token"
	default:
		return nil, ErrInvalidConfiguration
	}
	ip, err := netip.ParseAddr(profile.STSPrivateIP)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	endpoint := "https://" + host + path
	client, err := pinnedPrivateClient(PrivateEndpoint{URL: endpoint, IP: ip}, path)
	if err != nil {
		return nil, err
	}
	return &privateFederation{profile: profile, region: region, tokenFile: tokenFile, endpoint: endpoint, client: client}, nil
}

// Check the expected identity before transmission. The STS provider verifies
// JWT signatures and audience and enforces the configured trust relationship.
func (f *privateFederation) source(token string, now time.Time) (time.Time, bool) {
	pieces := strings.Split(token, ".")
	if len(pieces) != 3 || pieces[0] == "" || pieces[2] == "" {
		return time.Time{}, false
	}
	data, err := base64.RawURLEncoding.DecodeString(pieces[1])
	var claims struct {
		Iss, Sub string
		Aud      json.RawMessage
		Exp, Nbf int64
	}
	if err != nil || json.Unmarshal(data, &claims) != nil || claims.Iss != f.profile.Issuer || claims.Sub != f.profile.Subject || claims.Nbf > now.Unix() || claims.Exp <= now.Add(time.Minute).Unix() || claims.Exp > now.Add(24*time.Hour).Unix() {
		return time.Time{}, false
	}
	var audience string
	var audiences []string
	if json.Unmarshal(claims.Aud, &audience) != nil && json.Unmarshal(claims.Aud, &audiences) != nil {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), audience == f.profile.TokenAudience || slices.Contains(audiences, f.profile.TokenAudience)
}

func (f *privateFederation) sign(req *http.Request, body []byte) error {
	token, ok := privateModelToken(f.tokenFile)
	now := time.Now()
	expires, match := f.source(token, now)
	if !ok || !match {
		return ErrGeneration
	}
	key := digest(token)
	f.mu.Lock()
	if err := req.Context().Err(); err != nil {
		f.mu.Unlock()
		return ErrGeneration
	}
	if key != f.sourceHash || !f.cached.expires.After(now.Add(time.Minute)) {
		session, err := f.exchange(req.Context(), token, now)
		if err != nil {
			f.mu.Unlock()
			return ErrGeneration
		}
		if session.expires.After(expires) {
			session.expires = expires
		}
		f.sourceHash, f.cached = key, session
	}
	session := f.cached
	f.mu.Unlock()
	if session.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+session.bearer)
		return nil
	}
	hash := sha256.Sum256(body)
	return v4.NewSigner().SignHTTP(req.Context(), session.aws, req, hex.EncodeToString(hash[:]), "bedrock", f.region, now)
}

func (f *privateFederation) exchange(ctx context.Context, token string, now time.Time) (federatedSession, error) {
	var session federatedSession
	params := url.Values{}
	if f.profile.RoleARN != "" {
		params.Set("Action", "AssumeRoleWithWebIdentity")
		params.Set("Version", "2011-06-15")
		params.Set("DurationSeconds", "900")
		params.Set("RoleSessionName", "zasp-model")
		params.Set("RoleArn", f.profile.RoleARN)
		params.Set("WebIdentityToken", token)
	} else {
		params.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		params.Set("audience", f.profile.WorkloadProvider)
		params.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
		params.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
		params.Set("subject_token", token)
		params.Set("scope", "https://www.googleapis.com/auth/cloud-platform")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return session, ErrGeneration
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return session, ErrGeneration
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return session, ErrGeneration
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(data) > 16384 {
		return session, ErrGeneration
	}
	if f.profile.RoleARN != "" {
		var reply struct {
			Result struct {
				Role        struct{ Arn string } `xml:"AssumedRoleUser"`
				Credentials struct {
					AccessKeyId, SecretAccessKey, SessionToken string
					Expiration                                 time.Time
				}
			} `xml:"AssumeRoleWithWebIdentityResult"`
		}
		if xml.Unmarshal(data, &reply) != nil {
			return session, ErrGeneration
		}
		creds := reply.Result.Credentials
		parts := modelRoleARN.FindStringSubmatch(f.profile.RoleARN)
		role := parts[2][strings.LastIndex(parts[2], "/")+1:]
		if reply.Result.Role.Arn != "arn:aws:sts::"+parts[1]+":assumed-role/"+role+"/zasp-model" || creds.AccessKeyId == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" || !creds.Expiration.After(now.Add(time.Minute)) || creds.Expiration.After(now.Add(16*time.Minute)) {
			return session, ErrGeneration
		}
		session.aws = aws.Credentials{AccessKeyID: creds.AccessKeyId, SecretAccessKey: creds.SecretAccessKey, SessionToken: creds.SessionToken, CanExpire: true, Expires: creds.Expiration}
		session.expires = creds.Expiration
	} else {
		var reply struct {
			Token   string `json:"access_token"`
			Type    string `json:"token_type"`
			Issued  string `json:"issued_token_type"`
			Expires int    `json:"expires_in"`
		}
		if json.Unmarshal(data, &reply) != nil || !strings.EqualFold(reply.Type, "bearer") || reply.Issued != "urn:ietf:params:oauth:token-type:access_token" || reply.Expires < 61 || reply.Expires > 3600 || !validPrivateCredential("secret_ref_planner/workload", reply.Token, 1) {
			return session, ErrGeneration
		}
		session.bearer, session.expires = reply.Token, now.Add(time.Duration(reply.Expires)*time.Second)
	}
	return session, nil
}
