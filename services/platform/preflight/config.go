package preflight

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const MaximumConfigBytes = 65536
const supportedProfile = "canonical61-temporal78-authorization79-80-worker-v1"

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
var dnsPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)
var keyPattern = regexp.MustCompile(`^key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func DecodeConfig(payload []byte) (Config, error) {
	var config Config
	if len(payload) == 0 || len(payload) > MaximumConfigBytes || !uniqueJSON(payload) {
		return config, ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&config) != nil {
		return Config{}, ErrRejected
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !validConfig(config) {
		return Config{}, ErrRejected
	}
	return config, nil
}
func uniqueJSON(payload []byte) bool {
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var read func(int) bool
	read = func(depth int) bool {
		if depth > 16 {
			return false
		}
		t, e := d.Token()
		if e != nil || t == nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				v, e := d.Token()
				key, ok := v.(string)
				if e != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !read(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !read(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !read(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func validConfig(c Config) bool {
	if !validCoreDependencies(CoreDependencies{Neon: c.Neon, Stytch: c.Stytch}) {
		return false
	}
	if c.Kubernetes != nil && !validKubernetesAuthority(c.Kubernetes) {
		return false
	}
	if c.Sensor != nil && (c.Sensor.Validate() != nil || c.Kubernetes == nil || c.Kubernetes.ClusterUID != c.Sensor.ClusterUID) {
		return false
	}
	d := c.Deployment
	if c.Schema != "agentsec-preflight-config-v1" || (!accountPattern.MatchString(d.AccountID) || d.AccountID == "000000000000") || !regionPattern.MatchString(d.Region) || d.Profile != supportedProfile || !namePattern.MatchString(d.ReleaseVersion) || !partitionRegion(d.Partition, d.Region) {
		return false
	}
	for _, id := range []string{c.Scope.OrganizationID, c.Scope.WorkspaceID, c.Scope.EnvironmentID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return false
		}
	}
	if c.Scope.OrganizationID == c.Scope.WorkspaceID || c.Scope.OrganizationID == c.Scope.EnvironmentID || c.Scope.WorkspaceID == c.Scope.EnvironmentID {
		return false
	}
	cr := c.Credentials
	if !arnIn(c, cr.ExpectedRoleARN, "iam", "") || !strings.HasPrefix(strings.SplitN(cr.ExpectedRoleARN, ":", 6)[5], "role/") || !namePattern.MatchString(strings.TrimPrefix(strings.SplitN(cr.ExpectedRoleARN, ":", 6)[5], "role/")) {
		return false
	}
	switch cr.Kind {
	case "operator_file":
		if !filepath.IsAbs(cr.File) || len(cr.File) > 4096 || cr.TokenFile != "" || cr.Namespace != "" || cr.ServiceAccount != "" {
			return false
		}
	case "operator_environment":
		if cr.File != "" || cr.TokenFile != "" || cr.Namespace != "" || cr.ServiceAccount != "" {
			return false
		}
	case "workload_web_identity":
		if cr.File != "" || cr.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !dnsPattern.MatchString(cr.Namespace) || !dnsPattern.MatchString(cr.ServiceAccount) {
			return false
		}
	default:
		return false
	}
	if c.Features.AttackLab != "enabled" && c.Features.AttackLab != "disabled" || c.Features.SensorMode != "disabled" && c.Features.SensorMode != "optional" && c.Features.SensorMode != "required" {
		return false
	}
	if len(c.AWS.Buckets) > 16 || len(c.AWS.Secrets) > 32 || len(c.AWS.Queues) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, b := range c.AWS.Buckets {
		if len(b.Name) < 3 || !dnsPattern.MatchString(b.Name) || strings.Contains(b.Name, "..") || b.Owner != d.AccountID || b.Region != d.Region || !validKey(c, b.KMSKeyARN) || (b.Class != "evidence" && b.Class != "runtime-raw") || seen["bucket:"+b.Name] {
			return false
		}
		seen["bucket:"+b.Name] = true
	}
	for _, s := range c.AWS.Secrets {
		if !namePattern.MatchString(s.LogicalName) || !arnIn(c, s.ARN, "secretsmanager", d.Region) || !strings.HasPrefix(strings.SplitN(s.ARN, ":", 6)[5], "secret:") || !namePattern.MatchString(strings.TrimPrefix(strings.SplitN(s.ARN, ":", 6)[5], "secret:")) || seen["secret:"+s.ARN] {
			return false
		}
		seen["secret:"+s.ARN] = true
	}
	for _, q := range c.AWS.Queues {
		if !validQueue(c, q.URL, q.ARN) || !validQueue(c, q.DeadLetterURL, q.DeadLetterARN) || q.URL == q.DeadLetterURL || q.MaximumReceiveCount < 1 || q.MaximumReceiveCount > 1000 || !validKey(c, q.KMSKeyARN) || (q.Purpose != "producer" && q.Purpose != "consumer") || seen["queue:"+q.URL] {
			return false
		}
		seen["queue:"+q.URL] = true
	}
	return true
}
func partitionRegion(p, r string) bool {
	switch p {
	case "aws":
		return !strings.HasPrefix(r, "cn-") && !strings.HasPrefix(r, "us-gov-") && !strings.Contains(r, "-iso")
	case "aws-cn":
		return strings.HasPrefix(r, "cn-")
	case "aws-us-gov":
		return strings.HasPrefix(r, "us-gov-")
	}
	return false
}
func arnIn(c Config, value, service, region string) bool {
	p := strings.SplitN(value, ":", 6)
	return len(p) == 6 && p[0] == "arn" && p[1] == c.Deployment.Partition && p[2] == service && p[3] == region && p[4] == c.Deployment.AccountID && p[5] != "" && len(value) <= 512 && !strings.ContainsAny(value, " \t\r\n*?")
}
func validKey(c Config, value string) bool {
	return arnIn(c, value, "kms", c.Deployment.Region) && keyPattern.MatchString(strings.SplitN(value, ":", 6)[5])
}
func validQueue(c Config, raw, arn string) bool {
	if !arnIn(c, arn, "sqs", c.Deployment.Region) {
		return false
	}
	name := strings.SplitN(arn, ":", 6)[5]
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(name) {
		return false
	}
	suffix := "amazonaws.com"
	if c.Deployment.Partition == "aws-cn" {
		suffix += ".cn"
	}
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host == "sqs."+c.Deployment.Region+"."+suffix && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" && u.Path == "/"+c.Deployment.AccountID+"/"+name
}
