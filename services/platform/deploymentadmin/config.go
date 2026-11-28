// Package deploymentadmin serves installation operators on an authority separate
// from the organizations and users in the product database.
package deploymentadmin

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	errConfig  = errors.New("invalid deployment administrator configuration")
	identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
	hostName   = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
	account    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@+/-]{0,127}$`)
	kubeRef    = regexp.MustCompile(`^kubernetes://[a-z0-9]([a-z0-9-]*[a-z0-9])?/[a-z0-9]([a-z0-9.-]*[a-z0-9])?#[a-zA-Z0-9._-]+$`)
	vaultRef   = regexp.MustCompile(`^vault://[a-zA-Z0-9_-]+(/[a-zA-Z0-9_.-]+)+#[a-zA-Z0-9_.-]+$`)
	awsRef     = regexp.MustCompile(`^arn:aws(-us-gov|-cn)?:secretsmanager:[a-z]{2}(-[a-z0-9]+)+-[0-9]+:[0-9]{12}:secret:[a-zA-Z0-9/_+=.@-]+$`)
)

type Pointer struct {
	APIURL        string `json:"api_url"`
	DashboardURL  string `json:"dashboard_url"`
	LoginHint     string `json:"login_hint"`
	CredentialRef string `json:"credential_ref"`
}
type Pointers struct {
	Nango      Pointer `json:"nango"`
	OpenSearch Pointer `json:"opensearch"`
}
type Settings struct {
	DeploymentID string `json:"deployment_id"`
	Version      int64  `json:"version"`
	Pointers
}
type Config struct {
	id, origin, dsn string
	passwordHash    [32]byte
	initial         Pointers
}

func accessURL(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 2048 || strings.ContainsAny(value, "?#\\\r\n\t ") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || strings.Contains(u.Host, "%") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if ip == nil && (!hostName.MatchString(host) || strings.Contains(host, "..")) {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".svc") || ip != nil && (ip.IsPrivate() || ip.IsLoopback()))
}
func (p Pointer) valid() bool {
	ref := p.CredentialRef
	return accessURL(p.APIURL) && accessURL(p.DashboardURL) && (p.LoginHint == "" || account.MatchString(p.LoginHint)) && len(ref) <= 512 && (ref == "" || kubeRef.MatchString(ref) || vaultRef.MatchString(ref) || awsRef.MatchString(ref))
}

// Configured paths point to private, read-only Secret projections mounted only
// in the API process. Kubernetes uses an atomically replaced symlink and fsGroup.
func secretFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errConfig
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errConfig
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 || info.Size() > 8192 {
		return "", errConfig
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		return "", errConfig
	}
	value := strings.TrimSuffix(string(data), "\n")
	clear(data)
	if value == "" || strings.ContainsAny(value, "\n\r\x00") {
		return "", errConfig
	}
	return value, nil
}

func Load(getenv func(string) string) (*Config, error) {
	id := getenv("ZASP_DEPLOYMENT_ADMIN_ID")
	passFile := getenv("ZASP_DEPLOYMENT_ADMIN_PASSWORD_FILE")
	dsnFile := getenv("ZASP_DEPLOYMENT_ADMIN_DSN_FILE")
	dsn := getenv("ZASP_DEPLOYMENT_ADMIN_DSN")
	seed := getenv("ZASP_DEPLOYMENT_ADMIN_INITIAL_POINTERS")
	if id == "" && passFile == "" && dsn == "" && dsnFile == "" && seed == "" {
		return nil, nil
	}
	origin := getenv("ZASP_PUBLIC_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || origin != "https://"+u.Host || u.User != nil || !identifier.MatchString(id) || (dsn == "") == (dsnFile == "") {
		return nil, errConfig
	}
	password, err := secretFile(passFile)
	if err != nil || len(password) < 32 || len(password) > 256 || strings.TrimSpace(password) != password {
		return nil, errConfig
	}
	if dsnFile != "" {
		dsn, err = secretFile(dsnFile)
		if err != nil {
			return nil, errConfig
		}
	}
	db, err := url.Parse(dsn)
	if err != nil || (db.Scheme != "postgres" && db.Scheme != "postgresql") || db.User == nil || db.User.Username() == "" || db.Host == "" || db.Path == "" || strings.ContainsAny(dsn, "\r\n\x00") {
		return nil, errConfig
	}
	ip := net.ParseIP(db.Hostname())
	local := ip != nil && ip.IsLoopback()
	query, err := url.ParseQuery(db.RawQuery)
	if err != nil || db.Fragment != "" || strings.ContainsAny(db.Host, ",%") {
		return nil, errConfig
	}
	for key, values := range query {
		if len(values) != 1 || (key != "sslmode" && key != "sslrootcert" && key != "connect_timeout") {
			return nil, errConfig
		}
	}
	if _, present := db.User.Password(); present && dsnFile == "" {
		return nil, errConfig
	}
	if !local && (dsnFile == "" || query.Get("sslmode") != "verify-full") {
		return nil, errConfig
	}
	config := &Config{id: id, origin: origin, dsn: dsn, passwordHash: sha256.Sum256([]byte(password))}
	if seed != "" {
		decoder := json.NewDecoder(strings.NewReader(seed))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&config.initial) != nil || decoder.Decode(new(any)) != io.EOF || !config.initial.Nango.valid() || !config.initial.OpenSearch.valid() {
			return nil, errConfig
		}
	}
	return config, nil
}
