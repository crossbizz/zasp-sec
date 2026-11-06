package preflight

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

type KubernetesCredentials struct {
	Kind      string `json:"kind"`
	TokenFile string `json:"token_file"`
}
type KubernetesAuthority struct {
	Endpoint    string                `json:"endpoint"`
	CAFile      string                `json:"ca_file"`
	ClusterUID  string                `json:"cluster_uid"`
	Credentials KubernetesCredentials `json:"credentials"`
}

func validKubernetesAuthority(k *KubernetesAuthority) bool {
	if k == nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(k.ClusterUID) || k.ClusterUID == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	u, e := url.Parse(k.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !filepath.IsAbs(k.CAFile) || !filepath.IsAbs(k.Credentials.TokenFile) || len(k.CAFile) > 4096 || len(k.Credentials.TokenFile) > 4096 {
		return false
	}
	switch k.Credentials.Kind {
	case "existing_service_account":
		return k.Credentials.TokenFile == "/var/run/secrets/kubernetes.io/serviceaccount/token" && k.CAFile == "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	case "explicit_bearer_file":
		return true
	}
	return false
}
func readKubernetesCA(k *KubernetesAuthority) ([]byte, error) {
	path := k.CAFile
	if k.Credentials.Kind == "existing_service_account" {
		root, e := os.OpenRoot(filepath.Dir(path))
		if e != nil {
			return nil, ErrRejected
		}
		defer root.Close()
		f, e := root.Open("ca.crt")
		if e != nil {
			return nil, ErrRejected
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 1<<20+1))
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&022 != 0 || before.Size() < 1 || before.Size() > 1<<20 {
		return nil, ErrRejected
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return nil, ErrRejected
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrRejected
	}
	defer f.Close()
	held, e := f.Stat()
	if e != nil || !os.SameFile(before, held) {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	after, ae := os.Lstat(path)
	if e != nil || ae != nil || !os.SameFile(before, after) || len(b) > 1<<20 {
		return nil, ErrRejected
	}
	return b, nil
}
func readKubernetesToken(k *KubernetesAuthority) ([]byte, error) {
	if k.Credentials.Kind == "explicit_bearer_file" {
		b, e := privateFile(k.Credentials.TokenFile, 16384)
		if e != nil || !validCredentialValue(string(b), 16, 16384) {
			clear(b)
			return nil, ErrRejected
		}
		return b, nil
	}
	root, e := os.OpenRoot("/var/run/secrets/kubernetes.io/serviceaccount")
	if e != nil {
		return nil, ErrRejected
	}
	defer root.Close()
	f, e := root.Open("token")
	if e != nil {
		return nil, ErrRejected
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&022 != 0 || info.Size() < 16 || info.Size() > 16384 {
		return nil, ErrRejected
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || !validCredentialValue(string(b), 16, 16384) {
		clear(b)
		return nil, ErrRejected
	}
	return b, nil
}
func (r *Runner) sensor(ctx context.Context, report *Report) {
	if r.config.Features.SensorMode == "disabled" {
		return
	}
	passed := false
	attempted := false
	code := "sensor_authority_or_selection_required"
	identity := "none"
	var target any = r.config.Sensor
	if r.config.Sensor != nil && r.config.Sensor.Validate() == nil && validKubernetesAuthority(r.config.Kubernetes) && r.config.Kubernetes.ClusterUID == r.config.Sensor.ClusterUID {
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		ca, e := readKubernetesCA(r.config.Kubernetes)
		if e == nil {
			reader, e := sensoradapter.NewCoverageHTTPReader(r.config.Kubernetes.Endpoint, ca, func(c context.Context) ([]byte, error) {
				if c.Err() != nil {
					return nil, ErrRejected
				}
				return readKubernetesToken(r.config.Kubernetes)
			}, *r.config.Sensor)
			if e == nil {
				defer reader.Close()
				attempted = true
				identity = "operator-kubernetes"
				if r.config.Kubernetes.Credentials.Kind == "existing_service_account" {
					identity = "workload-kubernetes"
				}
				result, e := sensoradapter.ObserveNodeCoverage(bounded, reader, *r.config.Sensor, time.Now().UTC(), 30*time.Second)
				passed = e == nil && result.Complete
				code = "selected_node_coverage_incomplete"
				if passed {
					code = "current_selected_node_reports"
				}
				target = struct {
					Selection       *sensoradapter.NodeCoverageSelection `json:"selection"`
					InventoryDigest string                               `json:"inventory_digest"`
				}{r.config.Sensor, result.TargetDigest}
			}
		}
	}
	for _, name := range []string{"kernel_supported", "btf_present", "tetragon_supported"} {
		if !attempted {
			dependencyCode(report, name, code)
			continue
		}
		r.record(report, name, passed, code, identity, target, attempted)
		if !passed && attempted {
			for i := range report.Checks {
				for j := range report.Checks[i].Observations {
					o := &report.Checks[i].Observations[j]
					if o.Name == name && len(o.Failures) < 32 {
						o.Failures = append(o.Failures, Failure{Operation: "kubernetes:ReadSelectedCoverage", Hint: "verify explicit Kubernetes authority, selected Node LIST, kube-system GET, exact named DaemonSet GETs, namespace Pod LISTs and sensor Lease LIST", TargetDigest: singleTargetDigest(target), Outcome: "unavailable"})
					}
				}
			}
		}
	}
}
