package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
	"golang.org/x/sys/unix"
)

var imageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ruleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)

type profile struct {
	Scanner, Image, Entry string
	Flags                 []string
}

func getProfile(scanner, image string) (profile, error) {
	if !imageID.MatchString(image) {
		return profile{}, errors.New("a local image ID pinned by SHA-256 is required")
	}
	switch scanner {
	case "cisco_skill_scanner":
		return profile{scanner, image, "skill-scanner", []string{"scan", "/review", "--format", "sarif"}}, nil
	case "nvidia_skillspector":
		return profile{scanner, image, "skillspector", []string{"scan", "/review", "--no-llm", "--format", "sarif"}}, nil
	default:
		return profile{}, errors.New("unsupported scanner")
	}
}
func (p profile) arguments(snapshot, name string) []string {
	args := []string{
		"--host", "unix:///var/run/docker.sock", "run", "--pull=never", "--rm", "--name", name,
		"--runtime=runsc", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
		"--read-only", "--user=65532:65532", "--pids-limit=64", "--cpus=1", "--memory=768m", "--memory-swap=768m",
		"--ulimit=nofile=256:256", "--ulimit=fsize=16777216:16777216", "--log-driver=none",
		"--workdir=/tmp", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
		"--env", "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "--env", "PYTHONSAFEPATH=1",
		"--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "XDG_CACHE_HOME=/tmp/cache",
		"--mount", "type=bind,src=" + snapshot + ",dst=/review,readonly", "--entrypoint", p.Entry, p.Image,
	}
	return append(args, p.Flags...)
}
func (p profile) digest() string {
	spec, _ := json.Marshal(p.arguments("/immutable-snapshot", "unique-name"))
	return fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte("zasp-offline-static-v1\x00"), spec...)))
}

// Snapshot verified bytes into an operator-owned directory. The v1 manifest
// hashes paths, lengths and bytes, so static copies can safely lose execute bits.
func snapshotSkill(folder, destination string) (string, error) {
	src, err := filepath.Abs(folder)
	if err != nil {
		return "", err
	}
	report := addons.Scan(src)
	if report.Status != "complete" || !imageID.MatchString(report.ManifestDigest) || len(report.Files) == 0 || len(report.Files) > 1024 {
		return "", errors.New("skill requires a complete bounded native manifest")
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err = os.Mkdir(destination, 0755); err != nil {
		return "", err
	}
	for _, file := range report.Files {
		if !filepath.IsLocal(file.Path) || file.Size < 0 || file.Size > 2<<20 {
			return "", errors.New("invalid native manifest file")
		}
		if err = copyManifestFile(root, destination, file); err != nil {
			return "", err
		}
	}
	if err := filepath.WalkDir(destination, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0444)
	}); err != nil {
		return "", err
	}
	rechecked := addons.Scan(destination)
	if rechecked.Status != "complete" || rechecked.ManifestDigest != report.ManifestDigest {
		return "", errors.New("snapshot differs from source manifest")
	}
	return rechecked.ManifestDigest, nil
}
func copyManifestFile(root *os.Root, destination string, file addons.File) error {
	f, err := root.OpenFile(file.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != file.Size {
		return errors.New("source file changed during review")
	}
	raw, err := io.ReadAll(io.LimitReader(f, file.Size+1))
	if err != nil || int64(len(raw)) != file.Size {
		return errors.New("source read incomplete")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != file.SHA256 {
		return errors.New("reviewed source changed")
	}
	path := filepath.Join(destination, file.Path)
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0444)
}

type reportSink struct {
	data     bytes.Buffer
	exceeded bool
	cancel   context.CancelFunc
}

func (s *reportSink) Write(raw []byte) (int, error) {
	if len(raw) > 2<<20-s.data.Len() {
		s.exceeded = true
		s.cancel()
		return 0, errors.New("scanner report exceeded size bound")
	}
	return s.data.Write(raw)
}
func runScanner(ctx context.Context, p profile, snapshot, name, config string) ([]byte, error) {
	path := ""
	for _, candidate := range []string{"/usr/bin/docker", "/usr/local/bin/docker"} {
		if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0022 == 0 {
			path = candidate
			break
		}
	}
	if path == "" {
		return nil, errors.New("local Docker client unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	// The compiled options never include a caller-selected binary, tool flag,
	// upstream registry, writable mount, host credential or skill entrypoint.
	cmd := exec.CommandContext(ctx, path, p.arguments(snapshot, name)...)
	cmd.Env = []string{"DOCKER_CONFIG=" + config, "LANG=C.UTF-8"}
	out := &reportSink{cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil || out.exceeded {
		cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
		defer stop()
		remove := exec.CommandContext(cleanup, path, "--host", "unix:///var/run/docker.sock", "rm", "--force", name)
		remove.Env = cmd.Env
		_ = remove.Run()
		return nil, errors.New("offline scan did not produce a complete report; check the pinned local image, runsc and resource limits")
	}
	return out.data.Bytes(), nil
}

type sarifRun struct {
	Results *[]struct {
		Rule string `json:"ruleId"`
	} `json:"results"`
	Invocations []struct {
		ExecutionSuccessful *bool `json:"executionSuccessful"`
	} `json:"invocations"`
	Tool struct {
		Driver struct {
			Name string `json:"name"`
		} `json:"driver"`
	} `json:"tool"`
}

func observations(scanner string, raw []byte) (map[string]int, []string, error) {
	var report struct {
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	if len(raw) > 2<<20 || json.Unmarshal(raw, &report) != nil || report.Version != "2.1.0" || len(report.Runs) != 1 || report.Runs[0].Results == nil || strings.TrimSpace(report.Runs[0].Tool.Driver.Name) == "" {
		return nil, nil, errors.New("invalid SARIF 2.1.0 report")
	}
	run := report.Runs[0]
	for _, inv := range run.Invocations {
		if inv.ExecutionSuccessful != nil && !*inv.ExecutionSuccessful {
			return nil, nil, errors.New("incomplete scanner invocation")
		}
	}
	if len(*run.Results) > 4096 {
		return nil, nil, errors.New("scanner report exceeds finding bound")
	}
	counts := map[string]int{}
	indicators := []string{}
	// Retain every bounded vendor rule count locally. Only reviewed mappings can
	// enter the public signed receipt's closed vocabulary.
	mapping := map[string]string{
		"cisco_skill_scanner/DATA_EXFIL_NETWORK_REQUESTS":   "network_reference",
		"cisco_skill_scanner/TOOL_ABUSE_UNDECLARED_NETWORK": "network_reference",
		"nvidia_skillspector/E1":                            "network_reference",
		"nvidia_skillspector/AR3":                           "instruction_override",
	}

	for _, r := range *run.Results {
		if !ruleID.MatchString(r.Rule) {
			return nil, nil, errors.New("invalid scanner rule ID")
		}
		counts[r.Rule]++
		if len(counts) > 256 {
			return nil, nil, errors.New("too many scanner rules")
		}
		if v := mapping[scanner+"/"+r.Rule]; v != "" && !slices.Contains(indicators, v) {
			indicators = append(indicators, v)
		}
	}
	slices.Sort(indicators)
	return counts, indicators, nil
}
