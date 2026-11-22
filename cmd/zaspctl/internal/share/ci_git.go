package share

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

// Only immutable local Git objects are read. These commands don't check out
// files, run filters or hooks, dereference Git links, or fetch missing blobs.
func readGitObject(ctx context.Context, repository string, limit int, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"--no-replace-objects", "-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-C", repository}, args...)...)
	command.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(stream, int64(limit+1)))
	if err != nil || len(raw) > limit {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("oversized or unreadable Git object")
	}
	if err = command.Wait(); err != nil {
		return nil, err
	}
	return raw, nil
}
func scanCommit(ctx context.Context, repository, bundle, commit string) (addons.Report, error) {
	var empty addons.Report
	if !ciCommitID.MatchString(commit) || !fs.ValidPath(bundle) || bundle == "." || strings.ContainsAny(bundle, "\\:\n\r") || strings.Contains(bundle, ".git/") {
		return empty, errReport
	}
	exact, err := readGitObject(ctx, repository, 66, "rev-parse", "--verify", commit+"^{commit}")
	if err != nil || strings.TrimSpace(string(exact)) != commit {
		return empty, errReport
	}
	tree := commit + ":" + bundle
	kind, err := readGitObject(ctx, repository, 16, "cat-file", "-t", tree)
	if err != nil || string(kind) != "tree\n" {
		return empty, errReport
	}
	raw, err := readGitObject(ctx, repository, 512<<10, "ls-tree", "-rzl", tree)
	if err != nil {
		return empty, errReport
	}
	entries := bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0})
	if len(entries) > 1024 {
		return empty, errReport
	}
	dir, err := os.MkdirTemp("", "zasp-ci-manifest-*")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	var total int
	for _, entry := range entries {
		header, name, ok := strings.Cut(string(entry), "\t")
		if !ok || !fs.ValidPath(name) || strings.Contains(name, "\\") || strings.ContainsAny(name, ":\n\r") {
			return empty, errReport
		}
		for _, component := range strings.Split(name, "/") {
			if strings.EqualFold(component, ".git") {
				return empty, errReport
			}
		}
		parts := strings.Fields(header)
		if len(parts) != 4 || (parts[0] != "100644" && parts[0] != "100755") || parts[1] != "blob" || !ciCommitID.MatchString(parts[2]) {
			return empty, errReport
		}
		size, err := strconv.Atoi(parts[3])
		if err != nil || size < 0 || size > 2<<20 || total+size > 12<<20 {
			return empty, errReport
		}
		total += size
		contents, err := readGitObject(ctx, repository, size, "cat-file", "blob", parts[2])
		if err != nil || len(contents) != size {
			return empty, errReport
		}
		local, err := filepath.Localize(name)
		if err != nil {
			return empty, err
		}
		if err = root.MkdirAll(filepath.Dir(local), 0700); err != nil {
			return empty, err
		}
		f, err := root.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return empty, err
		}
		_, writeErr := f.Write(contents)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return empty, errReport
		}
	}
	report := addons.Scan(dir)
	if report.Status != "complete" {
		return empty, errReport
	}
	return report, nil
}
