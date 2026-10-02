package apiserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Observer is test-only progress instrumentation; native callers pass nil.
// Tests cancel during real writes or immediately before the real link boundary.
func publishPrivateReference(ctx context.Context, path string, inputs []string, payload []byte, limit int, observe func(string)) (orderedSupplementPublication, error) {
	var result orderedSupplementPublication
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 16*1024*1024 || len(payload) == 0 || len(payload) > limit {
		return result, supplementRefusal("private publication bounds/context")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return result, supplementRefusal("private output parent")
	}
	destination := filepath.Join(parent, filepath.Base(path))
	for _, input := range inputs {
		resolved, e := filepath.EvalSymlinks(input)
		if e != nil {
			p, e2 := filepath.EvalSymlinks(filepath.Dir(input))
			if e2 != nil {
				return result, supplementRefusal("private input path")
			}
			resolved = filepath.Join(p, filepath.Base(input))
		}
		if resolved == destination {
			return result, supplementRefusal("private input collision")
		}
	}
	if _, e := os.Lstat(destination); !os.IsNotExist(e) {
		return result, supplementRefusal("private output exists")
	}
	if ctx.Err() != nil {
		return result, supplementRefusal("private publication cancelled")
	}
	temp, err := os.CreateTemp(parent, ".ordered-private-reference-")
	if err != nil {
		return result, supplementRefusal("private output temporary")
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	raw := append(append([]byte{}, payload...), '\n')
	for start := 0; start < len(raw); start += 64 * 1024 {
		if ctx.Err() != nil {
			return result, supplementRefusal("private publication cancelled")
		}
		end := start + 64*1024
		if end > len(raw) {
			end = len(raw)
		}
		if n, e := temp.Write(raw[start:end]); e != nil || n != end-start {
			return result, supplementRefusal("private output write")
		}
		if start == 0 && observe != nil {
			observe("write")
		}
	}
	if ctx.Err() != nil {
		return result, supplementRefusal("private publication cancelled")
	}
	if errors.Join(temp.Sync(), temp.Close()) != nil {
		return result, supplementRefusal("private output finish")
	}
	if observe != nil {
		observe("precommit")
	}
	// This check immediately precedes the non-overwriting link commit. Cancellation
	// observed here refuses publication; the filesystem and context are not an
	// atomic pair. A successful link is the linearization point. Later cancellation
	// does not retroactively delete an already committed immutable artifact.
	if ctx.Err() != nil {
		return result, supplementRefusal("private publication cancelled")
	}
	if os.Link(temp.Name(), destination) != nil {
		return result, supplementRefusal("private output commit")
	}
	if observe != nil {
		observe("committed")
	}
	return orderedSupplementPublication{PayloadSHA256: supplementSHA(payload), FileSHA256: supplementSHA(raw), Bytes: len(raw)}, nil
}

func TestPrivateReferencePublicationCancellation(t *testing.T) {
	for _, stage := range []string{"before", "write", "precommit", "committed", "none"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "reference.json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			payload := []byte(strings.Repeat("x", 128*1024))
			publication, err := publishPrivateReference(ctx, output, nil, payload, 1024*1024, func(at string) {
				if at == "write" || at == "precommit" {
					entries, e := os.ReadDir(dir)
					if e != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".ordered-private-reference-") {
						t.Fatal("cancellation hook did not consume a real private temporary")
					}
					written, e := os.ReadFile(filepath.Join(dir, entries[0].Name()))
					if e != nil || len(written) == 0 {
						t.Fatal("cancellation hook preceded actual write")
					}
					if at == "precommit" && string(written) != string(payload)+"\n" {
						t.Fatal("precommit hook preceded complete write/close")
					}
				}
				if at == stage {
					cancel()
				}
			})
			refused := stage == "before" || stage == "write" || stage == "precommit"
			if (err != nil) != refused {
				t.Fatal("publication cancellation outcome", stage)
			}
			entries, e := os.ReadDir(dir)
			if e != nil {
				t.Fatal(e)
			}
			if refused {
				if len(entries) != 0 || publication != (orderedSupplementPublication{}) {
					t.Fatal("cancelled publication retained output/temp")
				}
				return
			}
			raw, e := os.ReadFile(output)
			if e != nil || string(raw) != string(payload)+"\n" || publication.PayloadSHA256 != supplementSHA(payload) || publication.FileSHA256 != supplementSHA(raw) || publication.Bytes != len(raw) {
				t.Fatal("committed bytes/hashes changed")
			}
			info, e := os.Stat(output)
			if e != nil || info.Mode().Perm() != 0600 || len(entries) != 1 {
				t.Fatal("private publication or cleanup changed")
			}
		})
	}
}

func TestPrivateReferencePublicationRefusals(t *testing.T) {
	for _, mode := range []string{"existing", "collision", "relative", "oversize", "commit-race"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "reference")
			inputs := []string{}
			limit := 16
			payload := []byte("capture")
			observe := func(string) {}
			switch mode {
			case "existing":
				if os.WriteFile(output, []byte("retained"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "collision":
				inputs = []string{output}
			case "relative":
				output = "relative"
			case "oversize":
				limit = 1
			case "commit-race":
				observe = func(stage string) {
					if stage == "precommit" {
						if os.WriteFile(output, []byte("retained"), 0600) != nil {
							t.Fatal("fixture")
						}
					}
				}
			}
			if _, e := publishPrivateReference(context.Background(), output, inputs, payload, limit, observe); e == nil {
				t.Fatal("invalid output published")
			}
			if mode == "existing" || mode == "commit-race" {
				raw, e := os.ReadFile(output)
				if e != nil || string(raw) != "retained" {
					t.Fatal("unowned output overwritten")
				}
			}
			entries, e := os.ReadDir(dir)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".ordered-") {
					t.Fatal("own temporary leaked")
				}
			}
		})
	}
}
