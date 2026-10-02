package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type orderedSupplementRule struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields"`
}
type orderedSupplementFrame struct {
	Session, Role, SearchPath, TimeZone, Postgres, ServerVersionNum, Pgcrypto string
	ReadOnly                                                                  bool
}
type orderedSupplementIO struct {
	Begin     func(context.Context) error
	Exec      func(context.Context, string) error
	Frame     func(context.Context) (orderedSupplementFrame, error)
	Admission func(context.Context) error
	Collect   func(context.Context, func(json.RawMessage) error) error
	Rollback  func(context.Context) error
	Dispose   func(context.Context) error
}
type orderedSupplementShape struct {
	Rules             []orderedSupplementRule
	Fields            map[string]map[string]string
	CategoryMaxRows   map[string]int
	RuleMaxRows       map[string]int
	MaxRows, MaxBytes int
}
type orderedSupplementPublication struct {
	PayloadSHA256, FileSHA256 string
	Bytes                     int
}

func supplementRefusal(phase string) error { return errors.New("supplement refused: " + phase) }

// Preserve raw JSON while rejecting duplicate object keys before decoding maps.
func supplementJSON(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return supplementRefusal("json depth")
		}
		token, err := d.Token()
		if err != nil {
			return supplementRefusal("json shape")
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter == '{' {
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					s, ok := key.(string)
					if e != nil || !ok || seen[s] {
						return supplementRefusal("json keys")
					}
					seen[s] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
			} else if delimiter == '[' {
				for d.More() {
					if e := value(depth + 1); e != nil {
						return e
					}
				}
			} else {
				return supplementRefusal("json delimiter")
			}
			if _, e := d.Token(); e != nil {
				return supplementRefusal("json end")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return supplementRefusal("json trailing")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(target) != nil {
		return supplementRefusal("json fields")
	}
	return nil
}

func supplementAtom(raw json.RawMessage, kind string) bool {
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	var value any
	if supplementJSON(raw, &value) != nil {
		return false
	}
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "array", "acl":
		if kind == "acl" {
			if _, ok := value.(string); ok {
				return true
			}
		}
		a, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range a {
			if _, ok := item.(string); !ok {
				return false
			}
		}
		return true
	case "integer", "number":
		n, ok := value.(json.Number)
		if !ok || strings.ContainsAny(n.String(), "eE") {
			return false
		}
		v, e := strconv.ParseFloat(n.String(), 64)
		return e == nil && !math.IsInf(v, 0) && !math.IsNaN(v) && !(v == 0 && strings.HasPrefix(n.String(), "-")) && (kind != "integer" || math.Trunc(v) == v)
	}
	return false
}

func checkOrderedSupplementRows(shape orderedSupplementShape, rows []json.RawMessage) error {
	if len(shape.Rules) == 0 || shape.MaxRows <= 0 || shape.MaxRows > 10000 || shape.MaxBytes <= 0 || shape.MaxBytes > 16*1024*1024 || rows == nil || len(rows) > shape.MaxRows {
		return supplementRefusal("row bounds")
	}
	rules := map[string]orderedSupplementRule{}
	kinds := map[string]bool{}
	for _, r := range shape.Rules {
		categoryCap, categoryOK := shape.CategoryMaxRows[r.Kind]
		ruleCap, ruleOK := shape.RuleMaxRows[r.ID]
		if r.ID == "" || r.Kind == "" || rules[r.ID].ID != "" || len(r.Fields) == 0 || !categoryOK || categoryCap < 0 || categoryCap > shape.MaxRows || !ruleOK || ruleCap < 0 || ruleCap > categoryCap {
			return supplementRefusal("rule shape")
		}
		kinds[r.Kind] = true
		fields := map[string]bool{}
		for _, f := range r.Fields {
			typ := shape.Fields[r.Kind][f]
			if f == "" || fields[f] || !strings.Contains("|string|boolean|integer|number|array|acl|", "|"+typ+"|") || typ == "" {
				return supplementRefusal("field shape")
			}
			fields[f] = true
		}
		rules[r.ID] = r
	}
	if len(shape.RuleMaxRows) != len(rules) || len(shape.CategoryMaxRows) != len(kinds) {
		return supplementRefusal("cap keys")
	}
	counts := map[string]int{}
	ruleCounts := map[string]int{}
	seen := map[string]bool{}
	total := 0
	for _, raw := range rows {
		total += len(raw)
		if total > shape.MaxBytes {
			return supplementRefusal("row bytes")
		}
		var row struct {
			Kind     string                     `json:"kind"`
			Identity string                     `json:"identity"`
			Fact     map[string]json.RawMessage `json:"fact"`
		}
		if supplementJSON(raw, &row) != nil || row.Kind == "" || row.Identity == "" || row.Fact == nil {
			return supplementRefusal("row shape")
		}
		var key []string
		if supplementJSON([]byte(row.Identity), &key) != nil || len(key) != 2 || key[0] == "" || key[1] == "" || strings.ContainsRune(row.Identity, 0) {
			return supplementRefusal("row identity")
		}
		rule, ok := rules[key[0]]
		if !ok || rule.Kind != row.Kind || len(row.Fact) != len(rule.Fields) {
			return supplementRefusal("row fields")
		}
		for _, f := range rule.Fields {
			atom, ok := row.Fact[f]
			if !ok || !supplementAtom(atom, shape.Fields[row.Kind][f]) {
				return supplementRefusal("row value")
			}
		}
		canonical := row.Kind + "\x00" + key[0] + "\x00" + key[1]
		if seen[canonical] {
			return supplementRefusal("row duplicate")
		}
		seen[canonical] = true
		counts[row.Kind]++
		ruleCounts[rule.ID]++
		if counts[row.Kind] > shape.CategoryMaxRows[row.Kind] || ruleCounts[rule.ID] > shape.RuleMaxRows[rule.ID] {
			return supplementRefusal("category bounds")
		}
	}
	return nil
}

func runOrderedSupplementBoundary(ctx context.Context, session string, shape orderedSupplementShape, io orderedSupplementIO) (rows []json.RawMessage, frame orderedSupplementFrame, result error) {
	if ctx == nil || ctx.Err() != nil || (session != "zasp_test" && session != "zasp_e2e") || io.Begin == nil || io.Exec == nil || io.Frame == nil || io.Admission == nil || io.Collect == nil || io.Rollback == nil || io.Dispose == nil {
		return nil, frame, supplementRefusal("dependencies")
	}
	if err := checkOrderedSupplementRows(shape, []json.RawMessage{}); err != nil {
		return nil, frame, err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = bounded
	original, err := io.Frame(ctx)
	if err != nil || original.Session != session || original.Role != session || original.Postgres == "" || original.ServerVersionNum == "" || original.Pgcrypto == "" {
		return nil, frame, supplementRefusal("original frame")
	}
	if io.Begin(ctx) != nil {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if io.Dispose(cleanup) != nil {
			return nil, frame, supplementRefusal("begin and close")
		}
		return nil, frame, supplementRefusal("begin")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if io.Rollback(cleanup) != nil {
			result = errors.Join(result, supplementRefusal("rollback"))
			closeCtx, closeDone := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			if io.Dispose(closeCtx) != nil {
				result = errors.Join(result, supplementRefusal("close"))
			}
			closeDone()
		} else {
			restored, e := io.Frame(cleanup)
			if e != nil || restored != original {
				result = errors.Join(result, supplementRefusal("restored frame"))
				closeCtx, closeDone := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				if io.Dispose(closeCtx) != nil {
					result = errors.Join(result, supplementRefusal("close"))
				}
				closeDone()
			}
		}
		if result != nil {
			rows = nil
			frame = orderedSupplementFrame{}
		}
	}()
	if io.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'; SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`) != nil {
		return nil, frame, supplementRefusal("configure")
	}
	if io.Admission(ctx) != nil {
		return nil, frame, supplementRefusal("admission before")
	}
	if io.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`) != nil {
		return nil, frame, supplementRefusal("collector role")
	}
	frame, err = io.Frame(ctx)
	if err != nil || frame.Session != session || frame.Role != "zasp_discovery_authority" || frame.SearchPath != "pg_catalog" || frame.TimeZone != "UTC" || !frame.ReadOnly || frame.Postgres != original.Postgres || frame.ServerVersionNum != original.ServerVersionNum || frame.Pgcrypto != original.Pgcrypto {
		return nil, frame, supplementRefusal("collector frame")
	}
	rows = []json.RawMessage{}
	var emitErr error
	rowBytes := 0
	if io.Collect(ctx, func(raw json.RawMessage) error {
		if emitErr != nil {
			return emitErr
		}
		rowBytes += len(raw)
		if ctx.Err() != nil || rowBytes > shape.MaxBytes || len(rows) >= shape.MaxRows {
			emitErr = supplementRefusal("stream bounds")
			return emitErr
		}
		if emitErr = checkOrderedSupplementRows(shape, []json.RawMessage{raw}); emitErr != nil {
			return emitErr
		}
		rows = append(rows, append(json.RawMessage{}, raw...))
		return nil
	}) != nil || emitErr != nil || ctx.Err() != nil || checkOrderedSupplementRows(shape, rows) != nil {
		return nil, frame, supplementRefusal("collect")
	}
	if io.Exec(ctx, `RESET ROLE`) != nil {
		return nil, frame, supplementRefusal("reset role")
	}
	if io.Admission(ctx) != nil || ctx.Err() != nil {
		return nil, frame, supplementRefusal("admission after")
	}
	return rows, frame, nil
}

func publishOrderedSupplement(path string, inputs []string, payload []byte, limit int) (orderedSupplementPublication, error) {
	var result orderedSupplementPublication
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 16*1024*1024 || len(payload) == 0 || len(payload) > limit {
		return result, supplementRefusal("publication bounds")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return result, supplementRefusal("output parent")
	}
	destination := filepath.Join(parent, filepath.Base(path))
	for _, input := range inputs {
		resolved, e := filepath.EvalSymlinks(input)
		if e != nil {
			p, e2 := filepath.EvalSymlinks(filepath.Dir(input))
			if e2 != nil {
				return result, supplementRefusal("input path")
			}
			resolved = filepath.Join(p, filepath.Base(input))
		}
		if resolved == destination {
			return result, supplementRefusal("input collision")
		}
	}
	if _, e := os.Lstat(destination); !os.IsNotExist(e) {
		return result, supplementRefusal("output exists")
	}
	temp, err := os.CreateTemp(parent, ".ordered-supplement-")
	if err != nil {
		return result, supplementRefusal("output temporary")
	}
	temporary := temp.Name()
	defer os.Remove(temporary)
	raw := append(append([]byte{}, payload...), '\n')
	if _, err = temp.Write(raw); err != nil {
		temp.Close()
		return result, supplementRefusal("output write")
	}
	if err = errors.Join(temp.Sync(), temp.Close()); err != nil {
		return result, supplementRefusal("output finish")
	}
	// Hard-link publication is atomic and refuses an existing destination; unlike
	// Rename it cannot overwrite a concurrently created output. The private temp
	// stays in the same directory/filesystem and is always removed.
	if os.Link(temporary, destination) != nil {
		return result, supplementRefusal("output publish")
	}
	p, f := sha256.Sum256(payload), sha256.Sum256(raw)
	return orderedSupplementPublication{PayloadSHA256: hex.EncodeToString(p[:]), FileSHA256: hex.EncodeToString(f[:]), Bytes: len(raw)}, nil
}
