package addons

import (
	"bytes"
	"path"
	"strings"
)

// scriptViews keeps source offsets and newlines stable in both views. The
// executable view additionally masks string bodies, so a quoted API name
// cannot establish a process or network operation.
func scriptViews(name string, source []byte) (clean, executable []byte) {
	clean = bytes.Clone(source)
	executable = bytes.Clone(source)
	ext := strings.ToLower(path.Ext(name))
	py, ps := ext == ".py", ext == ".ps1"
	sh := ext == ".sh" || ext == ".bash"
	js := !py && !ps && !sh
	mask := func(from, to int, comments bool) {
		for j := from; j < to; j++ {
			if source[j] != '\n' && source[j] != '\r' {
				executable[j] = ' '
				if comments {
					clean[j] = ' '
				}
			}
		}
	}
	for i := 0; i < len(source); {
		at := source[i:]
		jsComment := js && bytes.HasPrefix(at, []byte("//"))
		shellBoundary := i == 0 || bytes.ContainsRune([]byte(" \t\r\n;|&()"), rune(source[i-1]))
		if jsComment || source[i] == '#' && (py || ps || sh && shellBoundary) {
			end := bytes.IndexByte(at, '\n')
			if end < 0 {
				end = len(at)
			}
			mask(i, i+end, true)
			i += end
			continue
		}
		endMarker := ""
		if js && bytes.HasPrefix(at, []byte("/*")) {
			endMarker = "*/"
		}
		if ps && bytes.HasPrefix(at, []byte("<#")) {
			endMarker = "#>"
		}
		if endMarker != "" {
			end := bytes.Index(at[2:], []byte(endMarker))
			if end < 0 {
				end = len(at)
			} else {
				end += 4
			}
			mask(i, i+end, true)
			i += end
			continue
		}
		q := source[i]
		if q != '\'' && q != '"' && !(js && q == '`') {
			i++
			continue
		}
		triple := py && len(at) >= 3 && at[1] == q && at[2] == q
		width := 1
		if triple {
			width = 3
		}
		start := i
		i += width
		for i < len(source) {
			escape := source[i] == '\\' && (!sh || q != '\'') && !ps || ps && source[i] == '`'
			if escape {
				i = min(len(source), i+2)
				continue
			}
			if source[i] == q && (!triple || i+2 < len(source) && source[i+1] == q && source[i+2] == q) {
				i += width
				break
			}
			i++
		}
		doc := false
		if triple {
			doc = standaloneDocString(source[:start])
		}
		mask(start, i, doc)
	}
	return clean, executable
}

// Each backward scan visits at most the indentation of its own literal.
func standaloneDocString(prefix []byte) bool {
	i := len(prefix) - 1
	if i >= 0 && (prefix[i] == 'r' || prefix[i] == 'R' || prefix[i] == 'u' || prefix[i] == 'U') {
		i--
	}
	for i >= 0 && (prefix[i] == ' ' || prefix[i] == '\t') {
		i--
	}
	return i < 0 || prefix[i] == '\n'
}
