package redteamadapter

import (
	"errors"
	"testing"
)

func TestWorkerTokenLoaderRejectsEveryPathOutsideFixedProjectedVolume(t *testing.T) {
	for _, path := range []string{"", "/tmp/token", "/var/run/secrets/zasp/red-team-adapter/../token"} {
		token, err := LoadWorkerToken(path)
		if token != nil || !errors.Is(err, ErrAdapter) {
			t.Fatalf("path=%q token=%q err=%v", path, token, err)
		}
	}
}
