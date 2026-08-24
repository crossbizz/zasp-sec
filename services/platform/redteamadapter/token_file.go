package redteamadapter

import (
	"io"
	"os"
)

func LoadWorkerToken(path string) ([]byte, error) {
	if path != "/var/run/secrets/zasp/red-team-adapter/token" {
		return nil, ErrAdapter
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 64 || before.Size() > 4096 {
		return nil, ErrAdapter
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrAdapter
	}
	opened, statErr := file.Stat()
	token, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 || !os.SameFile(before, opened) || !os.SameFile(opened, after) || int64(len(token)) != opened.Size() || !validWorkerToken(token) {
		clear(token)
		return nil, ErrAdapter
	}
	return token, nil
}
