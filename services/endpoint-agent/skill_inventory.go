package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const installedScanner = "/usr/local/libexec/zaspctl"

func collectInstalledSkills(ctx context.Context, socket, scanner, project string) error {
	args := []string{"addons", "inventory", "--local", "--harness", "all", "--json"}
	if project != "" {
		args = append(args, "--scope", "project", "--project", project)
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, scanner, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	raw, readErr := boundedRead(stdout, wireLimit)
	if readErr != nil {
		cancel()
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if readErr != nil || (err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 3)) || !json.Valid(raw) {
		return errInvalid
	}
	_, err = call(socket, request{Operation: "inventory", Project: project, Hook: raw})
	return err
}

// A LaunchAgent may start before enrollment or before the listening socket is
// ready. Wait for a broker lifecycle event without inspecting employee files.
func awaitInventoryEnrollment(ctx context.Context, socket string) error {
	if permission, err := call(socket, request{Operation: "inventory-enabled"}); err == nil && permission.InventoryEnabled {
		return nil
	}
	watcher, err := newSkillWatcher([]string{socket})
	if err != nil {
		return err
	}
	defer watcher.close()
	for {
		permission, err := call(socket, request{Operation: "inventory-enabled"})
		if err == nil && permission.InventoryEnabled {
			return nil
		}
		if !watcher.wait(ctx) {
			return ctx.Err()
		}
	}
}

func watchInstalledSkills(ctx context.Context, socket, scanner, project string) error {
	if os.Geteuid() == 0 || (project != "" && (!filepath.IsAbs(project) || filepath.Clean(project) != project)) {
		return errInvalid
	}
	if err := awaitInventoryEnrollment(ctx, socket); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	home, err = canonicalSkillBase(home)
	if err != nil {
		return err
	}
	roots := []string{filepath.Join(home, ".claude/skills"), filepath.Join(home, ".agents/skills"), "/Library/Application Support/ClaudeCode/skills", "/private/etc/codex/skills"}
	if project != "" {
		project, err = canonicalSkillBase(project)
		if err != nil {
			return err
		}
		roots = []string{filepath.Join(project, ".claude/skills"), filepath.Join(project, ".agents/skills")}
	}
	roots = append(roots, socket)
	for ctx.Err() == nil {
		// Arm the change notification before reading. An installation that
		// finishes during the scan will wake the next pass.
		watcher, err := newSkillWatcher(roots)
		if err != nil {
			return err
		}
		if err := collectInstalledSkills(ctx, socket, scanner, project); err != nil && ctx.Err() == nil {
			// Keep listening so a corrected bundle can recover on its next edit.
			fmt.Fprintln(os.Stderr, "Could not record the installed skill scan.")
		}
		changed := watcher.wait(ctx)
		watcher.close()
		if !changed {
			return ctx.Err()
		}
		if err := awaitInventoryEnrollment(ctx, socket); err != nil {
			return err
		}
	}
	return nil
}

// FSEvents names files by their physical paths. Accept the standard macOS
// system aliases, but never follow an employee-controlled assignment symlink.
func canonicalSkillBase(path string) (string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if canonical == path {
		return path, nil
	}
	for _, alias := range []string{"/tmp", "/var", "/etc"} {
		if (path == alias || strings.HasPrefix(path, alias+"/")) && canonical == "/private"+path {
			return canonical, nil
		}
	}
	return "", errors.New("skill inventory requires a physical directory path")
}
