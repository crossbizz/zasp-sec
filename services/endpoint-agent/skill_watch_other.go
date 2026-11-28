//go:build !darwin || !cgo

package main

import "context"

// Only the managed macOS package installs the user-context LaunchAgent.
type skillWatcher struct{}

func newSkillWatcher([]string) (*skillWatcher, error) { return nil, errUnavailable }
func (*skillWatcher) close()                          {}
func (*skillWatcher) wait(context.Context) bool       { return false }
