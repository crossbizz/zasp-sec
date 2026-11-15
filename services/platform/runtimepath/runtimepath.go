// Package runtimepath resolves the fixed file paths the programs read keys,
// tokens and analyzer programs from.
//
// In a pod those paths are mounted by Kubernetes and are used exactly as
// written. On a workstation they sit in directories only root can create, so
// a local stack may set ZASP_LOCAL_RUNTIME_ROOT to a private directory it
// owns: the same fixed path is then expected beneath that directory. The
// paths stay fixed either way; only the directory they start from moves.
//
// The setting is ignored inside Kubernetes, and unless the directory is
// absolute, owned by the user running the program and closed to everyone
// else, so it cannot point a production program at files someone else wrote.
package runtimepath

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// RootVariable names the environment variable a local stack sets.
const RootVariable = "ZASP_LOCAL_RUNTIME_ROOT"

var (
	once sync.Once
	root string
)

// Fixed returns the path a program must use for fixed, which is fixed itself
// unless a valid local runtime root is set.
func Fixed(fixed string) string {
	once.Do(func() { root = resolve(os.Getenv(RootVariable), os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getuid()) })
	if root == "" {
		return fixed
	}
	return filepath.Join(root, fixed)
}

func resolve(value, kubernetesHost string, uid int) string {
	if value == "" || kubernetesHost != "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
		return ""
	}
	info, err := os.Lstat(value)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ""
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != uid {
		return ""
	}
	return value
}
