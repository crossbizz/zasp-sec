//go:build unix

package mcpschema

import "syscall"

const readFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
