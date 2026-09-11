package sensoradapter

import (
	"os"
	"strings"
	"syscall"
)

func validCursorName(name string) bool {
	// No cursor may occupy another cursor's lock or temporary namespace.
	return !strings.HasSuffix(name, ".lock") && !strings.HasPrefix(name, checkpointTemporaryPrefix)
}

// ReservedCursorNames returns the cursor, lock and temporary basenames. Names
// alone don't establish a collision; compare pinned parent identity as well.
func ReservedCursorNames(cursorName string) [3]string {
	return [3]string{cursorName, cursorName + ".lock", temporaryCheckpointName(cursorName)}
}

func cursorInputDisjoint(cursorRoot *os.Root, cursorName string, inputRoot *os.Root, inputName string) bool {
	names := ReservedCursorNames(cursorName)
	if inputName != names[0] && inputName != names[1] && inputName != names[2] {
		return true
	}
	cursorDirectory, err := cursorRoot.Open(".")
	if err != nil {
		return false
	}
	defer cursorDirectory.Close()
	inputDirectory, err := inputRoot.Open(".")
	if err != nil {
		return false
	}
	defer inputDirectory.Close()
	cursorInfo, cursorErr := cursorDirectory.Stat()
	inputInfo, inputErr := inputDirectory.Stat()
	return cursorErr == nil && inputErr == nil && !os.SameFile(cursorInfo, inputInfo)
}

func acquireCursorLock(root *os.Root, name string) (*os.File, error) {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrStream
	}
	if !validCursorLock(root, name, file) || syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !validCursorLock(root, name, file) {
		_ = file.Close()
		return nil, ErrStream
	}
	return file, nil
}

func validCursorLock(root *os.Root, name string, file *os.File) bool {
	if root == nil || file == nil {
		return false
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 || opened.Size() != 0 {
		return false
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return false
	}
	current, err := root.Lstat(name)
	return err == nil && current.Mode().IsRegular() && current.Mode().Perm() == 0o600 && os.SameFile(current, opened)
}
