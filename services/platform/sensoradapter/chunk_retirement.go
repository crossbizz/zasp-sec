package sensoradapter

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ChunkRetirementConfig is supplied by a caller that has authenticated the
// producer's complete reclamation record against its trusted installation.
// Authorize must recheck that pinned evidence under the caller's ownership lock.
// This API cannot establish producer authority or remote delivery on its own.
type ChunkRetirementConfig struct {
	CursorPath       string
	Source           LineageSource
	Destination      string
	Consumption      VerifiedConsumption
	MaximumProcesses int
	ProtectedInputs  []PinnedInput
	DisjointRoots    []*os.Root
	Authorize        func(context.Context) error
	StateBinding     *ChunkStateBinding
	SpoolRoot        *os.Root
}

// RetireConsumedCheckpoint removes only a matching, non-pending checkpoint.
// Its persistent slot lock stays in place. The caller must use a bounded set of
// cursor slots and retire the ACK separately after this durability barrier.
func RetireConsumedCheckpoint(ctx context.Context, config ChunkRetirementConfig) error {
	if !config.Source.valid() {
		return ErrStream
	}
	return retireConsumedCheckpoint(ctx, config, chunkCheckpointVersion, runtimeEnvelopeVersion)
}

func retireConsumedCheckpoint(ctx context.Context, config ChunkRetirementConfig, checkpointVersion, envelopeVersion string) error {
	proof := config.Consumption
	if ctx == nil || ctx.Err() != nil || config.Authorize == nil || proof.Source != config.Source || proof.Destination != config.Destination || !validConsumptionDestination(config.Destination) || proof.Inode == 0 || config.MaximumProcesses < 1 || config.MaximumProcesses > 100_000 || len(config.ProtectedInputs) > 8 || len(config.DisjointRoots) > 8 || !validAbsoluteFilePath(config.CursorPath) || !validCursorName(filepath.Base(config.CursorPath)) {
		return ErrStream
	}
	binding := chunkSourceIdentityBinding(config.Source, proof.Device, proof.Inode)
	if !validChunkProgress(proof.Progress, ChunkProgress{NextSequence: 1, Chain: chunkChain(binding, 0, "")}) {
		return ErrStream
	}
	parentPath := filepath.Dir(config.CursorPath)
	if parentPath == string(filepath.Separator) {
		return ErrStream
	}
	parent, err := os.OpenRoot(filepath.Dir(parentPath))
	if err != nil {
		return ErrStream
	}
	defer parent.Close()
	root, err := parent.OpenRoot(filepath.Base(parentPath))
	if err != nil {
		return ErrStream
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return ErrStream
	}
	defer directory.Close()
	name := filepath.Base(config.CursorPath)
	state := &chunkRetirementState{parent: parent, root: root, directory: directory, parentName: filepath.Base(parentPath), name: name}
	if !state.validDirectory() {
		return ErrStream
	}
	info, err := directory.Stat()
	if err != nil {
		return ErrStream
	}
	if binding := config.StateBinding; binding != nil {
		spoolInfo, err := chunkRootInfo(config.SpoolRoot)
		if err != nil || binding.Source != config.Source || binding.Destination != config.Destination || binding.CursorName != name || binding.SourceDevice != proof.Device || binding.SourceInode != proof.Inode || !chunkStateIdentityMatches(info, binding.CursorDevice, binding.CursorInode) || !chunkStateIdentityMatches(spoolInfo, binding.SpoolDevice, binding.SpoolInode) {
			return ErrStream
		}
	}
	for _, other := range config.DisjointRoots {
		otherInfo, err := chunkRootInfo(other)
		if err != nil || os.SameFile(info, otherInfo) {
			return ErrStream
		}
	}
	for _, input := range config.ProtectedInputs {
		if input.Parent == nil || input.Name == "" || input.Name == "." || input.Name == ".." || filepath.Base(input.Name) != input.Name || !cursorInputDisjoint(root, name, input.Parent, input.Name) {
			return ErrStream
		}
	}
	// Never create or unlink a lock during retirement. A missing/replaced slot
	// lock is evidence loss; unlinking a held lock could split writer ownership.
	lock, err := root.OpenFile(name+".lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrStream
	}
	defer lock.Close()
	state.lock = lock
	if !state.valid() || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !state.valid() {
		return ErrStream
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		// The authenticated producer completion is the authority, not absence.
		// This path also retries an unlink whose directory sync was uncertain.
		if safeChunkRetirementAuthorize(ctx, config.Authorize) != nil || ctx.Err() != nil || !state.valid() {
			return ErrStream
		}
		return state.syncAbsent(ctx)
	}
	if err != nil {
		return ErrStream
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || held.Size() < 1 || held.Size() > maximumCheckpointBytes || !retirementOwnedFile(held, held.Size()) {
		return ErrStream
	}
	raw := make([]byte, int(held.Size()))
	if _, err := io.ReadFull(file, raw); err != nil || !checkpointJSONBounded(raw, config.MaximumProcesses) {
		return ErrStream
	}
	var checkpoint chunkCheckpoint
	if json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Version != checkpointVersion || checkpoint.Source != binding || checkpoint.Target != (streamTarget{Mode: envelopeVersion, Destination: config.Destination, Enrollment: config.Source.EnrollmentBinding}) || checkpoint.Pending != nil || checkpoint.Committed != proof.Progress || len(checkpoint.Cache) > proof.Progress.Submitted {
		return ErrStream
	}
	if _, err := cacheCheckpointSize(checkpoint.Cache, config.MaximumProcesses); err != nil {
		return ErrStream
	}
	for _, identity := range checkpoint.Cache {
		if identity.Node != config.Source.NodeName {
			return ErrStream
		}
	}
	comparison := &checkpointComparisonWriter{expected: raw}
	if json.NewEncoder(comparison).Encode(&checkpoint) != nil || comparison.offset != len(raw) {
		return ErrStream
	}
	digest := sha256.Sum256(raw)
	if !state.validFile(file, int64(len(raw)), digest) || safeChunkRetirementAuthorize(ctx, config.Authorize) != nil || ctx.Err() != nil || !state.valid() || !state.validFile(file, int64(len(raw)), digest) {
		return ErrStream
	}
	if root.Remove(name) != nil {
		return ErrStream
	}
	return state.syncAbsent(ctx)
}

func (state *chunkRetirementState) syncAbsent(ctx context.Context) error {
	if ctx.Err() != nil || !state.valid() {
		return ErrStream
	}
	if _, err := state.root.Lstat(state.name); !os.IsNotExist(err) {
		return ErrStream
	}
	if state.directory.Sync() != nil || ctx.Err() != nil || !state.valid() {
		return ErrStream
	}
	if _, err := state.root.Lstat(state.name); !os.IsNotExist(err) {
		return ErrStream
	}
	return nil
}

type chunkRetirementState struct {
	parent, root     *os.Root
	directory, lock  *os.File
	parentName, name string
}

func (state *chunkRetirementState) validDirectory() bool {
	held, err := state.directory.Stat()
	named, namedErr := state.parent.Lstat(state.parentName)
	parentInfo, parentErr := chunkRootInfo(state.parent)
	if err != nil || namedErr != nil || parentErr != nil || !privateChunkCursorDirectory(held) || !named.IsDir() || !os.SameFile(held, named) {
		return false
	}
	stat, ok := parentInfo.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && parentInfo.Mode().Perm()&0022 == 0 && parentInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func (state *chunkRetirementState) valid() bool {
	if !state.validDirectory() || !validCursorLock(state.root, state.name+".lock", state.lock) {
		return false
	}
	_, err := state.root.Lstat(temporaryCheckpointName(state.name))
	return os.IsNotExist(err)
}

func (state *chunkRetirementState) validFile(file *os.File, size int64, digest [32]byte) bool {
	held, err := file.Stat()
	named, namedErr := state.root.Lstat(state.name)
	if err != nil || namedErr != nil || !retirementOwnedFile(held, size) || !retirementOwnedFile(named, size) || !os.SameFile(held, named) {
		return false
	}
	hash := sha256.New()
	if n, err := io.Copy(hash, io.NewSectionReader(file, 0, size)); err != nil || n != size {
		return false
	}
	var actual [32]byte
	copy(actual[:], hash.Sum(nil))
	after, err := file.Stat()
	named, namedErr = state.root.Lstat(state.name)
	return actual == digest && err == nil && namedErr == nil && retirementOwnedFile(after, size) && retirementOwnedFile(named, size) && os.SameFile(held, named) && held.ModTime() == after.ModTime()
}

func retirementOwnedFile(info os.FileInfo, size int64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Size() == size
}

func safeChunkRetirementAuthorize(ctx context.Context, authorize func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrStream
		}
	}()
	if ctx.Err() != nil {
		return ErrStream
	}
	return authorize(ctx)
}
