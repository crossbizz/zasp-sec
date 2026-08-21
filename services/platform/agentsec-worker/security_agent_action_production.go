package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func composeSecurityAgentActionWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, privateKey ed25519.PrivateKey) (workerRuntimeDependencies, error) {
	defer clear(privateKey)
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeSecurityAgentAction || database == nil || len(privateKey) != ed25519.PrivateKeySize {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewSecurityAgentActionRepository(database)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	ready, err := newBoundedCachedWorkerReadiness(repository.Ready, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{
		Authority: repository, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3,
		KeyID: config.GatewaySigningKeyID, PrivateKey: privateKey, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
		NewProductID: func() (string, error) {
			value, newErr := domain.NewProductID()
			return value.String(), newErr
		},
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: processor.Close}, nil
}

func loadSecurityAgentActionPrivateKey(path string) (ed25519.PrivateKey, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errRuntimeUnavailable
	}
	directory, name := filepath.Split(path)
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != 86 || before.Mode().Perm()&0o007 != 0 || before.Mode().Perm()&0o222 != 0 {
		return nil, errRuntimeUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, 88))
	if err != nil || len(raw) != 86 {
		clear(raw)
		return nil, errRuntimeUnavailable
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || after.Size() != before.Size() {
		clear(raw)
		return nil, errRuntimeUnavailable
	}
	encoded := string(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	clear(raw)
	if err != nil || len(decoded) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errRuntimeUnavailable
	}
	return ed25519.PrivateKey(decoded), nil
}
