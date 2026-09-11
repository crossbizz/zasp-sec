package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
)

type lineageProducerDaemonConfig struct {
	SpoolDirectory, AckDirectory, SocketPath, BootFile string
	Loop                                               lineageProducerLoopConfig
	PollInterval, ShutdownTimeout                      time.Duration
}

func loadLineageProducerDaemonConfig(getenv func(string) string) (lineageProducerDaemonConfig, error) {
	var config lineageProducerDaemonConfig
	if getenv == nil || getenv("ZASP_SENSOR_ROLE") != "lineage-producer" || getenv("ZASP_SENSOR_TOKEN_FILE") != "" {
		return config, errSensorConfig
	}
	config.SpoolDirectory, config.AckDirectory = getenv("ZASP_LINEAGE_SPOOL_DIRECTORY"), getenv("ZASP_LINEAGE_ACK_DIRECTORY")
	config.SocketPath, config.BootFile = getenv("ZASP_TETRAGON_SOCKET"), getenv("ZASP_HOST_BOOT_ID_FILE")
	config.Loop.NodeName = getenv("ZASP_SENSOR_NODE_NAME")
	config.Loop.Scope.EnrollmentBinding = getenv("ZASP_SENSOR_ENROLLMENT_BINDING")
	config.Loop.Scope.Destination = getenv("ZASP_SENSOR_CONTROL_PLANE_URL") + "/internal/v1/runtime/events"
	uid, err := parseBoundedInteger(getenv("ZASP_LINEAGE_CONSUMER_UID"), 1, 2147483647)
	if err != nil {
		return config, errSensorConfig
	}
	config.Loop.Scope.ConsumerUID = uint32(uid)
	config.Loop.Pump.BatchSize, err = parseBoundedInteger(getenv("ZASP_SENSOR_BATCH_SIZE"), 1, 1000)
	if err != nil {
		return config, errSensorConfig
	}
	for _, item := range []struct {
		name     string
		target   *time.Duration
		min, max time.Duration
	}{
		{"ZASP_LINEAGE_FLUSH_INTERVAL", &config.Loop.Pump.FlushInterval, 50 * time.Millisecond, 30 * time.Second},
		{"ZASP_LINEAGE_IDENTITY_INTERVAL", &config.Loop.Pump.CheckInterval, 50 * time.Millisecond, time.Minute},
		{"ZASP_LINEAGE_MAX_GENERATION_AGE", &config.Loop.Pump.MaximumDuration, time.Second, time.Hour},
		{"ZASP_SENSOR_OPERATION_TIMEOUT", &config.Loop.OperationTimeout, time.Second, 30 * time.Second},
		{"ZASP_SENSOR_POLL_INTERVAL", &config.PollInterval, time.Second, 30 * time.Second},
		{"ZASP_SENSOR_SHUTDOWN_TIMEOUT", &config.ShutdownTimeout, 10 * time.Second, time.Minute},
	} {
		*item.target, err = parseBoundedDuration(getenv(item.name), item.min, item.max)
		if err != nil {
			return config, errSensorConfig
		}
	}
	if !validLineageProducerDaemonConfig(config) {
		return config, errSensorConfig
	}
	return config, nil
}

func validLineageProducerDaemonConfig(config lineageProducerDaemonConfig) bool {
	if !validKubernetesName(config.Loop.NodeName) || !enrollmentBindingPattern.MatchString(config.Loop.Scope.EnrollmentBinding) || !validLineageDestination(config.Loop.Scope.Destination) || config.Loop.Scope.ConsumerUID == 0 || config.Loop.Scope.ConsumerUID > 2147483647 || !validLineagePumpConfig(config.Loop.Pump) || config.Loop.Pump.MaximumDuration < time.Second || config.Loop.Pump.MaximumDuration > time.Hour || config.Loop.OperationTimeout < time.Second || config.Loop.OperationTimeout > 30*time.Second || config.PollInterval < time.Second || config.PollInterval > 30*time.Second || config.ShutdownTimeout < 10*time.Second || config.ShutdownTimeout > time.Minute {
		return false
	}
	for _, path := range []string{config.SpoolDirectory, config.AckDirectory, config.SocketPath, config.BootFile} {
		if !validAbsolute(path) {
			return false
		}
	}
	return lineagePathsSeparate([]string{config.SpoolDirectory, config.AckDirectory, filepath.Dir(config.SocketPath), filepath.Dir(config.BootFile), "/var/run/secrets/kubernetes.io/serviceaccount"})
}

func lineagePathsSeparate(paths []string) bool {
	for index, path := range paths {
		for _, other := range paths[:index] {
			if path == other || strings.HasPrefix(path, other+string(filepath.Separator)) || strings.HasPrefix(other, path+string(filepath.Separator)) {
				return false
			}
		}
	}
	return true
}

type lineageProducerDependencies struct {
	config          lineageProducerDaemonConfig
	spool           *lineageSpool
	receipts        *lineageReceiptReader
	boot            *hostBootReader
	api             *lineageKubernetesAPI
	mu              sync.Mutex
	running, closed bool
}

// Only the root producer role opens the raw Tetragon socket and host boot source.
// Product tokens and consumer state aren't opened here. The consumer UID is also
// its read-only group; deployment must set runAsGroup to that trusted value.
func buildProductionLineageProducer(config lineageProducerDaemonConfig) (_ *lineageProducerDependencies, err error) {
	if !validLineageProducerDaemonConfig(config) || runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getegid() != int(config.Loop.Scope.ConsumerUID) {
		return nil, errSensorRuntime
	}
	dependencies := &lineageProducerDependencies{config: config}
	defer func() {
		if err != nil {
			dependencies.Close()
		}
	}()
	paths := []string{config.SpoolDirectory, config.AckDirectory, filepath.Dir(config.SocketPath), filepath.Dir(config.BootFile), "/var/run/secrets/kubernetes.io/serviceaccount"}
	var roots []*os.Root
	defer func() {
		for _, root := range roots {
			root.Close()
		}
	}()
	var physical []os.FileInfo
	var resolved []string
	for _, path := range paths {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, errSensorRuntime
		}
		resolved = append(resolved, actual)
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, errSensorRuntime
		}
		roots = append(roots, root)
		info, err := lineageReadOnlyRootInfo(root)
		if err != nil {
			return nil, errSensorRuntime
		}
		for _, previous := range physical {
			if os.SameFile(previous, info) {
				return nil, errSensorRuntime
			}
		}
		physical = append(physical, info)
	}
	if !lineagePathsSeparate(resolved) {
		return nil, errSensorRuntime
	}
	spoolStat, ok := physical[0].Sys().(*syscall.Stat_t)
	if !ok || !physical[0].IsDir() || physical[0].Mode().Perm() != 0750 || physical[0].Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || spoolStat.Uid != 0 || spoolStat.Gid != config.Loop.Scope.ConsumerUID {
		return nil, errSensorRuntime
	}
	dependencies.boot, err = newProcBootReader(config.BootFile)
	if err != nil {
		return nil, errSensorRuntime
	}
	dependencies.receipts, err = newProductionLineageReceiptReader(config.AckDirectory, config.Loop.Scope.ConsumerUID)
	if err != nil {
		return nil, errSensorRuntime
	}
	inCluster, err := rest.InClusterConfig()
	if err != nil {
		return nil, errSensorRuntime
	}
	dependencies.api, err = newLineageKubernetesAPI(inCluster, config.Loop.NodeName)
	if err != nil {
		return nil, errSensorRuntime
	}
	dependencies.spool, err = newBoundLineageSpool(config.SpoolDirectory, 0, physical[0])
	if err != nil {
		return nil, errSensorRuntime
	}
	return dependencies, nil
}

func (dependencies *lineageProducerDependencies) run(ctx context.Context, ticks <-chan time.Time, ready func(bool)) error {
	dependencies.mu.Lock()
	if dependencies.closed || dependencies.running {
		dependencies.mu.Unlock()
		return errSensorRuntime
	}
	dependencies.running = true
	dependencies.mu.Unlock()
	defer func() { dependencies.mu.Lock(); dependencies.running = false; dependencies.mu.Unlock() }()
	return runLineageProducerLoop(ctx, dependencies.spool, dependencies.receipts, dependencies.config.Loop, func(ctx context.Context) (*lineageGeneration, error) {
		endpoint, err := newProductionLineageSocket(dependencies.config.SocketPath)
		if err != nil {
			return nil, err
		}
		return startLineageGeneration(ctx, dependencies.config.Loop.NodeName, dependencies.config.Loop.Scope.EnrollmentBinding, dependencies.api, dependencies.boot, endpoint, dependencies.spool)
	}, ticks, ready)
}

func (dependencies *lineageProducerDependencies) Close() error {
	if dependencies == nil {
		return nil
	}
	dependencies.mu.Lock()
	defer dependencies.mu.Unlock()
	if dependencies.running {
		return errSensorRuntime
	}
	if dependencies.closed {
		return nil
	}
	dependencies.closed = true
	if dependencies.api != nil {
		dependencies.api.Close()
	}
	var failed bool
	if dependencies.boot != nil {
		failed = dependencies.boot.Close() != nil || failed
	}
	if dependencies.receipts != nil {
		failed = dependencies.receipts.Close() != nil || failed
	}
	if dependencies.spool != nil {
		failed = dependencies.spool.Close() != nil || failed
	}
	if failed {
		return errSensorRuntime
	}
	return nil
}
