package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type workerProcessor interface{ RunOnce(context.Context) error }

type workerRuntimeDependencies struct {
	Processor workerProcessor
	Ready     func(context.Context) error
	Close     func() error
	Metrics   func() string
}

func buildWorkerRuntime(ctx context.Context, config workerRuntimeConfig) (workerRuntimeDependencies, error) {
	return buildWorkerRuntimeWithIO(ctx, config, productionWorkerIO())
}

// Only external provider/storage transports vary. Database authority, runtime
// service clients, processors and SDK registration stay on this shared path.
type workerExternalIO struct {
	planner   func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error)
	temporal  func(workerRuntimeConfig) (temporalExecutionIO, error)
	discovery func(productionDiscoveryDependencyConfig) (discoveryDependencyIO, error)
	outbox    func(workerRuntimeConfig) (outboxDependencyIO, error)
	redTeam   func(workerRuntimeConfig) (*productionRedTeamDependencies, error)
	// Optional constructor-only observer decorators. Production leaves this nil;
	// diagnostics delegate the same IO/product before any worker is registered.
	temporalDiagnostic *temporalDiagnosticDecorator
}

type temporalDiagnosticDecorator struct {
	driver     func(apiserver.PostgresDriver) apiserver.PostgresDriver
	database   func(apiserver.JSONDatabase) apiserver.JSONDatabase
	singleTest func(orchestration.SingleTestProduct) orchestration.SingleTestProduct
}

func productionWorkerIO() workerExternalIO {
	return workerExternalIO{planner: newProductionSecurityAgentPlanner, temporal: newTemporalExecutionIO, discovery: newProductionDiscoveryIO, outbox: newProductionOutboxIO, redTeam: newProductionRedTeamDependencies}
}
func buildWorkerRuntimeWithIO(ctx context.Context, config workerRuntimeConfig, external workerExternalIO) (workerRuntimeDependencies, error) {
	if external.planner == nil || external.temporal == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	connectCtx, cancel := context.WithTimeout(ctx, minDuration(config.LeaseDuration/2, 5*time.Second))
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(config.PostgresDSN)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns, poolConfig.MinConns = int32(config.BatchSize+2), 1
	poolConfig.HealthCheckPeriod = config.PollInterval
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if workerStartupProfileReady(connectCtx, pool, config) != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if config.Mode == workerModeSecurityAgent {
		installed, err := database.SecurityAgentTestSelectorAvailable(connectCtx)
		if err != nil || installed && !config.RuntimeServices.Enabled {
			database.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
	}
	if config.Mode == workerModeDiscovery || config.Mode == workerModeScheduler {
		installed, err := database.TemporalDiscoveryAvailable(connectCtx, config.DatabaseAuthority)
		if err != nil {
			database.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		if installed {
			return buildTemporalDiscoveryRuntime(ctx, config, database, external)
		}
	}
	dependencies, err := composeWorkerRuntimeWithIO(connectCtx, config, database, external)
	if err != nil {
		_ = database.Close()
		return workerRuntimeDependencies{}, err
	}
	dependencies.Close = closeWorkerRuntimeDatabase(config.Mode, dependencies.Close, database.Close)
	services, err := runtimeservices.Connect(ctx, config.RuntimeServices)
	if err != nil {
		_ = dependencies.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if services != nil {
		var temporalRuntime *temporalSecurityAgentRuntime
		if config.Mode == workerModeSecurityAgent {
			engine, err := orchestration.NewTemporalEngine(services.Temporal, config.RuntimeServices.TaskQueue, config.RuntimeServices.Timeout)
			if err != nil {
				_ = services.Close()
				_ = dependencies.Close()
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			temporalRuntime, err = buildTemporalSecurityAgentRuntimeWithIO(ctx, config, services.Temporal, services.FGA, external)
			if err != nil {
				_ = services.Close()
				_ = dependencies.Close()
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: &orchestration.Relay{Store: orchestration.SQLStore{Database: database, Timeout: config.RuntimeServices.Timeout}, Engine: retainedTemporalEngine{engine: engine, product: temporalRuntime.product}}}
			if temporalRuntime.product.singleTestEnabled {
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: temporalRuntime.product.singleTestControlRelay(func(ctx context.Context, kind string, q orchestration.StartRequest) error {
					if kind == "cancel" {
						return engine.CancelSingleTest(ctx, q)
					}
					if kind == "approval" {
						return engine.WakeSingleTest(ctx, q)
					}
					return orchestration.ErrInvalid
				})}
				// The outer start relay runs first. A decision remains pending when
				// start acceptance failed, and retries on the next ordinary pass.
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: temporalRuntime.product.singleTestRelay(engine.StartSingleTest)}
			}
			if temporalRuntime.selector != nil {
				// Selector composition is unchanged by cleanup recovery.
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: temporalRuntime.selector}
			}
			if temporalRuntime.recoveryActivities != nil {
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: &singleTestRecoveryRelay{database: temporalRuntime.product.executor, start: engine.StartSingleTestRecovery}}
			}
			if temporalRuntime.finding != nil {
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: temporalRuntime.finding}
			}
			if temporalRuntime.automatic != nil {
				dependencies.Processor = temporalOutboxProcessor{legacy: dependencies.Processor, relay: temporalRuntime.automatic}
			}
		}
		if config.Mode == workerModeRedTeam {
			installed, err := singleTestRuntimeAvailable(ctx, database, true)
			if err != nil {
				services.Close()
				dependencies.Close()
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			if installed {
				engine, err := orchestration.NewTemporalEngine(services.Temporal, config.RuntimeServices.TaskQueue, config.RuntimeServices.Timeout)
				gated, ok := dependencies.Processor.(readinessGatedWorkerProcessor)
				processor, valid := gated.delegate.(*redTeamProcessor)
				if err != nil || !ok || !valid || processor.bindSingleTestDelivery(database, engine.WakeSingleTest) != nil {
					services.Close()
					dependencies.Close()
					return workerRuntimeDependencies{}, errRuntimeUnavailable
				}
				previous := dependencies.Ready
				dependencies.Ready = func(ctx context.Context) error {
					if previous(ctx) != nil {
						return errRuntimeUnavailable
					}
					if installed, err := singleTestRuntimeAvailable(ctx, database, true); err != nil || !installed {
						return errRuntimeUnavailable
					}
					return nil
				}
			}
		}
		previousReady, previousClose := dependencies.Ready, dependencies.Close
		dependencies.Ready = func(ctx context.Context) error {
			if err := services.Ready(ctx); err != nil {
				return err
			}
			if temporalRuntime != nil {
				if err := temporalRuntime.Ready(ctx); err != nil {
					return err
				}
			}
			return previousReady(ctx)
		}
		dependencies.Close = closeWorkerRuntimeServices(previousClose, services.Close)
		if temporalRuntime != nil {
			closeRest := dependencies.Close
			dependencies.Close = func() error {
				if err := temporalRuntime.Close(); err != nil {
					return err
				}
				return closeRest()
			}
		}
	}
	if config.Mode == workerModeOutbox {
		dependencies = joinDiscoveryOutboxRuntime(dependencies, config.ShutdownTimeout)
	}
	return dependencies, nil
}

type temporalOutboxProcessor struct{ legacy, relay workerProcessor }

func (p temporalOutboxProcessor) RunOnce(ctx context.Context) error {
	// Delivery keeps progressing even when the old processor refuses work.
	// Each component has its own transaction; neither can acknowledge the other.
	relayErr := p.relay.RunOnce(ctx)
	return errors.Join(relayErr, p.legacy.RunOnce(ctx))
}

// Relay RPCs observe loop cancellation and finite deadlines. SDK Close also
// cancels in-flight RPCs if the worker's shutdown join reaches its timeout.
func closeWorkerRuntimeServices(previous, services func() error) func() error {
	return func() error { return errors.Join(previous(), services()) }
}

func closeWorkerRuntimeDatabase(mode workerMode, closeDependencies, closeDatabase func() error) func() error {
	return func() error {
		dependencyErr := closeDependencies()
		if dependencyErr != nil && (mode == workerModeAuditExport || mode == workerModeAuditExportOutbox || mode == workerModeTestReconciler || mode == workerModeAttackLabReconciler || mode == workerModeComplianceExport || mode == workerModeComplianceCleanup) {
			// The audit runtime retains clients while canceled borrowers join.
			// Its database must survive that failed Close for the same reason.
			return dependencyErr
		}
		databaseErr := closeDatabase()
		if dependencyErr != nil {
			return dependencyErr
		}
		return databaseErr
	}
}

func composeWorkerRuntime(ctx context.Context, config workerRuntimeConfig, database apiserver.JSONDatabase) (workerRuntimeDependencies, error) {
	return composeWorkerRuntimeWithIO(ctx, config, database, productionWorkerIO())
}
func composeWorkerRuntimeWithIO(ctx context.Context, config workerRuntimeConfig, database apiserver.JSONDatabase, external workerExternalIO) (workerRuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(config) || database == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	switch config.Mode {
	case workerModeAttackLabReconciler:
		reader, err := newAttackLabLinkProductionDependencies(config)
		if err != nil {
			return workerRuntimeDependencies{}, err
		}
		deps, err := composeAttackLabLinkRuntime(config, database, reader)
		if err != nil {
			_ = reader.Close()
			return workerRuntimeDependencies{}, err
		}
		return deps, nil
	case workerModeComplianceExport, workerModeComplianceCleanup:
		clients, err := newComplianceExportProductionClients(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		deps, err := composeComplianceExportWorkerRuntime(ctx, config, database, clients)
		if err != nil {
			clients.transport.CloseIdleConnections()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return deps, nil
	case workerModeTestReconciler:
		reader, err := newExistingTestProductionDependencies(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeExistingTestRuntime(config, database, reader)
		if err != nil {
			_ = reader.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeAuditExport, workerModeAuditExportOutbox:
		clients, err := newAuditExportProductionClients(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
		if err != nil {
			clients.transport.CloseIdleConnections()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeOutbox, workerModeRuntimeOutbox, workerModeRedTeamOutbox, workerModeAttackLabOutbox, workerModeRecoveryOutbox:
		publisher, err := newProductionOutboxPublisherWithIO(ctx, config, external.outbox)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		var dependencies workerRuntimeDependencies
		if config.Mode == workerModeRedTeamOutbox {
			dependencies, err = composeRedTeamOutboxWorkerRuntime(config, database, publisher.publisher, publisher.ready)
		} else if config.Mode == workerModeAttackLabOutbox {
			dependencies, err = composeAttackLabOutboxWorkerRuntime(config, database, publisher.publisher, publisher.ready)
		} else if config.Mode == workerModeRecoveryOutbox {
			authority, authorityErr := newPostgresRecoveryOutboxAuthority(database)
			if authorityErr != nil {
				_ = publisher.close()
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			dependencies, err = composeRecoveryOutboxWorkerRuntime(config, authority, publisher.publisher, publisher.ready)
		} else {
			dependencies, err = composeOutboxWorkerRuntime(config, database, publisher.publisher, publisher.ready)
		}
		if err != nil {
			_ = publisher.close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies.Close = publisher.close
		return dependencies, nil
	case workerModeRecovery:
		authority, err := newPostgresRecoveryOperationAuthority(database)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		recoveryDependencies, err := newProductionRecoveryDependencies(ctx, config, authority.PostgresLSN)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeRecoveryWorkerRuntime(config, authority, recoveryDependencies)
		if err != nil {
			_ = recoveryDependencies.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeRedTeam:
		factory := external.redTeam
		if factory == nil {
			factory = newProductionRedTeamDependencies
		}
		redTeam, err := factory(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeRedTeamWorkerRuntime(config, database, redTeam)
		if err != nil {
			_ = redTeam.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeAttackLabController:
		attackLab, err := newProductionAttackLabDependencies(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeAttackLabWorkerRuntime(config, database, attackLab)
		if err != nil {
			_ = attackLab.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeScheduler:
		repository, err := apiserver.NewDiscoveryExecutionRepository(database, apiserver.DiscoveryExecutionAuthorityScheduler)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		processor, err := newSchedulerProcessor(schedulerProcessorConfig{Authority: repository, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: repository.Ready}, Ready: repository.Ready, Close: func() error { return nil }}, nil
	case workerModeSecurityAgent:
		basePlanner, err := external.planner(config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		var planner securityAgentPlanner = basePlanner
		if config.TemporalPricingBindingsFile != "" {
			if probe, ok := database.(interface {
				SecurityAgentCompatibilityAvailable(context.Context) (bool, error)
			}); ok {
				installed, err := probe.SecurityAgentCompatibilityAvailable(ctx)
				if err != nil {
					basePlanner.Close()
					return workerRuntimeDependencies{}, errRuntimeUnavailable
				}
				if installed {
					bindings, err := loadTemporalPricingBindings(config.TemporalPricingBindingsFile)
					if err != nil {
						basePlanner.Close()
						return workerRuntimeDependencies{}, errRuntimeUnavailable
					}
					for _, binding := range bindings {
						if !release61PlannerAvailable(basePlanner, binding) {
							basePlanner.Close()
							return workerRuntimeDependencies{}, errRuntimeUnavailable
						}
					}
					planner = &installedLegacyPricedPlanner{planner: basePlanner, database: database, bindings: bindings}
				}
			}
		}
		dependencies, err := composeSecurityAgentWorkerRuntime(config, database, planner)
		if err != nil {
			_ = planner.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeSecurityAgentAction:
		privateKey, err := loadSecurityAgentActionPrivateKey(config.GatewaySigningPrivateFile)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeSecurityAgentActionWorkerRuntime(config, database, privateKey)
	case workerModePolicyDeployment:
		privateKey, err := loadSecurityAgentActionPrivateKey(config.GatewaySigningPrivateFile)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composePolicyDeploymentWorkerRuntime(config, database, privateKey)
	case workerModeDiscovery:
		discovery, err := newProductionDiscoveryDependenciesWithIO(productionDiscoveryDependenciesConfig(config), external.discovery)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeDiscoveryWorkerRuntime(config, database, discovery)
		if err != nil {
			_ = discovery.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeRuntimeCoordinator:
		runtimeQueue, err := newProductionRuntimeQueue(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeRuntimeCoordinatorWorkerRuntime(config, database, runtimeQueue)
		if err != nil {
			_ = runtimeQueue.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeRuntimeArchive, workerModeRuntimeIndex, workerModeRuntimeCorrelation, workerModeRuntimeProjection, workerModeRuntimeComplete:
		var stage *productionRuntimeStageDependencies
		var err error
		if config.Mode == workerModeRuntimeArchive {
			stage, err = newProductionRuntimeArchive(ctx, config)
		} else if config.Mode == workerModeRuntimeIndex {
			stage, err = newProductionRuntimeIndex(ctx, config)
		} else if config.Mode == workerModeRuntimeCorrelation {
			stage, err = newProductionRuntimeCorrelation(ctx, config, database)
		} else if config.Mode == workerModeRuntimeProjection {
			stage, err = newProductionRuntimeProjection(ctx, config)
		} else {
			stage, err = newProductionRuntimeComplete(ctx, config)
		}
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeRuntimeStageWorkerRuntime(config, database, stage)
		if err != nil {
			_ = stage.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeProjectionRisk:
		repository, err := apiserver.NewDiscoveryExecutionRepository(database, apiserver.DiscoveryExecutionAuthorityProjectionRisk)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		projector, err := newProductionRiskProjection(repository)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeProjectionWorkerRuntime(config, database, projector)
	case workerModeProjectionSearch:
		projector, err := newProductionSearchProjection(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeProjectionWorkerRuntime(config, database, projector)
	case workerModeProjectionGraph:
		projector, err := newProductionGraphProjection(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeProjectionWorkerRuntime(config, database, projector)
	default:
		// Modes with an external provider or projection side effect are composed
		// only when their exact production driver is supplied. Returning unavailable
		// keeps the workload and public capability honest.
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
}

func composeSecurityAgentWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, planner securityAgentPlanner) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeSecurityAgent || database == nil || planner == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewSecurityAgentWorkerRepository(database)
	if err != nil || !repository.SecurityAgentPlannerAvailable() {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	ready, err := newBoundedCachedWorkerReadiness(repository.Ready, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: repository, Planner: planner, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3,
		Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
		NewProductID: func() (string, error) {
			value, newErr := domain.NewProductID()
			return value.String(), newErr
		},
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: planner.Close}, nil
}

func composeRuntimeCoordinatorWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, runtimeQueue *productionRuntimeQueueDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRuntimeCoordinator || database == nil || runtimeQueue == nil || runtimeQueue.Queue == nil || runtimeQueue.ready == nil || runtimeQueue.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCoordinator)
	if config.RuntimeDeliverySchema == "runtime-event-v2" {
		repository, err = runtimeevent.NewPostgresPrecisePipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCoordinator)
	}
	if workerUsesCurrentRuntimeProfile(config) {
		repository, err = runtimeevent.NewPostgresCurrentRuntimePipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCoordinator)
	}
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || runtimeQueue.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	constructor := newRuntimeCoordinator
	if workerUsesCurrentRuntimeProfile(config) || config.RuntimeDeliverySchema == "runtime-event-v2" {
		constructor = newPreciseRuntimeCoordinator
	}
	processor, err := constructor(runtimeCoordinatorConfig{
		Authority: repository, Queue: runtimeQueue.Queue, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), VisibilitySeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10),
		HeartbeatInterval: config.LeaseDuration / 3, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: runtimeQueue.Close}, nil
}

func composeRuntimeStageWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, stage *productionRuntimeStageDependencies) (workerRuntimeDependencies, error) {
	wantStage, authority, ok := runtimeStageBinding(config.Mode)
	if !validWorkerRuntimeConfig(config) || database == nil || stage == nil || stage.Executor == nil || stage.ready == nil || stage.close == nil || !ok || stage.Stage != wantStage {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if wantStage == runtimeevent.RuntimeStageIndex && (nilWorkerDependency(stage.Sessions) || stage.SessionReady == nil) || wantStage != runtimeevent.RuntimeStageIndex && (!nilWorkerDependency(stage.Sessions) || stage.SessionReady != nil) {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, authority)
	if wantStage == runtimeevent.RuntimeStageCorrelate && config.RuntimeStageVersion == "runtime-correlation-v2" {
		repository, err = runtimeevent.NewPostgresCorrelationPipelineRepository(database)
	}
	if wantStage == runtimeevent.RuntimeStageCorrelate && config.RuntimeStageVersion == "runtime-correlation-v3" {
		repository, err = runtimeevent.NewPostgresSandboxCorrelationPipelineRepository(database)
	}
	if wantStage == runtimeevent.RuntimeStageProject && config.RuntimeStageVersion == "runtime-projection-v2" || wantStage == runtimeevent.RuntimeStageComplete && config.RuntimeStageVersion == "runtime-complete-v2" {
		repository, err = runtimeevent.NewPostgresSandboxSessionPipelineRepository(database, authority)
	}
	if runtimePrecisionVersion(config.RuntimeStageVersion) {
		repository, err = runtimeevent.NewPostgresPrecisePipelineRepository(database, authority)
	}
	if workerUsesCurrentRuntimeProfile(config) {
		repository, err = runtimeevent.NewPostgresCurrentRuntimePipelineRepository(database, authority)
	}
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	var sessionAuthority *postgresRuntimeSessionSearchAuthority
	if wantStage == runtimeevent.RuntimeStageIndex {
		sessionAuthority, err = newConfiguredPostgresRuntimeSessionSearchAuthority(database, config.RuntimeSessionIndex)
		if config.RuntimeStageVersion == "runtime-index-v2" {
			sessionAuthority, err = newPrecisePostgresRuntimeSessionSearchAuthority(database)
		}
		if workerUsesCurrentRuntimeProfile(config) {
			sessionAuthority, err = newCurrentPostgresRuntimeSessionSearchAuthority(database)
		}
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || stage.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		if wantStage == runtimeevent.RuntimeStageComplete && repository.ReadySessionProjection(ctx) != nil {
			return errRuntimeUnavailable
		}
		if wantStage == runtimeevent.RuntimeStageCorrelate && config.RuntimeStageVersion == "runtime-correlation-v2" && repository.ReadyCandidates(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: repository, Executor: stage.Executor, Stage: stage.Stage, ImplementationVersion: config.RuntimeStageVersion, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), HeartbeatInterval: config.LeaseDuration / 3, RetrySeconds: int(config.LeaseDuration / time.Second), NewLeaseToken: newWorkerLeaseToken})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	var combined workerProcessor = readinessGatedWorkerProcessor{delegate: processor, ready: ready}
	healthReady := ready
	if sessionAuthority != nil {
		sessions, err := newRuntimeSessionSearchProcessor(runtimeSessionSearchProcessorConfig{Authority: sessionAuthority, Executor: stage.Sessions, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), HeartbeatInterval: config.LeaseDuration / 3, RetrySeconds: int(config.LeaseDuration / time.Second), NewLeaseToken: newWorkerLeaseToken})
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		sessionReady, err := newBoundedCachedWorkerReadiness(func(ctx context.Context) error {
			if stage.SessionReady(ctx) != nil || sessionAuthority.Ready(ctx) != nil {
				return errRuntimeUnavailable
			}
			return nil
		}, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		combined = runtimeIndexAndSessionProcessor{raw: combined, sessions: readinessGatedWorkerProcessor{delegate: sessions, ready: sessionReady}}
		healthReady = func(ctx context.Context) error { return errors.Join(ready(ctx), sessionReady(ctx)) }
	}
	return workerRuntimeDependencies{Processor: combined, Ready: healthReady, Close: stage.Close}, nil
}

func runtimeStageBinding(mode workerMode) (runtimeevent.RuntimeStage, runtimeevent.ProductionPipelineAuthority, bool) {
	switch mode {
	case workerModeRuntimeArchive:
		return runtimeevent.RuntimeStageArchive, runtimeevent.ProductionPipelineAuthorityArchive, true
	case workerModeRuntimeIndex:
		return runtimeevent.RuntimeStageIndex, runtimeevent.ProductionPipelineAuthorityIndex, true
	case workerModeRuntimeCorrelation:
		return runtimeevent.RuntimeStageCorrelate, runtimeevent.ProductionPipelineAuthorityCorrelation, true
	case workerModeRuntimeProjection:
		return runtimeevent.RuntimeStageProject, runtimeevent.ProductionPipelineAuthorityProjection, true
	case workerModeRuntimeComplete:
		return runtimeevent.RuntimeStageComplete, runtimeevent.ProductionPipelineAuthorityCoordinator, true
	default:
		return "", "", false
	}
}

func productionDiscoveryDependenciesConfig(config workerRuntimeConfig) productionDiscoveryDependencyConfig {
	return productionDiscoveryDependencyConfig{
		Cloud:       productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.DiscoveryRoleARN, TokenFile: config.DiscoveryTokenFile, SecretRoot: config.DiscoverySecretPrefix, Timeout: config.ProviderTimeout, Clock: func() time.Time { return time.Now().UTC() }},
		Artifacts:   productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaximumBytes: 64 << 20},
		GitHubAppID: config.GitHubAppID, GitHubPrivateKeyReference: config.GitHubPrivateKeyReference, OktaClientID: config.OktaClientID, OktaClientSecretReference: config.OktaClientSecretReference,
		AWSCollectorVersion: config.AWSCollectorVersion, KubernetesCollectorVersion: config.KubernetesCollectorVersion, GitHubCollectorVersion: config.GitHubCollectorVersion, OktaCollectorVersion: config.OktaCollectorVersion,
		ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, KubernetesAllowedCIDRs: config.KubernetesEgressCIDRs, ProviderTimeout: config.ProviderTimeout, ReadinessTimeout: config.DiscoveryReadinessTimeout,
		QueueURL: config.DiscoveryQueueURL, QueueOperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), LeaseDuration: config.LeaseDuration, ShutdownTimeout: config.ShutdownTimeout,
	}
}

func composeDiscoveryWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, discovery *productionDiscoveryDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeDiscovery || database == nil || discovery == nil || discovery.Factory == nil || discovery.Queue == nil || discovery.ready == nil || discovery.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewDiscoveryExecutionRepository(database, apiserver.DiscoveryExecutionAuthorityWorker)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{
		Authority: repository, Queue: discovery.Queue, CollectorFactory: discovery.Factory, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || discovery.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: discovery.Close}, nil
}

func composeOutboxWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, publisher outboxPublisher, publisherReady func(context.Context) error) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeOutbox && config.Mode != workerModeRuntimeOutbox || database == nil || publisher == nil || publisherReady == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	var repository productionOutboxAuthority
	var err error
	topic := discoveryOutboxTopic
	if config.Mode == workerModeRuntimeOutbox {
		if workerUsesCurrentRuntimeProfile(config) {
			repository, err = apiserver.NewCurrentRuntimeOutboxRepository(database)
		} else if config.RuntimeDeliverySchema == "runtime-event-v2" {
			repository, err = apiserver.NewPreciseRuntimeOutboxRepository(database)
		} else {
			repository, err = apiserver.NewRuntimeOutboxRepository(database)
		}
		topic = runtimeOutboxTopic
	} else {
		repository, err = apiserver.NewDiscoveryExecutionOutboxRepository(database)
	}
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || publisherReady(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	constructor := newOutboxProcessor
	if config.RuntimeDeliverySchema == "runtime-event-v2" {
		constructor = newPreciseOutboxProcessor
	}
	processor, err := constructor(outboxProcessorConfig{
		Authority: repository, Publisher: publisher, Topic: topic, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), RetrySeconds: int(config.LeaseDuration / time.Second), NewLeaseToken: newWorkerLeaseToken, Ready: ready,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: processor, Ready: ready, Close: func() error { return nil }}, nil
}

func composeRecoveryOutboxWorkerRuntime(config workerRuntimeConfig, repository recoveryOutboxAuthority, publisher outboxPublisher, publisherReady func(context.Context) error) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRecoveryOutbox || repository == nil || publisher == nil || publisherReady == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || publisherReady(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newRecoveryOutboxProcessor(recoveryOutboxProcessorConfig{
		Authority: repository, Publisher: publisher, Topic: config.RecoveryOutboxTopic, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, RetrySeconds: int(config.LeaseDuration / time.Second), NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: func() error { return nil }}, nil
}

func composeRecoveryWorkerRuntime(config workerRuntimeConfig, repository recoveryOperationAuthority, recoveryDependencies *productionRecoveryDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeRecovery || repository == nil || recoveryDependencies == nil || recoveryDependencies.Queue == nil || recoveryDependencies.ready == nil || recoveryDependencies.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	metrics := newRecoveryMetrics()
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || recoveryDependencies.Ready(ctx) != nil {
			metrics.observeDriverReadiness(false)
			return errRuntimeUnavailable
		}
		metrics.observeDriverReadiness(true)
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	var processor workerProcessor
	if config.RecoveryOperationKind == "backup" && recoveryDependencies.Publisher != nil && recoveryDependencies.Loader == nil && recoveryDependencies.Infrastructure == nil {
		processor, err = newRecoveryBackupProcessor(recoveryBackupProcessorConfig{
			Authority: repository, Queue: recoveryDependencies.Queue, Publisher: recoveryDependencies.Publisher, Metrics: metrics, WorkerID: config.WorkerID,
			LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, PageSize: 100, NewLeaseToken: newWorkerLeaseToken,
		})
	} else if config.RecoveryOperationKind == "restore" && recoveryDependencies.Publisher == nil && recoveryDependencies.Loader != nil && recoveryDependencies.Infrastructure != nil {
		processor, err = newRecoveryRestoreProcessor(recoveryRestoreProcessorConfig{
			Authority: repository, Queue: recoveryDependencies.Queue, Loader: recoveryDependencies.Loader, Infrastructure: recoveryDependencies.Infrastructure, Metrics: metrics, WorkerID: config.WorkerID,
			LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, NewLeaseToken: newWorkerLeaseToken,
		})
	} else {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: recoveryDependencies.Close, Metrics: metrics.render}, nil
}

type productionOutboxAuthority interface {
	outboxAuthority
	Ready(context.Context) error
}

type readinessGatedWorkerProcessor struct {
	delegate workerProcessor
	ready    func(context.Context) error
}

func (processor readinessGatedWorkerProcessor) RunOnce(ctx context.Context) error {
	if processor.delegate == nil || processor.ready == nil || ctx == nil || ctx.Err() != nil || processor.ready(ctx) != nil {
		return errWorkerExecution
	}
	return processor.delegate.RunOnce(ctx)
}

type boundedCachedWorkerReadiness struct {
	mu        sync.Mutex
	check     func(context.Context) error
	timeout   time.Duration
	ttl       time.Duration
	checkedAt time.Time
	now       func() time.Time
	ready     bool
}

func newBoundedCachedWorkerReadiness(check func(context.Context) error, timeout, ttl time.Duration) (func(context.Context) error, error) {
	if check == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second || ttl < 10*time.Millisecond || ttl > time.Minute {
		return nil, errRuntimeUnavailable
	}
	readiness := &boundedCachedWorkerReadiness{check: check, timeout: timeout, ttl: ttl, now: time.Now}
	return readiness.Ready, nil
}

func (readiness *boundedCachedWorkerReadiness) Ready(ctx context.Context) error {
	if readiness == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	if ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	now := readiness.now()
	elapsed := now.Sub(readiness.checkedAt)
	if readiness.ready && elapsed >= 0 && elapsed < readiness.ttl {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, readiness.timeout)
	defer cancel()
	if readiness.check(bounded) != nil || bounded.Err() != nil {
		readiness.ready = false
		return errRuntimeUnavailable
	}
	readiness.checkedAt = now
	readiness.ready = true
	return nil
}

func workerReadinessCacheTTL(time.Duration) time.Duration {
	return 30 * time.Second
}

func composeProjectionWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, projector productionProjectionProjector) (workerRuntimeDependencies, error) {
	if !stringInWorker(config.ProjectionKind, "risk", "graph", "search") || projector.projectionProjector == nil || projector.ready == nil || projector.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	authority := apiserver.DiscoveryExecutionAuthorityProjectionRisk
	if config.ProjectionKind == "graph" {
		authority = apiserver.DiscoveryExecutionAuthorityProjectionGraph
	} else if config.ProjectionKind == "search" {
		authority = apiserver.DiscoveryExecutionAuthorityProjectionSearch
	}
	repository, err := apiserver.NewDiscoveryExecutionRepository(database, authority)
	if err != nil {
		_ = projector.close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	metrics := newWorkerMetrics()
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: repository, Projector: projector.projectionProjector, Kind: config.ProjectionKind, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, NewLeaseToken: newWorkerLeaseToken, Metrics: metrics,
	})
	if err != nil {
		_ = projector.close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if err := repository.Ready(ctx); err != nil {
			metrics.observeDriverReadiness(false)
			return errRuntimeUnavailable
		}
		if err := projector.ready(ctx); err != nil {
			metrics.observeDriverReadiness(false)
			return errRuntimeUnavailable
		}
		metrics.observeDriverReadiness(true)
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		_ = projector.close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: projector.close, Metrics: metrics.render}, nil
}

func serveWorkerRuntime(ctx context.Context, output interface{ Write([]byte) (int, error) }, version string, config workerRuntimeConfig, dependencies workerRuntimeDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if ctx == nil || output == nil || !validBuildVersion(version) || !validWorkerRuntimeConfig(config) || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		if closeErr := dependencies.Close(); closeErr != nil && resultErr == nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if err := run(output, version); err != nil {
		return err
	}
	listener, err := listen("tcp", healthListenAddress)
	if err != nil || listener == nil {
		return errRuntimeUnavailable
	}
	var executingReady atomic.Bool
	server, err := healthserver.New(healthserver.Config{Service: "agentsec-worker", Version: version, Metrics: dependencies.Metrics, ReadyInterval: maxDuration(config.PollInterval, 100*time.Millisecond), ReadyMaxInterval: minDuration(maxDuration(config.PollInterval*8, time.Second), time.Minute), ReadyCheck: func(checkCtx context.Context) bool {
		return executingReady.Load() && dependencies.Ready(checkCtx) == nil
	}})
	if err != nil {
		_ = listener.Close()
		return errRuntimeUnavailable
	}
	loopDone := make(chan struct{})
	loopContext, stopLoop := context.WithCancel(ctx)
	defer stopLoop()
	go func() {
		runWorkerPollingLoop(loopContext, dependencies.Processor, config.PollInterval, &executingReady)
		close(loopDone)
	}()
	serveErr := server.Serve(ctx, listener)
	stopLoop()
	shutdownTimer := time.NewTimer(config.ShutdownTimeout)
	select {
	case <-loopDone:
		if !shutdownTimer.Stop() {
			<-shutdownTimer.C
		}
	case <-shutdownTimer.C:
		executingReady.Store(false)
	}
	if serveErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func runWorkerPollingLoop(ctx context.Context, processor workerProcessor, interval time.Duration, ready *atomic.Bool) {
	if ctx == nil || processor == nil || ready == nil || interval <= 0 {
		return
	}
	for {
		ready.Store(processor.RunOnce(ctx) == nil)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			ready.Store(false)
			return
		case <-timer.C:
		}
	}
}

func newWorkerLeaseToken() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errWorkerExecution
	}
	return hex.EncodeToString(value), nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

type workerPostgresDriver struct{ pool *pgxpool.Pool }

func (driver *workerPostgresDriver) QueryRow(ctx context.Context, statement string, arguments ...any) apiserver.PostgresRow {
	if driver == nil || driver.pool == nil {
		return workerUnavailableRow{}
	}
	return driver.pool.QueryRow(ctx, statement, arguments...)
}
func (driver *workerPostgresDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	if driver == nil || driver.pool == nil {
		return errors.New("database unavailable")
	}
	_, err := driver.pool.Exec(ctx, statement, arguments...)
	return err
}
func (driver *workerPostgresDriver) Close() error {
	if driver != nil && driver.pool != nil {
		driver.pool.Close()
	}
	return nil
}

type workerUnavailableRow struct{}

func (workerUnavailableRow) Scan(...any) error { return errors.New("database unavailable") }
