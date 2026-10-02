package artifactstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumArtifactBytes    = 64 * 1024 * 1024
)

var (
	ErrConfiguration = errors.New("artifact store configuration rejected")
	ErrArtifact      = errors.New("artifact rejected")
	ErrPut           = errors.New("artifact put failed")
	ErrGet           = errors.New("artifact get failed")
	// ErrIntegrity marks a successful read whose content violates its pinned contract.
	ErrIntegrity = errors.New("artifact integrity rejected")
	ErrDelete    = errors.New("artifact delete failed")
	ErrReference = errors.New("artifact reference failed")
)

type Config struct {
	OperationTimeout time.Duration
	MaximumBytes     int64
}

type Locator struct {
	domain.Scope
	Reference domain.EvidenceRef
	VersionID string
}

type PutRequest struct {
	Locator
	MediaType string
	Body      []byte
}

type Artifact struct {
	Locator
	MediaType string
	Body      []byte
	Size      int64
	SHA256    [sha256.Size]byte
}

type DriverLocator struct {
	Key string
	domain.Scope
	Reference domain.EvidenceRef
	VersionID string
}

type DriverObject struct {
	DriverLocator
	MediaType string
	Body      []byte
	Size      int64
	SHA256    [sha256.Size]byte
}

type Driver interface {
	Put(context.Context, DriverObject) (DriverObject, error)
	Get(context.Context, DriverLocator) (DriverObject, error)
	Delete(context.Context, DriverLocator) error
}

type ArtifactStore interface {
	Put(context.Context, PutRequest) (Artifact, error)
	Get(context.Context, Locator) (Artifact, error)
	Delete(context.Context, Locator) error
}

type ObjectReferencingArtifactStore interface {
	ArtifactStore
	ObjectReference(Locator) (string, error)
}

type DriverObjectReferencer interface {
	ObjectReference(DriverLocator) (string, error)
}

// DriverPlannedObjectReferencer computes a destination without provider I/O.
// It does not attest that an object or immutable version exists.
type DriverPlannedObjectReferencer interface {
	PlannedObjectReference(DriverLocator) (string, error)
}

type PlannedObjectReferencingArtifactStore interface {
	ObjectReferencingArtifactStore
	PlannedObjectReference(Locator) (string, error)
}

type Store struct {
	driver Driver
	config Config
	export bool
}

func New(driver Driver, config Config) (*Store, error) {
	if nilInterface(driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout ||
		config.MaximumBytes <= 0 || config.MaximumBytes > maximumArtifactBytes {
		return nil, ErrConfiguration
	}
	return &Store{driver: driver, config: config}, nil
}

// NewExport selects the fixed scoped export key profile. Pair it with an
// export-profile driver; a legacy driver rejects those keys before provider I/O.
func NewExport(driver Driver, config Config) (*Store, error) {
	store, err := New(driver, config)
	if err != nil {
		return nil, err
	}
	store.export = true
	return store, nil
}

func (store *Store) Put(ctx context.Context, request PutRequest) (artifact Artifact, resultErr error) {
	if store == nil || nilInterface(store.driver) || ctx == nil {
		return Artifact{}, ErrPut
	}
	if !validLocator(request.Locator) || request.VersionID != "" || !validMediaType(request.MediaType) ||
		len(request.Body) == 0 || int64(len(request.Body)) > store.config.MaximumBytes {
		return Artifact{}, ErrArtifact
	}
	body := bytes.Clone(request.Body)
	locator, err := store.buildDriverLocator(request.Scope, request.Reference)
	if err != nil {
		return Artifact{}, ErrArtifact
	}
	expected := DriverObject{
		DriverLocator: locator,
		MediaType:     request.MediaType,
		Body:          body,
		Size:          int64(len(body)),
		SHA256:        sha256.Sum256(body),
	}

	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return Artifact{}, ErrPut
	}
	returned, err := putDriver(store.driver, operationCtx, cloneDriverObject(expected))
	if err != nil || operationCtx.Err() != nil || !exactDriverObject(returned, expected, store.config.MaximumBytes) {
		return Artifact{}, ErrPut
	}
	return artifactFromDriver(returned), nil
}

func (store *Store) Get(ctx context.Context, locator Locator) (artifact Artifact, resultErr error) {
	if store == nil || nilInterface(store.driver) || ctx == nil {
		return Artifact{}, ErrGet
	}
	if !validLocator(locator) {
		return Artifact{}, ErrArtifact
	}
	expected, err := store.buildDriverLocator(locator.Scope, locator.Reference)
	if err != nil {
		return Artifact{}, ErrArtifact
	}
	expected.VersionID = locator.VersionID
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return Artifact{}, errors.Join(ErrGet, operationCtx.Err())
	}
	returned, err := getDriver(store.driver, operationCtx, expected)
	if operationCtx.Err() != nil {
		return Artifact{}, errors.Join(ErrGet, operationCtx.Err())
	}
	if err != nil {
		// Preserve only safe categories, never a driver's diagnostic text.
		for _, category := range []error{context.Canceled, context.DeadlineExceeded, ErrIntegrity} {
			if errors.Is(err, category) {
				return Artifact{}, errors.Join(ErrGet, category)
			}
		}
		return Artifact{}, ErrGet
	}
	if !validDriverObject(returned, store.config.MaximumBytes) ||
		returned.DriverLocator != expected {
		return Artifact{}, errors.Join(ErrGet, ErrIntegrity)
	}
	return artifactFromDriver(returned), nil
}

func (store *Store) Delete(ctx context.Context, locator Locator) (resultErr error) {
	if store == nil || nilInterface(store.driver) || ctx == nil {
		return ErrDelete
	}
	if !validLocator(locator) {
		return ErrArtifact
	}
	driverLocator, err := store.buildDriverLocator(locator.Scope, locator.Reference)
	if err != nil {
		return ErrArtifact
	}
	driverLocator.VersionID = locator.VersionID
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrDelete
	}
	if err := deleteDriver(store.driver, operationCtx, driverLocator); err != nil || operationCtx.Err() != nil {
		return ErrDelete
	}
	return nil
}

func (store *Store) ObjectReference(locator Locator) (reference string, resultErr error) {
	if store == nil || nilInterface(store.driver) || !validLocator(locator) || locator.VersionID == "" {
		return "", ErrReference
	}
	driver, ok := store.driver.(DriverObjectReferencer)
	if !ok || nilInterface(driver) {
		return "", ErrReference
	}
	driverLocator, err := store.buildDriverLocator(locator.Scope, locator.Reference)
	if err != nil {
		return "", ErrReference
	}
	driverLocator.VersionID = locator.VersionID
	defer func() {
		if recover() != nil {
			reference = ""
			resultErr = ErrReference
		}
	}()
	reference, err = driver.ObjectReference(driverLocator)
	if err != nil || reference == "" {
		return "", ErrReference
	}
	return reference, nil
}

// PlannedObjectReference binds an unversioned request to this store's fixed
// profile before a write. Use ObjectReference for a returned immutable version.
func (store *Store) PlannedObjectReference(locator Locator) (reference string, resultErr error) {
	if store == nil || nilInterface(store.driver) || !validLocator(locator) || locator.VersionID != "" {
		return "", ErrReference
	}
	driver, ok := store.driver.(DriverPlannedObjectReferencer)
	if !ok || nilInterface(driver) {
		return "", ErrReference
	}
	driverLocator, err := store.buildDriverLocator(locator.Scope, locator.Reference)
	if err != nil {
		return "", ErrReference
	}
	defer func() {
		if recover() != nil {
			reference = ""
			resultErr = ErrReference
		}
	}()
	reference, err = driver.PlannedObjectReference(driverLocator)
	if err != nil || reference == "" {
		return "", ErrReference
	}
	return reference, nil
}

func (store *Store) buildDriverLocator(scope domain.Scope, reference domain.EvidenceRef) (DriverLocator, error) {
	if store.export {
		key, err := bucketlayout.ExportKey(scope, reference.ArtifactID())
		if err != nil {
			return DriverLocator{}, ErrArtifact
		}
		return DriverLocator{Key: key, Scope: scope, Reference: reference}, nil
	}
	return buildDriverLocator(scope, reference)
}

func buildDriverLocator(scope domain.Scope, reference domain.EvidenceRef) (DriverLocator, error) {
	if !validLocator(Locator{Scope: scope, Reference: reference}) {
		return DriverLocator{}, ErrArtifact
	}
	return DriverLocator{
		Key: "organizations/" + scope.OrganizationID().String() +
			"/workspaces/" + scope.WorkspaceID().String() +
			"/environments/" + scope.EnvironmentID().String() +
			"/artifacts/" + reference.String(),
		Scope:     scope,
		Reference: reference,
	}, nil
}

func validLocator(locator Locator) bool {
	return locator.Scope.Validate() == nil && locator.Reference.Validate() == nil && validVersionID(locator.VersionID)
}

func validMediaType(value string) bool {
	switch value {
	case "application/json", "application/octet-stream", "application/gzip", "text/plain",
		"application/vnd.zasp.recovery-configuration+json", "application/vnd.zasp.recovery-projection+json",
		"application/vnd.zasp.recovery-evidence+json", "application/vnd.zasp.recovery-manifest+json":
		return true
	default:
		return false
	}
}

func validDriverObject(object DriverObject, maximumBytes int64) bool {
	if object.Key == "" || !validLocator(Locator{Scope: object.Scope, Reference: object.Reference}) ||
		!validMediaType(object.MediaType) || len(object.Body) == 0 || int64(len(object.Body)) > maximumBytes ||
		object.Size != int64(len(object.Body)) || !validVersionID(object.VersionID) {
		return false
	}
	return object.SHA256 == sha256.Sum256(object.Body)
}

func validVersionID(value string) bool {
	if len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func exactDriverObject(value, expected DriverObject, maximumBytes int64) bool {
	return validDriverObject(value, maximumBytes) && sameDriverLocator(value.DriverLocator, expected.DriverLocator) &&
		value.MediaType == expected.MediaType && value.Size == expected.Size && value.SHA256 == expected.SHA256 &&
		bytes.Equal(value.Body, expected.Body)
}

func sameDriverLocator(value, expected DriverLocator) bool {
	return value.Key == expected.Key && value.Scope == expected.Scope && value.Reference == expected.Reference &&
		(expected.VersionID == "" || value.VersionID == expected.VersionID)
}

func artifactFromDriver(object DriverObject) Artifact {
	return Artifact{
		Locator:   Locator{Scope: object.Scope, Reference: object.Reference, VersionID: object.VersionID},
		MediaType: object.MediaType,
		Body:      bytes.Clone(object.Body),
		Size:      object.Size,
		SHA256:    object.SHA256,
	}
}

func cloneDriverObject(object DriverObject) DriverObject {
	object.Body = bytes.Clone(object.Body)
	return object
}

func putDriver(driver Driver, ctx context.Context, object DriverObject) (result DriverObject, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverObject{}
			resultErr = ErrPut
		}
	}()
	return driver.Put(ctx, object)
}

func getDriver(driver Driver, ctx context.Context, locator DriverLocator) (result DriverObject, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverObject{}
			resultErr = ErrGet
		}
	}()
	return driver.Get(ctx, locator)
}

func deleteDriver(driver Driver, ctx context.Context, locator DriverLocator) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrDelete
		}
	}()
	return driver.Delete(ctx, locator)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
