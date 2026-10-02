package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type discoveryArtifactCacheKey struct {
	bucket, owner, kms string
	locator            artifactstore.Locator
}

// Only verified immutable bytes are cached. The mutex joins synchronous
// operations before Close clears memory; no authorization result is retained.
type discoveryArtifactCache struct {
	mu             sync.Mutex
	store          artifactstore.ObjectReferencingArtifactStore
	config         productionDiscoveryArtifactConfig
	entries        map[discoveryArtifactCacheKey]artifactstore.Artifact
	order          []discoveryArtifactCacheKey
	maxEntries     int
	maxBytes, used int64
	closed         bool
}

func newDiscoveryArtifactCache(store artifactstore.ObjectReferencingArtifactStore, config productionDiscoveryArtifactConfig, entries int, bytes int64) (*discoveryArtifactCache, error) {
	if nilWorkerDependency(store) || config.Bucket == "" || config.ExpectedBucketOwner == "" || config.KMSKeyARN == "" || entries < 1 || entries > 10000 || bytes < 1 || bytes > 64<<20 {
		return nil, errRuntimeUnavailable
	}
	return &discoveryArtifactCache{store: store, config: config, entries: make(map[discoveryArtifactCacheKey]artifactstore.Artifact), maxEntries: entries, maxBytes: bytes}, nil
}

func (c *discoveryArtifactCache) key(l artifactstore.Locator) discoveryArtifactCacheKey {
	return discoveryArtifactCacheKey{c.config.Bucket, c.config.ExpectedBucketOwner, c.config.KMSKeyARN, l}
}

func cloneDiscoveryArtifact(a artifactstore.Artifact) artifactstore.Artifact {
	a.Body = bytes.Clone(a.Body)
	return a
}

func (c *discoveryArtifactCache) remember(a artifactstore.Artifact) {
	if a.Size < 1 || a.Size > c.maxBytes || a.Size != int64(len(a.Body)) || a.VersionID == "" || sha256.Sum256(a.Body) != a.SHA256 {
		return
	}
	key := c.key(a.Locator)
	if _, exists := c.entries[key]; exists {
		return
	}
	for len(c.entries) >= c.maxEntries || c.used+a.Size > c.maxBytes {
		old := c.order[0]
		c.order = c.order[1:]
		entry := c.entries[old]
		c.used -= entry.Size
		clear(entry.Body)
		delete(c.entries, old)
	}
	c.entries[key] = cloneDiscoveryArtifact(a)
	c.order = append(c.order, key)
	c.used += a.Size
}

func (c *discoveryArtifactCache) Put(ctx context.Context, q artifactstore.PutRequest) (artifactstore.Artifact, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return artifactstore.Artifact{}, artifactstore.ErrPut
	}
	a, err := c.store.Put(ctx, q)
	if err == nil {
		c.remember(a)
	}
	return a, err
}
func (c *discoveryArtifactCache) Get(ctx context.Context, q artifactstore.Locator) (artifactstore.Artifact, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	a, err := c.store.Get(ctx, q)
	if err == nil {
		c.remember(a)
	}
	return a, err
}
func (c *discoveryArtifactCache) ObjectReference(q artifactstore.Locator) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", artifactstore.ErrReference
	}
	return c.store.ObjectReference(q)
}
func (c *discoveryArtifactCache) Delete(ctx context.Context, q artifactstore.Locator) error {
	// Discovery collection never deletes evidence. Retain the authority's
	// refusal rather than adding an invalidation/delete capability to this cache.
	return artifactstore.ErrDelete
}

func (c *discoveryArtifactCache) GetEffectBatch(ctx context.Context, effect string, scope domain.Scope, locators []artifactstore.Locator) ([]artifactstore.Artifact, error) {
	if ctx == nil || ctx.Err() != nil || scope.Validate() != nil || len(locators) < 1 || len(locators) > 10000 {
		return nil, artifactstore.ErrGet
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, artifactstore.ErrGet
	}
	for _, locator := range locators {
		if locator.Scope != scope || locator.VersionID == "" {
			return nil, artifactstore.ErrGet
		}
		if _, err := c.store.ObjectReference(locator); err != nil {
			return nil, artifactstore.ErrGet
		}
	}
	// Authenticate before any miss IO. Every actual send still checks again in
	// its transport. Hits are copied synchronously after this current check.
	if err := collection.RequireScopedProductEffect(ctx, effect, scope); err != nil {
		return nil, err
	}
	staged := make([]artifactstore.Artifact, 0, len(locators))
	missed := false
	var total int64
	for _, locator := range locators {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a, hit := c.entries[c.key(locator)]
		if !hit {
			var err error
			a, err = c.store.Get(ctx, locator)
			if err != nil {
				return nil, err
			}
			missed = true
		}
		if a.Locator != locator || a.Size < 1 || a.Size != int64(len(a.Body)) || sha256.Sum256(a.Body) != a.SHA256 || total+a.Size > 64<<20 {
			return nil, artifactstore.ErrIntegrity
		}
		total += a.Size
		staged = append(staged, a)
	}
	// A storage miss crossed IO since the initial check. Recheck immediately
	// before copying this bounded in-memory batch; hits never inherit freshness
	// from an earlier storage operation. Do not evict staged entries yet.
	if missed {
		if err := collection.RequireScopedProductEffect(ctx, effect, scope); err != nil {
			return nil, err
		}
	}
	result := make([]artifactstore.Artifact, 0, len(staged))
	for _, a := range staged {
		body := make([]byte, len(a.Body))
		for offset := 0; offset < len(body); offset += 65536 {
			if err := ctx.Err(); err != nil {
				clear(body)
				return nil, err
			}
			copy(body[offset:min(offset+65536, len(body))], a.Body[offset:min(offset+65536, len(body))])
		}
		a.Body = body
		result = append(result, a)
	}
	for _, a := range result {
		c.remember(a)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *discoveryArtifactCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for key, entry := range c.entries {
		clear(entry.Body)
		delete(c.entries, key)
	}
	c.order, c.used = nil, 0
	return nil
}
