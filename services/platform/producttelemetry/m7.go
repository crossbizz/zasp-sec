package producttelemetry

import (
	"context"
	"sort"
	"sync"
	"time"
)

type ProductEvent struct {
	Name   string
	Fields map[string]string
}

func SerializeProductEvent(event ProductEvent) (map[string]string, error) {
	if event.Name != "screen_viewed" || len(event.Fields) == 0 || len(event.Fields) > 8 {
		return nil, ErrEvent
	}
	allowed := map[string]bool{"screen": true, "surface": true, "action": true, "result": true}
	record := map[string]string{"event": event.Name}
	for key, value := range event.Fields {
		if !allowed[key] || !validSource(value) {
			return nil, ErrEvent
		}
		record[key] = value
	}
	return record, nil
}

type flagValue struct {
	value bool
	at    time.Time
}
type FlagCache struct {
	mu       sync.Mutex
	defaults map[string]bool
	values   map[string]flagValue
	maxAge   time.Duration
}

func NewFlagCache(defaults map[string]bool, maxAge time.Duration) *FlagCache {
	copyDefaults := map[string]bool{}
	for key, value := range defaults {
		if validSource(key) {
			copyDefaults[key] = value
		}
	}
	return &FlagCache{defaults: copyDefaults, values: map[string]flagValue{}, maxAge: maxAge}
}
func (c *FlagCache) Resolve(ctx context.Context, key string, provider func(context.Context, string) (bool, error), now time.Time) bool {
	if c == nil || ctx == nil || ctx.Err() != nil || provider == nil || c.maxAge <= 0 || !validSource(key) || now.Location() != time.UTC {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	value, err := provider(ctx, key)
	if err == nil {
		c.values[key] = flagValue{value: value, at: now}
		return value
	}
	if cached, ok := c.values[key]; ok && now.Sub(cached.at) <= c.maxAge {
		return cached.value
	}
	return c.defaults[key]
}
func SortedProductEventKeys(record map[string]string) []string {
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
