package core

import "sync"

type replayCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]struct{}
	order    []string
}

func newReplayCache(capacity int) *replayCache {
	return &replayCache{
		capacity: capacity,
		entries:  make(map[string]struct{}),
		order:    make([]string, 0, capacity),
	}
}

// seenOrAdd atomically records key and reports whether it already existed.
func (c *replayCache) seenOrAdd(key string) bool {
	if c == nil || c.capacity <= 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, found := c.entries[key]; found {
		return true
	}
	for len(c.order) >= c.capacity {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[key] = struct{}{}
	c.order = append(c.order, key)
	return false
}
