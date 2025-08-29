package cache

import (
	"time"

	go_cache "github.com/eko/gocache/lib/v4/cache"
	gocstore "github.com/eko/gocache/store/go_cache/v4"
	goc "github.com/patrickmn/go-cache"
)

type Backend string

const (
	BackendGoCache Backend = ""
	BackendRedis   Backend = "redis"
)

type CacheSettings struct {
	Backend
}

type MakeClient func(defaultExpiration, cleanupInterval time.Duration) gocstore.GoCacheClientInterface
type MakeStore func(client gocstore.GoCacheClientInterface) *gocstore.GoCacheStore

type Dependencies struct {
	MakeClient MakeClient
	MakeStore  MakeStore
}

func (d *Dependencies) DefaultOutput() error {
	if d.MakeClient == nil {
		d.MakeClient = func(defaultExpiration, cleanupInterval time.Duration) gocstore.GoCacheClientInterface {
			return goc.New(defaultExpiration, cleanupInterval)
		}
	}
	if d.MakeStore == nil {
		d.MakeStore = func(client gocstore.GoCacheClientInterface) *gocstore.GoCacheStore {
			return gocstore.NewGoCache(client)
		}

	}
	return nil

}

func NewCache[T any](cachesets CacheSettings, dep Dependencies) *go_cache.Cache[T] {
	switch cachesets.Backend {
	case BackendGoCache:
		client := dep.MakeClient(5*time.Minute, 10*time.Minute)
		gocacheStore := dep.MakeStore(client)
		return go_cache.New[T](gocacheStore)
	case BackendRedis:
		panic("not implemented")
	}
	return nil
}

// cache:

// The raw bytes (cheap?) keyed by tsl url+ sequence number

// The index -- lightweight maps, with ttl up to the tls nextupdate

//by ski (or -- der fingerprint) hit the index maps



