package cache

import (
	"time"
)

type fakeGoCacheClient struct {
	defaultExpiration time.Duration
	items             map[string]any
}

func (f *fakeGoCacheClient) Get(k string) (any, bool) { return nil, false }
func (f *fakeGoCacheClient) GetWithExpiration(k string) (any, time.Time, bool) {
	return nil, time.Time{}, false
}
func (f *fakeGoCacheClient) Set(k string, x any, d time.Duration) {

}
func (f *fakeGoCacheClient) Delete(k string) {}
func (f *fakeGoCacheClient) Flush()          {}
