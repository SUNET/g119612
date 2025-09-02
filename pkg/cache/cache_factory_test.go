package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/SUNET/g119612/pkg/etsi119612"
	"github.com/eko/gocache/lib/v4/codec"
	gocstore "github.com/eko/gocache/store/go_cache/v4"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
)

func TestCacheFactory(t *testing.T) {
	deps := Dependencies{}
	callsMakeClient := 0
	deps.MakeClient = func(defaultExpiration, cleanupInterval time.Duration) gocstore.GoCacheClientInterface {
		callsMakeClient++
		return &fakeGoCacheClient{}
	}
	callsMakeStore := 0
	deps.MakeStore = func(client gocstore.GoCacheClientInterface) *gocstore.GoCacheStore {
		callsMakeStore++
		return gocstore.NewGoCache(client)
	}
	cachesets := CacheSettings{Backend: BackendGoCache}
	receivedCodec := NewCache[string](cachesets, deps).GetCodec()

	assert.IsType(t, (*codec.Codec)(nil), receivedCodec)
	assert.Equal(t, callsMakeStore, 1)
	assert.Equal(t, callsMakeClient, 1)
}

func TestCachSetGetIntegration(t *testing.T) {
	cachesets := CacheSettings{Backend: BackendGoCache}
	deps := Dependencies{}
	deps.DefaultOutput()
	newCache := NewCache[[]byte](cachesets, deps)

	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("../etsi119612/testdata/EWC-TL.xml")

	resp, signer, err := etsi119612.FetchTSLBytes("https://ewc-consortium.github.io/EWC-TL")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	err = newCache.Set(ctx, "https://ewc-consortium.github.io", resp)
	if err != nil {
		panic(err)
	}

	value, err := newCache.Get(ctx, "https://ewc-consortium.github.io")
	if err != nil {
		panic(err)
	}
	fmt.Print(value)
	expirationTime, val, err := newCache.GetWithTTL(ctx, "https://ewc-consortium.github.io")
	fmt.Printf("%v %v %v", expirationTime, val, err)
	tsl, error := etsi119612.UnmarshalCleanCerts(resp, signer, "https://ewc-consortium.github.io")
	if error != nil {
		panic(err)
	}
	fmt.Print(tsl)
	assert.True(t, tsl.Signed)
}

//change fetch function and move it to bites
