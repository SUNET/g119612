package etsi119612

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	go_cache "github.com/eko/gocache/lib/v4/cache"
	gocstore "github.com/eko/gocache/store/go_cache/v4"
	"github.com/h2non/gock"
	goc "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

func TestWalker(t *testing.T) {
	headerMock, err := os.ReadFile("./testdata/x5c-test-root-leaf.json")
	if err != nil {
		t.Fatalf("Failed while reading json: %v", err)
	}
	assert.NotEmpty(t, headerMock)
	var jwt JWTCertBundle
	err = json.Unmarshal(headerMock, &jwt)
	if err != nil {
		t.Fatalf("Failed updating jwt bundle")
	}
	leafDER, err := base64.StdEncoding.DecodeString(jwt.X5c[0])
	assert.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	assert.NoError(t, err)
	gock.New("https://eidas.agid.gov.it").
		Get("/TL/TSL-IT.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_it-tsl.xml")

	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_se-tl.xml")

	defer gock.Off()
	gock.New("https://ec.europa.eu").
		Get("/tools/lotl/eu-lotl.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_lotl.xml")

	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	graph, error := GraphSearch("https://ec.europa.eu/tools/lotl/eu-lotl.xml", newCache, leafCert, nil)

	if error != nil {
		t.Fatal(error)
	}
	t.Logf("%v", graph.adj)
}

func TestWalkerLOTLInCache(t *testing.T) {
	headerMock, err := os.ReadFile("./testdata/x5c-test-root-leaf.json")
	if err != nil {
		t.Fatalf("Failed while reading json: %v", err)
	}
	assert.NotEmpty(t, headerMock)
	var jwt JWTCertBundle
	err = json.Unmarshal(headerMock, &jwt)
	if err != nil {
		t.Fatalf("Failed updating jwt bundle")
	}
	leafDER, err := base64.StdEncoding.DecodeString(jwt.X5c[0])
	assert.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	assert.NoError(t, err)
	gock.New("https://eidas.agid.gov.it").
		Get("/TL/TSL-IT.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_it-tsl.xml")

	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_se-tl.xml")

	defer gock.Off()
	gock.New("https://ec.europa.eu").
		Get("/tools/lotl/eu-lotl.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_lotl.xml")

	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	bodyBytes, err := FetchTSLBytes("https://ec.europa.eu/tools/lotl/eu-lotl.xml")
	assert.NoError(t, err)
	ctx := context.Background()
	err = newCache.Set(ctx, "https://ec.europa.eu/tools/lotl/eu-lotl.xml", bodyBytes)
	assert.NoError(t, err)
	graph, error := GraphSearch("https://ec.europa.eu/tools/lotl/eu-lotl.xml", newCache, leafCert, nil)

	if error != nil {
		t.Fatal(error)
	}
	t.Logf("%v", graph.adj)
}

func TestWalkerSELOTLInCache(t *testing.T) {
	headerMock, err := os.ReadFile("./testdata/x5c-test-root-leaf.json")
	if err != nil {
		t.Fatalf("Failed while reading json: %v", err)
	}
	assert.NotEmpty(t, headerMock)
	var jwt JWTCertBundle
	err = json.Unmarshal(headerMock, &jwt)
	if err != nil {
		t.Fatalf("Failed updating jwt bundle")
	}
	leafDER, err := base64.StdEncoding.DecodeString(jwt.X5c[0])
	assert.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	assert.NoError(t, err)
	gock.New("https://eidas.agid.gov.it").
		Get("/TL/TSL-IT.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_it-tsl.xml")

	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_se-tl.xml")

	defer gock.Off()
	gock.New("https://ec.europa.eu").
		Get("/tools/lotl/eu-lotl.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_lotl.xml")

	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	lotlbodyBytes, err := FetchTSLBytes("https://ec.europa.eu/tools/lotl/eu-lotl.xml")
	assert.NoError(t, err)
	ctx := context.Background()
	err = newCache.Set(ctx, "https://ec.europa.eu/tools/lotl/eu-lotl.xml", lotlbodyBytes)
	assert.NoError(t, err)
	slbodyBytes, err := FetchTSLBytes("https://trustedlist.pts.se/SE-TL.xml")
	assert.NoError(t, err)
	err = newCache.Set(ctx, "https://trustedlist.pts.se/SE-TL.xml", slbodyBytes)
	assert.NoError(t, err)
	graph, error := GraphSearch("https://ec.europa.eu/tools/lotl/eu-lotl.xml", newCache, leafCert, nil)

	if error != nil {
		t.Fatal(error)
	}
	t.Logf("%v", graph.adj)
}

func TestWalkerwithIntermediatesSuccess(t *testing.T) {
	headerMock, err := os.ReadFile("./testdata/x5c-test.json")
	if err != nil {
		t.Fatalf("Failed while reading json: %v", err)
	}
	assert.NotEmpty(t, headerMock)
	var jwt JWTCertBundle
	err = json.Unmarshal(headerMock, &jwt)
	if err != nil {
		t.Fatalf("Failed updating jwt bundle")
	}
	leafDER, err := base64.StdEncoding.DecodeString(jwt.X5c[0])
	assert.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	assert.NoError(t, err)
	interDER, err := base64.StdEncoding.DecodeString(jwt.X5c[1])
	assert.NoError(t, err, "Failed to decode intermediate")
	interCert, err := x509.ParseCertificate(interDER)
	assert.NoError(t, err, "Failed to parse intermediate certificate")
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(interCert)

	gock.New("https://eidas.agid.gov.it").
		Get("/TL/TSL-IT.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_it-tsl.xml")

	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_se-tl.xml")

	defer gock.Off()
	gock.New("https://ec.europa.eu").
		Get("/tools/lotl/eu-lotl.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_lotl.xml")

	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	_, err = GraphSearch("https://ec.europa.eu/tools/lotl/eu-lotl.xml", newCache, leafCert, intermediatePool)
	assert.NoError(t, err)

}

func TestWalkerwithIntermediatesError(t *testing.T) {
	headerMock, err := os.ReadFile("./testdata/x5c-test.json")
	if err != nil {
		t.Fatalf("Failed while reading json: %v", err)
	}
	assert.NotEmpty(t, headerMock)
	var jwt JWTCertBundle
	err = json.Unmarshal(headerMock, &jwt)
	if err != nil {
		t.Fatalf("Failed updating jwt bundle")
	}
	leafDER, err := base64.StdEncoding.DecodeString(jwt.X5c[0])
	assert.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	assert.NoError(t, err)
	interDER, err := base64.StdEncoding.DecodeString(jwt.X5c[1])
	assert.NoError(t, err, "Failed to decode intermediate")
	interCert, err := x509.ParseCertificate(interDER)
	assert.NoError(t, err, "Failed to parse intermediate certificate")
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(interCert)

	gock.New("https://eidas.agid.gov.it").
		Get("/TL/TSL-IT.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_it-tsl.xml")

	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_se-tl.xml")

	defer gock.Off()
	gock.New("https://ec.europa.eu").
		Get("/tools/lotl/eu-lotl.xml").
		Reply(200).
		File("./testdata/testdata_walker/signed_lotl.xml")

	//probably mock here better
	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	_, err = GraphSearch("https://ec.europa.eu/tools/lotl/eu-lotl.xml", newCache, leafCert, nil)
	assert.Error(t, err)
}
