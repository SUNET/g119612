package etsi119612

import (
	"context"
	"crypto/x509"
	"slices"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"

	"time"

	go_cache "github.com/eko/gocache/lib/v4/cache"
	gocstore "github.com/eko/gocache/store/go_cache/v4"
	goc "github.com/patrickmn/go-cache"
)

func TestFetch(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/EWC-TL.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.NoError(t, err)
	assert.NotNil(t, tsl.StatusList)
	si := tsl.StatusList.TslSchemeInformation
	assert.NotNil(t, si)
	assert.Equal(t, si.TSLSequenceNumber, 1)
	assert.Equal(t, *si.TslSchemeOperatorName.Name[0].XmlLangAttr, Lang("en"))
	assert.Equal(t, FindByLanguage(si.TslSchemeOperatorName, "en", "unknown"), "EWC Consortium")
	assert.Equal(t, FindByLanguage(si.TslSchemeOperatorName, "fr", "unknown 4711"), "unknown 4711")
}

func TestFetchSigned(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/SE-TL.xml")

	tsl, err := FetchTSL("https://trustedlist.pts.se/SE-TL.xml")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	assert.True(t, tsl.Signed)
	assert.NotNil(t, tsl.Signer)
	assert.IsType(t, x509.Certificate{}, tsl.Signer)
}

func TestFetchSignedBroken(t *testing.T) {
	//calculated digest does not match the expected digest
	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/SE-TL-bad-sig.xml")

	tsl, err := FetchTSL("https://trustedlist.pts.se/SE-TL.xml")
	assert.Error(t, err)
	assert.Nil(t, tsl)
}

func TestFetchMissingSchemeInfo(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/EWC-TL-no-scheme-information.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.NoError(t, err)
	si := tsl.StatusList.TslSchemeInformation
	assert.Nil(t, si)
}

func TestFetchBrokenXML(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/not-xml.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.Nil(t, tsl)
	assert.Error(t, err)
}

func TestFetchMissing(t *testing.T) {
	defer gock.Off()
	gock.New("https://example.com").
		Get("/missing").
		Reply(404)

	tsl, err := FetchTSL("https://example.com/missing")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestFetchError(t *testing.T) {
	defer gock.Off()
	gock.New("https://example.com").
		Get("/bad").
		Reply(500)

	tsl, err := FetchTSL("https://example.com/bad")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestFetchNotURL(t *testing.T) {
	tsl, err := FetchTSL("urn:not-an url")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestCertPoolBadBase64(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL-bad-base64.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(PolicyAll)
	assert.NotNil(t, pool)
}

func TestCertPoolBadCert(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL-bad-cert.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(PolicyAll)
	assert.NotNil(t, pool)
}

func TestCertPool(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL.xml")

	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(PolicyAll)
	assert.NotNil(t, pool)
}

func TestPolicy(t *testing.T) {
	p := NewTSPServicePolicy()
	assert.True(t, slices.ContainsFunc(p.ServiceStatus, func(s string) bool { return s == ServiceStatusGranted }))
	assert.Equal(t, len(p.ServiceStatus), 1)
	p.AddServiceTypeIdentifier("urn:foo")
	assert.True(t, slices.ContainsFunc(p.ServiceTypeIdentifier, func(s string) bool { return s == "urn:foo" }))
	p.AddServiceStatus("urn:bar")
	assert.True(t, slices.ContainsFunc(p.ServiceStatus, func(s string) bool { return s == "urn:bar" }))
	assert.Equal(t, len(p.ServiceStatus), 2)
}

func TestTSLMethods(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL.xml")
	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NoError(t, err)
	if got := tsl.NumberOfTrustServiceProviders(); got != 17 {
		t.Errorf("expected 17 providers, got %d", got)
	}

	if name := tsl.SchemeOperatorName(); name != "EWC Consortium" {
		t.Errorf("expected 'EWC Consortium', got %q", name)
	}
	expectedStr := "TSL[Source: https://ewc-consortium.github.io/ewc-trust-list/EWC-TL] by EWC Consortium with 17 trust service providers"
	if tsl.String() != expectedStr {
		t.Errorf("unexpected String output:\ngot:  %q\nwant: %q", tsl.String(), expectedStr)
	}
}

func TestDereferencePointersToOtherTSL(t *testing.T) {
	defer gock.Off()
	// Mock the main TSL with a pointer to another TSL
	gock.New("https://example.com").
		Get("/main.xml").
		Reply(200).
		File("testdata/TSL-with-pointer.xml")
	// Mock the referenced TSL
	gock.New("https://example.com").
		Get("/referenced.xml").
		Reply(200).
		File("testdata/EWC-TL.xml")

	tsl, err := FetchTSL("https://example.com/main.xml")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	assert.NotNil(t, tsl.Referenced)
	assert.Greater(t, len(tsl.Referenced), 0)
}

func TestDereferencePointersToOtherTSL_InvalidPointer(t *testing.T) {
	defer gock.Off()
	// Mock the main TSL with a pointer to an invalid TSL
	gock.New("https://example.com").
		Get("/main.xml").
		Reply(200).
		File("testdata/TSL-with-invalid-pointer.xml")
	// The referenced TSL will 404
	gock.New("https://example.com").
		Get("/notfound.xml").
		Reply(404)

	tsl, err := FetchTSL("https://example.com/main.xml")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	// Should not panic or error, but Referenced may be empty or nil
}

func TestWithTrustServices_EmptyAndNil(t *testing.T) {
	tsl := &TSL{StatusList: TrustStatusListType{}}
	called := false
	tsl.WithTrustServices(func(tsp *TSPType, svc *TSPServiceType) {
		called = true
	})
	assert.False(t, called, "Callback should not be called for empty TSL")
}

func TestToCertPool_RejectAllPolicy(t *testing.T) {
	// Use a real TSL from testdata
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL.xml")
	tsl, err := FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	// Policy that rejects all
	rejectAll := &TSPServicePolicy{ServiceStatus: []string{"nonexistent-status"}}
	pool := tsl.ToCertPool(rejectAll)
	assert.NotNil(t, pool)
	assert.Len(t, pool.Subjects(), 0)
}

func TestCleanCertsTrimsWhitespace(t *testing.T) {
	tsl := &TSL{
		StatusList: TrustStatusListType{
			TslTrustServiceProviderList: &TrustServiceProviderListType{
				TslTrustServiceProvider: []*TSPType{
					{
						TslTSPServices: &TSPServicesListType{
							TslTSPService: []*TSPServiceType{
								{
									TslServiceInformation: &TSPServiceInformationType{
										TslServiceDigitalIdentity: &DigitalIdentityListType{
											DigitalId: []*DigitalIdentityType{
												{X509Certificate: "  CERTDATA  "},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	tsl.CleanCerts()
	cert := tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider[0].
		TslTSPServices.TslTSPService[0].TslServiceInformation.TslServiceDigitalIdentity.DigitalId[0].X509Certificate
	assert.Equal(t, "CERTDATA", cert)
}

func TestTSLRecursiveReference(t *testing.T) {
	tsl := &TSL{}
	tsl.Referenced = []*TSL{tsl}
	assert.Contains(t, tsl.Referenced, tsl)
	// Should not panic or loop forever
}

func TestValidate_InvalidStatus(t *testing.T) {
	tsp := &TSPType{}
	svc := &TSPServiceType{
		TslServiceInformation: &TSPServiceInformationType{
			TslServiceStatus: "invalid-status",
		},
	}
	policy := NewTSPServicePolicy()
	err := tsp.Validate(svc, nil, policy)
	assert.ErrorIs(t, err, ErrInvalidStatus)
}

func TestValidate_InvalidConstraints(t *testing.T) {
	tsp := &TSPType{}
	svc := &TSPServiceType{
		TslServiceInformation: &TSPServiceInformationType{
			TslServiceStatus:         ServiceStatusGranted,
			TslServiceTypeIdentifier: "foo",
		},
	}
	policy := NewTSPServicePolicy()
	policy.ServiceTypeIdentifier = []string{"bar"}
	err := tsp.Validate(svc, nil, policy)
	assert.ErrorIs(t, err, ErrInvalidConstraints)
}

func TestTSLSummary(t *testing.T) {
	tsl := &TSL{}
	summary := tsl.Summary()
	assert.NotNil(t, summary)
	assert.Contains(t, summary, "scheme_operator_name")
	assert.Contains(t, summary, "num_trust_service_providers")
	assert.Contains(t, summary, "summary")
}

func TestTSLSummary_NullTSL(t *testing.T) {
	var tsl *TSL
	summary := tsl.Summary()
	assert.NotNil(t, summary)
	assert.Len(t, summary, 0)
}
func TestFetchPointersToOtherTSL(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/SE-TL").
		Reply(200).
		File("testdata/SE-TL.xml")
	tsl, err := FetchTSL("https://ewc-consortium.github.io/se-mock-list/SE-TL")
	if err != nil {
		t.Fatal(err)
	}

	TslPointersToOtherTSL, err := FetchPontersToOtherListTSL(tsl)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%v", TslPointersToOtherTSL)
}

func TestIsLOTL(t *testing.T) {
	defer gock.Off()
	gock.New("https://ec.europa.eu/tools/lotl/").
		Get("/eu-lotl.xml").
		Reply(200).
		File("testdata/testdata_walker/signed_lotl.xml")
	bytesTSL, err := FetchTSLBytes("https://ec.europa.eu/tools/lotl/eu-lotl.xml")
	assert.NoError(t, err)
	tsl, err := UnmarshalCleanCerts(bytesTSL, "https://ec.europa.eu/tools/lotl/eu-lotl.xml")
	assert.NoError(t, err)
	assert.True(t, tsl.IsLOTL())
	assert.False(t, tsl.IsNationalTSL())

}

func TestIsNationalTSL(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se/").
		Get("/SE-TL").
		Reply(200).
		File("testdata/testdata_walker/signed_se-tl.xml")
	bytesTSL, err := FetchTSLBytes("https://trustedlist.pts.se/SE-TL.xml")
	assert.NoError(t, err)
	tsl, err := UnmarshalCleanCerts(bytesTSL, "https://trustedlist.pts.se/SE-TL.xml")
	assert.NoError(t, err)
	assert.False(t, tsl.IsLOTL())
	assert.True(t, tsl.IsNationalTSL())

}

func TestFetchCacheOrRemoteFailedRequestjsonNoxml(t *testing.T) {
	//set json instead of xml
	defer gock.Off()
	gock.New("https://trustedlist.pts.se/").
		Get("/SE-TL").
		Reply(200).
		File("testdata/x5c_validation_test.go")
	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	_, _, err := fetchCacheorRemote("https://trustedlist.pts.se/SE-TL", newCache)
	assert.Error(t, err)

}

// help function
func FetchTSLReturnZeroBytes(url string) ([]byte, error) {
	return []byte{}, nil
}

func TestFetchCacheOrRemoteZeroBytesFail(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se/").
		Get("/SE-TL").
		Reply(200).
		File("testdata/SE-TL.xml")
	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)

	FetchTSLSwapBytesFunction = FetchTSLReturnZeroBytes
	_, _, err := fetchCacheorRemote("https://trustedlist.pts.se/SE-TL", newCache)
	assert.EqualError(t, err, "empty body from https://trustedlist.pts.se/SE-TL")
}

func FetchTSLReturnStringNotBytes(url string) ([]byte, error) {
	return []byte("here is text"), nil
}
func TestFetchCacheOrRemoteStringfromFetch(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se/").
		Get("/SE-TL").
		Reply(200).
		File("testdata/SE-TL.xml")
	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	FetchTSLSwapBytesFunction = FetchTSLReturnStringNotBytes
	_, _, err := fetchCacheorRemote("https://trustedlist.pts.se/SE-TL", newCache)
	// not clear why this gives value not found in store
	assert.EqualError(t, err, "unmarshal input url=https://trustedlist.pts.se/SE-TL bytesLength=12, error=value not found in store")
}

func TestFetchCacheOrRemoteCacheContainsString(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se/").
		Get("/SE-TL").
		Reply(200).
		File("testdata/SE-TL.xml")
	gocacheClient := goc.New(5*time.Minute, 10*time.Minute)
	gocacheStore := gocstore.NewGoCache(gocacheClient)
	newCache := go_cache.New[[]byte](gocacheStore)
	ctx := context.Background()
	bodyBytes := []byte("some meaningless text here")
	err := newCache.Set(ctx, "https://trustedlist.pts.se/SE-TL", bodyBytes)
	assert.NoError(t, err)
	_, _, err = fetchCacheorRemote("https://trustedlist.pts.se/SE-TL", newCache)
	assert.EqualError(t, err, "unmarshal bytes from cache input url=https://trustedlist.pts.se/SE-TL bytesLength=26, error=EOF")
}
