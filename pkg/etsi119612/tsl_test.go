package etsi119612_test

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/SUNET/g119612/pkg/etsi119612"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
)

func TestFetch(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/EWC-TL.xml")

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.NoError(t, err)
	assert.NotNil(t, tsl.StatusList)
	si := tsl.StatusList.TslSchemeInformation
	assert.NotNil(t, si)
	assert.Equal(t, si.TSLSequenceNumber, 1)
	assert.Equal(t, *si.TslSchemeOperatorName.Name[0].XmlLangAttr, etsi119612.Lang("en"))
	assert.Equal(t, etsi119612.FindByLanguage(si.TslSchemeOperatorName, "en", "unknown"), "EWC Consortium")
	assert.Equal(t, etsi119612.FindByLanguage(si.TslSchemeOperatorName, "fr", "unknown 4711"), "unknown 4711")
}

func TestFetchSigned(t *testing.T) {
	defer gock.Off()
	gock.New("https://trustedlist.pts.se").
		Get("/SE-TL.xml").
		Reply(200).
		File("./testdata/SE-TL.xml")

	tsl, err := etsi119612.FetchTSL("https://trustedlist.pts.se/SE-TL.xml")
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

	tsl, err := etsi119612.FetchTSL("https://trustedlist.pts.se/SE-TL.xml")
	assert.Error(t, err)
	assert.Nil(t, tsl)
}

func TestFetchMissingSchemeInfo(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/EWC-TL-no-scheme-information.xml")

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
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

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.Nil(t, tsl)
	assert.Error(t, err)
}

func TestFetchMissing(t *testing.T) {
	defer gock.Off()
	gock.New("https://example.com").
		Get("/missing").
		Reply(404)

	tsl, err := etsi119612.FetchTSL("https://example.com/missing")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestFetchError(t *testing.T) {
	defer gock.Off()
	gock.New("https://example.com").
		Get("/bad").
		Reply(500)

	tsl, err := etsi119612.FetchTSL("https://example.com/bad")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestFetchNotURL(t *testing.T) {
	tsl, err := etsi119612.FetchTSL("urn:not-an url")
	assert.Nil(t, tsl)
	assert.NotNil(t, err)
}

func TestCertPoolBadBase64(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL-bad-base64.xml")

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(etsi119612.PolicyAll)
	assert.NotNil(t, pool)
}

func TestCertPoolBadCert(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL-bad-cert.xml")

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(etsi119612.PolicyAll)
	assert.NotNil(t, pool)
}

func TestCertPool(t *testing.T) {
	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("testdata/EWC-TL.xml")

	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NotNil(t, tsl)
	assert.Nil(t, err)
	pool := tsl.ToCertPool(etsi119612.PolicyAll)
	assert.NotNil(t, pool)
}

func TestPolicy(t *testing.T) {
	p := etsi119612.NewTSPServicePolicy()
	assert.True(t, slices.ContainsFunc(p.ServiceStatus, func(s string) bool { return s == etsi119612.ServiceStatusGranted }))
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
	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
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

	tsl, err := etsi119612.FetchTSL("https://example.com/main.xml")
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

	tsl, err := etsi119612.FetchTSL("https://example.com/main.xml")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	// Should not panic or error, but Referenced may be empty or nil
}

func TestWithTrustServices_EmptyAndNil(t *testing.T) {
	tsl := &etsi119612.TSL{StatusList: etsi119612.TrustStatusListType{}}
	called := false
	tsl.WithTrustServices(func(tsp *etsi119612.TSPType, svc *etsi119612.TSPServiceType) {
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
	tsl, err := etsi119612.FetchTSL("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")
	assert.NoError(t, err)
	assert.NotNil(t, tsl)
	// Policy that rejects all
	rejectAll := &etsi119612.TSPServicePolicy{ServiceStatus: []string{"nonexistent-status"}}
	pool := tsl.ToCertPool(rejectAll)
	assert.NotNil(t, pool)
	assert.Len(t, pool.Subjects(), 0)
}

func TestCleanCertsTrimsWhitespace(t *testing.T) {
	tsl := &etsi119612.TSL{
		StatusList: etsi119612.TrustStatusListType{
			TslTrustServiceProviderList: &etsi119612.TrustServiceProviderListType{
				TslTrustServiceProvider: []*etsi119612.TSPType{
					{
						TslTSPServices: &etsi119612.TSPServicesListType{
							TslTSPService: []*etsi119612.TSPServiceType{
								{
									TslServiceInformation: &etsi119612.TSPServiceInformationType{
										TslServiceDigitalIdentity: &etsi119612.DigitalIdentityListType{
											DigitalId: []*etsi119612.DigitalIdentityType{
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
	tsl := &etsi119612.TSL{}
	tsl.Referenced = []*etsi119612.TSL{tsl}
	assert.Contains(t, tsl.Referenced, tsl)
	// Should not panic or loop forever
}

func TestValidate_InvalidStatus(t *testing.T) {
	tsp := &etsi119612.TSPType{}
	svc := &etsi119612.TSPServiceType{
		TslServiceInformation: &etsi119612.TSPServiceInformationType{
			TslServiceStatus: "invalid-status",
		},
	}
	policy := etsi119612.NewTSPServicePolicy()
	err := tsp.Validate(svc, nil, policy)
	assert.ErrorIs(t, err, etsi119612.ErrInvalidStatus)
}

func TestValidate_InvalidConstraints(t *testing.T) {
	tsp := &etsi119612.TSPType{}
	svc := &etsi119612.TSPServiceType{
		TslServiceInformation: &etsi119612.TSPServiceInformationType{
			TslServiceStatus:         etsi119612.ServiceStatusGranted,
			TslServiceTypeIdentifier: "foo",
		},
	}
	policy := etsi119612.NewTSPServicePolicy()
	policy.ServiceTypeIdentifier = []string{"bar"}
	err := tsp.Validate(svc, nil, policy)
	assert.ErrorIs(t, err, etsi119612.ErrInvalidConstraints)
}

func TestTSLSummary(t *testing.T) {
	tsl := &etsi119612.TSL{}
	summary := tsl.Summary()
	assert.NotNil(t, summary)
	assert.Contains(t, summary, "scheme_operator_name")
	assert.Contains(t, summary, "num_trust_service_providers")
	assert.Contains(t, summary, "summary")
}

func TestTSLSummary_NullTSL(t *testing.T) {
	var tsl *etsi119612.TSL
	summary := tsl.Summary()
	assert.NotNil(t, summary)
	assert.Len(t, summary, 0)
}
