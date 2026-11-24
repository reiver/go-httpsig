package rfc9421_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/reiver/go-rfc9651"

	"github.com/reiver/go-httpsig"
	"github.com/reiver/go-httpsig/rfc9421"
)

// The test-request and test-response messages of RFC 9421 Appendix B.2.

func testRequest() rfc9421.Message {
	var header http.Header = http.Header{}
	header.Set("Host", "example.com")
	header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	header.Set("Content-Type", "application/json")
	header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	header.Set("Content-Length", "18")

	return rfc9421.Message{
		Header: header,
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: "example.com", Path: "/foo", RawQuery: "param=Value&Pet=dog"},
	}
}

func testResponse() rfc9421.Message {
	var header http.Header = http.Header{}
	header.Set("Date", "Tue, 20 Apr 2021 02:07:56 GMT")
	header.Set("Content-Type", "application/json")
	header.Set("Content-Digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:")
	header.Set("Content-Length", "23")

	return rfc9421.Message{Header: header, Status: 200}
}

// The proxy's request of RFC 9421 Appendix B.3.
func testProxyRequest() rfc9421.Message {
	var header http.Header = http.Header{}
	header.Set("Host", "service.internal.example")
	header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", "18")
	header.Set("Client-Cert", ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:")

	return rfc9421.Message{
		Header: header,
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: "service.internal.example", Path: "/foo", RawQuery: "param=Value&Pet=dog"},
	}
}

type rfcExample struct {
	Name           string
	Message        func() rfc9421.Message
	SignatureInput string // the member's value (after "label=")
	Signature      string // base64
	ExpectedBase   string
	Algorithm      httpsig.Algorithm
	PublicKey      func(*testing.T) any
}

// The examples of RFC 9421 Appendices B.2 and B.3 (with the RFC 8792 line wrapping undone).
var rfcExamples = []rfcExample{
	{
		Name:           "B.2.1 minimal, rsa-pss-sha512",
		Message:        testRequest,
		SignatureInput: `();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
		Signature:      "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==",
		ExpectedBase:   `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
		Algorithm:      httpsig.AlgorithmRSAPSSSHA512,
		PublicKey:      func(t *testing.T) any { return testKeyRSAPSSPublic(t) },
	},
	{
		Name:           "B.2.2 selective, rsa-pss-sha512",
		Message:        testRequest,
		SignatureInput: `("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`,
		Signature:      "LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==",
		ExpectedBase: `"@authority": example.com
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@query-param";name="Pet": dog
"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`,
		Algorithm: httpsig.AlgorithmRSAPSSSHA512,
		PublicKey: func(t *testing.T) any { return testKeyRSAPSSPublic(t) },
	},
	{
		Name:           "B.2.3 full, rsa-pss-sha512",
		Message:        testRequest,
		SignatureInput: `("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
		Signature:      "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==",
		ExpectedBase: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
		Algorithm: httpsig.AlgorithmRSAPSSSHA512,
		PublicKey: func(t *testing.T) any { return testKeyRSAPSSPublic(t) },
	},
	{
		Name:           "B.2.4 response, ecdsa-p256-sha256",
		Message:        testResponse,
		SignatureInput: `("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`,
		Signature:      "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==",
		ExpectedBase: `"@status": 200
"content-type": application/json
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-length": 23
"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`,
		Algorithm: httpsig.AlgorithmECDSAP256SHA256,
		PublicKey: func(t *testing.T) any { return testKeyECCP256Public(t) },
	},
	{
		Name:           "B.2.5 request, hmac-sha256",
		Message:        testRequest,
		SignatureInput: `("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`,
		Signature:      "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
		ExpectedBase: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@authority": example.com
"content-type": application/json
"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`,
		Algorithm: httpsig.AlgorithmHMACSHA256,
		PublicKey: func(t *testing.T) any { return testSharedSecret(t) },
	},
	{
		Name:           "B.2.6 request, ed25519",
		Message:        testRequest,
		SignatureInput: `("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
		Signature:      "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
		ExpectedBase: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
		Algorithm: httpsig.AlgorithmEd25519,
		PublicKey: func(t *testing.T) any { return testKeyEd25519Public(t) },
	},
	{
		Name:           "B.3 TLS-terminating proxy, ecdsa-p256-sha256",
		Message:        testProxyRequest,
		SignatureInput: `("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"`,
		Signature:      "xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==",
		ExpectedBase: `"@path": /foo
"@query": ?param=Value&Pet=dog
"@method": POST
"@authority": service.internal.example
"client-cert": :MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:
"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"`,
		Algorithm: httpsig.AlgorithmECDSAP256SHA256,
		PublicKey: func(t *testing.T) any { return testKeyECCP256Public(t) },
	},
}

func parseSignatureParams(t *testing.T, s string) rfc9421.SignatureParams {
	t.Helper()

	list, err := rfc9651.ParseList(s)
	if nil != err || 1 != len(list) {
		t.Fatalf("Expected one inner list in %q (error: %v).", s, err)
	}
	innerList, casted := list[0].(rfc9651.InnerList)
	if !casted {
		t.Fatalf("Expected an inner list in %q.", s)
	}
	params, err := rfc9421.ParseSignatureParams(innerList)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return params
}

func TestRFCExamples_signatureBase(t *testing.T) {
	for _, example := range rfcExamples {
		base, err := rfc9421.SignatureBase(example.Message(), parseSignatureParams(t, example.SignatureInput))
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", example.Name, err, err)
			continue
		}
		if example.ExpectedBase != string(base) {
			t.Errorf("For %q, the signature base is not what was expected.", example.Name)
			t.Logf("EXPECTED:\n%s", example.ExpectedBase)
			t.Logf("ACTUAL:\n%s", base)
		}
	}
}

func TestRFCExamples_verify(t *testing.T) {
	for _, example := range rfcExamples {
		signature, err := base64.StdEncoding.DecodeString(example.Signature)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}

		var base []byte = []byte(example.ExpectedBase)
		if err := rfc9421.VerifyBase(example.Algorithm, example.PublicKey(t), base, signature); nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", example.Name, err, err)
		}

		// A changed signature base does not verify.
		var changed []byte = []byte(strings.Replace(example.ExpectedBase, "1618884473", "1618884474", 1))
		if err := rfc9421.VerifyBase(example.Algorithm, example.PublicKey(t), changed, signature); !errors.Is(err, httpsig.ErrSignatureInvalid) {
			t.Errorf("For %q, expected ErrSignatureInvalid but actually got: %v", example.Name, err)
		}
	}
}

// The whole message — Signature-Input and Signature fields included — verifies (B.2.2 has a tag).
func TestRFCExamples_verifyMessage(t *testing.T) {
	var example rfcExample = rfcExamples[1]

	var message rfc9421.Message = example.Message()
	message.Header.Set("Signature-Input", "sig-b22="+example.SignatureInput)
	message.Header.Set("Signature", "sig-b22=:"+example.Signature+":")

	signature, err := rfc9421.Verify(message, rfc9421.Requirements{
		Tag: "header-example",
		Components: []rfc9421.Component{
			{Name: "@authority"},
			{Name: "content-digest"},
			{Name: "@query-param", Params: rfc9651.Params{{Key: "name", Value: "Pet"}}},
		},
		Algorithm: httpsig.AlgorithmRSAPSSSHA512,
		KeyID:     "test-key-rsa-pss",
	}, testKeyRSAPSSPublic(t))
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if "sig-b22" != signature.Label {
		t.Errorf("Expected label sig-b22 but actually got %q.", signature.Label)
	}
	if created, _ := signature.Params.Created(); 1618884473 != created {
		t.Errorf("Unexpected created: %d", created)
	}
}

// hmac-sha256 and ed25519 are deterministic: signing gives exactly the RFC's signatures.
func TestRFCExamples_signDeterministic(t *testing.T) {
	tests := []struct {
		Example    rfcExample
		Label      string
		PrivateKey func(*testing.T) any
	}{
		{Example: rfcExamples[4], Label: "sig-b25", PrivateKey: func(t *testing.T) any { return testSharedSecret(t) }},
		{Example: rfcExamples[5], Label: "sig-b26", PrivateKey: func(t *testing.T) any { return testKeyEd25519Private(t) }},
	}

	for _, test := range tests {
		signed, err := rfc9421.Sign(test.Example.Message(), test.Label, parseSignatureParams(t, test.Example.SignatureInput), test.Example.Algorithm, test.PrivateKey(t))
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", test.Example.Name, err, err)
			continue
		}
		if expected := test.Label + "=" + test.Example.SignatureInput; expected != signed.SignatureInput {
			t.Errorf("For %q, expected Signature-Input %q but actually got %q.", test.Example.Name, expected, signed.SignatureInput)
		}
		if expected := test.Label + "=:" + test.Example.Signature + ":"; expected != signed.Signature {
			t.Errorf("For %q, expected Signature %q but actually got %q.", test.Example.Name, expected, signed.Signature)
		}
	}
}

// ECDSA and RSA are not deterministic: what is signed verifies.
func TestSign_roundTrip(t *testing.T) {
	tests := []struct {
		Name       string
		Algorithm  httpsig.Algorithm
		PrivateKey func(*testing.T) any
		PublicKey  func(*testing.T) any
	}{
		{Name: "ecdsa-p256-sha256", Algorithm: httpsig.AlgorithmECDSAP256SHA256, PrivateKey: func(t *testing.T) any { return testKeyECCP256Private(t) }, PublicKey: func(t *testing.T) any { return testKeyECCP256Public(t) }},
		{Name: "rsa-pss-sha512", Algorithm: httpsig.AlgorithmRSAPSSSHA512, PrivateKey: func(t *testing.T) any { return testKeyRSAPrivate(t) }, PublicKey: func(t *testing.T) any { return testKeyRSAPublic(t) }},
		{Name: "rsa-v1_5-sha256", Algorithm: httpsig.AlgorithmRSAV15SHA256, PrivateKey: func(t *testing.T) any { return testKeyRSAPrivate(t) }, PublicKey: func(t *testing.T) any { return testKeyRSAPublic(t) }},
	}

	for _, test := range tests {
		var message rfc9421.Message = testRequest()
		var params rfc9421.SignatureParams = parseSignatureParams(t, `("@method" "@authority" "content-digest");tag="round-trip"`)

		signed, err := rfc9421.Sign(message, "sig1", params, test.Algorithm, test.PrivateKey(t))
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
			continue
		}
		signed.AddTo(message.Header)

		_, err = rfc9421.Verify(message, rfc9421.Requirements{Tag: "round-trip", Components: params.Components, Algorithm: test.Algorithm}, test.PublicKey(t))
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
		}
	}
}
