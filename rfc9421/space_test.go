package rfc9421_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/reiver/go-rfc9651"

	"github.com/reiver/go-httpsig"
	"github.com/reiver/go-httpsig/rfc9421"
)

// How ATProto spaces use RFC 9421 (as in the reference implementation): a credential signature, and MACs.

var credentialComponents = []rfc9421.Component{{Name: "authorization"}, {Name: "atproto-space-audience"}}

var credentialRequirements = rfc9421.Requirements{
	Tag:        "atproto-space-credential",
	Components: credentialComponents,
	Algorithm:  httpsig.AlgorithmECDSAP256SHA256,
}

func credentialRequest() rfc9421.Message {
	var header http.Header = http.Header{}
	header.Set("Authorization", "Atproto-Space-Credential credential")
	header.Set("Atproto-Space-Audience", "did:example:repo")
	return rfc9421.Message{Header: header, Method: "GET"}
}

func TestSpaceCredential(t *testing.T) {
	var privateKey *ecdsa.PrivateKey = testKeyECCP256Private(t)

	var message rfc9421.Message = credentialRequest()
	var params rfc9421.SignatureParams = rfc9421.SignatureParams{
		Components: credentialComponents,
		Params:     rfc9651.Params{{Key: "tag", Value: "atproto-space-credential"}},
	}

	signed, err := rfc9421.Sign(message, "sig", params, httpsig.AlgorithmECDSAP256SHA256, privateKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if expected := `sig=("authorization" "atproto-space-audience");tag="atproto-space-credential"`; expected != signed.SignatureInput {
		t.Errorf("Expected %q but actually got %q.", expected, signed.SignatureInput)
	}

	base, err := rfc9421.SignatureBase(message, params)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if expected := "\"authorization\": Atproto-Space-Credential credential\n\"atproto-space-audience\": did:example:repo\n\"@signature-params\": (\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\""; expected != string(base) {
		t.Errorf("Unexpected signature base:\n%s", base)
	}

	signed.AddTo(message.Header)
	signature, err := rfc9421.Verify(message, credentialRequirements, &privateKey.PublicKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// The signature is r‖s (64 bytes), with a low s.
	if 64 != len(signature.Value) {
		t.Fatalf("Expected 64 bytes but actually got %d.", len(signature.Value))
	}
	var n *big.Int = elliptic.P256().Params().N
	var s *big.Int = new(big.Int).SetBytes(signature.Value[32:])
	if 0 < s.Cmp(new(big.Int).Rsh(n, 1)) {
		t.Error("Expected a low s.")
	}

	// Signing always gives a low s. (A random s is high half the time, so try many times.)
	for range 32 {
		value, err := rfc9421.SignBase(httpsig.AlgorithmECDSAP256SHA256, privateKey, base)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		if 0 < new(big.Int).SetBytes(value[32:]).Cmp(new(big.Int).Rsh(n, 1)) {
			t.Fatal("Expected a low s.")
		}
	}

	// The same signature with a high s (n−s) verifies too.
	var high []byte = append([]byte(nil), signature.Value[:32]...)
	high = append(high, new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))...)
	if err := rfc9421.VerifyBase(httpsig.AlgorithmECDSAP256SHA256, &privateKey.PublicKey, base, high); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// Another key does not verify it.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if _, err := rfc9421.Verify(message, credentialRequirements, &otherKey.PublicKey); !errors.Is(err, httpsig.ErrSignatureInvalid) {
		t.Errorf("Expected ErrSignatureInvalid but actually got: %v", err)
	}

	// A changed audience does not verify.
	message.Header.Set("Atproto-Space-Audience", "did:example:other")
	if _, err := rfc9421.Verify(message, credentialRequirements, &privateKey.PublicKey); !errors.Is(err, httpsig.ErrSignatureInvalid) {
		t.Errorf("Expected ErrSignatureInvalid but actually got: %v", err)
	}
}

// signedCredentialHeader returns a credential request whose Signature-Input and Signature are 'input' and 'signature'.
func signedCredentialHeader(input string, signature string) http.Header {
	var header http.Header = credentialRequest().Header
	header.Set("Signature-Input", input)
	header.Set("Signature", signature)
	return header
}

func TestFindSignature(t *testing.T) {
	const components = `("authorization" "atproto-space-audience")`
	const value = ":AAAA:"

	// Found by its tag, under any label, with other signatures and extra parameters around it.
	signature, err := rfc9421.FindSignature(signedCredentialHeader(
		`other=("@method");tag="other", whatever=`+components+`;created=1700000000;tag="atproto-space-credential";keyid="did:key:zDnaExample";alg="ecdsa-p256-sha256"`,
		"other=:AQID:, whatever="+value,
	), rfc9421.Requirements{Tag: "atproto-space-credential", Components: credentialComponents, Algorithm: httpsig.AlgorithmECDSAP256SHA256, KeyID: "did:key:zDnaExample"})
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if "whatever" != signature.Label || 3 != len(signature.Value) {
		t.Errorf("Unexpected signature: %#v", signature)
	}
	if created, _ := signature.Params.Created(); 1700000000 != created {
		t.Errorf("Unexpected created: %d", created)
	}

	tests := []struct {
		Name      string
		Input     string
		Signature string
		Expected  error
	}{
		{Name: "no tag", Input: "sig=" + components, Signature: "sig=" + value, Expected: httpsig.ErrSignatureNotFound},
		{Name: "another tag", Input: "sig=" + components + `;tag="other"`, Signature: "sig=" + value, Expected: httpsig.ErrSignatureNotFound},
		{Name: "two with the tag", Input: "a=" + components + `;tag="atproto-space-credential", b=` + components + `;tag="atproto-space-credential"`, Signature: "a=" + value + ", b=" + value, Expected: rfc9421.ErrTooManySignatures},
		{Name: "no Signature member", Input: "sig=" + components + `;tag="atproto-space-credential"`, Signature: "other=" + value, Expected: httpsig.ErrSignatureNotFound},
		{Name: "Signature not a byte sequence", Input: "sig=" + components + `;tag="atproto-space-credential"`, Signature: `sig="AAAA"`, Expected: rfc9421.ErrBadSignature},
		{Name: "Signature with parameters", Input: "sig=" + components + `;tag="atproto-space-credential"`, Signature: "sig=" + value + ";x", Expected: rfc9421.ErrBadSignature},
		{Name: "Signature-Input not a dictionary", Input: "(((", Signature: "sig=" + value, Expected: rfc9421.ErrBadSignatureInput},
		{Name: "Signature not a dictionary", Input: "sig=" + components + `;tag="atproto-space-credential"`, Signature: "(((", Expected: rfc9421.ErrBadSignature},
		{Name: "a component that is not a string", Input: `sig=(authorization "atproto-space-audience");tag="atproto-space-credential"`, Signature: "sig=" + value, Expected: rfc9421.ErrBadSignatureParams},
		{Name: "fewer components", Input: `sig=("authorization");tag="atproto-space-credential"`, Signature: "sig=" + value, Expected: rfc9421.ErrRequirementsNotMet},
		{Name: "components in another order", Input: `sig=("atproto-space-audience" "authorization");tag="atproto-space-credential"`, Signature: "sig=" + value, Expected: rfc9421.ErrRequirementsNotMet},
		{Name: "a component with a parameter", Input: `sig=("authorization";sf "atproto-space-audience");tag="atproto-space-credential"`, Signature: "sig=" + value, Expected: rfc9421.ErrRequirementsNotMet},
		{Name: "another algorithm", Input: "sig=" + components + `;tag="atproto-space-credential";alg="ed25519"`, Signature: "sig=" + value, Expected: rfc9421.ErrRequirementsNotMet},
		{Name: "another keyid", Input: "sig=" + components + `;tag="atproto-space-credential";keyid="did:key:zDnaOther"`, Signature: "sig=" + value, Expected: rfc9421.ErrRequirementsNotMet},
	}

	for _, test := range tests {
		_, err := rfc9421.FindSignature(signedCredentialHeader(test.Input, test.Signature), rfc9421.Requirements{
			Tag: "atproto-space-credential", Components: credentialComponents, Algorithm: httpsig.AlgorithmECDSAP256SHA256, KeyID: "did:key:zDnaExample",
		})
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %q, expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	if _, err := rfc9421.FindSignature(credentialRequest().Header, credentialRequirements); !errors.Is(err, httpsig.ErrSignatureNotFound) {
		t.Errorf("Expected ErrSignatureNotFound but actually got: %v", err)
	}
}

// A commit MAC: hmac-sha256 over the Atproto-Space-Commit header, covered with the sf flag.
func TestSpaceCommitMAC(t *testing.T) {
	var secret []byte = make([]byte, 32)
	for index := range secret {
		secret[index] = byte(index)
	}

	const covered = `ver=1, repo="did:example:alice", space="at://did:example:space/space/app.bsky.group/test", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:`
	const params = `("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit"`

	// Computed independently (with Python's hmac and hashlib).
	const expectedMAC = "15D5NbCdiwPuLCJNzdQyHvkuvXjmT4ouomAYc/EEY/w="

	var macComponents = []rfc9421.Component{{Name: "atproto-space-commit", Params: rfc9651.Params{{Key: "sf", Value: true}}}}

	// The syncer's Accept-Signature header.
	acceptSignature, err := rfc9421.SignatureParams{
		Components: macComponents,
		Params:     rfc9651.Params{{Key: "keyid", Value: "did:key:zDnaExample"}, {Key: "tag", Value: "atproto-space-commit"}},
	}.Member("mac")
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if "mac="+params != acceptSignature {
		t.Errorf("Expected %q but actually got %q.", "mac="+params, acceptSignature)
	}

	// The host's response — with insignificant whitespace in the covered header, which the sf flag removes.
	var header http.Header = http.Header{}
	header.Set("Atproto-Space-Commit", strings.ReplaceAll(covered, ", ", ",   "))
	header.Set("Signature-Input", "mac="+params)
	header.Set("Signature", "mac=:"+expectedMAC+":")

	var message rfc9421.Message = rfc9421.Message{
		Header:     header,
		Status:     200,
		FieldTypes: map[string]rfc9421.FieldType{"atproto-space-commit": rfc9421.FieldTypeDictionary},
	}

	var required = rfc9421.Requirements{
		Tag:        "atproto-space-commit",
		Components: macComponents,
		Algorithm:  httpsig.AlgorithmHMACSHA256,
		KeyID:      "did:key:zDnaExample",
	}

	if _, err := rfc9421.Verify(message, required, secret); nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// Signing gives the same MAC.
	signed, err := rfc9421.Sign(message, "mac", parseSignatureParams(t, params), httpsig.AlgorithmHMACSHA256, secret)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if "mac=:"+expectedMAC+":" != signed.Signature {
		t.Errorf("Expected %q but actually got %q.", "mac=:"+expectedMAC+":", signed.Signature)
	}

	// Another secret does not verify.
	if _, err := rfc9421.Verify(message, required, []byte("another secret")); !errors.Is(err, httpsig.ErrSignatureInvalid) {
		t.Errorf("Expected ErrSignatureInvalid but actually got: %v", err)
	}

	// A tampered header does not verify.
	header.Set("Atproto-Space-Commit", strings.Replace(covered, "3kbcq3p7ad400", "3kbcq3p7ad401", 1))
	if _, err := rfc9421.Verify(message, required, secret); !errors.Is(err, httpsig.ErrSignatureInvalid) {
		t.Errorf("Expected ErrSignatureInvalid but actually got: %v", err)
	}

	// Without the field's type, the sf flag cannot be used.
	header.Set("Atproto-Space-Commit", covered)
	message.FieldTypes = nil
	if _, err := rfc9421.Verify(message, required, secret); !errors.Is(err, rfc9421.ErrUnknownFieldType) {
		t.Errorf("Expected ErrUnknownFieldType but actually got: %v", err)
	}
}

func TestAlgorithms_errors(t *testing.T) {
	var base []byte = []byte(`"@signature-params": ()`)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// ecdsa-p384-sha384 round-trips, with a 96-byte r‖s.
	signature, err := rfc9421.SignBase(httpsig.AlgorithmECDSAP384SHA384, p384, base)
	if nil != err || 96 != len(signature) {
		t.Fatalf("Expected a 96-byte signature, but actually got %d bytes (error: %v).", len(signature), err)
	}
	if err := rfc9421.VerifyBase(httpsig.AlgorithmECDSAP384SHA384, &p384.PublicKey, base, signature); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	tests := []struct {
		Name      string
		Algorithm httpsig.Algorithm
		Key       any
		Expected  error
	}{
		{Name: "P-384 key for P-256", Algorithm: httpsig.AlgorithmECDSAP256SHA256, Key: p384, Expected: httpsig.ErrKeyTypeInvalid},
		{Name: "string for HMAC", Algorithm: httpsig.AlgorithmHMACSHA256, Key: "secret", Expected: httpsig.ErrKeyTypeInvalid},
		{Name: "ECDSA key for Ed25519", Algorithm: httpsig.AlgorithmEd25519, Key: p384, Expected: httpsig.ErrKeyTypeInvalid},
		{Name: "nil for RSA", Algorithm: httpsig.AlgorithmRSAPSSSHA512, Key: nil, Expected: httpsig.ErrKeyTypeInvalid},
		{Name: "draft-cavage algorithm", Algorithm: httpsig.AlgorithmHS2019, Key: []byte("x"), Expected: httpsig.ErrAlgorithmNotSupported},
	}
	for _, test := range tests {
		if _, err := rfc9421.SignBase(test.Algorithm, test.Key, base); !errors.Is(err, test.Expected) {
			t.Errorf("For %q (sign), expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	// A signature of the wrong length is invalid, not a panic.
	if err := rfc9421.VerifyBase(httpsig.AlgorithmECDSAP384SHA384, &p384.PublicKey, base, signature[:95]); !errors.Is(err, httpsig.ErrSignatureInvalid) {
		t.Errorf("Expected ErrSignatureInvalid but actually got: %v", err)
	}

	// The alg parameter must name the signing algorithm.
	params := rfc9421.SignatureParams{Params: rfc9651.Params{{Key: "alg", Value: "ed25519"}}}
	if _, err := rfc9421.Sign(credentialRequest(), "sig", params, httpsig.AlgorithmHMACSHA256, []byte("x")); !errors.Is(err, rfc9421.ErrBadSignatureParams) {
		t.Errorf("Expected ErrBadSignatureParams but actually got: %v", err)
	}

}
