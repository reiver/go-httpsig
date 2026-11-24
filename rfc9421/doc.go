/*
Package rfc9421 implements HTTP Message Signatures (IETF RFC 9421) — signing and verifying — for the Go programming language.

An HTTP message signature covers chosen parts ("components") of an HTTP request or response:
header fields (ex: "content-digest"), and derived components (ex: "@method", "@authority", "@path").
The signature and its parameters travel in two Dictionary header fields, under the same label. For example:

	Signature-Input: sig1=("@method" "@authority" "content-digest");created=1618884473;keyid="test-key";tag="example"
	Signature: sig1=:MEUCIQDX…:

What is signed is the signature base: one line per covered component, then the signature parameters. For example:

	"@method": POST
	"@authority": example.com
	"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
	"@signature-params": ("@method" "@authority" "content-digest");created=1618884473;keyid="test-key";tag="example"

RFC 9421 is here:

https://www.rfc-editor.org/rfc/rfc9421

# Components

HTTP field components may have the parameters:

	• sf  — the field is re-serialized strictly as a Structured Field (its type must be given in [Message.FieldTypes]),
	• key — one member of a Dictionary field,
	• bs  — each field line is wrapped as a Byte Sequence.

The derived components are: @method, @target-uri, @authority, @scheme, @request-target, @path, @query, @query-param (with a name parameter), and @status.

(Not supported: the req parameter — request components in a response's signature — and the tr parameter — trailers.)

# Algorithms

hmac-sha256, ecdsa-p256-sha256, ecdsa-p384-sha384, ed25519, rsa-pss-sha512, and rsa-v1_5-sha256. (See [SignBase] and [VerifyBase].)

ECDSA signatures are r‖s (not DER). Signing gives a low s; verifying accepts a high s too.

# Verifying

An application says what it requires of the signature with [Requirements] — the signature is found by its tag (labels carry no meaning):

	signature, err := rfc9421.Verify(rfc9421.RequestMessage(r), rfc9421.Requirements{
		Tag:        "atproto-space-credential",
		Components: []rfc9421.Component{{Name: "authorization"}, {Name: "atproto-space-audience"}},
		Algorithm:  httpsig.AlgorithmECDSAP256SHA256,
	}, publicKey)
	if nil != err {
		return err
	}

[Verify] does not check the "created", "expires", or "nonce" parameters — the application can, with signature.Params.

# Signing

	signed, err := rfc9421.Sign(rfc9421.RequestMessage(r), "sig", rfc9421.SignatureParams{
		Components: []rfc9421.Component{{Name: "authorization"}, {Name: "atproto-space-audience"}},
		Params:     rfc9651.Params{{Key: "tag", Value: "atproto-space-credential"}},
	}, httpsig.AlgorithmECDSAP256SHA256, privateKey)
	if nil != err {
		return err
	}

	signed.AddTo(r.Header)

# Accept-Signature

An Accept-Signature member (asking the other side for a signature) is [SignatureParams.Member]:

	s, err := rfc9421.SignatureParams{
		Components: []rfc9421.Component{{Name: "atproto-space-commit", Params: rfc9651.Params{{Key: "sf", Value: true}}}},
		Params:     rfc9651.Params{{Key: "keyid", Value: keyShare}, {Key: "tag", Value: "atproto-space-commit"}},
	}.Member("mac")

	// s == `mac=("atproto-space-commit";sf);keyid="did:key:…";tag="atproto-space-commit"`
*/
package rfc9421
