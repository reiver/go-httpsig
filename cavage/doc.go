/*
Package cavage implements HTTP-Signature signing and verification per draft-cavage-http-signatures-12 (draft-cavage):

https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12

This is the version of HTTP-signatures currently used by most of the Fediverse that uses HTTP-signatures (such as Mastodon, GoToSocial, Pleroma/Akkoma, Misskey, Lemmy, etc) for ActivityPub server-to-server federation.

# The Problem It Solves

You probably already know the role that TLS (HTTPS) plays to "protect" the transport layer:

	• confidentiality (through encryption) — it ensures that packets sent between the HTTP-client and the HTTP-server are encrypted,
	• server authentication — it provides the HTTP-client with a form of certainty that the HTTP-server it is talking to is the "real" one an impersonator,
	• integrity (of the connection and data) — it provides the HTTP-client and HTTP-server with a form of certainty that the packages sent between them have not been altered.

However, if an HTTP-client's HTTP-request passes through an intermediary (such as a CDN (content distribution network), a load balancer, or a proxy), then TLS terminates there (and doesn't go all the way to the "real" HTTP-server the HTTP-client was trying to talk to).
The HTTP-client "thought" it was talking to the "real" HTTP-server, but it wasn't.
For example, a proxy (HTTP) server can see the raw headers and body, modify them, and re-sign the request to the origin server.
(The "origin server" wad the "real" server.)

These servers in the middle could be malicious.
And, could do something harmful.

draft-cavage deals with this problem.
draft-cavage deals with this problem by providing: application-layer integrity.

With draft-cavage the HTTP-client signs a specific set of HTTP-headers (and optionally the body) so that even if a proxy changes other headers, the origin server can verify that the payload hasn't been tampered with.

# The Signing String (The Core Mechanism)

The clever (and painful) part of draft-cavage of this is: Canonicalization.

To create a digital signature, the HTTP-client first need a deterministic "message" to sign.
Because HTTP-headers can be reordered or contain more or less white-space and still the be the "same" HTTP-request, the HTTP-client cannot simply sign the raw  HTTP-request
—
as changing the order of HTTP-headers, or changing the white-space would change the signature.
And, we need need the signature to always be the same for the same HTTP-request.

To deal with this, the HTTP-client was construct a: Signing String.

How to construct it:

	1. Select the headers: The HTTP-client choose which headers to sign (e.g., "(request-target)", "host", "date", "digest")
	2. The "(request-target)" pseudo-header: This is a custom requirement of the specification. It combines the HTT- method and the path (e.g., get /api/v1/users). This prevents "method swapping" attacks..
	3. Concatenation: The HTTP-client create a newline-separated string of the chosen headers.

Here is what it looks like:

	(request-target): get /api/v1/users/123
	host: example.com
	date: Tue, 10 Mar 2026 15:15:10 GMT
	igest: SHA-256=base64(hash_of_body)

The Signing String is literally that text block, joined by "\n".
The HTTP-client then sign that string using its private key (RSA-SHA256 is the most common).

# Signing a Request (Client Side)

To sign an HTTP-request, first create a [Signer] with the cryptographic algorithm and HTTP-headers to sign, and then call [Signer.SignRequest] to add a Signature header to the request:

	signer := &cavage.Signer{
		Algorithm: httpsig.AlgorithmRSASHA256,
		Headers:   []string{"(request-target)", "host", "date", "digest"},
	}

	err := signer.SignRequest(privateKey, "https://example.com/users/alice#main-key", r)
	// The Signature header is now set on r. Send it normally.

The [Signer.Headers] field controls which HTTP-headers get signed.
For a Fediverse POST the HTTP-client would typically sign "(request-target)", "host", "date", and "digest".
For a GET, drop "digest".

# Verifying a Request (Server Side)

Call [VerifyRequest] with the request and a key-lookup function.
The key-lookup function resolves a keyId string to a public key.
For the Fediverse, this would typically fetch the ActivityPub actor document and extract the publicKeyPem field:

	keyLookup := func(ctx context.Context, keyID string) (crypto.PublicKey, error) {
		// fetch the actor at keyID, parse the PEM, return the public key
	}

	err := cavage.VerifyRequest(ctx, r, keyLookup)

[VerifyRequest] handles parsing the Signature header (or Authorization: Signature),
reconstructing the signing string, and checking the cryptographic signature.
*/
package cavage
