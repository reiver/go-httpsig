/*
Package cavage implements HTTP-Signature signing and verification per draft-cavage-http-signatures-12:

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

draft-cavage-http-signatures-12 deals with this problem.
draft-cavage-http-signatures-12 deals with this problem by providing: application-layer integrity.

With draft-cavage-http-signatures-12 you sign a specific set of HTTP-headers (and optionally the body) so that even if a proxy changes other headers, the origin server can verify that the payload hasn't been tampered with.

# The Signing String (The Core Mechanism)

The clever (and painful) part of draft-cavage-http-signatures-12 of this is: Canonicalization.

To create a digital signature, you first need a deterministic "message" to sign.
Because HTTP-headers can be reordered or contain various white-space, you cannot simply sign the raw buffer of the HTTP-request
—
as changing the order of HTTP-headers, or changing the white-space would change the signature.

To deal with, the HTTP-client was construct a: Signing String.

# Signing a Request (Client Side)

To sign an HTTP-request, first create a [Signer] with the cryptographic algorithm and HTTP-headers to sign, and then call [Signer.SignRequest] to add a Signature header to the request:

	signer := &cavage.Signer{
		Algorithm: httpsig.AlgorithmRSASHA256,
		Headers:   []string{"(request-target)", "host", "date", "digest"},
	}

	err := signer.SignRequest(privateKey, "https://example.com/users/alice#main-key", r)
	// The Signature header is now set on r. Send it normally.

The [Signer.Headers] field controls which HTTP-headers get signed.
For a Fediverse POST you would typically sign "(request-target)", "host", "date", and "digest".
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
