/*
Package cavage implements HTTP Signature signing and verification per draft-cavage-http-signatures-12.

This is the version of HTTP signatures used by the Fediverse (Mastodon, GoToSocial, Pleroma/Akkoma, Misskey, Lemmy, etc.) for ActivityPub server-to-server federation.

# Signing a Request (Client Side)

To sign an HTTP request, first create a [Signer] with the cryptographic algorithm and HTTP headers to sign, and then call [Signer.SignRequest] to add a Signature header to the request:

	signer := &cavage.Signer{
		Algorithm: httpsig.AlgorithmRSASHA256,
		Headers:   []string{"(request-target)", "host", "date", "digest"},
	}

	err := signer.SignRequest(privateKey, "https://example.com/users/alice#main-key", r)
	// The Signature header is now set on r. Send it normally.

The [Signer.Headers] field controls which HTTP headers get signed.
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
