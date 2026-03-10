/*
Package fedi provides Fediverse-compatible convenience functions for HTTP Signature signing and verification.

This package wraps [github.com/reiver/go-httpsig/cavage] with defaults and quirks handling
that make it work out-of-the-box with Mastodon, GoToSocial, Pleroma/Akkoma, Misskey, Lemmy,
PeerTube, Pixelfed, and other Fediverse implementations.

# Signing

To sign a POST request (e.g., delivering an activity to an inbox):

	body := []byte(`{"type":"Create",...}`)
	r, _ := http.NewRequest("POST", "https://remote.example/inbox", bytes.NewReader(body))
	r.Header.Set("Host", "remote.example")
	r.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	err := fedi.SignPOST(privateKey, "https://example.com/users/alice#main-key", r, body)

[SignPOST] sets the Digest header (SHA-256) and signs (request-target), host, date, and digest
using RSA-SHA256. This matches what Mastodon and other Fediverse servers expect.

To sign a GET request (e.g., fetching an actor for authorized fetch / secure mode):

	r, _ := http.NewRequest("GET", "https://remote.example/users/bob", nil)
	r.Header.Set("Host", "remote.example")
	r.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	err := fedi.SignGET(privateKey, "https://example.com/users/alice#main-key", r)

[SignGET] signs (request-target), host, and date.

For other HTTP methods, use [SignRequest], which inspects the body to determine
whether to include a Digest header.

# Verification

To verify an incoming request:

	err := fedi.VerifyRequest(ctx, r, body, keyLookup)

[VerifyRequest] is lenient in what it accepts, handling known Fediverse quirks:

  - Accepts signatures from both the Signature header and the Authorization header
  - Falls back to verifying without the query string in (request-target), for compatibility with Mastodon's historical behavior
  - Handles hs2019 algorithm by trying RSA-SHA256 first, then RSA-SHA512
  - Checks clock skew on the Date header (default tolerance: 1 hour)
  - Verifies the Digest header against the body if a Digest header is present

# Signing Conventions

This package always uses the Signature header (not Authorization: Signature) for signing.
Most Fediverse servers only parse the Signature header. The Authorization header is accepted
on the verification side for maximum tolerance.

This package never includes (created) or (expires) pseudo-headers when signing with
rsa-sha256, because Mastodon rejects them for that algorithm.

This package always uses SHA-256 for the Digest header, because Mastodon only accepts SHA-256.
*/
package fedi
