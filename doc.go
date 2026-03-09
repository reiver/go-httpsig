/*
Package httpsig provides an implementation of HTTP signatures, supporting both draft-cavage-http-signatures-12 and RFC 9421 (HTTP Message Signatures).

This package is designed for use in the Fediverse (Mastodon, GoToSocial, Pleroma, etc.), but works for any HTTP signature use case.

The top-level package defines shared interfaces and types.
Sub-packages provide the spec-specific implementations:

	• github.com/reiver/go-httpsig/cavage — draft-cavage-http-signatures-12
	• github.com/reiver/go-httpsig/rfc9421 — RFC 9421
	• github.com/reiver/go-httpsig/fediverse — Fediverse convenience profile
*/
package httpsig
