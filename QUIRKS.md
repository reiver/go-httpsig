# QUIRKS.md — Fediverse HTTP Signature Interoperability Quirks

This document catalogs known quirks, bugs, and deviations in how Fediverse implementations handle HTTP Signatures.

---

## 1. Query String in (request-target)

Mastodon historically omitted the query string from the `(request-target)` pseudo-header, signing only the path.
GoToSocial included query parameters, which broke paged Collection fetches against Mastodon.

Both implementations now use a **double-attempt** strategy:
- **Signing:** Sign with query parameters. If the remote returns 401, retry without.
- **Verification:** Verify with query parameters. If verification fails, retry without.

**Sources:**
- [GoToSocial Query Params Issue #894](https://github.com/superseriousbusiness/gotosocial/issues/894)
- [GoToSocial HTTP Signatures Documentation](https://docs.gotosocial.org/en/latest/federation/http_signatures/)
- [Mastodon signature_verification.rb](https://github.com/mastodon/mastodon/blob/main/app/controllers/concerns/signature_verification.rb)

---

## 2. hs2019 Algorithm Interpretation

The `hs2019` algorithm string is a placeholder meaning "determine the actual algorithm from the key metadata."
Different implementations interpret it differently:

- **Mastodon:** Treats `hs2019` as **RSA-SHA256** (RSASSA-PKCS1-v1_5 with SHA-256).
- **PeerTube:** Treats `hs2019` as **RSA-SHA512**.
- **GoToSocial:** Signs outgoing as `hs2019` but actually uses RSA-SHA256. For verification, tries RSA-SHA256, RSA-SHA512, and Ed25519 in order.
- **Lemmy:** Sends `hs2019` as the algorithm string.

**Sources:**
- [PeerTube hs2019 Issue #4431](https://github.com/Chocobozzz/PeerTube/issues/4431)
- [GoToSocial HTTP Signatures Documentation](https://docs.gotosocial.org/en/latest/federation/http_signatures/)
- [SWICG ActivityPub HTTP Signatures Report](https://swicg.github.io/activitypub-http-signature/)

---

## 3. (created) and (expires) Pseudo-Headers

Mastodon **rejects** `(created)` and `(expires)` pseudo-headers unless the algorithm is `hs2019`.
Sending `algorithm="rsa-sha256"` with `(created)` in the headers list produces:

> "Invalid pseudo-header (created) for rsa-sha256"

GoToSocial v0.16.0-rc1 switched to using `(created)` instead of `Date`, which broke federation with Akkoma/Pleroma and Bookwyrm. This was reverted.
Older Pleroma versions do not support `(created)` at all.

**Sources:**
- [Mastodon signature_verification.rb](https://github.com/mastodon/mastodon/blob/main/app/controllers/concerns/signature_verification.rb)
- [GoToSocial (created) Pseudo-Header Issue #2991](https://github.com/superseriousbusiness/gotosocial/issues/2991)
- [Akkoma Signed Fetch Statistics PR #312](https://akkoma.dev/AkkomaGang/akkoma/pulls/312)

---

## 4. URL Encoding in (request-target)

Pleroma does **not** URL-decode the request-target path before constructing the signing string.
Mastodon **does** URL-decode the path.

If an inbox path contains percent-encoded characters (e.g., `%40` for `@`), one implementation will sign the encoded form and the other will verify against the decoded form, causing verification failure.

The community consensus is to use the path as-is on the wire, without decoding. However, web frameworks (Rails, ASP.NET) may automatically decode before the application sees the value.

**Security note:** Percent-encoded newlines (`%0A`) in the path could inject fake header lines into the signing string if the path is decoded before signing string construction.

**Sources:**
- [URL Encoding in request-target Issue #26](https://github.com/w3c-ccg/http-signatures/issues/26)
- [SWICG ActivityPub HTTP Signatures Report](https://swicg.github.io/activitypub-http-signature/)

---

## 5. Signature Header vs Authorization Header

The draft-cavage spec defines two equivalent mechanisms: the `Signature` header and the `Authorization` header with scheme `Signature`.

In practice, virtually all Fediverse implementations exclusively use the `Signature` header.
Mastodon's `SignedRequest` class parses from `request.headers['Signature']` and does **not** fall back to `Authorization`.

Sending `Authorization: Signature keyId=...` instead of `Signature: keyId=...` will likely be ignored by most Fediverse servers.

**Sources:**
- [Fediverse Developer Network - HTTP Signatures Reference](https://fedidevs.org/reference/signatures/)
- [Mastodon signature_verification.rb](https://github.com/mastodon/mastodon/blob/main/app/controllers/concerns/signature_verification.rb)

---

## 6. Clock Skew Tolerance

Different implementations use wildly different tolerance windows:

| Implementation | Window |
|----------------|--------|
| **Mastodon** | `CLOCK_SKEW_MARGIN = 1 hour`, `EXPIRATION_WINDOW_LIMIT = 12 hours` |
| **Pleroma/Akkoma** | Up to 2 hours old, max 40 minutes future clock skew |
| **SWICG recommendation** | "An hour plus a few minutes buffer in either direction" |
| **Some implementations** | As tight as 30 seconds |

**Sources:**
- [Mastodon signature_verification.rb](https://github.com/mastodon/mastodon/blob/main/app/controllers/concerns/signature_verification.rb)
- [SWICG ActivityPub HTTP Signatures Report](https://swicg.github.io/activitypub-http-signature/)
- [Akkoma Signed Fetch Statistics PR #312](https://akkoma.dev/AkkomaGang/akkoma/pulls/312)

---

## 7. keyId Format Divergence

Different implementations use different URI formats for `keyId`:

- **Mastodon:** Fragment URI — `https://example.com/users/alice#main-key`. Dereferencing returns the full actor document; the key is identified by the fragment.
- **GoToSocial:** Path URI — `https://example.com/users/alice/main-key`. Dereferencing returns a partial actor stub containing only the public key; the `owner` property links back to the full actor.

Receivers must handle both by fetching the `keyId` URL and possibly following the `owner` link.

If `publicKey` is an array in the actor document, the implementation must match the `keyId` against key `id` values to find the correct key.

**Sources:**
- [GoToSocial HTTP Signatures Documentation](https://docs.gotosocial.org/en/latest/federation/http_signatures/)
- [Mastodon Security Documentation](https://docs.joinmastodon.org/spec/security/)
- [SWICG ActivityPub HTTP Signatures Report](https://swicg.github.io/activitypub-http-signature/)

---

## 8. Digest Header

### Mastodon Only Accepts SHA-256

Mastodon raises a `SignatureVerificationError` if `sha-256` is not found in the Digest header.
Sending `SHA-512=...` alone will be rejected.
Mastodon validates that the decoded digest is exactly 32 bytes.

### Case Sensitivity

Mastodon lowercases the algorithm name when parsing the Digest header and checks for `sha-256`.
The canonical format sent by all implementations is uppercase `SHA-256=`.
Mixed case (e.g., `Sha-256=`) is accepted by Mastodon but may not be by other implementations.

### Empty Body

A POST with an empty body must include a Digest of the empty string:
```
SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

### Digest vs Content-Digest

RFC 9530 renames the `Digest` header to `Content-Digest`. Mastodon 4.5+ accepts both for incoming requests. Most Fediverse implementations still send the old `Digest` header.

**Sources:**
- [Mastodon signature_verification.rb](https://github.com/mastodon/mastodon/blob/main/app/controllers/concerns/signature_verification.rb)
- [Mastodon 4.5 for Developers](https://blog.joinmastodon.org/2025/10/mastodon-4-5-for-devs/)
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)

---

## 9. Base64 Encoding

All major implementations use **standard base64 with padding** (not URL-safe base64) for the `signature` value.

Mastodon uses Ruby's `Base64.strict_encode64` (standard base64, no embedded newlines).
Ruby's `Base64.encode64` inserts newlines every 60 characters per RFC 2045 — using the wrong one produces signatures with embedded newlines that will fail verification.

Some implementations have historically had bugs with padding — the Mastodon ostatus2 library had a confirmed bug where it sent base64 with padding when the Salmon spec required no padding.

**Sources:**
- [Mastodon ostatus2 Issue #4](https://github.com/mastodon/ostatus2/issues/4)
- [SocialHub: HTTP Signature Claimed Invalid](https://socialhub.activitypub.rocks/t/http-signature-claimed-to-be-invalid/3111)

---

## 10. Multi-Value Header Concatenation

The spec requires multiple values for the same header to be concatenated with `, ` (comma-space).

Pixelfed historically did **not** comma-separate values of headers with the same key, causing signature verification failures against GoToSocial and Mastodon in secure mode. This was fixed in PR #4504.

**Sources:**
- [Pixelfed HTTP Signature Issue #2935](https://github.com/pixelfed/pixelfed/issues/2935)

---

## 11. Trailing Newline in Signing String

The signing string must **not** include a trailing ASCII newline after the last header line.
Multiple SocialHub discussions document this as a common implementation mistake that causes silent verification failures.

**Sources:**
- [SocialHub: HTTP Signature Issues (Rust)](https://socialhub.activitypub.rocks/t/http-signature-issues/4227)
- [SocialHub: HTTP Signature Claimed Invalid](https://socialhub.activitypub.rocks/t/http-signature-claimed-to-be-invalid/3111)

---

## 12. Unsigned GET Requests

Pixelfed did not sign GET requests until 2021, breaking federation with any server running authorized fetch / secure mode (Mastodon, GoToSocial).

GoToSocial requires signed GET requests in all modes. Mastodon requires them when "secure mode" / "authorized fetch" is enabled.

**Sources:**
- [Pixelfed Unsigned GET Issue #1850](https://github.com/pixelfed/pixelfed/issues/1850)
- [GoToSocial HTTP Signatures Documentation](https://docs.gotosocial.org/en/latest/federation/http_signatures/)

---

## 13. PeerTube Signature Header Prefix Bug (Fixed)

PeerTube v2.1.1 prefixed the `Signature` header value with the literal string `"Signature "`, producing:
```
Signature: Signature keyId=...
```

This was caused by using an older version (1.2.0) of the `http-signature` npm library. Fixed in PeerTube v2.2.

**Sources:**
- [PeerTube Incorrect Signatures Issue #3075](https://github.com/Chocobozzz/PeerTube/issues/3075)

---

## 14. Misskey Digest/Host Validation Bug (Fixed, CVE-2023-49079)

Misskey prior to v2023.11.1 did **not** validate the `Digest` or `Host` headers — it only checked that the cryptographic signature existed and was valid. This allowed attackers to craft requests with valid signatures but spoofed bodies, impersonating any remote user.

Rated CVSS 9.3 Critical.

**Sources:**
- [Misskey CVE-2023-49079 Advisory](https://github.com/misskey-dev/misskey/security/advisories/GHSA-3f39-6537-3cgc)

---

## 15. Reverse Proxy / Host Header Issues

When a reverse proxy (nginx, CloudFront, etc.) rewrites the `Host` header, the signed `host` value won't match what the application sees. This must be handled via configuration (`proxy_set_header Host $host` in nginx).

A documented real-world case: Ghost on AWS behind CloudFront had federation break because CloudFront sends `CloudFront-Forwarded-Proto` instead of the standard `X-Forwarded-Proto`, causing the app to generate HTTP URLs instead of HTTPS, breaking actor ID matching and signature verification.

**Sources:**
- [Ghost on AWS ActivityPub Federation](https://subaud.io/blog/ghost-on-aws-activitypub-federation/)
- [SocialHub: HTTP Signature Issues (Rust)](https://socialhub.activitypub.rocks/t/http-signature-issues/4227)

---

## 16. IDN / Punycode in Host Headers

Instances with non-ASCII domain names (e.g., Cyrillic) store the punycode version internally but may receive the Unicode version in incoming requests (or vice versa).

The community consensus is to use ASCII/punycode in all URLs and `Host` headers. If a remote server sends a Unicode `Host` and the local server compares against punycode, signature verification of the `host` header will fail.

**Sources:**
- [SocialHub: IDN/Punycode/Non-Latin Domain Names](https://socialhub.activitypub.rocks/t/idn-punycode-non-latin-domain-names/610)

---

## 17. HTTP/1.1 Line Folding

The canonicalization algorithm in draft-cavage does not account for HTTP/1.1 obs-fold (continuation lines starting with whitespace), even though a non-normative example in the spec shows one.
While line folding is deprecated, it could still appear from legacy clients or proxies.

**Sources:**
- [HTTP Header Line Folding Issue #1306](https://github.com/httpwg/http-extensions/issues/1306)

---

## 18. Shared Library Landscape

Very few implementations share signature code:

| Shared Library | Used By |
|----------------|---------|
| `@peertube/http-signature` (npm) | PeerTube, Misskey |
| `pleroma/http_signatures` (Elixir) | Pleroma, Mobilizon |
| Everyone else | Custom implementations |

This means the same spec ambiguity can be interpreted differently by 10+ independent codebases.

**Sources:**
- [SWICG ActivityPub HTTP Signatures Report](https://swicg.github.io/activitypub-http-signature/)
- [Fediverse Developer Network - HTTP Signatures Reference](https://fedidevs.org/reference/signatures/)
