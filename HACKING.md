# HACKING.md

## HTTP Signatures: What They Are

HTTP Signatures let a sender cryptographically prove **identity** and **integrity** over parts of an HTTP message.
There are two specifications:

|                  | **draft-cavage-http-signatures**            | **RFC 9421** (Feb 2024)                          |
|------------------|---------------------------------------------|--------------------------------------------------|
| Status           | Expired individual draft (v12)              | IETF Proposed "Standard"                         |
| Headers          | Single `Signature` header                   | `Signature-Input` + `Signature`                  |
| Metadata signed? | No (attacker can alter `algorithm`/`keyId`) | Yes (`@signature-params` is signed)              |
| Multiple sigs    | No | Yes (labeled: `sig1`, `proxy-sig`)     |                                                  |
| Request target   | `(request-target)` pseudo-header            | `@method`, `@authority`, `@path`, `@query`, etc. |
| Body integrity   | `Digest` header (ad-hoc)                    | `Content-Digest` (RFC 9530)                      |

---

## How the Fediverse Uses HTTP Signatures

In the Fediverse **draft-cavage-12** seems to be commonly used for all server-to-server ActivityPub federation.
I.e., it is the _standard_ on the Fediverse.
On the Fediverse, it is used for:

* **POST requests** (inbox delivery): Always signed. Headers signed: `(request-target)`, `host`, `date`, `digest`
* **GET requests** (fetching actors): Optionally signed; required in Mastodon's "authorized fetch" / secure mode
* **Algorithm**: Almost universally **RSA-SHA256** (RSASSA-PKCS1-v1_5), 2048-bit keys. `hs2019` exists but usually still means RSA-SHA256
* **Key discovery**: `keyId` in the signature is a URL pointing to an ActivityPub actor document containing a `publicKey` PEM field

### Known Fediverse Quirks

- Mastodon historically omitted query strings from `(request-target)`
- `keyId` format varies: fragment URIs (`actor#main-key`) vs path URIs (`/users/alice/main-key`)
- Clock skew tolerance ranges from 30 seconds to 12 hours across implementations
- Very little shared library code — most implementations rolled their own
- "Double-knocking" (retry with different spec version) is the interop workaround

### The Transition to RFC 9421

- Mastodon 4.4: Verifies RFC 9421 signatures
- Mastodon 4.5: Signs outgoing with RFC 9421
- Fedify (TypeScript) already supports dual-spec with capability caching
