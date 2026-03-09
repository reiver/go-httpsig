# HACKING.md

A `HACKING.md` file (like this one) is a document with **technical information** that provides background-information and guidance for contributors to understand, and to make changes to a project.

## HTTP Signatures: What They Are

HTTP Signatures let a sender cryptographically prove **identity** and **integrity** over parts of an HTTP message.
There are two specifications:

|                  | **draft-cavage-http-signatures**            | **RFC 9421** (Feb 2024)                          |
|------------------|---------------------------------------------|--------------------------------------------------|
| Status           | Expired individual draft (v12)              | IETF Proposed "Standard"                         |
| Headers          | Single `Signature` header                   | `Signature-Input` + `Signature`                  |
| Metadata signed? | No (attacker can alter `algorithm`/`keyId`) | Yes (`@signature-params` is signed)              |
| Multiple sigs    | No                                          | Yes (labeled: `sig1`, `proxy-sig`)               |
| Request target   | `(request-target)` pseudo-header            | `@method`, `@authority`, `@path`, `@query`, etc. |
| Body integrity   | `Digest` header (ad-hoc)                    | `Content-Digest` (RFC 9530)                      |
