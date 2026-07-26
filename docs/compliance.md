# Compliance — Mneurix DID Issuer

> Standards, security, and privacy mapping for the `mneurix-did-issuer` service.
> Each standard maps to a concrete requirement this component meets.

## W3C Verifiable Credentials 2.0

The issuer mints W3C VC 2.0 credentials in two envelope formats:
- **Data-Integrity (OB3)** — Ed25519 signatures over JCS-canonical verify data,
  with a `proof` block carrying `proofValue` (base58btc multibase).
- **SD-JWT VC (RFC 9901)** — Ed25519-signed SD-JWT with selective disclosures +
  a KB-JWT holder binding on verification.

**Requirement met:** credentials are syntactically valid W3C VC 2.0 + verifiable
by any conformant verifier without trusting the issuer's database.

## VC-JOSE-COSE (W3C Recommendation)

The SD-JWT VC path uses JOSE (JWS) with Ed25519 (EdDSA). The issuer publishes its
JWKS at `/.well-known/jwt-vc-issuer` + `/.well-known/jwks.json`.

**Requirement met:** key discovery is via well-known endpoints; alg is pinned
(EdDSA); no `none` alg is accepted on verify.

## RFC 9901 — SD-JWT VC

The SD-JWT issuance (`POST /v1/vcs:issue` with `format: "sd-jwt"`) produces an
SD-JWT VC with `_sd` selective-disclosure hashes. Verification rejects
unreferenced disclosures (§7.1) + validates the KB-JWT holder binding.

**Requirement met:** selective disclosures are cryptographically bound; the
verifier rejects tampered or unreferenced claims.

## did:web

The issuer mints `did:web` identifiers + publishes DID documents to multiple
origins (multi-cloud resilience). Resolution fans out to all origins + quorums
on the majority hash. The DID document carries the issuer's Ed25519 public key
(Multikey multibase).

**Requirement met:** DID documents are resolvable + the key is discoverable via
the DID document's `verificationMethod`.

## Status List 2021

Issued credentials carry a `credentialStatus` entry pointing to a Bitstring
Status List. Revocation flips the bit; the list is re-signed on each mutation.
Verifiers fail-closed when the status list is unreachable or tampered.

**Requirement met:** revocation is verifiable + tamper-evident; the status list
is a separate, signed resource.

## OWASP ASVS L2

- **V2 (Authn):** operator auth via service-token (constant-time compare) +
  two-person revocation quorum.
- **V3 (Session):** no server-side sessions (stateless service-token auth).
- **V5 (Validation):** all request bodies validated with zod; no `as` casts on
  untrusted input.
- **V6 (Crypto):** Ed25519 only; no SHA-1; no ECB; canonicalization via JCS.
- **V9 (Comms):** TLS required for remote origins; `http://` rejected.
- **V13 (API):** rate-limiting + service-token on all mutating endpoints.

**Requirement met:** the service targets ASVS L2 controls.

## GDPR / FERPA / POPIA

- **Data minimization:** the issuer stores only the DID, the public key, +
  status-list indices — no learner PII. The `learnerId` is a pseudonym
  (HMAC'd by the lattice, not the issuer).
- **Right to erasure:** revoking a credential flips the status-list bit (the
  credential is unusable but the immutable record is retained for the dispute
  window per R17). The DID document may be tombstoned.
- **Data residency:** self-hosted — the operator controls where the data lives.
  No data leaves the operator's infrastructure.

**Requirement met:** the issuer holds no learner PII; erasure is via revocation.

## Key custody (G-CRYPTO-1)

The issuer's Ed25519 master key is sealed (AES-GCM) with a passphrase. Key
escrow (Shamir split) is supported. The plaintext PEM provider is forbidden in
production (boot guard). Key rotation + signed-revocation tombstones are
supported.

**Requirement met:** the signing key is sealed at rest + escrowed.