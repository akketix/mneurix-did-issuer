# did:web Method Rubric Scoring — Mneurix DID Issuer

> The [W3C DID Method Rubric](https://w3c.github.io/did-rubric/) scores DID
> methods on decentralization, security, privacy, + interoperability. This
> document scores `did:web` as used by the Mneurix DID Issuer, with the
> multi-origin resilience extension.

## Summary

`did:web` is a "low-decentralization, high-interoperability" method. It trusts
DNS + HTTPS (the domain registrant controls the DID document). For a
self-hostable, fair-priced product this is an **accepted tradeoff** — the
operator owns their domain + their infrastructure. The multi-origin extension
mitigates single-origin availability/Integrity risks.

## Scoring

### 1. Decentralization — LOW

- **No blockchain:** the DID document is served from a web origin (HTTPS). The
  domain registrant can update or remove it.
- **Accepted for self-host:** the operator IS the domain registrant. There is no
  external party that can unilaterally revoke the DID (unlike a hosted SaaS).

### 2. Security — MEDIUM (raised by multi-origin)

- **Multi-origin resilience:** the DID document is published to 3+ independent
  origins (e.g. DO Space + GitHub Pages + a static host). Resolution fans out +
  quorums on the majority hash. A single compromised origin cannot forge a
  document (the quorum rejects the minority).
- **Key custody:** the signing key is sealed (AES-GCM) + escrowed (Shamir split).
  Rotation + signed-revocation tombstones are supported.
- **TLS:** all origin reads are over HTTPS; `http://` is rejected.

### 3. Privacy — MEDIUM

- **Pseudonymous:** the DID does not carry PII. The `did:web:<origin>:<id>` path
  segment is a server-generated identifier, not a learner name or ORCID.
- **Correlation risk:** a DID is stable (same DID across sessions), enabling
  cross-session correlation. This is inherent to `did:web` + accepted (the DID
  is the learner's verifiable identifier, not a tracking cookie).
- **No public ledger:** unlike `did:ethr`, the DID document is not published to a
  public blockchain — there is no global correlation surface.

### 4. Interoperability — HIGH

- **W3C conformant:** `did:web` is a registered DID method. Any conformant DID
  resolver can resolve the document.
- **Standard verification:** the DID document carries a Multikey public key
  (Ed25519) usable for Data-Integrity + SD-JWT verification.
- **No vendor lock-in:** the DID document is a standard JSON-LD document on a
  static host. The operator can migrate origins without changing the DID.

## Multi-origin extension (M4)

The vanilla `did:web` spec publishes to a single origin. The Mneurix extension:
1. **Publish** the document to N origins (2-phase atomic — all-or-nothing).
2. **Resolve** by fanning out to all origins + quoruming on the majority hash.
3. **Pin** the publish-time hash on the stored record so the issuer's own
   resolver detects a tampered origin.

This raises the Security score from LOW (single origin) to MEDIUM (quorum).

## Accepted tradeoffs

- **DNS/HTTPS trust:** `did:web` trusts the domain's DNS + TLS. A compromised
  domain registrar or CA could forge a DID document. Mitigated by: multi-origin
  quorum (a single origin compromise is detected) + DNSSEC (operator-deployable).
- **No key rotation history:** the DID document shows the current key, not the
  history. Revocation is via the signed-revocation tombstone (not the DID
  document itself).
- **Stable identifier:** the DID does not change across sessions (by design —
  it's the learner's verifiable identity).