# Data Processing Agreement (DPA) Template — Mneurix DID Issuer

> Fill-in template. Replace `[BRACKETS]` with the operator's details. This DPA
> accompanies the commercial license for self-hosted deployments of the
> `mneurix-did-issuer` service.

## 1. Parties

- **Processor:** [Operator name] (the self-hosting organization).
- **Controller:** [Same as Processor for self-host, or the data controller if
  the Operator processes on behalf of a third party].
- **Effective date:** [DATE].

## 2. Scope

This DPA covers the processing of personal data by the `mneurix-did-issuer`
service, which mints + resolves `did:web` identifiers and issues/verifies W3C
Verifiable Credentials.

## 3. Data processed

The DID issuer processes:
- **DID identifiers** (`did:web:<origin>:<id>`) — pseudonymous, not PII.
- **Public keys** (Ed25519) — public material, not PII.
- **Status-list indices** — integers, not PII.
- **Audit log entries** — operator ids + timestamps (governance attribution).

The DID issuer does **NOT** process learner names, emails, ORCID iDs, biometric
data, or any direct identifiers. The `learnerId` passed by the lattice is an
HMAC'd pseudonym (not recomputable without the lattice's pepper).

## 4. Data residency

The service is self-hosted on the Operator's infrastructure. No data leaves the
Operator's infrastructure. The Operator is responsible for physical + logical
access controls.

## 5. Retention

- **DID documents:** retained for the lifetime of the identifier (the operator
  controls deletion).
- **Status lists:** retained for the credential validity period + the dispute
  window (R17).
- **Audit log:** retained per the Operator's audit-retention policy (the lattice
  defaults to 7 years for governance events).

## 6. Sub-processors

None. The service is self-hosted; the Operator is the sole processor.

## 7. Data subject rights

Erasure requests are handled by the **lattice** (the system of record for learner
PII). The DID issuer revokes the credential (status-list bit flip) on
instruction from the lattice. The DID document may be tombstoned.

## 8. Security measures

See `docs/compliance.md` (OWASP ASVS L2, key custody, TLS).

## 9. Breach notification

The Operator notifies affected data subjects per applicable law (GDPR Art. 34,
POPIA §70). The DID issuer's audit log supports breach investigation.

## 10. Governing law

[JURISDICTION].