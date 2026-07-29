# Security policy

Thank you for helping keep Mneurix DID Issuer + its users safe.

## Reporting a vulnerability (private disclosure)

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately so they can be triaged + fixed before public
disclosure. Preferred channels, in order:

1. **GitHub Security Advisory (private vulnerability reporting).** Go to the
   **Security** tab → "Report a vulnerability". This is encrypted + visible only
   to the repository maintainers.
2. **Email.** Send to the security contact listed on the mainpage
   (`akketix/mneurix` → contact). Include:
   - a description of the issue + its impact,
   - the affected version/commit,
   - steps to reproduce or a proof-of-concept,
   - your suggested fix (if any), and
   - how you'd like to be credited.

## What to include / scope

In scope: the `mneurix-did-issuer` engine source — key custody, auth, crypto
(Ed25519 / SD-JWT / did:web / status-list), input validation, the CI/release
supply chain, and any path that could expose a private key, forge a credential,
bypass auth, or phone-home/leak data.

Out of scope: self-hosted misconfiguration, dependency vulnerabilities already
tracked in `npm audit` / Trivy (report those upstream), or issues that require
already-compromised customer keys.

## Response

We acknowledge reports promptly, triage within a reasonable window, and
coordinate a fix + disclosure timeline with you. Safe-harbor: we will not take
legal action against good-faith security research.

## Security posture (what this repo already does)

- Ed25519-only (no `none`/alg-confusion); holder `cnf.jwk` pinned to Ed25519 on
  KB-JWT verify.
- Sealed-key custody (AES-GCM) + prod boot guard (refuses plaintext keys).
- Per-install DEK salt; service-token + operator-role auth on all mutations
  (refused in production if operators are unset).
- No phone-home / no telemetry / no DRM / no obfuscation — license verify + meter
  are local/offline.
- CI hard gate + Trivy secret scan (hard-fail) + signed release images
  (cosign/Sigstore) + pinned actions + base-image digest.