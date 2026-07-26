# Multi-Cloud DID Origin Runbook — Mneurix DID Issuer

> The M4 multi-origin mechanism publishes the DID document to N independent
> origins + resolves by fanning out + quoruming on the majority hash. This
> runbook documents the **real cloud publishers** (deferred from M4 — the
> mechanism was built against local HTTP test origins). The `LocalHttpPublisher`
> is retained for tests.

## Architecture

```
issuer ──publish──► origin-1 (DO Space)    ─┐
        ──publish──► origin-2 (GitHub Pages) ├─► resolver (fanout + quorum)
        ──publish──► origin-3 (static host) ─┘
```

- **Publish** (2-phase atomic): the document is uploaded to all N origins; if
  any upload fails, the publish is rolled back (no partial publish).
- **Resolve**: the resolver fetches from all N origins + quorums on the majority
  hash. A single compromised/stale origin is outvoted.
- **Pin**: the publish-time hash is stored on the issuer's record so its own
  resolver detects a tampered origin.

## Origin providers

### 1. DigitalOcean Spaces (S3-compatible)

- **Bucket:** `did-docs.<org>` (public-read).
- **URL:** `https://did-docs.<org>.<region>.cdn.digitaloceanspaces.com/<did-path>/did.json`
- **Publish:** `PUT` the DID document JSON to the bucket path.
- **Auth:** Spaces access key + secret (env: `MNEURIX_DID_ORIGIN_DO_KEY` /
  `MNEURIX_DID_ORIGIN_DO_SECRET`).
- **CORS:** the bucket must allow public GET (the resolver fetches without auth).

### 2. GitHub Pages (static)

- **Repo:** `<org>/did-docs` (public, GitHub Pages enabled on the `main` branch).
- **URL:** `https://<org>.github.io/did-docs/<did-path>/did.json`
- **Publish:** commit the DID document JSON to the repo + push. GitHub Pages
  serves it after a build (seconds).
- **Auth:** GitHub PAT with `repo` scope (env: `MNEURIX_DID_ORIGIN_GH_TOKEN`).
- **Note:** GitHub Pages has a deploy delay (seconds to minutes). The quorum
  handles this — the resolver waits for the majority, not all.

### 3. Static host (operator-supplied)

- **URL:** `https://did.<operator-domain>/<did-path>/did.json`
- **Publish:** `PUT` or `scp` the document to the operator's static host.
- **Auth:** operator-defined (e.g. SSH key, bearer token).

## Configuration

Set the origins in the did-issuer env (`.env.do` / `.env.onprem`):

```env
MNEURIX_DID_ORIGINS=https://did-docs.<org>.<region>.cdn.digitaloceanspaces.com,https://<org>.github.io/did-docs,https://did.<operator-domain>
MNEURIX_DID_ORIGIN_DO_KEY=...
MNEURIX_DID_ORIGIN_DO_SECRET=...
MNEURIX_DID_ORIGIN_GH_TOKEN=...
```

The issuer fans out to all configured origins on publish + resolve.

## LocalHttpPublisher (tests)

The `LocalHttpPublisher` (M4) publishes to local HTTP endpoints for integration
tests. It is NOT used in production. Set `MNEURIX_DID_ORIGINS=http://localhost:9001,http://localhost:9002`
in tests.

## Going online (checklist)

1. Provision 3 origins (DO Space + GitHub Pages + a static host).
2. Set `MNEURIX_DID_ORIGINS` + the origin credentials in the did-issuer env.
3. Mint a test DID + verify it resolves from all 3 origins (quorum).
4. Simulate an origin failure (take one down) + verify the resolver still
   succeeds (majority quorum).
5. Simulate a tampered origin (serve a different document) + verify the resolver
   rejects the minority (quorum).

## Quorum + integrity

- **N=3, M=2:** the resolver needs 2 matching hashes. One tampered/stale origin
  is outvoted.
- **N=5, M=3:** higher resilience (2 origins can fail/tamper).
- The publish-time hash is pinned on the issuer's record; the issuer's own
  resolver detects a tampered origin even if the quorum passes (defense-in-depth).