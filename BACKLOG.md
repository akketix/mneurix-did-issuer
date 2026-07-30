# Backlog — akketix/mneurix-did-issuer

> Items deferred from active wallet-expansion work, tracked here so they are
> not lost. Each item: scope, approach, risks, pre-conditions.

## B-1 — Author anonymity: rewrite git history to `Mneurix <hello@mneurix.dev>`

**Status:** BACKLOGED (not started). A coordinated effort is rewriting the
author across the OTHER mneurix repos in parallel via another agent; this item
is the did-issuer's own.

**Problem.** Every commit in this repo's history is authored/comitted under a
personal email address, not the canonical `Mneurix <hello@mneurix.dev>`. To
maintain a modicum of anonymity, the author + committer of ALL existing
commits should be rewritten to `Mneurix <hello@mneurix.dev>`.

**Scope.** All commits on `main` (and any merged feature branches' history that
is reachable). The 3 wallet-expansion PRs (#1 `17af088`, #2 `8350b6f`, #3
`79ecb25`) and everything before them.

**Going forward (DONE).** The repo's local git config is set to
`user.email=hello@mneurix.dev`, `user.name=Mneurix`, so all NEW commits are
anonymized. This item is only the HISTORICAL rewrite.

**Approach.**
1. Coordinate timing with the parallel agent doing the other repos (avoid
   mid-rewrite pushes colliding).
2. Rewrite author + committer with `git filter-repo --mailmap` (preferred) or
   `git filter-branch --env-filter` (fallback). Mailmap maps every old
   `Name <old-email>` -> `Mneurix <hello@mneurix.dev>`.
3. Force-push the rewritten `main`: `git push --force github main`.
4. Re-create the signed release tags (`v*`) on the rewritten SHAs + re-push
   (`git push --force github --tags`) — the release workflow re-signs on tag
   push; old tag objects point at dead SHAs after the rewrite.
5. Verify: `git log --format='%an <%ae>' | sort -u` shows only
   `Mneurix <hello@mneurix.dev>`.

**Pre-conditions / risks.**
- The repo is PUBLIC + branch-protected (`require PR`, `required_linear_history`,
  `Build + test + smoke` required). Force-push to `main` is blocked by
  `allow_force_pushes: false` -> temporarily relax branch protection
  (`gh api -X PUT repos/.../branches/main/protection` with
  `allow_force_pushes: true`, admin override) for the rewrite, then restore it.
  Alternatively rewrite via a fast-forward of a rewritten main if protection
  is paused by an admin.
- History rewrite changes EVERY commit SHA -> existing clones/checkouts are
  stale; anyone with a clone must reset. No public forks exist yet, so no
  downstream breakage.
- Open PRs (none at rewrite time) would dangle on old SHAs.
- GitHub PR objects (#1/#2/#3) stay "merged" but reference old SHAs (cosmetic;
  the merge commits are rewritten too).
- The signed-release cosign signatures are by TAG (not per-commit), so they
  are re-issued cleanly when tags are re-pushed (the release workflow re-runs).

**Verification of done.** `git log --all --format='%an <%ae> %cn <%ce>' | sort -u`
lists only `Mneurix <hello@mneurix.dev>`; tags re-point at rewritten SHAs; CI
green on the rewritten main.