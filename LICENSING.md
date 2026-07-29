# Licensing

> Canonical source: `akketix/mneurix` → `src/pages/licensing.astro`
> (last updated 2026-07-25). This file mirrors the website's licensing terms so
> the repo + the public site stay in sync. The legal license text is in
> [`LICENSE`](./LICENSE) (Elastic License 2.0).

Last updated: 2026-07-25

MNEURIX Core infrastructure is sold as self-hostable, per-module licenses (you
install and run each module on your own servers, not ours) — not as a hosted
SaaS (software we run for you, which you log into rather than install). You run
the software on your own infrastructure; we hand you the bundle and a signed
license file. This page governs software purchases and is separate from the
site Terms of Service.

Looking to buy a module? See the Sovereign Credential Infrastructure — the
first product (pre-GA, meaning it's still in development and not yet available
to purchase).

## The license: Elastic License 2.0 (ELv2)

Our modules ship under the [Elastic License 2.0](https://elastic.co/licensing/elastic-license).
In plain terms, ELv2 lets you:

- **Use, copy, modify, and extend** the software for your own purposes,
  including internal deployment.
- **Create derivative works** (your own modified versions) and distribute them
  under the same license.
- **Self-host** for yourself or your organisation without per-seat restrictions
  on usage (no limits on how many people in your team can use it).

It does **not** let you:

- **Remove or circumvent** license keys or copy protection.
- **Offer the software to third parties as a hosted or managed service** without
  our explicit written permission. You can build on it internally; you can't
  re-sell it as a competing SaaS.

We chose ELv2 deliberately: it gives you the freedom of open source for
self-hosting and extension, while protecting us from having our own work sold
back to us as a hosted competitor. If you need rights beyond ELv2 (for example,
to operate a hosted offering), contact us for a commercial addendum.

## What you get per module

- A container image and a `docker-compose` bundle (pre-packaged software that
  runs identically on any server, plus a file that starts all the pieces with
  one command), ready to run on your infrastructure.
- An Ed25519-signed license file (cryptographically signed, so it can't be
  forged) keyed to your entitlement. The software boots only with a valid,
  unexpired license; if it expires, the software keeps running but warns you
  rather than shutting down immediately (see the module's documentation for
  grace details).
- Download links that expire after a short time and can be regenerated on
  demand, hosted on a private server — artifacts are never published publicly.
- The module's `.env` example and install runbook.

## Purchase terms

- **Merchant of Record.** Sales are processed by Paddle, the company that
  legally processes your payment and handles worldwide tax (VAT/GST/sales tax)
  collection and remittance, invoicing, and receipts. Your payment relationship
  is with Paddle, not MNEURIX.
- **Delivery.** On confirmed payment you receive a download path. Download
  links are time-limited and can be regenerated from your customer portal; the
  underlying artifacts remain available while your license is active.
- **License scope.** Each license covers one named module, for self-hosting by
  the purchasing organisation (you can't resell or host it for other companies).
  Bundles and multi-module licenses are available on request.
- **Updates.** Licenses include access to updates for the published term of the
  license. Renewal terms are shown at checkout.

## Refund policy (14-day money-back)

We offer a 14-day, no-questions-asked money-back guarantee from the date of
purchase. If the module isn't right for you, email us within 14 days and we'll
refund the full purchase price. Refunds are issued back to the original payment
method via Paddle, and your license is revoked on refund.

## No warranty

The software is provided "as is" and "as available", without warranties of any
kind, express or implied, including fitness for a particular purpose. Because
it is self-hosted software, you are responsible for operating, securing, and
backing up your own deployment. To the maximum extent permitted by law,
MNEURIX's liability is limited to the amount you paid for the module.

## Changes

We may update these terms; the "last updated" date above reflects the latest
revision. Terms in effect at the time of your purchase govern that purchase.

## Contact

For licensing questions, commercial addenda (extra contract terms for custom
deals), or refunds, get in touch.