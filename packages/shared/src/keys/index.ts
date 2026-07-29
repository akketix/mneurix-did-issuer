// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** @mneurix/shared/keys — issuer key custody (ported from mneurix-lattice).
 * boot-guard is NOT ported (lattice-specific prod boot wiring); the DID issuer
 * uses its own service-token boot guard. */
export * from "./keyMaterial";
export * from "./provider";
export * from "./local-sealed";
export * from "./shamir";
export * from "./rest-encryption-guard";
