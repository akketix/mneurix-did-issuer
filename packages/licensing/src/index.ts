// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * @mneurix/licensing — on-prem platform licensing (Phase F).
 *
 * Lean, tamper-evident, air-gap-friendly licensing:
 *
 *   - A `PlatformLicense` is a flat JSON object (orgId, product, tier,
 *     validUntil, seats?, issuedAt, version, mneurixKeyId) + a base64 Ed25519
 *     `signature` over the JCS-canonical license-minus-signature. Mneurix signs
 *     it with the license-signing key; the on-prem install verifies it against
 *     an embedded Mneurix public key — no network required.
 *
 *   - `assertPlatformLicense` is the boot gate. It HARD-REFUSES (throws) only
 *     when the license file is missing or its signature is invalid — i.e. the
 *     install is not licensed at all. A validly-signed but EXPIRED license
 *     boots with a warning (warn-only, never a hard stop on expiry); at
 *     `validUntil + grace` the install DEGRADES (proctoring disabled + online
 *     refresh stops). Services keep booting.
 *
 *   - `refreshLicenseOnline` is a best-effort, non-blocking refresh: if a
 *     `MNEURIX_LICENSE_SERVER_URL` is set + reachable, it can apply a denylist
 *     or shorten validity. Network failure is a no-op (fall back to the
 *     offline validUntil). It stops once degraded.
 *
 * Everything is unit-testable via an injected `now()` + a mock `fetcher`.
 */
import { sign, verify, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import canonicalize from "canonicalize";

const MS_PER_DAY = 86_400_000;
const DEFAULT_GRACE_DAYS = 90;
/** Trial window (days) for unlicensed installs — test before buying. */
const DEFAULT_TRIAL_DAYS = 90;

/** Build-time minimum license version floor (CISO F65). Licenses with a
 * `version` below this are rejected by `assertPlatformLicense` even when
 * signature-valid — prevents an attacker (or a stale Mneurix key) from
 * relying on a legacy license format. Overridable via opts for tests. */
export const MIN_LICENSE_VERSION = 1;

/** Default read-only pinned-pubkey keyring path. Agent 3 mounts this
 * read-only into the on-prem image so the operator cannot swap the
 * verification key (CISO F4). */
const DEFAULT_PUBKEY_FILE = "/app/keys/license-signing.pub";

/** Wildcard key id: a keyring entry under this kid verifies ANY license
 * `mneurixKeyId`. Used ONLY for the single-pinned-pubkey escape (raw PEM
 * file or a directly-injected `pubKeyPem` in dev/test). A JSON kid→pem
 * keyring uses real kids and rejects un-pinned ones (CISO F38). */
export const LICENSE_WILDCARD_KID = "*";

/** A license-signing keyring: `mneurixKeyId → Ed25519 public key PEM`. */
export type LicenseKeyring = Map<string, string>;

// ---------------------------------------------------------------------------
// Schema + signature
// ---------------------------------------------------------------------------

export const PlatformLicenseSchema = z.object({
	orgId: z.string().min(1),
	product: z.enum(["onprem", "did-issuer-onprem", "proctoring-onprem"]),
	tier: z.string().min(1),
	licenseType: z.enum(["personal", "commercial"]),
	teamSize: z.enum(["solo", "small", "large"]).optional(),
	validUntil: z.string().datetime({ offset: true }).optional(),
	seats: z.number().int().positive().optional(),
	issuedAt: z.string().datetime({ offset: true }),
	version: z.number().int().min(1),
	/** Mneurix license-signing key id (identifies which public key verifies). */
	mneurixKeyId: z.string().min(1),
	/** base64 Ed25519 over JCS(canonicalLicenseInput(license minus signature)). */
	signature: z.string().min(1),
});
export type PlatformLicense = z.infer<typeof PlatformLicenseSchema>;

/** The unsigned license (for signing / canonical input). */
export type UnsignedPlatformLicense = Omit<PlatformLicense, "signature">;

/** Canonical string to sign/verify: JCS of the license minus `signature`. */
export function canonicalLicenseInput(lic: UnsignedPlatformLicense): string {
	const canon = canonicalize(lic);
	if (!canon) throw new Error("license canonicalization failed");
	return canon;
}

/** Sign an unsigned license with an Ed25519 private key (PEM). Returns base64. */
export function signLicense(
	unsigned: UnsignedPlatformLicense,
	privateKeyPem: string,
): string {
	const data = Buffer.from(canonicalLicenseInput(unsigned), "utf8");
	return sign(null, data, createPrivateKey(privateKeyPem)).toString("base64");
}

/** Verify a license's signature against an Ed25519 public key (PEM). */
export function verifyLicense(
	lic: PlatformLicense,
	publicKeyPem: string,
): boolean {
	try {
		const { signature, ...rest } = lic;
		const sig = Buffer.from(signature, "base64");
		const data = Buffer.from(canonicalLicenseInput(rest), "utf8");
		return verify(null, data, createPublicKey(publicKeyPem), sig);
	} catch {
		return false;
	}
}

/** Verify a license against a pinned keyring (CISO F4 + F38). Selects the
 * public key by `lic.mneurixKeyId`; falls back to the wildcard entry for the
 * single-pinned-pubkey case. Returns false if the kid is not pinned (no
 * wildcard) — the caller MUST treat that as "not licensed". */
export function verifyLicenseWithKeyring(
	lic: PlatformLicense,
	keyring: LicenseKeyring,
): boolean {
	const pem =
		keyring.get(lic.mneurixKeyId) ?? keyring.get(LICENSE_WILDCARD_KID);
	if (!pem) return false; // un-pinned mneurixKeyId → reject
	return verifyLicense(lic, pem);
}

/** Load a pinned keyring from a read-only file (CISO F4). Supports two
 * shapes: a JSON object `{ kid: pem }` (or `[{ kid, pem }]`) for multi-key
 * rotation (F38), or a raw SPKI PEM for a single pinned key (mapped to the
 * wildcard kid). Returns null if the file is missing or unrecognized. */
export function loadLicenseKeyringFromFile(
	path: string,
): LicenseKeyring | null {
	if (!existsSync(path)) return null;
	let raw: string;
	try {
		raw = readFileSync(path, "utf8").trim();
	} catch {
		return null;
	}
	// JSON map / array first.
	try {
		const parsed = JSON.parse(raw) as unknown;
		const map = new Map<string, string>();
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			for (const [kid, pem] of Object.entries(
				parsed as Record<string, unknown>,
			)) {
				if (typeof pem === "string" && pem.includes("-----BEGIN")) {
					map.set(kid, pem);
				}
			}
		} else if (Array.isArray(parsed)) {
			for (const e of parsed) {
				if (
					e &&
					typeof (e as { kid?: unknown }).kid === "string" &&
					typeof (e as { pem?: unknown }).pem === "string"
				) {
					map.set((e as { kid: string }).kid, (e as { pem: string }).pem);
				}
			}
		}
		if (map.size > 0) return map;
	} catch {
		// Not JSON — fall through to raw PEM.
	}
	// Raw SPKI PEM: single pinned key, wildcard kid (pubkey still pinned).
	if (raw.includes("-----BEGIN")) {
		return new Map([[LICENSE_WILDCARD_KID, raw]]);
	}
	return null;
}

// ---------------------------------------------------------------------------
// Boot guard + license state
// ---------------------------------------------------------------------------

export class PlatformLicenseError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "PlatformLicenseError";
	}
}

export interface LicenseState {
	loaded: boolean;
	validSignature: boolean;
	expired: boolean;
	degraded: boolean;
	/** True if no license file is present (running in trial mode). */
	unlicensed: boolean;
	/** True if the trial window has expired (no license + past the trial days). */
	trialExpired: boolean;
	orgId?: string;
	validUntil?: string;
	graceDays: number;
	licenseType?: "personal" | "commercial";
	teamSize?: "solo" | "small" | "large";
}

let licenseState: LicenseState | null = null;

/** Reset the module-level state (test helper). */
export function resetLicenseState(): void {
	licenseState = null;
}

/** Current license state, or null if the boot guard has not run. */
export function getLicenseState(): LicenseState | null {
	return licenseState;
}

/** Proctoring is allowed unless the license is degraded (warn-only model). */
export function isProctoringAllowed(): boolean {
	return !(licenseState?.degraded ?? false);
}

/** True once the install is past the grace window (validUntil + grace). */
export function isLicenseDegraded(): boolean {
	return licenseState?.degraded ?? false;
}

export interface AssertPlatformLicenseOptions {
	/** Path to license.json. Defaults to data/license.json (or $MNEURIX_LICENSE_FILE). */
	licensePath?: string;
	/** Mneurix license-signing public key (PEM). DEV/TEST ONLY — a
	 * directly-injected single pinned key. In an on-prem build this is IGNORED
	 * (CISO F4: the verification key is pinned in the image, never read from
	 * operator-writable env). */
	pubKeyPem?: string;
	/** Pinned keyring (kid → PEM) for multi-key verification (CISO F38).
	 * Takes precedence over `pubKeyFile` and `pubKeyPem`. */
	keyring?: LicenseKeyring;
	/** Path to a read-only pinned-pubkey keyring file (CISO F4). Defaults to
	 * $MNEURIX_LICENSE_PUBKEY_FILE or `/app/keys/license-signing.pub`. */
	pubKeyFile?: string;
	/** True for the baked on-prem image (CISO F3). When true the boot guard
	 * runs the hard gate REGARDLESS of `MNEURIX_ENV` (the operator cannot
	 * unset the baked `MNEURIX_ON_PREM=1`), and the verification key MUST
	 * come from the pinned keyring file — `pubKeyPem` is ignored. Defaults to
	 * `process.env.MNEURIX_ON_PREM === "1"`. */
	onPrem?: boolean;
	/** Minimum license version floor (CISO F65). Defaults to
	 * `MIN_LICENSE_VERSION`. Licenses with `version <` this are rejected. */
	minLicenseVersion?: number;
	/** Grace window in days after validUntil before degrade. Default 90. */
	graceDays?: number;
	/** Trial window in days for unlicensed installs. Default 90. */
	trialDays?: number;
	/** Path to the first-run timestamp file (for the trial). Defaults to data/first-run.json or $MNEURIX_FIRST_RUN_FILE. */
	firstRunPath?: string;
	/** Injectable clock for tests. Defaults to Date.now. */
	now?: () => number;
	/** Environment: "production" triggers the hard gate (mirrors the other boot
	 * guards). Anything else is a no-op unless MNEURIX_LICENSE_REQUIRED=true or
	 * `onPrem` is true. Defaults to process.env.MNEURIX_ENV. */
	env?: string;
}

/**
 * The boot gate. Loads + verifies the platform license.
 *
 * THROWS (refuses to boot) only when:
 *   - the license file is missing, OR
 *   - it fails to parse, OR
 *   - its signature is invalid (not licensed at all).
 *
 * For a validly-signed but EXPIRED license: does NOT throw — sets `expired`
 * (+ `degraded` once past the grace window) and warns on boot. Services keep
 * booting (warn-only expiry per the Phase F decision).
 */

/** Pure expiry evaluation (extracted for lower complexity + direct unit testing).
 * expired = now past validUntil; degraded = expired AND past the grace window. */
export function evaluateLicenseExpiry(
	validUntil: string | undefined,
	graceDays: number,
	nowMs: number,
): { expired: boolean; degraded: boolean } {
	if (!validUntil) return { expired: false, degraded: false }; // perpetual license — never expires
	const untilMs = Date.parse(validUntil);
	const expired = nowMs > untilMs;
	const degraded = expired && nowMs > untilMs + graceDays * MS_PER_DAY;
	return { expired, degraded };
}

export function assertPlatformLicense(
	opts: AssertPlatformLicenseOptions,
): LicenseState {
	const onPrem = opts.onPrem ?? process.env.MNEURIX_ON_PREM === "1";
	const env = opts.env ?? process.env.MNEURIX_ENV;
	const isProd = env === "production";
	const forced = process.env.MNEURIX_LICENSE_REQUIRED === "true";
	if (!onPrem && !isProd && !forced) {
		return {
			loaded: false,
			validSignature: false,
			expired: false,
			degraded: false,
			unlicensed: false,
			trialExpired: false,
			graceDays: opts.graceDays ?? DEFAULT_GRACE_DAYS,
		};
	}

	const path =
		opts.licensePath ?? process.env.MNEURIX_LICENSE_FILE ?? "data/license.json";

	// --- Trial mode: no license file → 90-day evaluation window (not a hard refuse) ---
	if (!existsSync(path)) {
		const firstRunPath =
			opts.firstRunPath ?? process.env.MNEURIX_FIRST_RUN_FILE ?? "data/first-run.json";
		const nowMs = (opts.now ?? Date.now)();
		let firstRunMs: number;
		if (existsSync(firstRunPath)) {
			try {
				firstRunMs = Date.parse(JSON.parse(readFileSync(firstRunPath, "utf8")).firstRun);
			} catch {
				firstRunMs = nowMs; // corrupt first-run → reset the trial
			}
		} else {
				firstRunMs = nowMs;
				try {
					mkdirSync(dirname(firstRunPath), { recursive: true });
					writeFileSync(firstRunPath, JSON.stringify({ firstRun: new Date(firstRunMs).toISOString() }), { mode: 0o640 });
				} catch {
					// can't persist the first-run → trial starts now each boot (can't enforce)
				}
		}
		const trialDays = opts.trialDays ?? DEFAULT_TRIAL_DAYS;
		const trialExpired = nowMs > firstRunMs + trialDays * MS_PER_DAY;
		const state: LicenseState = {
			loaded: false,
			validSignature: false,
			expired: false,
			degraded: false,
			unlicensed: true,
			trialExpired,
			graceDays: opts.graceDays ?? DEFAULT_GRACE_DAYS,
		};
		licenseState = state;
		if (trialExpired) {
			console.warn(
				`[license] TRIAL EXPIRED: no license registered + the ${trialDays}-day evaluation period has ended. Issuance is disabled. Register at https://mneurix.dev/credential-infrastructure`,
			);
		} else {
			console.warn(
				`[license] TRIAL: no license registered — running the ${trialDays}-day evaluation period. Register at https://mneurix.dev/credential-infrastructure`,
			);
		}
		return state;
	}

	// --- Licensed mode: license file present → resolve the keyring + verify ---
	let keyring = opts.keyring ?? null;
	if (!keyring) {
		// C1 fix: on-prem ignores the operator-set MNEURIX_LICENSE_PUBKEY_FILE env var
		// (the operator could point it at their own key → forge a license). Only the
		// baked DEFAULT_PUBKEY_FILE or an explicit opts.pubKeyFile (from the service
		// code, not the operator) is trusted on-prem.
		const file = onPrem
			? (opts.pubKeyFile ?? DEFAULT_PUBKEY_FILE)
			: (opts.pubKeyFile ?? process.env.MNEURIX_LICENSE_PUBKEY_FILE ?? DEFAULT_PUBKEY_FILE);
		keyring = loadLicenseKeyringFromFile(file);
	}
	if (onPrem && !keyring) {
		throw new PlatformLicenseError(
			`on-prem build requires a pinned license-signing keyring file (MNEURIX_LICENSE_PUBKEY_FILE or ${DEFAULT_PUBKEY_FILE}) — refusing to boot without a Mneurix-pinned verification key (CISO F4).`,
		);
	}
	if (!keyring && opts.pubKeyPem) {
		keyring = new Map([[LICENSE_WILDCARD_KID, opts.pubKeyPem]]);
	}
	if (!keyring) {
		throw new PlatformLicenseError(
			"a pinned license-signing keyring (file or pubKeyPem) is required to verify the platform license.",
		);
	}

	let raw: string;
	try {
		raw = readFileSync(path, "utf8");
	} catch (e) {
		throw new PlatformLicenseError(`could not read license file: ${String(e)}`);
	}
	const parsed = PlatformLicenseSchema.safeParse(JSON.parse(raw));
	if (!parsed.success) {
		throw new PlatformLicenseError(
			`license file is not a valid PlatformLicense: ${parsed.error.message}`,
		);
	}
	const lic = parsed.data;
	if (!verifyLicenseWithKeyring(lic, keyring)) {
		const kidPinned =
			keyring.has(lic.mneurixKeyId) || keyring.has(LICENSE_WILDCARD_KID);
		throw new PlatformLicenseError(
			kidPinned
				? "platform license signature is invalid — on-prem refuses to boot (Phase F). Obtain a valid license at https://mneurix.dev/credential-infrastructure"
				: `platform license mneurixKeyId "${lic.mneurixKeyId}" is not in the pinned keyring — on-prem refuses to boot (CISO F4). See https://mneurix.dev/credential-infrastructure`,
		);
	}
	const minVer = opts.minLicenseVersion ?? MIN_LICENSE_VERSION;
	if (lic.version < minVer) {
		throw new PlatformLicenseError(
			`platform license version ${lic.version} is below the minimum ${minVer} — on-prem refuses to boot (CISO F65).`,
		);
	}

	const graceDays = opts.graceDays ?? DEFAULT_GRACE_DAYS;
	const nowMs = (opts.now ?? Date.now)();
	const { expired, degraded } = evaluateLicenseExpiry(
		lic.validUntil,
		graceDays,
		nowMs,
	);

	const state: LicenseState = {
		loaded: true,
		validSignature: true,
		expired,
		degraded,
		unlicensed: false,
		trialExpired: false,
		orgId: lic.orgId,
		...(lic.validUntil ? { validUntil: lic.validUntil } : {}),
		graceDays,
		licenseType: lic.licenseType,
		...(lic.teamSize ? { teamSize: lic.teamSize } : {}),
	};
	licenseState = state;

	if (degraded) {
		console.warn(
			`[license] DEGRADED: license for ${lic.orgId} expired ${lic.validUntil ?? "(perpetual)"} and is past the ${graceDays}-day grace. Renew at https://mneurix.dev/credential-infrastructure`,
		);
	} else if (expired) {
		console.warn(
			`[license] EXPIRED: license for ${lic.orgId} expired ${lic.validUntil}. Booting with a warning. Renew within the ${graceDays}-day grace at https://mneurix.dev/credential-infrastructure`,
		);
	}
	return state;
}

// ---------------------------------------------------------------------------
// Best-effort online refresh (never blocks boot, never throws past the caller)
// ---------------------------------------------------------------------------

export interface RefreshLicenseOnlineOptions {
	/** License-server base URL (MNEURIX_LICENSE_SERVER_URL). Omit to skip. */
	serverUrl?: string;
	orgId: string;
	/** Injectable fetcher for tests. Defaults to global fetch. */
	fetcher?: typeof fetch;
	/** Injectable clock for tests. Defaults to Date.now. */
	now?: () => number;
}

/**
 * Best-effort, non-blocking online refresh. If a license server is reachable,
 * it can apply a denylist (revoke) or shorten validity; on any failure it is a
 * no-op (the offline file's validUntil stands). STOPS once the license is
 * degraded. Always resolves (never rejects) — callers fire-and-forget it.
 */
export async function refreshLicenseOnline(
	opts: RefreshLicenseOnlineOptions,
): Promise<void> {
	// Stop refreshing once degraded (per the Phase F decision).
	if (licenseState?.degraded) return;
	if (!opts.serverUrl) return;
	const fetcher = opts.fetcher ?? fetch;
	try {
		const url = new URL("/v1/check", opts.serverUrl);
		url.searchParams.set("orgId", encodeURIComponent(opts.orgId));
		const res = await fetcher(url, { headers: { accept: "application/json" } });
		if (!res.ok) return;
		const body = (await res.json()) as {
			revoked?: boolean;
			validUntil?: string;
		};
		if (body.revoked) {
			// A revoked license degrades immediately (denylist).
			if (licenseState) licenseState.degraded = true;
			console.warn(
				`[license] online refresh: license for ${opts.orgId} is revoked by the denylist — degrading.`,
			);
			return;
		}
		if (body.validUntil && licenseState) {
			// Shorten validity if the server says it expires sooner than the file.
			const serverMs = Date.parse(body.validUntil);
			const fileMs = licenseState.validUntil
				? Date.parse(licenseState.validUntil)
				: Number.POSITIVE_INFINITY;
			if (Number.isFinite(serverMs) && serverMs < fileMs) {
				licenseState.validUntil = body.validUntil;
				// Re-evaluate expired/degraded against the shortened validity.
				const nowMs = (opts.now ?? Date.now)();
				licenseState.expired = nowMs > serverMs;
				licenseState.degraded =
					licenseState.expired &&
					nowMs > serverMs + licenseState.graceDays * MS_PER_DAY;
			}
		}
	} catch {
		// Network/parse failure: no-op, fall back to the offline file.
	}
}
