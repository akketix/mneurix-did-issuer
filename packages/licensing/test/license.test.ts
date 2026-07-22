// packages/licensing/test/license.test.ts — Phase F platform licensing tests.
// Run via npm test. Generates a real Ed25519 keypair, signs test licenses, and
// exercises the boot guard + online refresh with an injected clock + fake
// fetcher. Zero network, zero live Mneurix key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	PlatformLicenseSchema,
	signLicense,
	verifyLicense,
	verifyLicenseWithKeyring,
	loadLicenseKeyringFromFile,
	assertPlatformLicense,
	refreshLicenseOnline,
	resetLicenseState,
	getLicenseState,
	isProctoringAllowed,
	isLicenseDegraded,
	PlatformLicenseError,
	LICENSE_WILDCARD_KID,
	type UnsignedPlatformLicense,
	type LicenseKeyring,
} from "../src/index";

// Real Ed25519 keypair for the test "Mneurix" license-signing key.
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const PRIV = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
const PUB = publicKey.export({ format: "pem", type: "spki" }).toString();

const tmp = mkdtempSync(join(tmpdir(), "mneurix-license-test-"));

function unsigned(opts: {
	orgId?: string;
	validUntil: string;
	tier?: string;
}): UnsignedPlatformLicense {
	return {
		orgId: opts.orgId ?? "acme",
		product: "onprem",
		tier: opts.tier ?? "enterprise",
		validUntil: opts.validUntil,
		issuedAt: "2026-01-01T00:00:00Z",
		version: 1,
		mneurixKeyId: "lic-test-1",
	};
}

function writeLicense(
	path: string,
	u: UnsignedPlatformLicense,
	priv: string = PRIV,
): void {
	const signature = signLicense(u, priv);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	writeFileSync(path, JSON.stringify(lic), "utf8");
}

test("verifyLicense: a validly-signed license verifies against the pubkey", () => {
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	assert.equal(verifyLicense(lic, PUB), true);
});

test("verifyLicense: a tampered license fails", () => {
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	const tampered = { ...lic, tier: "ultimate" }; // changed after signing
	assert.equal(verifyLicense(tampered, PUB), false);
});

test("assertPlatformLicense: dev (env unset) is a no-op — no file needed", () => {
	resetLicenseState();
	const state = assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: join(tmp, "nonexistent.json"),
		env: undefined,
	});
	assert.equal(state.loaded, false);
	assert.equal(isProctoringAllowed(), true); // not degraded
});

test("assertPlatformLicense: missing file in production throws (hard gate)", () => {
	resetLicenseState();
	assert.throws(
		() =>
			assertPlatformLicense({
				pubKeyPem: PUB,
				licensePath: join(tmp, "nonexistent.json"),
				env: "production",
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: invalid signature in production throws", () => {
	resetLicenseState();
	// Sign with a DIFFERENT keypair so the signature won't verify against PUB.
	const other = generateKeyPairSync("ed25519");
	const otherPriv = other.privateKey
		.export({ format: "pem", type: "pkcs8" })
		.toString();
	const path = join(tmp, "bad-sig.json");
	writeLicense(
		path,
		unsigned({ validUntil: "2027-01-01T00:00:00Z" }),
		otherPriv,
	);
	assert.throws(
		() =>
			assertPlatformLicense({
				pubKeyPem: PUB,
				licensePath: path,
				env: "production",
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: valid + unexpired -> clean boot, proctoring allowed", () => {
	resetLicenseState();
	const path = join(tmp, "valid.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	const state = assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	assert.equal(state.expired, false);
	assert.equal(state.degraded, false);
	assert.equal(isProctoringAllowed(), true);
	assert.equal(isLicenseDegraded(), false);
});

test("assertPlatformLicense: expired but within grace -> warn-only, proctoring still on", () => {
	resetLicenseState();
	const path = join(tmp, "expired-grace.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// 2027-02-01: 31 days past validUntil (grace 45) -> expired, not degraded.
	const state = assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2027-02-01T00:00:00Z"),
	});
	assert.equal(state.expired, true);
	assert.equal(state.degraded, false);
	assert.equal(isProctoringAllowed(), true);
});

test("assertPlatformLicense: past grace -> degraded, proctoring disabled", () => {
	resetLicenseState();
	const path = join(tmp, "degraded.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// 2027-03-15: ~73 days past validUntil (grace 45) -> degraded.
	const state = assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2027-03-15T00:00:00Z"),
	});
	assert.equal(state.degraded, true);
	assert.equal(isProctoringAllowed(), false);
	assert.equal(isLicenseDegraded(), true);
});

test("assertPlatformLicense: custom graceDays widens the runway", () => {
	resetLicenseState();
	const path = join(tmp, "grace120.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// 2027-03-15 (~73d) with graceDays=120 -> expired but NOT degraded.
	const state = assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		graceDays: 120,
		now: () => Date.parse("2027-03-15T00:00:00Z"),
	});
	assert.equal(state.expired, true);
	assert.equal(state.degraded, false);
	assert.equal(isProctoringAllowed(), true);
});

test("refreshLicenseOnline: a revoked org on the denylist degrades the state", async () => {
	resetLicenseState();
	const path = join(tmp, "refresh-revoke.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	assert.equal(isLicenseDegraded(), false);
	await refreshLicenseOnline({
		serverUrl: "https://license.test",
		orgId: "acme",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
		fetcher: (async () =>
			new Response(JSON.stringify({ revoked: true }), {
				status: 200,
				headers: { "content-type": "application/json" },
			})) as typeof fetch,
	});
	assert.equal(isLicenseDegraded(), true);
	assert.equal(isProctoringAllowed(), false);
});

test("refreshLicenseOnline: a shorter server validUntil clamps the state", async () => {
	resetLicenseState();
	const path = join(tmp, "refresh-shorten.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	await refreshLicenseOnline({
		serverUrl: "https://license.test",
		orgId: "acme",
		// Server says it expires sooner (2026-08-01) -> the state should clamp.
		now: () => Date.parse("2026-07-17T00:00:00Z"),
		fetcher: (async () =>
			new Response(JSON.stringify({ validUntil: "2026-08-01T00:00:00Z" }), {
				status: 200,
				headers: { "content-type": "application/json" },
			})) as typeof fetch,
	});
	const state = getLicenseState();
	assert.equal(state?.validUntil, "2026-08-01T00:00:00Z");
});

test("refreshLicenseOnline: unreachable server is a no-op (offline file stands)", async () => {
	resetLicenseState();
	const path = join(tmp, "refresh-down.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	const before = getLicenseState()?.validUntil;
	await refreshLicenseOnline({
		serverUrl: "https://license.test",
		orgId: "acme",
		fetcher: (async () => Promise.reject(new Error("network down"))) as typeof fetch,
	});
	assert.equal(getLicenseState()?.validUntil, before);
	assert.equal(isLicenseDegraded(), false);
});

test("refreshLicenseOnline: stops refreshing once degraded", async () => {
	resetLicenseState();
	const path = join(tmp, "refresh-stops.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// Boot already degraded (past grace).
	assertPlatformLicense({
		pubKeyPem: PUB,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2027-03-15T00:00:00Z"),
	});
	assert.equal(isLicenseDegraded(), true);
	let called = false;
	await refreshLicenseOnline({
		serverUrl: "https://license.test",
		orgId: "acme",
		fetcher: (async () => {
			called = true;
			return new Response("{}", { status: 200 });
		}) as typeof fetch,
	});
	assert.equal(called, false, "refresh should not fetch once degraded");
});

// ---------------------------------------------------------------------------
// CISO F3/F4/F38/F65 — pinned keyring, on-prem fail-closed, version floor.
// ---------------------------------------------------------------------------

test("verifyLicenseWithKeyring: rejects a license whose mneurixKeyId is not pinned (F4/F38)", () => {
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	// Keyring pins a DIFFERENT kid — the license's kid is un-pinned.
	const keyring: LicenseKeyring = new Map([["lic-other", PUB]]);
	assert.equal(verifyLicenseWithKeyring(lic, keyring), false);
});

test("verifyLicenseWithKeyring: verifies a license whose kid IS pinned (F4)", () => {
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	const keyring: LicenseKeyring = new Map([["lic-test-1", PUB]]);
	assert.equal(verifyLicenseWithKeyring(lic, keyring), true);
});

test("verifyLicenseWithKeyring: rejects a forged license signed by a different key, even when kid is pinned (F4)", () => {
	const other = generateKeyPairSync("ed25519");
	const otherPriv = other.privateKey
		.export({ format: "pem", type: "pkcs8" })
		.toString();
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, otherPriv); // signed by attacker's key
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	// Keyring pins the REAL kid but the real pubkey — attacker's sig fails.
	const keyring: LicenseKeyring = new Map([["lic-test-1", PUB]]);
	assert.equal(verifyLicenseWithKeyring(lic, keyring), false);
});

test("verifyLicenseWithKeyring: wildcard entry accepts any kid (single-pinned-pubkey escape)", () => {
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	const keyring: LicenseKeyring = new Map([[LICENSE_WILDCARD_KID, PUB]]);
	assert.equal(verifyLicenseWithKeyring(lic, keyring), true);
});

test("loadLicenseKeyringFromFile: JSON kid->pem map loads as a strict keyring", () => {
	const keyringPath = join(tmp, "keyring-map.json");
	writeFileSync(keyringPath, JSON.stringify({ "lic-test-1": PUB }));
	const keyring = loadLicenseKeyringFromFile(keyringPath);
	assert.ok(keyring);
	assert.equal(keyring?.get("lic-test-1"), PUB);
	assert.equal(keyring?.has(LICENSE_WILDCARD_KID), false);
});

test("loadLicenseKeyringFromFile: raw PEM file loads as a wildcard single-key keyring", () => {
	const pemPath = join(tmp, "license-signing.pub");
	writeFileSync(pemPath, PUB);
	const keyring = loadLicenseKeyringFromFile(pemPath);
	assert.ok(keyring);
	// The loader trims surrounding whitespace; the pinned PEM still verifies.
	assert.equal(keyring?.get(LICENSE_WILDCARD_KID), PUB.trim());
});

test("loadLicenseKeyringFromFile: missing file returns null", () => {
	const keyring = loadLicenseKeyringFromFile(join(tmp, "no-such-keyring.json"));
	assert.equal(keyring, null);
});

test("assertPlatformLicense: pinned keyring verifies a valid license + rejects a forged one (F4)", () => {
	resetLicenseState();
	const path = join(tmp, "keyring-valid.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	const keyring: LicenseKeyring = new Map([["lic-test-1", PUB]]);
	const state = assertPlatformLicense({
		keyring,
		licensePath: path,
		env: "production",
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	assert.equal(state.loaded, true);
	assert.equal(state.validSignature, true);

	// Forged license (signed by a different key) with the SAME kid → rejected.
	resetLicenseState();
	const other = generateKeyPairSync("ed25519");
	const otherPriv = other.privateKey
		.export({ format: "pem", type: "pkcs8" })
		.toString();
	const forgedPath = join(tmp, "keyring-forged.json");
	writeLicense(
		forgedPath,
		unsigned({ validUntil: "2027-01-01T00:00:00Z" }),
		otherPriv,
	);
	assert.throws(
		() =>
			assertPlatformLicense({
				keyring,
				licensePath: forgedPath,
				env: "production",
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: keyring rejects a license with an un-pinned mneurixKeyId (F38)", () => {
	resetLicenseState();
	const path = join(tmp, "unpinned-kid.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// License kid is "lic-test-1"; keyring pins a different kid.
	const keyring: LicenseKeyring = new Map([["lic-other", PUB]]);
	assert.throws(
		() =>
			assertPlatformLicense({
				keyring,
				licensePath: path,
				env: "production",
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: MIN_LICENSE_VERSION rejects an old version (F65)", () => {
	resetLicenseState();
	const path = join(tmp, "old-version.json");
	const u = unsigned({ validUntil: "2027-01-01T00:00:00Z" });
	const signature = signLicense(u, PRIV);
	const lic = PlatformLicenseSchema.parse({ ...u, signature });
	writeFileSync(path, JSON.stringify(lic));
	// Raise the floor above the license's version (1) → rejected.
	assert.throws(
		() =>
			assertPlatformLicense({
				pubKeyPem: PUB,
				licensePath: path,
				env: "production",
				minLicenseVersion: 2,
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: on-prem fails-closed on a missing pinned keyring file (F3+F4)", () => {
	resetLicenseState();
	const path = join(tmp, "onprem-no-keyring.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	assert.throws(
		() =>
			assertPlatformLicense({
				licensePath: path,
				env: "development", // operator typoed/unset MNEURIX_ENV
				onPrem: true, // ...but the baked on-prem flag still forces the gate
				pubKeyFile: join(tmp, "no-such-keyring.json"),
				// pubKeyPem intentionally omitted: on-prem must not trust env pubkeys.
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: on-prem ignores operator-supplied pubKeyPem + fails-closed without a pinned file (F4)", () => {
	resetLicenseState();
	const path = join(tmp, "onprem-env-pubkey.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	// Operator supplies their own pubkey via env (forgery attempt). On-prem
	// must IGNORE it and require the pinned file → fail-closed.
	assert.throws(
		() =>
			assertPlatformLicense({
				pubKeyPem: PUB, // simulates MNEURIX_LICENSE_PUBKEY_PEM from env
				licensePath: path,
				env: "production",
				onPrem: true,
				pubKeyFile: join(tmp, "no-such-keyring.json"),
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});

test("assertPlatformLicense: on-prem boots with a pinned keyring file (F3+F4 happy path)", () => {
	resetLicenseState();
	const path = join(tmp, "onprem-happy.json");
	writeLicense(path, unsigned({ validUntil: "2027-01-01T00:00:00Z" }));
	const keyringPath = join(tmp, "onprem-keyring.json");
	writeFileSync(keyringPath, JSON.stringify({ "lic-test-1": PUB }));
	const state = assertPlatformLicense({
		licensePath: path,
		env: "development", // even with MNEURIX_ENV unset, on-prem flag forces the gate
		onPrem: true,
		pubKeyFile: keyringPath,
		now: () => Date.parse("2026-07-17T00:00:00Z"),
	});
	assert.equal(state.loaded, true);
	assert.equal(state.validSignature, true);
	assert.equal(isProctoringAllowed(), true);
});

test("assertPlatformLicense: on-prem rejects an invalid-signature license even with the pinned keyring (F3)", () => {
	resetLicenseState();
	const other = generateKeyPairSync("ed25519");
	const otherPriv = other.privateKey
		.export({ format: "pem", type: "pkcs8" })
		.toString();
	const path = join(tmp, "onprem-bad-sig.json");
	writeLicense(
		path,
		unsigned({ validUntil: "2027-01-01T00:00:00Z" }),
		otherPriv,
	);
	const keyringPath = join(tmp, "onprem-keyring-2.json");
	writeFileSync(keyringPath, JSON.stringify({ "lic-test-1": PUB }));
	assert.throws(
		() =>
			assertPlatformLicense({
				licensePath: path,
				env: "production",
				onPrem: true,
				pubKeyFile: keyringPath,
				now: () => Date.parse("2026-07-17T00:00:00Z"),
			}),
		PlatformLicenseError,
	);
});
