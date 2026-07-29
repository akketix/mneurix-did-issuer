// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * @mneurix/shared/keys/shamir — Shamir Secret Sharing over GF(2^8) (CISO
 * security must-fix #2 for P1.1): split the sealed master key into N shares so
 * that any M reconstruct it, eliminating the single-sealed-master.key
 * total-loss cliff. No escrow service, no third-party lib — `node:crypto` only
 * (purity gate).
 *
 * Field: GF(2^8) with the AES reduction polynomial 0x11b and generator 3
 * (standard). Shares are byte-buffers prefixed with their x-coordinate:
 *   share = [ x (1 byte, 1..N) || y (secret.length bytes) ]
 * Evaluation is per-byte over a random polynomial of degree M-1 whose constant
 * term is the secret byte; reconstruction is Lagrange interpolation at x=0.
 *
 * Security notes:
 *  - Coefficients are `node:crypto` randomBytes (CSPRNG).
 *  - Fewer than M shares reveal NO information about the secret (information-
 *    theoretic secrecy).
 *  - Shares MUST be distributed offline to distinct operators; storing all
 *    shares on the same host as the sealed master.key defeats the escrow.
 *  - Recovery re-seals the SAME master bytes, so previously-sealed issuer keys
 *    remain unsealable.
 */
import { randomBytes } from "node:crypto";

// --- GF(2^8) tables (generator 3, polynomial 0x11b) ---------------------
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function buildTables(): void {
	let x = 1;
	for (let i = 0; i < 255; i++) {
		GF_EXP[i] = x;
		GF_LOG[x] = i;
		// x = x * 3 (generator 3, primitive under 0x11b) in GF(2^8): 3x = x ^ (2x
		// reduced by 0x1b when the high bit overflows). Russian-peasant step.
		const twoX = (x & 0x80) !== 0 ? (((x << 1) & 0xff) ^ 0x1b) : ((x << 1) & 0xff);
		x = twoX ^ x;
	}
	for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
	if (a === 0 || b === 0) return 0;
	return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}

function gfDiv(a: number, b: number): number {
	if (a === 0) return 0;
	if (b === 0) throw new Error("shamir: division by zero in GF(256)");
	return GF_EXP[(GF_LOG[a]! - GF_LOG[b]! + 255) % 255]!;
}

/** Evaluate a polynomial (coeffs[0] = constant) at x using Horner's rule in GF(2^8). */
function evalPoly(coeffs: Uint8Array, x: number): number {
	let acc = 0;
	for (let i = coeffs.length - 1; i >= 0; i--) {
		acc = gfMul(acc, x) ^ coeffs[i]!;
	}
	return acc;
}

export interface SplitOptions {
	/** Reconstruction threshold (M): any M shares recover the secret. */
	threshold: number;
	/** Total number of shares (N) to generate. */
	shares: number;
}

/**
 * Split a secret into N shares with threshold M. Each share is
 * `1 + secret.length` bytes: [ x || y ]. Throws if M/N out of range
 * (1 <= M <= N <= 255) or the secret is empty.
 */
export function splitSecret(secret: Buffer, opts: SplitOptions): Buffer[] {
	const { threshold: m, shares: n } = opts;
	if (m < 1 || n < 1 || m > n || n > 255) {
		throw new Error(`shamir: require 1 <= threshold <= shares <= 255 (got m=${m}, n=${n})`);
	}
	if (secret.length === 0) throw new Error("shamir: secret is empty");

	const out: Buffer[] = [];
	for (let x = 1; x <= n; x++) {
		const share = Buffer.alloc(1 + secret.length);
		share[0] = x;
		out.push(share);
	}
	for (let j = 0; j < secret.length; j++) {
		const coeffs = new Uint8Array(m);
		coeffs[0] = secret[j]!;
		if (m > 1) {
			const rand = randomBytes(m - 1);
			for (let k = 1; k < m; k++) coeffs[k] = rand[k - 1]!;
		}
		for (let x = 1; x <= n; x++) {
			out[x - 1]![1 + j] = evalPoly(coeffs, x);
		}
	}
	return out;
}

/**
 * Reconstruct the secret from >= M shares (Lagrange interpolation at x=0).
 * Shares may be given in any order and any count >= the threshold; fewer than
 * the threshold yields a wrong (but non-erroring) result — the caller must
 * supply enough shares. All shares must have the same y-length.
 */
export function combineSecret(shares: Buffer[]): Buffer {
	if (shares.length < 2) throw new Error("shamir: need at least 2 shares to reconstruct");
	const len = shares[0]!.length - 1;
	if (len <= 0) throw new Error("shamir: malformed share (no y bytes)");
	const xs = shares.map((s) => {
		if (s.length !== 1 + len) throw new Error("shamir: shares have mismatched lengths");
		return s[0]!;
	});
	// Distinct x check.
	const seen = new Set<number>();
	for (const x of xs) {
		if (x === 0 || seen.has(x)) throw new Error(`shamir: duplicate/invalid x=${x}`);
		seen.add(x);
	}
	const secret = Buffer.alloc(len);
	for (let j = 0; j < len; j++) {
		// Lagrange at x=0: sum_i y_i * prod_{k!=i} (x_k / (x_k ^ x_i)).
		let acc = 0;
		for (let i = 0; i < shares.length; i++) {
			const xi = xs[i]!;
			const yi = shares[i]![1 + j]!;
			let num = 1;
			let den = 1;
			for (let k = 0; k < shares.length; k++) {
				if (k === i) continue;
				const xk = xs[k]!;
				num = gfMul(num, xk); // (0 - x_k) = x_k in GF(2^8)
				den = gfMul(den, xi ^ xk); // (x_i - x_k) = x_i ^ x_k
			}
			acc ^= gfMul(yi, gfDiv(num, den));
		}
		secret[j] = acc;
	}
	return secret;
}

/** Encode a share buffer as lowercase hex (for offline transport/printing). */
export function shareToHex(share: Buffer): string {
	return share.toString("hex");
}

/** Decode a hex share string back into a buffer. */
export function hexToShare(hex: string): Buffer {
	return Buffer.from(hex, "hex");
}