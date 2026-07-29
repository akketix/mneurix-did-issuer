// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * @mneurix/shared/statusList — W3C Bitstring Status List codec + freshness SLA.
 *
 * One bit per credential per `statusPurpose`: a bit `1` in the `revocation`
 * list means revoked; in the `delisted` list means tombstoned (erasure anchor
 * for G-PRIV-2 / P2.2 and re-master tombstones). Multi-state (suspend) is out
 * of v1 scope — `un-revoke` flips the bit back to `0`.
 *
 * The bitstring is stored **raw** (base64url of the byte array), not
 * GCS-compressed: the W3C spec permits the expanded form, and a GCS dependency
 * would break the purity gate. GCS compression is a documented future
 * optimization that does not change the on-the-wire entry shape.
 *
 * Freshness SLA (CISO governance must-fix #2): every `StatusListDoc` carries a
 * monotonic `version`, an `updated` ISO timestamp, and a `statusListMaxAge`
 * (hours). A verifier MUST reject a list whose `age = now - updated` exceeds
 * `statusListMaxAge` (a stale list where a revoked bit is still `0` validates a
 * revoked badge — F9a).
 *
 * Purity: zod + node:crypto-free byte ops; no new deps.
 */
import { z } from "zod";

/** ISO-8601 with offset (defined locally to avoid a barrel import cycle). */
const IsoTimestampSchema = z.string().datetime({ offset: true });

/** Status purposes supported at v1 (mirrors `CredentialStatusSchema`). */
export const StatusPurposeSchema = z.enum(["revocation", "refresh", "delisted"]);
export type StatusPurpose = z.infer<typeof StatusPurposeSchema>;

/** The published, signed Bitstring Status List document. */
export const StatusListDocSchema = z.object({
	id: z.string().url(),
	type: z.literal("BitstringStatusList"),
	statusPurpose: StatusPurposeSchema,
	/** base64url of the raw bitstring bytes (1 bit per entry). */
	encodedList: z.string().min(1),
	bitsPerEntry: z.literal(1).default(1),
	/** Number of entries (indices) allocated in this list. */
	size: z.number().int().min(0),
	/** Monotonic version — bumped on every mutation (freshness SLA). */
	version: z.number().int().min(1),
	/** When the list was last mutated (ISO). */
	updated: IsoTimestampSchema,
	/** Max acceptable age in hours; verifiers reject older lists (freshness SLA). */
	statusListMaxAge: z.number().int().min(1),
	/** The statusKid whose key signs this doc (Data Integrity proof). */
	statusKid: z.string().min(1),
	/** If this list has been superseded by rotation, the new statusKid (forward
	 * pointer) — lets a verifier of an old entry find the current list. */
	supersededBy: z.string().optional(),
});
export type StatusListDoc = z.infer<typeof StatusListDocSchema>;

/** Decode a base64url raw bitstring into a Uint8Array. */
export function decodeBitstring(encodedList: string): Uint8Array {
	// base64url decode (Buffer tolerates both base64 and base64url; pad if needed).
	const s = encodedList.replace(/-/g, "+").replace(/_/g, "/");
	const pad = s.length % 4 === 0 ? s : s + "=".repeat(4 - (s.length % 4));
	return new Uint8Array(Buffer.from(pad, "base64"));
}

/** Encode a Uint8Array bitstring to base64url (no padding). */
export function encodeBitstring(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

/** Get a single bit (0 or 1) at `index` from a decoded bitstring. */
export function getBit(bytes: Uint8Array, index: number): 0 | 1 {
	const byte = bytes[index >> 3];
	if (byte === undefined) return 0;
	return (byte & (1 << (index & 7))) !== 0 ? 1 : 0;
}

/** Set a single bit at `index` in a (mutable) Uint8Array, growing it as needed. */
export function setBit(bytes: Uint8Array, index: number, value: 0 | 1): Uint8Array {
	const need = (index >> 3) + 1;
	let out = bytes;
	if (bytes.length < need) {
		out = new Uint8Array(need);
		out.set(bytes);
	}
	const mask = 1 << (index & 7);
	if (value === 1) out[index >> 3]! |= mask;
	else out[index >> 3]! &= ~mask & 0xff;
	return out;
}

/** Allocate a fresh, zeroed bitstring of `size` entries. */
export function emptyBitstring(size: number): Uint8Array {
	return new Uint8Array(Math.max(1, (size >> 3) + 1));
}

export interface FreshnessCheck {
	fresh: boolean;
	ageHours: number;
	reason?: string;
}

/** Verify the freshness SLA: reject lists older than `statusListMaxAge`. */
export function checkFreshness(
	doc: StatusListDoc,
	now: Date = new Date(),
): FreshnessCheck {
	const updatedMs = Date.parse(doc.updated);
	if (Number.isNaN(updatedMs)) {
		return { fresh: false, ageHours: Infinity, reason: "invalid `updated` timestamp" };
	}
	const ageHours = (now.getTime() - updatedMs) / 3_600_000;
	if (ageHours > doc.statusListMaxAge) {
		return {
			fresh: false,
			ageHours,
			reason: `status list is stale (${ageHours.toFixed(1)}h > maxAge ${doc.statusListMaxAge}h)`,
		};
	}
	return { fresh: true, ageHours };
}

/** Verify a credential's status bit against a decoded list. */
export function verifyStatus(
	doc: StatusListDoc,
	statusListIndex: number,
): { revoked: boolean; delisted: boolean } {
	if (statusListIndex < 0 || statusListIndex >= doc.size) {
		return { revoked: false, delisted: false };
	}
	const bytes = decodeBitstring(doc.encodedList);
	const bit = getBit(bytes, statusListIndex);
	if (doc.statusPurpose === "revocation") return { revoked: bit === 1, delisted: false };
	if (doc.statusPurpose === "delisted") return { revoked: false, delisted: bit === 1 };
	return { revoked: false, delisted: false };
}