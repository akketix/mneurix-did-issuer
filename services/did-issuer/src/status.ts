/** Status allocation (M5) — W3C Bitstring Status List for OB3 + a Token
 * Status List-shaped `status` claim for SD-JWT VC.
 *
 * Reuses the `@mneurix/shared` statusList codec (verbatim-copied from the
 * lattice). v1 is an in-memory per-purpose bitstring + monotonic index; the
 * durable signed StatusListDoc + the `GET /v1/credentials/:id/status`
 * endpoint land in M6 (the issuer owns status). Bit 0 = valid, bit 1 =
 * revoked (fail-closed), mirroring the lattice's `RevocationState`.
 *
 * Purity: none (in-memory Map); codec is pure. */
import { setBit, type StatusPurpose } from "@mneurix/shared";

/** The OB3 CredentialStatus entry shape (from the copied ob3.ts schema). */
export interface Ob3CredentialStatus {
	id: string;
	type: "BitstringStatusListEntry";
	statusPurpose: StatusPurpose;
	statusListIndex: number;
}

/** A minimal in-memory status allocator for one status purpose. */
class StatusList {
	private bits = new Uint8Array(64); // grows on demand
	private size = 0;
	private nextIndex = 0;

	allocate(statusListId: string, statusPurpose: StatusPurpose): Ob3CredentialStatus {
		const index = this.nextIndex++;
		this.bits = new Uint8Array(setBit(this.bits, index, 0)); // 0 = valid
		if (index + 1 > this.size) this.size = index + 1;
		return { id: statusListId, type: "BitstringStatusListEntry", statusPurpose, statusListIndex: index };
	}

	/** Flip a bit to revoked (fail-closed). */
	revoke(index: number): void {
		this.bits = new Uint8Array(setBit(this.bits, index, 1));
	}

	get encodedList(): string {
		// base64url of the raw bitstring (W3C spec expanded form; lattice uses raw).
		return Buffer.from(this.bits).toString("base64url");
	}
	get count(): number {
		return this.size;
	}
}

const lists = new Map<StatusPurpose, StatusList>();

function listFor(purpose: StatusPurpose): StatusList {
	let l = lists.get(purpose);
	if (!l) {
		l = new StatusList();
		lists.set(purpose, l);
	}
	return l;
}

/** Allocate a revocation status entry for an OB3 credential. */
export function allocateOb3Status(
	statusListId: string,
	statusPurpose: StatusPurpose = "revocation",
): Ob3CredentialStatus {
	return listFor(statusPurpose).allocate(statusListId, statusPurpose);
}

/** Build the SD-JWT VC `status` claim (Token Status List-shaped). */
export function allocateSdJwtStatus(
	statusListId: string,
	statusPurpose: StatusPurpose = "revocation",
): { id: string; type: string; statusPurpose: StatusPurpose; statusListIndex: number } {
	const entry = allocateOb3Status(statusListId, statusPurpose);
	return { id: entry.id, type: "statuslist", statusPurpose: entry.statusPurpose, statusListIndex: entry.statusListIndex };
}

/** Revoke a previously-allocated index (fail-closed). */
export function revokeStatus(statusPurpose: StatusPurpose, index: number): void {
	listFor(statusPurpose).revoke(index);
}

export function _resetStatusForTests(): void {
	lists.clear();
}