/** Issuer assertion key (M3). File-backed Ed25519 (plaintext PEM, dev).
 *
 * The full KeyProvider interface + LocalSealedKeyProvider + Shamir escrow are
 * PORTED into @mneurix/shared/keys (available); the prod sealed-custody boot
 * wiring lands in M9. M3 uses a single file-backed issuer key, sufficient for
 * did:web minting + the API. Purity: node:crypto + node:fs. */
import { generateKeyPairSync, createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface IssuerKey {
	kid: string;
	publicKeyPem: string;
	privateKeyPem: string;
}

export function loadOrCreateIssuerKey(dir: string | undefined): IssuerKey {
	if (dir) {
		const file = join(dir, "issuer.json");
		if (existsSync(file)) return JSON.parse(readFileSync(file, "utf8")) as IssuerKey;
		const k = generate();
		mkdirSync(dir, { recursive: true });
		writeFileSync(file, JSON.stringify(k), { mode: 0o600 });
		return k;
	}
	return generate();
}

function generate(): IssuerKey {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }) as string;
	const kid = "issuer-" + createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 12);
	return {
		kid,
		publicKeyPem,
		privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
	};
}
