// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Self-signed X.509v3 certificate generation for the ES256 (P-256) issuer key —
 * the dev `x5c` for the HAIP/EUDI wallet path (HAIP §6.1.1: the SD-JWT VC carries
 * the issuer signing cert chain in the `x5c` JOSE header). Node's stdlib can
 * parse X.509 (X509Certificate) but cannot create certs, so this hand-rolls the
 * minimal ASN.1 DER for a self-signed EC P-256 cert (ECDSA-with-SHA256).
 *
 * DEV ONLY: a self-signed cert exercises the x5c plumbing. HAIP prod requires a
 * NON-self-signed cert from a trust anchor (IACA procurement) — the prod cert
 * replaces this one. Purity: node:crypto. */
import { sign, createPublicKey, randomBytes } from "node:crypto";
import type { IssuerP256Key } from "./keys";

// --- ASN.1 DER helpers ---
function derLen(n: number): Buffer {
	if (n < 0x80) return Buffer.from([n]);
	const bytes: number[] = [];
	let m = n;
	while (m > 0) { bytes.unshift(m & 0xff); m = Math.floor(m / 256); }
	return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function der(tag: number, content: Buffer): Buffer {
	return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
function derSeq(c: Buffer): Buffer { return der(0x30, c); }
function derSet(c: Buffer): Buffer { return der(0x31, c); }
function derInt(bytes: Buffer): Buffer {
	let b = bytes;
	if (b.length > 0 && (b[0]! & 0x80)) b = Buffer.concat([Buffer.from([0x00]), b]); // positive int
	return der(0x02, b);
}
function encodeOid(oid: string): Buffer {
	const parts = oid.split(".").map(Number);
	const out: number[] = [40 * parts[0]! + parts[1]!];
	for (let i = 2; i < parts.length; i++) {
		let v = parts[i]!;
		const stack: number[] = [v & 0x7f];
		v = Math.floor(v / 128);
		while (v > 0) { stack.push((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
		for (let j = stack.length - 1; j >= 0; j--) out.push(stack[j]!);
	}
	return Buffer.from(out);
}
function derOid(oid: string): Buffer { return der(0x06, encodeOid(oid)); }
function derBitString(bytes: Buffer): Buffer { return der(0x03, Buffer.concat([Buffer.from([0x00]), bytes])); }
function derUtf8String(s: string): Buffer { return der(0x0c, Buffer.from(s, "utf8")); }
function derUtcTime(s: string): Buffer { return der(0x17, Buffer.from(s, "ascii")); }
function derExplicit(num: number, content: Buffer): Buffer { return der(0xa0 + num, content); }

const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_CN = "2.5.4.3";

function name(cn: string): Buffer {
	// Name ::= SEQUENCE { SET { SEQUENCE { OID CN, UTF8String cn } } }
	return derSeq(derSet(derSeq(Buffer.concat([derOid(OID_CN), derUtf8String(cn)]))));
}
function utcNow(offsetDays: number): string {
	const d = new Date(Date.now() + offsetDays * 86_400_000);
	const pad = (n: number) => String(n).padStart(2, "0");
	return `${pad(d.getUTCFullYear() % 100)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
}

/** Generate a self-signed X.509v3 EC P-256 cert for the issuer key + return the
 * `x5c` array (DER base64, leaf first). The cert is signed with the issuer's
 * P-256 private key (ECDSA-with-SHA256, DER sig). */
export function generateSelfSignedCert(p256Key: IssuerP256Key, cn: string): string[] {
	const sigAlg = derSeq(derOid(OID_ECDSA_SHA256));
	const serial = derInt(randomBytes(16));
	const validity = derSeq(Buffer.concat([derUtcTime(utcNow(-1)), derUtcTime(utcNow(365))]));
	const spki = createPublicKey(p256Key.publicKeyPem).export({ format: "der", type: "spki" }) as Buffer;
	const tbs = derSeq(Buffer.concat([
		derExplicit(0, derInt(Buffer.from([2]))), // version v3
		serial,
		sigAlg, // signature algorithm
		name(cn), // issuer
		validity,
		name(cn), // subject (self-signed)
		spki, // subjectPublicKeyInfo (EC P-256)
	]));
	const sig = sign("sha256", tbs, { key: p256Key.privateKeyPem, dsaEncoding: "der" });
	const cert = derSeq(Buffer.concat([tbs, sigAlg, derBitString(sig)]));
	return [cert.toString("base64")];
}