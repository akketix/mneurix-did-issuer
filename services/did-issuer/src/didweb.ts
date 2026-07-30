// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Cross-issuer did:web resolution — fetch a foreign did:web issuer's DID doc
 * over HTTPS + resolve its verification key, so the did-issuer's verifier can
 * verify credentials issued by ANY did:web issuer (incl. a customer's own), not
 * just its own (the local DID store).
 *
 * SSRF-safe (v1): an origin allow-list (MNEURIX_DIDWEB_ALLOW_ORIGINS, or `*`),
 * literal private/loopback/link-local host blocking, a fetch timeout, + no
 * redirects (redirect: "error"). Fail-closed on any guard violation or a
 * missing/invalid key. DNS-rebinding (a hostname resolving to a private IP) +
 * safe redirect-following are noted follow-ups (the allow-list is the primary
 * gate).
 *
 * The allow-list is read at each call (test/config friendly) + the default
 * fetch resolves `fetch` at call time (so tests can mock globalThis.fetch).
 * Purity: node:crypto + global fetch. */
import { createPublicKey } from "node:crypto";
import type { KeyMaterial } from "@mneurix/shared";

const FETCH_TIMEOUT_MS = 5000;
/** Max did:web doc size (DoS cap — a foreign doc larger than this is rejected). */
const MAX_DOC_BYTES = 1_000_000;

/** Block literal private/loopback/link-local hostnames + localhost. (Does NOT
 * catch DNS-rebinding — a hostname resolving to a private IP — which is a
 * noted follow-up; the allow-list is the primary gate.) */
function isBlockedHost(host: string): boolean {
	const h = host.toLowerCase();
	if (h === "localhost" || h.endsWith(".localhost")) return true;
	const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (ipv4) {
		const a = Number(ipv4[1]);
		const b = Number(ipv4[2]);
		if (a === 10 || a === 127 || a === 0) return true;
		if (a === 169 && b === 254) return true;
		if (a === 172 && b >= 16 && b <= 31) return true;
		if (a === 192 && b === 168) return true;
	}
	if (h === "::1" || h === "::" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
	return false;
}

function originAllowed(host: string): boolean {
	const list = (process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
	return list.includes("*") || list.includes(host);
}

interface DidWebDoc {
	verificationMethod: Array<{ id: string; publicKeyJwk: Record<string, string> }>;
}

/** Resolve the issuer's public KeyMaterial for `kid` from a cross-issuer did:web
 * DID doc (fetched over HTTPS). Returns null on any guard violation, fetch
 * failure, or missing key (fail-closed). `fetchFn` defaults to the global fetch
 * (resolved at call time, so tests can mock globalThis.fetch). */
export async function resolveDidWebIssuerKey(
	issuerDid: string,
	kid: string,
	fetchFn: (url: string, init?: RequestInit) => Promise<Response> = (url, init) => fetch(url, init),
): Promise<KeyMaterial | null> {
	if (!issuerDid.startsWith("did:web:")) return null;
	const rest = issuerDid.slice("did:web:".length);
	const [host, ...segs] = rest.split(":");
	if (!host || isBlockedHost(host) || !originAllowed(host)) return null;
	const docUrl = `https://${host}${segs.length ? "/" + segs.join("/") : ""}/.well-known/did.json`;
	try {
		const res = await fetchFn(docUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: "error" });
		if (!res.ok) return null;
		// Size cap (plan SSRF guard): reject an oversized did:web doc (DoS).
		const contentLength = Number(res.headers.get("content-length") ?? 0);
		if (contentLength > MAX_DOC_BYTES) return null;
		const text = await res.text();
		if (text.length > MAX_DOC_BYTES) return null;
		const doc = JSON.parse(text) as DidWebDoc;
		const vm = doc.verificationMethod.find((m) => m.id === `${issuerDid}#${kid}`);
		if (!vm) return null;
		const publicKeyPem = createPublicKey({ key: vm.publicKeyJwk, format: "jwk" }).export({ format: "pem", type: "spki" }) as string;
		return { privateKeyPem: "", publicKeyPem, kid };
	} catch {
		return null;
	}
}