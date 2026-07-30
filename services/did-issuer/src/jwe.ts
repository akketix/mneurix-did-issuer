// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** JWE (direct_post.jwt) helpers for OpenID4VP encrypted responses — the wallet
 * encrypts the response to the verifier's per-request ephemeral ECDH-ES public
 * key (advertised in the request's client_metadata); the receiver decrypts with
 * the matching ephemeral private key.
 *
 * Uses the audited `jose` lib (ECDH-ES Concat KDF + AES-GCM — not hand-rolled).
 * v1: the JWE plaintext is the form-encoded response params (vp_token + state);
 * the JARM signed-JWT layer is a follow-up. */
import { compactDecrypt, importPKCS8, importJWK, CompactEncrypt, type JWK } from "jose";

/** Decrypt a direct_post.jwt JWE (`response=<jwe>`) with the verifier's
 * per-request ephemeral P-256 private key. Returns the plaintext (form-encoded
 * response params). Throws on a wrong key / malformed JWE (the receiver
 * fail-closes on throw). */
export async function decryptResponse(jwe: string, recipientPrivateKeyPem: string): Promise<string> {
	const key = await importPKCS8(recipientPrivateKeyPem, "ES256");
	const { plaintext } = await compactDecrypt(jwe, key);
	return new TextDecoder().decode(plaintext);
}

/** Encrypt a plaintext (form-encoded response params) to a recipient's
 * ephemeral P-256 public JWK (ECDH-ES + A128GCM) — used by tests (the wallet
 * side) + as a reference for the wire format. */
export async function encryptResponse(plaintext: string, recipientPublicJwk: Record<string, unknown>): Promise<string> {
	const key = await importJWK(recipientPublicJwk as unknown as JWK, "ES256");
	return new CompactEncrypt(new TextEncoder().encode(plaintext))
		.setProtectedHeader({ alg: "ECDH-ES", enc: "A128GCM" })
		.encrypt(key);
}