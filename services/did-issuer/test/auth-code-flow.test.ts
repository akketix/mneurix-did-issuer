// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Phase-2 Task 1 — OID4VCI authorization-code flow (wallet-initiated, delegated
// user auth). A wallet-initiated flow: authorize -> consent -> code -> token ->
// credential (EdDSA). PKCE mismatch -> 400; replayed code -> 400; the metadata
// advertises authorization_code + PKCE S256; the delegated path (lattice
// callback) issues a code from a signed auth result. The pre-authorized-code
// flow is unchanged (covered by oid4vci.test.ts; asserted here for no-regression).
// Run: npx tsx services/did-issuer/test/auth-code-flow.test.ts
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, createSign, createHmac, randomBytes } from "node:crypto";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOid4vciForTests } from "../src/oid4vci";
import { _resetOauthForTests } from "../src/oauth";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;

function b64url(b: Buffer | string): string {
	return (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");
}
function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** A PKCE (S256) pair: the wallet generates a random code_verifier + derives the
 * code_challenge = base64url(sha256(verifier)). The challenge goes to
 * /oauth/authorize; the verifier goes to /oauth/token. */
function pkcePair(): { verifier: string; challenge: string } {
	const verifier = b64url(randomBytes(32));
	const challenge = b64url(createHash("sha256").update(verifier, "ascii").digest());
	return { verifier, challenge };
}

/** An ES256 holder keypair + a proof-JWT signer (the wallet proves possession of
 * its holder key, binding the credential's cnf.jwk to the wallet). */
function holderKeypairES256() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	return {
		jwk: publicKey.export({ format: "jwk" }) as Record<string, string>,
		signProof: (nonce: string) => {
			const header = b64url(JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk: publicKey.export({ format: "jwk" }) }));
			const payload = b64url(JSON.stringify({ nonce, iss: "did:web:wallet.example", aud: ISSUER_URL }));
			const signingInput = Buffer.from(header + "." + payload, "ascii");
			const sig = createSign("SHA256").update(signingInput).sign({ key: privateKey.export({ format: "pem", type: "pkcs8" }), dsaEncoding: "ieee-p1363" });
			return header + "." + payload + "." + b64url(sig);
		},
	};
}

/** Mint an authorization_code credential offer (operator-facing). Returns the
 * credential_offer object directly (the route returns result.credential_offer). */
async function mintAuthCodeOffer(vct: string = VCT): Promise<{ grants: { authorization_code: { issuer_state: string } } }> {
	const res = await app.request("/v1/credential-offers", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct, grantType: "authorization_code" }),
	});
	assert.equal(res.status, 201);
	return (await res.json()) as { grants: { authorization_code: { issuer_state: string } } };
}

/** Extract the `code` query param from a 302 Location header. */
function codeFromLocation(location: string): string {
	const url = new URL(location, ISSUER_URL);
	const code = url.searchParams.get("code");
	assert.ok(code, `expected code in Location ${location}`);
	return code;
}

beforeEach(() => { _resetStatusForTests(); _resetOid4vciForTests(); _resetOauthForTests(); });

test("1.6 OID4VCI auth-code: authorize -> consent -> code -> token -> credential (EdDSA)", async () => {
	const offer = await mintAuthCodeOffer();
	assert.ok(offer.grants.authorization_code, "offer advertises the authorization_code grant");

	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "wallet-state-123";

	// 1. Wallet opens the authorize endpoint in the learner's browser.
	const authorize = await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
		{ method: "GET" },
	);
	assert.equal(authorize.status, 200);
	assert.match(authorize.headers.get("content-type") ?? "", /text\/html/);
	const html = await authorize.text();
	assert.match(html, /Approve/, "consent page rendered");

	// 2. Learner consents (self-hosted fallback): POST the consent form.
	const consentForm = new URLSearchParams({
		learnerId: "learner-42",
		credential_configuration_id: VCT,
		redirect_uri: redirectUri,
		state,
		code_challenge: pkce.challenge,
		code_challenge_method: "S256",
	});
	const consent = await app.request("/oauth/consent", {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: consentForm.toString(),
		redirect: "manual",
	});
	assert.equal(consent.status, 302);
	const code = codeFromLocation(consent.headers.get("location")!);
	// The wallet's state is echoed back.
	assert.ok(consent.headers.get("location")!.includes(`state=${state}`));

	// 3. Wallet redeems the code + PKCE verifier at the token endpoint.
	const tokenRes = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(tokenRes.status, 200);
	const token = (await tokenRes.json()) as { access_token: string; c_nonce: string; token_type: string };
	assert.equal(token.token_type, "bearer");
	assert.ok(token.access_token);
	assert.ok(token.c_nonce, "c_nonce issued at the token endpoint");

	// 4. Wallet fetches the credential with a proof-of-possession JWT.
	const holder = holderKeypairES256();
	const credRes = await app.request("/credentials", {
		method: "POST",
		headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
		body: JSON.stringify({ proof: { jwt: holder.signProof(token.c_nonce), proof_type: "jwt" } }),
	});
	assert.equal(credRes.status, 200);
	const cred = (await credRes.json()) as { format: string; credential: string };
	assert.equal(cred.format, "vc+sd-jwt");
	assert.ok(cred.credential.includes("~"), "SD-JWT VC has a disclosure separator");
	const header = JSON.parse(b64urlDecode(cred.credential.split("~")[0]!.split(".")[0]!).toString("utf8")) as { alg: string };
	assert.equal(header.alg, "EdDSA");
});

test("1.6 OID4VCI auth-code: PKCE mismatch -> 400 INVALID_PKCE", async () => {
	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "s";
	await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
		{ method: "GET" },
	);
	const consentForm = new URLSearchParams({
		learnerId: "learner-99", credential_configuration_id: VCT, redirect_uri: redirectUri,
		state, code_challenge: pkce.challenge, code_challenge_method: "S256",
	});
	const consent = await app.request("/oauth/consent", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: consentForm.toString(), redirect: "manual",
	});
	const code = codeFromLocation(consent.headers.get("location")!);
	// Wrong verifier.
	const res = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: "wrong-verifier" }),
	});
	assert.equal(res.status, 400);
	const body = (await res.json()) as { error: { code: string } };
	assert.equal(body.error.code, "INVALID_PKCE");
});

test("1.6 OID4VCI auth-code: replayed code -> 400 INVALID_GRANT (single-use)", async () => {
	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "s2";
	await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
		{ method: "GET" },
	);
	const consentForm = new URLSearchParams({
		learnerId: "learner-5", credential_configuration_id: VCT, redirect_uri: redirectUri,
		state, code_challenge: pkce.challenge, code_challenge_method: "S256",
	});
	const consent = await app.request("/oauth/consent", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: consentForm.toString(), redirect: "manual",
	});
	const code = codeFromLocation(consent.headers.get("location")!);
	// First redeem succeeds.
	const ok = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(ok.status, 200);
	// Replay the same code -> rejected.
	const replay = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(replay.status, 400);
	const body = (await replay.json()) as { error: { code: string } };
	assert.equal(body.error.code, "INVALID_GRANT");
});

test("1.6 OID4VCI auth-code: /oauth/authorize missing code_challenge -> 400", async () => {
	const res = await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=https://w/cb&state=s`,
		{ method: "GET" },
	);
	assert.equal(res.status, 400);
});

test("1.6 OID4VCI auth-code: metadata advertises authorization_code + PKCE S256", async () => {
	const res = await app.request("/.well-known/oauth-authorization-server", { method: "GET" });
	assert.equal(res.status, 200);
	const meta = (await res.json()) as {
		authorization_endpoint: string; grant_types_supported: string[];
		response_types_supported: string[]; code_challenge_methods_supported: string[];
	};
	assert.equal(meta.authorization_endpoint, `${ISSUER_URL}/oauth/authorize`);
	assert.ok(meta.grant_types_supported.includes("authorization_code"));
	assert.ok(meta.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:pre-authorized_code"), "pre-authorized grant still advertised (no regression)");
	assert.deepEqual(meta.response_types_supported, ["code"]);
	assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
});

test("1.6 OID4VCI auth-code: pre-authorized-code flow unchanged (no regression)", async () => {
	const offerRes = await app.request("/v1/credential-offers", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: "did:web:lattice.mneurix.example/learners/9", vct: VCT, claims: { score: 0.9 } }),
	});
	assert.equal(offerRes.status, 201);
	const offer = (await offerRes.json()) as { grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { pre_authorized_code: string } } };
	const code = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].pre_authorized_code;
	const tok = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code", pre_authorized_code: code }),
	});
	assert.equal(tok.status, 200);
	const tokBody = (await tok.json()) as { access_token: string; c_nonce: string };
	assert.ok(tokBody.access_token);
	const holder = holderKeypairES256();
	const cred = await app.request("/credentials", {
		method: "POST",
		headers: { authorization: `Bearer ${tokBody.access_token}`, "content-type": "application/json" },
		body: JSON.stringify({ proof: { jwt: holder.signProof(tokBody.c_nonce), proof_type: "jwt" } }),
	});
	assert.equal(cred.status, 200);
});

test("1.6 OID4VCI auth-code: wallet sends issuer_state (no credential_config_id) — AltMe style", async () => {
	const offer = await mintAuthCodeOffer();
	const issuerState = offer.grants.authorization_code.issuer_state;
	assert.ok(issuerState, "offer carries an issuer_state");
	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "is-state";
	// authorize with issuer_state only (no credential_config_id) -> consent page renders
	const authorize = await app.request(
		`/oauth/authorize?issuer_state=${encodeURIComponent(issuerState)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&code_challenge=${pkce.challenge}&code_challenge_method=S256&response_type=code`,
		{ method: "GET" },
	);
	assert.equal(authorize.status, 200);
	assert.match(await authorize.text(), /Approve/);
	// consent -> code (the consent form carries the resolved vct as credential_configuration_id)
	const consentForm = new URLSearchParams({
		learnerId: "learner-is", credential_configuration_id: VCT,
		redirect_uri: redirectUri, state, code_challenge: pkce.challenge, code_challenge_method: "S256",
	});
	const consent = await app.request("/oauth/consent", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: consentForm.toString(), redirect: "manual",
	});
	assert.equal(consent.status, 302);
	const code = codeFromLocation(consent.headers.get("location")!);
	// token -> credential
	const tok = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(tok.status, 200);
	const tokBody = (await tok.json()) as { access_token: string; c_nonce: string };
	const holder = holderKeypairES256();
	const cred = await app.request("/credentials", {
		method: "POST",
		headers: { authorization: `Bearer ${tokBody.access_token}`, "content-type": "application/json" },
		body: JSON.stringify({ proof: { jwt: holder.signProof(tokBody.c_nonce), proof_type: "jwt" } }),
	});
	assert.equal(cred.status, 200);
	const credBody = (await cred.json()) as { credential: string };
	assert.ok(credBody.credential.includes("~"), "SD-JWT VC issued via the issuer_state path");
});

test("1.6 OID4VCI auth-code: wallet-supplied nonce returns as c_nonce (AltMe proof binding)", async () => {
	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "n-state";
	const walletNonce = "wallet-provided-nonce-xyz";
	const authorize = await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&code_challenge=${pkce.challenge}&code_challenge_method=S256&response_type=code&nonce=${encodeURIComponent(walletNonce)}`,
		{ method: "GET" },
	);
	assert.equal(authorize.status, 200);
	const html = await authorize.text();
	assert.ok(html.includes(`name="nonce"`), "consent page carries the wallet nonce hidden field");
	const consentForm = new URLSearchParams({
		learnerId: "learner-n", credential_configuration_id: VCT,
		redirect_uri: redirectUri, state, code_challenge: pkce.challenge, code_challenge_method: "S256",
		nonce: walletNonce,
	});
	const consent = await app.request("/oauth/consent", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: consentForm.toString(), redirect: "manual",
	});
	assert.equal(consent.status, 302);
	const code = codeFromLocation(consent.headers.get("location")!);
	const tok = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(tok.status, 200);
	const tokBody = (await tok.json()) as { access_token: string; c_nonce: string };
	assert.equal(tokBody.c_nonce, walletNonce, "c_nonce echoes the wallet-supplied nonce");
	// proof uses the WALLET nonce (== c_nonce) -> credential issued
	const holder = holderKeypairES256();
	const cred = await app.request("/credentials", {
		method: "POST",
		headers: { authorization: `Bearer ${tokBody.access_token}`, "content-type": "application/json" },
		body: JSON.stringify({ proof: { jwt: holder.signProof(walletNonce), proof_type: "jwt" } }),
	});
	assert.equal(cred.status, 200);
});

test("1.6 OID4VCI auth-code: did:jwk holder proof (AltMe style — key in kid/iss, not header.jwk)", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const pubJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
	const didJwk = "did:jwk:" + Buffer.from(JSON.stringify({ kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y })).toString("base64url");
	const signProofDidJwk = (nonce: string) => {
		const header = b64url(JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt", kid: didJwk + "#0" }));
		const payload = b64url(JSON.stringify({ nonce, iss: didJwk, aud: ISSUER_URL }));
		const signingInput = Buffer.from(header + "." + payload, "ascii");
		const sig = createSign("SHA256").update(signingInput).sign({ key: privateKey.export({ format: "pem", type: "pkcs8" }), dsaEncoding: "ieee-p1363" });
		return header + "." + payload + "." + b64url(sig);
	};
	const offer = await mintAuthCodeOffer();
	const issuerState = offer.grants.authorization_code.issuer_state;
	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "dj-state";
	const walletNonce = "dj-nonce-xyz";
	const authorize = await app.request(
		`/oauth/authorize?issuer_state=${encodeURIComponent(issuerState)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&code_challenge=${pkce.challenge}&code_challenge_method=S256&response_type=code&nonce=${encodeURIComponent(walletNonce)}`,
		{ method: "GET" },
	);
	assert.equal(authorize.status, 200);
	const consentForm = new URLSearchParams({
		learnerId: "learner-123", credential_configuration_id: VCT,
		redirect_uri: redirectUri, state, code_challenge: pkce.challenge, code_challenge_method: "S256", nonce: walletNonce,
	});
	const consent = await app.request("/oauth/consent", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: consentForm.toString(), redirect: "manual" });
	assert.equal(consent.status, 302);
	const code = codeFromLocation(consent.headers.get("location")!);
	const tok = await app.request("/oauth/token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }) });
	assert.equal(tok.status, 200);
	const tokBody = (await tok.json()) as { access_token: string; c_nonce: string };
	assert.equal(tokBody.c_nonce, walletNonce);
	// did:jwk proof — no header.jwk; the key is in kid/iss as a did:jwk DID
	const cred = await app.request("/credentials", { method: "POST", headers: { authorization: `Bearer ${tokBody.access_token}`, "content-type": "application/json" }, body: JSON.stringify({ proof: { jwt: signProofDidJwk(tokBody.c_nonce), proof_type: "jwt" } }) });
	const credText = await cred.text();
	assert.equal(cred.status, 200, `did:jwk proof credential fetch (got ${credText.slice(0, 200)})`);
	const credBody = JSON.parse(credText) as { credential: string };
	assert.ok(credBody.credential.includes("~"), "SD-JWT VC issued via the did:jwk proof path");
	const sdjwtPayload = JSON.parse(b64urlDecode(credBody.credential.split("~")[0]!.split(".")[1]!).toString("utf8")) as { sub?: string };
	assert.equal(sdjwtPayload.sub, didJwk, "credential sub is the wallet's did:jwk holder DID");
});

// --- Delegated path (lattice auth-result callback contract) ---
const SHARED_SECRET = "test-lattice-shared-secret";
let savedLatticeUrl: string | undefined;
let savedLatticeSecret: string | undefined;

function signHs256Jwt(payload: Record<string, unknown>, secret: string): string {
	const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
	const body = b64url(JSON.stringify(payload));
	const signingInput = Buffer.from(header + "." + body, "ascii");
	const sig = createHmac("sha256", secret).update(signingInput).digest();
	return header + "." + body + "." + b64url(sig);
}

afterEach(() => {
	if (savedLatticeUrl === undefined) delete process.env.MNEURIX_LATTICE_AUTH_URL;
	else process.env.MNEURIX_LATTICE_AUTH_URL = savedLatticeUrl;
	if (savedLatticeSecret === undefined) delete process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET;
	else process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET = savedLatticeSecret;
	savedLatticeUrl = undefined;
	savedLatticeSecret = undefined;
});

test("1.6 OID4VCI auth-code: delegated path — /oauth/authorize 302s to the lattice + /oauth/callback issues a code from a signed auth result", async () => {
	savedLatticeUrl = process.env.MNEURIX_LATTICE_AUTH_URL;
	savedLatticeSecret = process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET;
	process.env.MNEURIX_LATTICE_AUTH_URL = "https://lattice.mneurix.example/auth/lti-delegate";
	process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET = SHARED_SECRET;

	const pkce = pkcePair();
	const redirectUri = "https://wallet.example/callback";
	const state = "wallet-state-d";

	// /oauth/authorize delegates -> 302 to the lattice with callback + pending_state.
	const authorize = await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
		{ method: "GET", redirect: "manual" },
	);
	assert.equal(authorize.status, 302);
	const location = authorize.headers.get("location")!;
	assert.ok(location.startsWith("https://lattice.mneurix.example/auth/lti-delegate"), `delegated to lattice: ${location}`);
	const pendingState = new URL(location, ISSUER_URL).searchParams.get("pending_state");
	assert.ok(pendingState, "pending_state issued for the callback");

	// The lattice authenticates the learner + redirects back with a signed auth_result.
	const authResult = signHs256Jwt({ learnerId: "learner-delegated", iss: "https://lattice.mneurix.example", aud: ISSUER_URL }, SHARED_SECRET);
	const callback = await app.request(
		`/oauth/callback?pending_state=${encodeURIComponent(pendingState!)}&auth_result=${encodeURIComponent(authResult)}&state=${encodeURIComponent(state)}`,
		{ method: "GET", redirect: "manual" },
	);
	assert.equal(callback.status, 302);
	const code = codeFromLocation(callback.headers.get("location")!);
	assert.ok(callback.headers.get("location")!.includes(`state=${state}`), "wallet state echoed");

	// The wallet redeems the delegated-issued code + PKCE verifier -> credential.
	const tok = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: pkce.verifier }),
	});
	assert.equal(tok.status, 200);
	const tokBody = (await tok.json()) as { access_token: string; c_nonce: string };
	const holder = holderKeypairES256();
	const cred = await app.request("/credentials", {
		method: "POST",
		headers: { authorization: `Bearer ${tokBody.access_token}`, "content-type": "application/json" },
		body: JSON.stringify({ proof: { jwt: holder.signProof(tokBody.c_nonce), proof_type: "jwt" } }),
	});
	assert.equal(cred.status, 200);
});

test("1.6 OID4VCI auth-code: delegated callback with a bad signature -> 401", async () => {
	savedLatticeUrl = process.env.MNEURIX_LATTICE_AUTH_URL;
	savedLatticeSecret = process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET;
	process.env.MNEURIX_LATTICE_AUTH_URL = "https://lattice.mneurix.example/auth/lti-delegate";
	process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET = SHARED_SECRET;

	const pkce = pkcePair();
	const authorize = await app.request(
		`/oauth/authorize?credential_configuration_id=${encodeURIComponent(VCT)}&redirect_uri=https://w/cb&state=s&code_challenge=${pkce.challenge}&code_challenge_method=S256`,
		{ method: "GET", redirect: "manual" },
	);
	const pendingState = new URL(authorize.headers.get("location")!, ISSUER_URL).searchParams.get("pending_state")!;
	const badResult = signHs256Jwt({ learnerId: "x" }, "wrong-secret");
	const res = await app.request(
		`/oauth/callback?pending_state=${encodeURIComponent(pendingState)}&auth_result=${encodeURIComponent(badResult)}&state=s`,
		{ method: "GET" },
	);
	assert.equal(res.status, 401);
});

test("1.6 OID4VCI auth-code: /oauth/callback fail-closed when delegation unconfigured", async () => {
	// No MNEURIX_LATTICE_AUTH_URL set (default) -> the callback is unavailable.
	const res = await app.request("/oauth/callback?pending_state=x&auth_result=y&state=s", { method: "GET" });
	assert.equal(res.status, 400);
});