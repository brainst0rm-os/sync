/**
 * SYNC-4b — entitlement-token verifier: round-trip, fail-closed paths, and the
 * offline grace window. Tokens are signed here with WebCrypto Ed25519 (the
 * `brainstorm-cloud` Rust signer's behaviour, mirrored for tests).
 */

import { beforeAll, describe, expect, test } from "bun:test";
import {
	ENTITLEMENT_TOKEN_VERSION,
	type EntitlementClaims,
	EntitlementStatus,
	PlanTier,
	type VerifierKeySet,
	VerifyFailure,
	buildVerifierKeySet,
	verifyEntitlementToken,
} from "./entitlement";

const KID = "k1";
const b64 = (b: Uint8Array | string) =>
	Buffer.from(typeof b === "string" ? new TextEncoder().encode(b) : b).toString("base64url");
const data = (s: string): Uint8Array<ArrayBuffer> => {
	const e = new TextEncoder().encode(s);
	const out = new Uint8Array(e.byteLength);
	out.set(e);
	return out;
};
const genKeypair = async (): Promise<CryptoKeyPair> =>
	(await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as unknown as CryptoKeyPair;

let priv: CryptoKey;
let keys: VerifierKeySet;
let otherPriv: CryptoKey;

beforeAll(async () => {
	const kp = await genKeypair();
	priv = kp.privateKey;
	const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	keys = await buildVerifierKeySet({ [KID]: b64(rawPub) });
	otherPriv = (await genKeypair()).privateKey;
});

async function sign(claims: EntitlementClaims, kid = KID, key = priv): Promise<string> {
	const headerB64 = b64(JSON.stringify({ alg: "EdDSA", kid }));
	const claimsB64 = b64(JSON.stringify(claims));
	const sig = new Uint8Array(
		await crypto.subtle.sign({ name: "Ed25519" }, key, data(`${headerB64}.${claimsB64}`)),
	);
	return `${headerB64}.${claimsB64}.${b64(sig)}`;
}

function claims(over: Partial<EntitlementClaims> = {}): EntitlementClaims {
	return {
		v: ENTITLEMENT_TOKEN_VERSION,
		sub: "acc_42",
		plan: PlanTier.Plus,
		features: ["hosted-relay"],
		iat: 1000,
		softExp: 2000,
		hardExp: 3000,
		iss: "billing-edge",
		...over,
	};
}

describe("verifyEntitlementToken (SYNC-4b)", () => {
	test("a valid token verifies; claims are returned", async () => {
		const result = await verifyEntitlementToken(await sign(claims()), keys, 1500);
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.status).toBe(EntitlementStatus.Active);
			expect(result.claims.sub).toBe("acc_42");
			expect(result.claims.plan).toBe(PlanTier.Plus);
		}
	});

	test("between softExp and hardExp → Grace", async () => {
		const result = await verifyEntitlementToken(await sign(claims()), keys, 2500);
		expect(result.valid && result.status).toBe(EntitlementStatus.Grace);
	});

	test("at/after hardExp → HardExpired", async () => {
		const result = await verifyEntitlementToken(await sign(claims()), keys, 3000);
		expect(result).toEqual({ valid: false, reason: VerifyFailure.HardExpired });
	});

	test("unknown kid → UnknownKey", async () => {
		const result = await verifyEntitlementToken(await sign(claims(), "nope"), keys, 1500);
		expect(result).toEqual({ valid: false, reason: VerifyFailure.UnknownKey });
	});

	test("a signature from a different key → BadSignature", async () => {
		const forged = await sign(claims(), KID, otherPriv);
		const result = await verifyEntitlementToken(forged, keys, 1500);
		expect(result).toEqual({ valid: false, reason: VerifyFailure.BadSignature });
	});

	test("a tampered claims segment → BadSignature", async () => {
		const token = await sign(claims());
		const [h, , s] = token.split(".");
		const tampered = `${h}.${b64(JSON.stringify(claims({ plan: PlanTier.Enterprise })))}.${s}`;
		const result = await verifyEntitlementToken(tampered, keys, 1500);
		expect(result.valid).toBe(false);
	});

	test("malformed compact strings are rejected", async () => {
		for (const bad of ["", "a.b", "a.b.c.d", "!!.??.$$"]) {
			expect((await verifyEntitlementToken(bad, keys, 1500)).valid).toBe(false);
		}
	});

	test("a kid of __proto__ does not resolve via the prototype chain", async () => {
		const result = await verifyEntitlementToken(await sign(claims(), "__proto__"), keys, 1500);
		expect(result).toEqual({ valid: false, reason: VerifyFailure.UnknownKey });
	});

	test("a signed-but-shape-invalid token fails after the signature check", async () => {
		// hardExp missing → claims-shape invalid, but the signature is valid.
		const bad = { ...claims() } as Record<string, unknown>;
		bad.hardExp = undefined;
		const headerB64 = b64(JSON.stringify({ alg: "EdDSA", kid: KID }));
		const claimsB64 = b64(JSON.stringify(bad));
		const sig = new Uint8Array(
			await crypto.subtle.sign({ name: "Ed25519" }, priv, data(`${headerB64}.${claimsB64}`)),
		);
		const result = await verifyEntitlementToken(
			`${headerB64}.${claimsB64}.${b64(sig)}`,
			keys,
			1500,
		);
		expect(result).toEqual({ valid: false, reason: VerifyFailure.Malformed });
	});
});
