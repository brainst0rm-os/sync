/**
 * SYNC-4b — the two-proof admission handshake: a valid token + a nonce signed
 * by the claimed identity key admits; either proof failing rejects; a token
 * paired with the wrong identity key is rejected on the identity proof.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { Admission, AdmissionFailure, type AdmissionOptions, type AuthMessage } from "./admission";
import {
	ENTITLEMENT_TOKEN_VERSION,
	type EntitlementClaims,
	PlanTier,
	type VerifierKeySet,
	buildVerifierKeySet,
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

let billingPriv: CryptoKey;
let keys: VerifierKeySet;
let identity: CryptoKeyPair;
let account: string;

beforeAll(async () => {
	const billing = await genKeypair();
	billingPriv = billing.privateKey;
	keys = await buildVerifierKeySet({
		[KID]: b64(new Uint8Array(await crypto.subtle.exportKey("raw", billing.publicKey))),
	});
	identity = await genKeypair();
	account = b64(new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey)));
});

async function signToken(over: Partial<EntitlementClaims> = {}): Promise<string> {
	const claims: EntitlementClaims = {
		v: ENTITLEMENT_TOKEN_VERSION,
		sub: "acc_7",
		plan: PlanTier.Plus,
		features: ["hosted-relay"],
		iat: 0,
		softExp: 10_000,
		hardExp: 20_000,
		iss: "billing-edge",
		...over,
	};
	const headerB64 = b64(JSON.stringify({ alg: "EdDSA", kid: KID }));
	const claimsB64 = b64(JSON.stringify(claims));
	const sig = new Uint8Array(
		await crypto.subtle.sign({ name: "Ed25519" }, billingPriv, data(`${headerB64}.${claimsB64}`)),
	);
	return `${headerB64}.${claimsB64}.${b64(sig)}`;
}

async function signNonce(nonce: string, key = identity.privateKey): Promise<string> {
	const sig = await crypto.subtle.sign(
		{ name: "Ed25519" },
		key,
		new Uint8Array(Buffer.from(nonce, "base64url")),
	);
	return b64(new Uint8Array(sig));
}

function makeAdmission(over: Partial<AdmissionOptions> = {}): Admission {
	return new Admission({ keys, now: () => 1000, ...over });
}

describe("Admission (SYNC-4b)", () => {
	test("valid token + correctly-signed nonce → admitted, scoped to the account", async () => {
		const adm = makeAdmission();
		const nonce = adm.createChallenge();
		const msg: AuthMessage = {
			op: "auth",
			token: await signToken(),
			account,
			sig: await signNonce(nonce),
		};
		const result = await adm.verify(msg, nonce);
		expect(result.admitted).toBe(true);
		if (result.admitted) {
			expect(result.account).toBe(account);
			expect(result.sub).toBe("acc_7");
			expect(result.plan).toBe(PlanTier.Plus);
		}
	});

	test("each challenge is unique", () => {
		const adm = makeAdmission();
		expect(adm.createChallenge()).not.toBe(adm.createChallenge());
	});

	test("an expired token is rejected on the token proof", async () => {
		const adm = makeAdmission({ now: () => 99_999 });
		const nonce = adm.createChallenge();
		const result = await adm.verify(
			{ op: "auth", token: await signToken(), account, sig: await signNonce(nonce) },
			nonce,
		);
		expect(result).toMatchObject({ admitted: false, reason: AdmissionFailure.Token });
	});

	test("a valid token paired with a foreign identity key fails the identity proof", async () => {
		const adm = makeAdmission();
		const nonce = adm.createChallenge();
		const attacker = await genKeypair();
		// Attacker signs the nonce with their own key but claims the victim's account.
		const result = await adm.verify(
			{
				op: "auth",
				token: await signToken(),
				account,
				sig: await signNonce(nonce, attacker.privateKey),
			},
			nonce,
		);
		expect(result).toMatchObject({ admitted: false, reason: AdmissionFailure.Identity });
	});

	test("a signature over a different nonce is rejected (no replay)", async () => {
		const adm = makeAdmission();
		const nonce = adm.createChallenge();
		const result = await adm.verify(
			{ op: "auth", token: await signToken(), account, sig: await signNonce("AAAA") },
			nonce,
		);
		expect(result.admitted).toBe(false);
	});

	test("a malformed auth message is rejected", async () => {
		const adm = makeAdmission();
		const result = await adm.verify(
			{ op: "auth" } as unknown as AuthMessage,
			adm.createChallenge(),
		);
		expect(result).toMatchObject({ admitted: false, reason: AdmissionFailure.Malformed });
	});

	test("requiredFeature gates a token missing the flag", async () => {
		const adm = makeAdmission({ requiredFeature: "hosted-relay" });
		const nonce = adm.createChallenge();
		const ok = await adm.verify(
			{ op: "auth", token: await signToken(), account, sig: await signNonce(nonce) },
			nonce,
		);
		expect(ok.admitted).toBe(true);

		const nonce2 = adm.createChallenge();
		const missing = await adm.verify(
			{
				op: "auth",
				token: await signToken({ features: [] }),
				account,
				sig: await signNonce(nonce2),
			},
			nonce2,
		);
		expect(missing).toMatchObject({ admitted: false, reason: AdmissionFailure.Feature });
	});
});
