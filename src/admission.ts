/**
 * SYNC-4b — connection admission: the two-proof handshake.
 *
 * relay-blind-exempt: Ed25519 signature verification for AUTH only (no DEK, no
 * ciphertext, not on the fan-out path). See CLAUDE.md §SYNC-4.
 *
 * A gated node admits a connection on TWO independent proofs, because the two
 * planes deliberately don't share ids:
 *
 *   1. **Entitlement token** (`brainstorm-cloud`, `sub` = billing account) →
 *      *may you connect, on what plan, within what quota.* Verified offline
 *      against a bundled keyset (`entitlement.ts`).
 *   2. **Identity proof** (`account` = base64url Ed25519 identity pubkey = the
 *      wire `sender`) → *which entities are yours.* The node mints a per-
 *      connection nonce; the client signs it with its identity key; the node
 *      verifies against the pubkey decoded FROM the claimed account. This binds
 *      the connection to a proven `sender`, so the catalog query can be scoped
 *      to it (closing the SYNC-4a open-admission metadata leak) and emission can
 *      be checked against it.
 *
 * The two are independent authorizations: the token authorizes the billing
 * account; the identity proof authorizes the wire account. Neither implies the
 * other, which is exactly why the planes can keep separate id namespaces.
 */

import {
	type EntitlementStatus,
	type PlanTier,
	type VerifierKeySet,
	importVerifyKey,
	verifyEntitlementToken,
} from "./entitlement";

const ALG = { name: "Ed25519" } as const;
const NONCE_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/** Client→server auth message (control channel, gated mode). */
export type AuthMessage = {
	op: "auth";
	/** Compact entitlement token from `brainstorm-cloud`. */
	token: string;
	/** base64url Ed25519 identity public key (== the wire `sender`). */
	account: string;
	/** base64url Ed25519 signature over the raw challenge-nonce bytes. */
	sig: string;
};

export enum AdmissionFailure {
	Malformed = "malformed",
	Token = "token",
	Identity = "identity",
	Feature = "feature",
}

export type AdmissionResult =
	| {
			admitted: true;
			/** The proven wire account (= sender). Scopes catalog + emission. */
			account: string;
			/** The billing account (token `sub`). The metering key. */
			sub: string;
			plan: PlanTier;
			status: EntitlementStatus;
			features: string[];
	  }
	| { admitted: false; reason: AdmissionFailure; detail?: string };

export type AdmissionOptions = {
	keys: VerifierKeySet;
	now?: () => number;
	mintNonce?: () => string;
	/** If set, the token's `features` must include this flag (e.g. the managed
	 *  node requires `hosted-relay`). Unset ⇒ any valid token admits. */
	requiredFeature?: string;
};

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

function defaultMintNonce(): string {
	const bytes = new Uint8Array(NONCE_BYTES);
	crypto.getRandomValues(bytes);
	return Buffer.from(bytes).toString("base64url");
}

export function isAuthMessage(value: unknown): value is AuthMessage {
	if (typeof value !== "object" || value === null) return false;
	const o = value as Record<string, unknown>;
	return (
		o.op === "auth" &&
		typeof o.token === "string" &&
		o.token.length > 0 &&
		typeof o.account === "string" &&
		o.account.length > 0 &&
		typeof o.sig === "string" &&
		o.sig.length > 0
	);
}

export class Admission {
	readonly #keys: VerifierKeySet;
	readonly #now: () => number;
	readonly #mintNonce: () => string;
	readonly #requiredFeature: string | null;

	constructor(opts: AdmissionOptions) {
		this.#keys = opts.keys;
		// Entitlement claim times are epoch SECONDS (the brainstorm-cloud
		// contract), so the default clock is seconds — not `Date.now()` ms.
		this.#now = opts.now ?? (() => Math.floor(Date.now() / 1000));
		this.#mintNonce = opts.mintNonce ?? defaultMintNonce;
		this.#requiredFeature = opts.requiredFeature ?? null;
	}

	/** A fresh per-connection challenge nonce (base64url). */
	createChallenge(): string {
		return this.#mintNonce();
	}

	/** Verify both proofs against the challenge the node issued. */
	async verify(msg: AuthMessage, nonce: string): Promise<AdmissionResult> {
		if (!isAuthMessage(msg)) return { admitted: false, reason: AdmissionFailure.Malformed };

		const token = await verifyEntitlementToken(msg.token, this.#keys, this.#now());
		if (!token.valid) {
			return { admitted: false, reason: AdmissionFailure.Token, detail: token.reason };
		}
		if (this.#requiredFeature && !token.claims.features.includes(this.#requiredFeature)) {
			return { admitted: false, reason: AdmissionFailure.Feature, detail: this.#requiredFeature };
		}

		const identityOk = await this.#verifyIdentity(msg.account, nonce, msg.sig);
		if (!identityOk) return { admitted: false, reason: AdmissionFailure.Identity };

		return {
			admitted: true,
			account: msg.account,
			sub: token.claims.sub,
			plan: token.claims.plan,
			status: token.status,
			features: token.claims.features,
		};
	}

	/** Verify the nonce signature against the pubkey decoded from `account`. */
	async #verifyIdentity(account: string, nonce: string, sig: string): Promise<boolean> {
		let publicKeyBytes: Uint8Array<ArrayBuffer>;
		let signature: Uint8Array<ArrayBuffer>;
		let challenge: Uint8Array<ArrayBuffer>;
		try {
			publicKeyBytes = b64urlDecode(account);
			signature = b64urlDecode(sig);
			challenge = b64urlDecode(nonce);
		} catch {
			return false;
		}
		if (
			publicKeyBytes.length !== ED25519_PUBLIC_KEY_BYTES ||
			signature.length !== ED25519_SIGNATURE_BYTES ||
			challenge.length === 0
		) {
			return false;
		}
		try {
			const key = await importVerifyKey(publicKeyBytes);
			return await crypto.subtle.verify(ALG, key, signature, challenge);
		} catch {
			return false;
		}
	}
}
