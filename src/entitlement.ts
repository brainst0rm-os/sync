/**
 * SYNC-4b — entitlement-token verifier (the `brainstorm-cloud` seam).
 *
 * relay-blind-exempt: this module performs Ed25519 *signature verification* for
 * ADMISSION (auth), never content decryption. It is the one sanctioned crypto
 * surface in the node (CLAUDE.md §SYNC-4) — it touches no DEK, no ciphertext,
 * and is NOT on the route/fan-out path (`wire`/`router`/`server` stay blind).
 *
 * This is a deliberate standalone mirror of `brainstorm-cloud/packages/api-client`
 * §EntitlementClaims — the cross-plane WIRE CONTRACT, not shared code (exactly
 * as `wire.ts` mirrors the product's envelope codec; the planes share formats,
 * never imports). Compact JWS-style serialization:
 *
 *   base64url(header) "." base64url(claims) "." base64url(ed25519 sig)
 *
 * The signature covers the ASCII bytes of `header "." claims` (the exact
 * base64url strings, NOT a re-serialization) so the Rust signer and this
 * verifier agree byte-for-byte. Verified OFFLINE against a bundled keyset — the
 * node never calls `brainstorm-cloud` to admit a connection.
 *
 * Crypto is WebCrypto Ed25519 (Bun built-in) → zero runtime deps.
 */

export enum PlanTier {
	Free = "free",
	Plus = "plus",
	Pro = "pro",
	Team = "team",
	Enterprise = "enterprise",
}

export const ENTITLEMENT_TOKEN_VERSION = 1 as const;

export type EntitlementClaims = {
	v: typeof ENTITLEMENT_TOKEN_VERSION;
	/** Control-plane account id (NEVER a vault id; NEVER the wire sender). */
	sub: string;
	plan: PlanTier;
	features: string[];
	iat: number;
	softExp: number;
	hardExp: number;
	iss: string;
};

export enum EntitlementStatus {
	Active = "active",
	/** Past softExp, before hardExp — still entitled, should refresh soon. */
	Grace = "grace",
}

export enum VerifyFailure {
	Malformed = "malformed",
	UnknownKey = "unknown-key",
	BadSignature = "bad-signature",
	HardExpired = "hard-expired",
}

export type VerifyResult =
	| { valid: true; status: EntitlementStatus; claims: EntitlementClaims }
	| { valid: false; reason: VerifyFailure };

/** kid → imported Ed25519 public key (verify-only). >1 entry during rotation. */
export type VerifierKeySet = Record<string, CryptoKey>;

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ALG = { name: "Ed25519" } as const;
const TEXT_DECODER = new TextDecoder();

type TokenHeader = { alg: "EdDSA"; kid: string };

// WebCrypto's `BufferSource` requires an ArrayBuffer-backed view (not the
// `ArrayBufferLike` a bare `Uint8Array` annotation widens to), so both helpers
// return a fresh ArrayBuffer-backed copy.
function utf8(s: string): Uint8Array<ArrayBuffer> {
	const e = new TextEncoder().encode(s);
	const out = new Uint8Array(e.byteLength);
	out.set(e);
	return out;
}

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Import a raw 32-byte Ed25519 public key for verify (throws on bad length). */
export async function importVerifyKey(rawPublicKey: Uint8Array): Promise<CryptoKey> {
	if (rawPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
		throw new Error(`Ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`);
	}
	return crypto.subtle.importKey("raw", new Uint8Array(rawPublicKey), ALG, false, ["verify"]);
}

/**
 * Build a verifier keyset from a `{ kid: base64url-public-key }` record (the
 * shape the node reads from `ENTITLEMENT_KEYS`). Imports each key once at boot
 * so per-connection verification is a cheap async `verify`.
 */
export async function buildVerifierKeySet(
	rawKeys: Record<string, string>,
): Promise<VerifierKeySet> {
	const set: VerifierKeySet = {};
	for (const [kid, b64] of Object.entries(rawKeys)) {
		set[kid] = await importVerifyKey(b64urlDecode(b64));
	}
	return set;
}

function isTokenHeader(value: unknown): value is TokenHeader {
	if (typeof value !== "object" || value === null) return false;
	const o = value as Record<string, unknown>;
	return o.alg === "EdDSA" && typeof o.kid === "string" && o.kid.length > 0;
}

function isEntitlementClaims(value: unknown): value is EntitlementClaims {
	if (typeof value !== "object" || value === null) return false;
	const o = value as Record<string, unknown>;
	const num = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);
	return (
		o.v === ENTITLEMENT_TOKEN_VERSION &&
		typeof o.sub === "string" &&
		o.sub.length > 0 &&
		typeof o.plan === "string" &&
		(Object.values(PlanTier) as string[]).includes(o.plan) &&
		Array.isArray(o.features) &&
		o.features.every((f) => typeof f === "string") &&
		typeof o.iss === "string" &&
		num(o.iat) &&
		num(o.softExp) &&
		num(o.hardExp) &&
		o.softExp <= o.hardExp
	);
}

/**
 * Offline-verify an entitlement token. Fail-closed on every parse/crypto/shape
 * error: the algorithm is pinned (never trusts `alg` from the token), the key
 * is looked up by own-property only (a `kid` of "__proto__" can't resolve to an
 * inherited value), and the claim SHAPE is validated AFTER the signature so a
 * signed-but-malformed token can never slip past.
 */
export async function verifyEntitlementToken(
	compact: string,
	keys: VerifierKeySet,
	now: number,
): Promise<VerifyResult> {
	const parts = compact.split(".");
	if (parts.length !== 3) return { valid: false, reason: VerifyFailure.Malformed };
	const [headerB64, claimsB64, sigB64] = parts;
	if (
		headerB64 === undefined ||
		claimsB64 === undefined ||
		sigB64 === undefined ||
		!BASE64URL_SEGMENT.test(headerB64) ||
		!BASE64URL_SEGMENT.test(claimsB64) ||
		!BASE64URL_SEGMENT.test(sigB64)
	) {
		return { valid: false, reason: VerifyFailure.Malformed };
	}

	let header: unknown;
	let claims: unknown;
	let signature: Uint8Array<ArrayBuffer>;
	try {
		header = JSON.parse(TEXT_DECODER.decode(b64urlDecode(headerB64)));
		claims = JSON.parse(TEXT_DECODER.decode(b64urlDecode(claimsB64)));
		signature = b64urlDecode(sigB64);
	} catch {
		return { valid: false, reason: VerifyFailure.Malformed };
	}

	if (!isTokenHeader(header)) return { valid: false, reason: VerifyFailure.Malformed };
	if (signature.length !== ED25519_SIGNATURE_BYTES) {
		return { valid: false, reason: VerifyFailure.Malformed };
	}
	if (!Object.hasOwn(keys, header.kid)) return { valid: false, reason: VerifyFailure.UnknownKey };
	const publicKey = keys[header.kid];
	if (publicKey === undefined) return { valid: false, reason: VerifyFailure.UnknownKey };

	let ok = false;
	try {
		ok = await crypto.subtle.verify(ALG, publicKey, signature, utf8(`${headerB64}.${claimsB64}`));
	} catch {
		ok = false;
	}
	if (!ok) return { valid: false, reason: VerifyFailure.BadSignature };

	if (!isEntitlementClaims(claims)) return { valid: false, reason: VerifyFailure.Malformed };
	if (now >= claims.hardExp) return { valid: false, reason: VerifyFailure.HardExpired };
	const status = now >= claims.softExp ? EntitlementStatus.Grace : EntitlementStatus.Active;
	return { valid: true, status, claims };
}
