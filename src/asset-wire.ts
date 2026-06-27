/**
 * Asset-B3 — the node's copy of the blob-plane wire protocol (`WireKind.Asset`,
 * Asset-B2). Mirrors the shell's `packages/shell/src/main/assets/asset-wire.ts`
 * byte-for-byte (kept in lockstep, the way the relay duplicates `wire.ts`) so a
 * shell `WireAssetCas` talks to this node unchanged. This file is the
 * **responder** side: decode a request, apply it to a local `AssetCas`, encode
 * the response.
 *
 * The verbs are `Has` (skip already-present), `Put` (store a sealed chunk),
 * `Get` (fetch one) keyed by the ciphertext-hash. Framing:
 * `u32-be(headerLen) || JSON header || trailing chunk` (chunk present on a Put
 * request and a found Get response).
 *
 * **Relay-blind.** The hash is an opaque address (the node never computes it —
 * the client content-addresses + verifies). It is, however, VALIDATED here as
 * `[0-9a-f]{64}` at this untrusted wire edge so a hostile "hash" can't smuggle
 * a non-address into the store (path-traversal defense). No crypto. See
 * CLAUDE.md.
 */

import { type AssetCas, isAssetHash } from "./sync/asset-cas";

export enum AssetWireKind {
	Has = "has",
	Put = "put",
	Get = "get",
}

function invalid(message: string): Error {
	const err = new Error(message);
	err.name = "Invalid";
	return err;
}

/** `u32-be(headerLen) || headerJSON || trailingChunk`. */
function frame(header: unknown, chunk?: Uint8Array): Uint8Array {
	const headerBytes = new TextEncoder().encode(JSON.stringify(header));
	const tail = chunk ?? new Uint8Array(0);
	const out = new Uint8Array(4 + headerBytes.length + tail.length);
	new DataView(out.buffer).setUint32(0, headerBytes.length, false);
	out.set(headerBytes, 4);
	out.set(tail, 4 + headerBytes.length);
	return out;
}

function unframe(bytes: Uint8Array): { header: Record<string, unknown>; chunk: Uint8Array } {
	if (!(bytes instanceof Uint8Array) || bytes.length < 4) {
		throw invalid("asset frame: too short for a length prefix");
	}
	const headerLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
		0,
		false,
	);
	if (headerLen <= 0 || 4 + headerLen > bytes.length) {
		throw invalid("asset frame: header length out of range");
	}
	let header: unknown;
	try {
		header = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + headerLen)));
	} catch {
		throw invalid("asset frame: header is not valid JSON");
	}
	if (!header || typeof header !== "object" || Array.isArray(header)) {
		throw invalid("asset frame: header is not an object");
	}
	return { header: header as Record<string, unknown>, chunk: bytes.subarray(4 + headerLen) };
}

export type AssetRequest =
	| { kind: AssetWireKind.Has; hash: string }
	| { kind: AssetWireKind.Put; hash: string; chunk: Uint8Array }
	| { kind: AssetWireKind.Get; hash: string };

/** Encode a request (symmetric with {@link decodeAssetRequest}) — used by the
 *  node's tests + any node-side client. The shell builds these in production. */
export function encodeAssetRequest(req: AssetRequest): Uint8Array {
	if (req.kind === AssetWireKind.Put) return frame({ k: req.kind, hash: req.hash }, req.chunk);
	return frame({ k: req.kind, hash: req.hash });
}

const KINDS = new Set<string>([AssetWireKind.Has, AssetWireKind.Put, AssetWireKind.Get]);

/** Decode + VALIDATE an untrusted client request. Throws `Invalid` on a bad
 *  kind or a non-`[0-9a-f]{64}` address. */
export function decodeAssetRequest(bytes: Uint8Array): AssetRequest {
	const { header, chunk } = unframe(bytes);
	const k = header.k;
	if (typeof k !== "string" || !KINDS.has(k)) throw invalid(`asset request: bad kind ${String(k)}`);
	if (!isAssetHash(header.hash)) throw invalid("asset request: address must be 64-hex");
	const hash = header.hash;
	if (k === AssetWireKind.Put)
		return { kind: AssetWireKind.Put, hash, chunk: new Uint8Array(chunk) };
	if (k === AssetWireKind.Get) return { kind: AssetWireKind.Get, hash };
	return { kind: AssetWireKind.Has, hash };
}

export function encodeHasResponse(present: boolean): Uint8Array {
	return frame({ k: AssetWireKind.Has, present });
}
export function encodePutResponse(ok: boolean): Uint8Array {
	return frame({ k: AssetWireKind.Put, ok });
}
export function encodeGetResponse(chunk: Uint8Array | null): Uint8Array {
	return chunk
		? frame({ k: AssetWireKind.Get, found: true }, chunk)
		: frame({ k: AssetWireKind.Get, found: false });
}

/** The result of serving one asset request: the verb (so the caller meters a
 *  `Put` as ingress vs a `Get` as egress), the response frame to send back to
 *  the requesting connection, and the chunk byte count to meter (the chunk size
 *  on a Put / a found Get; 0 for Has / a miss). */
export type AssetServeResult = { kind: AssetWireKind; response: Uint8Array; meteredBytes: number };

/**
 * Decode a request, apply it to `cas`, and return the verb + response frame +
 * metered byte count. Pure routing — never touches a key. The node-side
 * counterpart to the shell's `serveAssetRequest`. Throws `Invalid` on a
 * malformed request (the caller drops it).
 */
export async function handleAssetRequest(
	cas: AssetCas,
	request: Uint8Array,
): Promise<AssetServeResult> {
	const req = decodeAssetRequest(request);
	if (req.kind === AssetWireKind.Has) {
		return {
			kind: req.kind,
			response: encodeHasResponse(await cas.has(req.hash)),
			meteredBytes: 0,
		};
	}
	if (req.kind === AssetWireKind.Put) {
		await cas.put(req.hash, req.chunk);
		return { kind: req.kind, response: encodePutResponse(true), meteredBytes: req.chunk.length };
	}
	const chunk = await cas.get(req.hash);
	return { kind: req.kind, response: encodeGetResponse(chunk), meteredBytes: chunk?.length ?? 0 };
}
