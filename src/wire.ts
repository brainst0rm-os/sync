/**
 * Wire decoder — the routing header the relay peeks at.
 *
 * **Cross-plane contract.** This is the sync plane's half of the wire format
 * the Brainstorm client speaks (the product's `packages/shell/src/main/sync`
 * envelope codec is the canonical source). It is deliberately a standalone copy
 * — this repo imports NOTHING from the product, exactly as the product's own
 * `packages/relay-server` keeps its own copy. The two move in lockstep on the
 * wire format only; that format is the contract (the sync analog of the
 * control plane's `api-client`).
 *
 * **Relay-blind invariant.** This module — and every module on the route path —
 * must not import any crypto / credential / envelope-seal code. The node reads
 * the routing header for fan-out + the audit log and forwards the ciphertext
 * body untouched; it can NEVER decode it (it holds no key). See CLAUDE.md.
 *
 * Wire layout (matches the client's envelope codec):
 *
 *   u32-be(headerLen) || canonicalHeaderBytes
 *     || u16-be(sigLen=64) || sig
 *     || u32-be(ctLen) || ciphertext
 *
 * The relay reads `headerLen` + the canonical header bytes; parses the header
 * (entity-id + sender for the audit log + kind for routing) and forwards the
 * entire untouched frame to subscribers. The ciphertext after the header is
 * opaque — the relay never decodes it.
 */

export const PROTOCOL_VERSION = 1 as const;
export const ED25519_SIG_BYTES = 64;

export enum WireKind {
	Update = "update",
	Snapshot = "snapshot",
	WrapBootstrap = "wrap-bootstrap",
	/** Pairing handshake transport (routed by `pairingChannelId` as the
	 *  `entityId`). The relay never inspects the body — same as every kind. */
	Pairing = "pairing",
	/** Transient awareness updates (cursor / presence). Body is sealed under
	 *  the entity DEK, opaque to the relay just like `Update` frames. */
	Awareness = "awareness",
}

export type RoutingHeader = {
	v: number;
	kind: WireKind;
	entityId: string;
	sender: string;
	seq: number;
	nonce: string;
	ts: number;
};

const KIND_SET = new Set<string>(Object.values(WireKind));
const DECODER = new TextDecoder();

/**
 * Strict-shape parse of canonical routing-header bytes. Throws `Invalid`
 * (named Error, kind="Invalid") on any deviation — wrong protocol version,
 * missing field, wrong type, unknown `kind`.
 */
export function parseRoutingHeaderJson(bytes: Uint8Array): RoutingHeader {
	let parsed: unknown;
	try {
		parsed = JSON.parse(DECODER.decode(bytes));
	} catch (error) {
		throw invalid(`routing header: malformed JSON (${(error as Error).message})`);
	}
	return assertHeader(parsed);
}

/**
 * Peek the routing header of a wire-framed envelope. Throws `Invalid` on any
 * structural deviation. Does NOT decode the ciphertext (it cannot — no key)
 * and does NOT verify the signature (the recipient is the last line of
 * defense). Returns `{ header, byteLength }` so the relay can log `byteLength`
 * without re-measuring the buffer.
 */
export function peekRoutingHeader(frame: Uint8Array): {
	header: RoutingHeader;
	byteLength: number;
} {
	if (frame.length < 4) throw invalid("peekRoutingHeader: truncated header length");
	const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
	const headerLen = view.getUint32(0, false);
	if (headerLen <= 0 || 4 + headerLen > frame.length) {
		throw invalid("peekRoutingHeader: truncated header bytes");
	}
	const headerBytes = frame.subarray(4, 4 + headerLen);
	const header = parseRoutingHeaderJson(headerBytes);
	return { header, byteLength: frame.length };
}

function assertHeader(value: unknown): RoutingHeader {
	if (!value || typeof value !== "object") {
		throw invalid("routing header: not an object");
	}
	const h = value as Record<string, unknown>;
	if (h.v !== PROTOCOL_VERSION) {
		throw invalid(`routing header: unsupported v=${String(h.v)} (expected ${PROTOCOL_VERSION})`);
	}
	if (typeof h.kind !== "string" || !KIND_SET.has(h.kind)) {
		throw invalid(`routing header: unknown kind=${String(h.kind)}`);
	}
	if (typeof h.entityId !== "string" || h.entityId === "") {
		throw invalid("routing header: entityId must be a non-empty string");
	}
	if (typeof h.sender !== "string" || h.sender === "") {
		throw invalid("routing header: sender must be a non-empty string");
	}
	if (typeof h.seq !== "number" || !Number.isFinite(h.seq)) {
		throw invalid("routing header: seq must be a finite number");
	}
	if (typeof h.nonce !== "string" || h.nonce === "") {
		throw invalid("routing header: nonce must be a non-empty string");
	}
	if (typeof h.ts !== "number" || !Number.isFinite(h.ts)) {
		throw invalid("routing header: ts must be a finite number");
	}
	return {
		v: h.v,
		kind: h.kind as WireKind,
		entityId: h.entityId,
		sender: h.sender,
		seq: h.seq,
		nonce: h.nonce,
		ts: h.ts,
	};
}

function invalid(message: string): Error {
	const err = new Error(message);
	err.name = "Invalid";
	return err;
}
