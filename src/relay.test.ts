/**
 * Blind-relay core behavior: fan-out, no-echo, malformed-drop, control parsing,
 * and the ciphertext-only audit invariant. Runs under `bun test` (zero deps).
 */

import { describe, expect, test } from "bun:test";
import { type ServerWebSocketLike, createRelayCore } from "./server";
import { PROTOCOL_VERSION, WireKind } from "./wire";

const FRAME_BYTE = 0x01;
const CONTROL_BYTE = 0x00;
const enc = new TextEncoder();

/** A fake socket that records everything the relay sends to it. */
function fakeWs(): ServerWebSocketLike & { sent: Uint8Array[] } {
	const sent: Uint8Array[] = [];
	return {
		sent,
		data: {},
		send(d: Uint8Array | string) {
			sent.push(d instanceof Uint8Array ? d : enc.encode(d));
		},
		close() {},
	};
}

/** Build a wire frame: u32-be(headerLen)||header || u16-be(64)||sig || u32-be(ctLen)||ct. */
function frame(header: Record<string, unknown>, ciphertext: Uint8Array): Uint8Array {
	const headerBytes = enc.encode(JSON.stringify(header));
	const sig = new Uint8Array(64); // opaque to the relay; zeros are fine
	const out = new Uint8Array(4 + headerBytes.length + 2 + 64 + 4 + ciphertext.length);
	const view = new DataView(out.buffer);
	let o = 0;
	view.setUint32(o, headerBytes.length, false);
	o += 4;
	out.set(headerBytes, o);
	o += headerBytes.length;
	view.setUint16(o, 64, false);
	o += 2;
	out.set(sig, o);
	o += 64;
	view.setUint32(o, ciphertext.length, false);
	o += 4;
	out.set(ciphertext, o);
	return out;
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

function header(entityId: string, sender: string) {
	return {
		v: PROTOCOL_VERSION,
		kind: WireKind.Update,
		entityId,
		sender,
		seq: 0,
		nonce: "n",
		ts: 1,
	};
}

let connCounter = 0;
const mintConnId = () => `c${++connCounter}`;

describe("blind relay fan-out", () => {
	test("a frame fans out to other subscribers of the entity, not the sender", () => {
		connCounter = 0;
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		const b = fakeWs();
		const c = fakeWs();
		const ca = core.handlers.onOpen(a);
		const cb = core.handlers.onOpen(b);
		const cc = core.handlers.onOpen(c);

		const subBody = enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_1"] }));
		for (const ws of [a, b, c]) core.handlers.onMessage(ws, channel(CONTROL_BYTE, subBody));

		const ct = enc.encode("OPAQUE-CIPHERTEXT");
		const f = frame(header("ent_1", "sender-A"), ct);
		core.handlers.onMessage(a, channel(FRAME_BYTE, f));

		// b + c receive it; a (the sender) does not.
		expect(a.sent.length).toBe(0);
		expect(b.sent.length).toBe(1);
		expect(c.sent.length).toBe(1);
		// Delivered bytes are the untouched frame, re-prefixed with the frame byte.
		expect(b.sent[0]?.[0]).toBe(FRAME_BYTE);
		expect([ca, cb, cc]).toEqual(["c1", "c2", "c3"]);
	});

	test("a frame for a different entity is not delivered", () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		const b = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onOpen(b);
		core.handlers.onMessage(
			b,
			channel(
				CONTROL_BYTE,
				enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_other"] })),
			),
		);
		core.handlers.onMessage(a, channel(FRAME_BYTE, frame(header("ent_1", "s"), enc.encode("x"))));
		expect(b.sent.length).toBe(0);
	});

	test("unsubscribe stops delivery", () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		const b = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onOpen(b);
		const sub = (op: string) =>
			channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op, entityIds: ["ent_1"] })));
		core.handlers.onMessage(b, sub("subscribe"));
		core.handlers.onMessage(b, sub("unsubscribe"));
		core.handlers.onMessage(a, channel(FRAME_BYTE, frame(header("ent_1", "s"), enc.encode("x"))));
		expect(b.sent.length).toBe(0);
	});

	test("close drops the connection's subscriptions", () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		const b = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onOpen(b);
		core.handlers.onMessage(
			b,
			channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_1"] }))),
		);
		core.handlers.onClose(b);
		core.handlers.onMessage(a, channel(FRAME_BYTE, frame(header("ent_1", "s"), enc.encode("x"))));
		expect(b.sent.length).toBe(0);
		expect(core.connections.size).toBe(1);
	});

	test("a malformed-header frame is dropped + counted, connection stays open", () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		const b = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onOpen(b);
		core.handlers.onMessage(
			b,
			channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_1"] }))),
		);
		// A frame whose "header" is not valid JSON of the right shape.
		const bad = channel(FRAME_BYTE, frame({ nope: true }, enc.encode("x")));
		core.handlers.onMessage(a, bad);
		expect(b.sent.length).toBe(0);
		expect(core.router.malformedDropped()).toBe(1);
		expect(core.connections.size).toBe(2);
	});
});

describe("ciphertext-only audit", () => {
	test("the audit log records routing metadata only — never the ciphertext body", () => {
		const lines: string[] = [];
		const core = createRelayCore({ mintConnId, auditSink: (l) => lines.push(l) });
		const a = fakeWs();
		const b = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onOpen(b);
		core.handlers.onMessage(
			b,
			channel(
				CONTROL_BYTE,
				enc.encode(JSON.stringify({ op: "subscribe", entityIds: ["ent_secret"] })),
			),
		);
		const secret = "SUPER-SECRET-PLAINTEXT-MARKER";
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_secret", "sender-A"), enc.encode(secret))),
		);
		expect(lines.length).toBe(1);
		const entry = JSON.parse(lines[0] as string);
		expect(entry.entityId).toBe("ent_secret");
		expect(entry.kind).toBe(WireKind.Update);
		expect(typeof entry.bytes).toBe("number");
		// The secret never appears anywhere in the audit line.
		expect(lines[0]).not.toContain(secret);
		expect(JSON.stringify(entry)).not.toContain("ciphertext");
	});
});
