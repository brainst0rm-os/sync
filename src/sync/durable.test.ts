/**
 * SYNC-2 — durable snapshot+tail store + server backfill. Zero-dep `bun test`.
 *
 * Covers the store contract (append/compact/backfill/version), the OQ-SYNC-3
 * persistence policy (doc-state only), filesystem durability across a restart,
 * and the server wiring: a routed frame persists, a late/cold subscriber gets
 * `snapshot ++ tail` replayed, a Snapshot frame compacts the tail, and the
 * forward-only (no-store) path is unchanged.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ServerWebSocketLike, createRelayCore } from "../server";
import { PROTOCOL_VERSION, WireKind } from "../wire";
import { FileSnapshotStore } from "./file-snapshot-store";
import { MemorySnapshotStore, persistFrame } from "./snapshot-store";

const FRAME_BYTE = 0x01;
const CONTROL_BYTE = 0x00;
const enc = new TextEncoder();

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

function frame(header: Record<string, unknown>, ciphertext: Uint8Array): Uint8Array {
	const headerBytes = enc.encode(JSON.stringify(header));
	const out = new Uint8Array(4 + headerBytes.length + 2 + 64 + 4 + ciphertext.length);
	const view = new DataView(out.buffer);
	let o = 0;
	view.setUint32(o, headerBytes.length, false);
	o += 4;
	out.set(headerBytes, o);
	o += headerBytes.length;
	view.setUint16(o, 64, false);
	o += 2;
	o += 64;
	view.setUint32(o, ciphertext.length, false);
	o += 4;
	out.set(ciphertext, o);
	return out;
}

function header(entityId: string, kind: WireKind = WireKind.Update, sender = "s") {
	return { v: PROTOCOL_VERSION, kind, entityId, sender, seq: 0, nonce: "n", ts: 1 };
}

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

const subBody = (op: string, entityIds: string[]) => enc.encode(JSON.stringify({ op, entityIds }));
const flush = () => new Promise((r) => setTimeout(r, 10));

/** Frame bytes the relay actually delivered (strip the leading FRAME_BYTE). */
function delivered(ws: { sent: Uint8Array[] }): Uint8Array[] {
	return ws.sent.filter((m) => m[0] === FRAME_BYTE).map((m) => m.subarray(1));
}

describe("MemorySnapshotStore", () => {
	test("appends a tail and reads it back; latestVersion is null with no snapshot", async () => {
		const s = new MemorySnapshotStore();
		await s.appendTail("e1", enc.encode("u1"));
		await s.appendTail("e1", enc.encode("u2"));
		const back = await s.readBackfill("e1");
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["u1", "u2"]);
		expect(back.version).toBe(0);
		expect(await s.latestVersion("e1")).toBeNull();
	});

	test("a snapshot bumps the version and RESETS the tail (client-driven compaction)", async () => {
		const s = new MemorySnapshotStore();
		await s.appendTail("e1", enc.encode("u1"));
		const v = await s.putSnapshot("e1", enc.encode("S1"));
		expect(v).toBe(1);
		await s.appendTail("e1", enc.encode("u2"));
		const back = await s.readBackfill("e1");
		// snapshot first, then ONLY the post-snapshot tail — u1 is subsumed.
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["S1", "u2"]);
		expect(back.version).toBe(1);
		expect(await s.latestVersion("e1")).toBe(1);
	});

	test("a stored frame is a defensive copy (caller mutation can't corrupt it)", async () => {
		const s = new MemorySnapshotStore();
		const buf = enc.encode("u1");
		await s.appendTail("e1", buf);
		buf[0] = 0; // mutate the caller's buffer after storing
		const back = await s.readBackfill("e1");
		expect(new TextDecoder().decode(back.frames[0] as Uint8Array)).toBe("u1");
	});
});

describe("persistFrame policy (doc-state + wraps; transient dropped)", () => {
	test("Update→tail, Snapshot→snapshot, WrapBootstrap→wrap (first); Awareness/Pairing skipped", async () => {
		const s = new MemorySnapshotStore();
		await persistFrame(s, "e1", WireKind.Update, enc.encode("u1"));
		await persistFrame(s, "e1", WireKind.Awareness, enc.encode("a1"));
		await persistFrame(s, "e1", WireKind.WrapBootstrap, enc.encode("w1"));
		await persistFrame(s, "e1", WireKind.Pairing, enc.encode("p1"));
		await persistFrame(s, "e1", WireKind.Snapshot, enc.encode("S1"));
		await persistFrame(s, "e1", WireKind.Update, enc.encode("u2"));
		const back = await s.readBackfill("e1");
		// Wrap first (DEK before state), then snapshot + post-snapshot tail. u1 is
		// subsumed by the snapshot; Awareness/Pairing never stored.
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["w1", "S1", "u2"]);
	});

	test("a wrap SURVIVES compaction (the DEK is still needed after a snapshot)", async () => {
		const s = new MemorySnapshotStore();
		await persistFrame(s, "e1", WireKind.WrapBootstrap, enc.encode("WRAP"));
		await persistFrame(s, "e1", WireKind.Snapshot, enc.encode("S1")); // resets tail, NOT wraps
		await persistFrame(s, "e1", WireKind.Snapshot, enc.encode("S2"));
		const back = await s.readBackfill("e1");
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["WRAP", "S2"]);
	});
});

describe("FileSnapshotStore", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "bs-sync-store-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	test("persists across a fresh store instance (durability)", async () => {
		const a = new FileSnapshotStore(dir);
		await a.appendTail("ent_1", enc.encode("u1"));
		await a.putSnapshot("ent_1", enc.encode("S1"));
		await a.appendTail("ent_1", enc.encode("u2"));

		const b = new FileSnapshotStore(dir); // simulate node restart
		const back = await b.readBackfill("ent_1");
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["S1", "u2"]);
		expect(back.version).toBe(1);
		expect(await b.latestVersion("ent_1")).toBe(1);
	});

	test("wraps persist across a restart, come first in backfill, and survive compaction", async () => {
		const a = new FileSnapshotStore(dir);
		await a.appendWrap("ent_w", enc.encode("W1"));
		await a.putSnapshot("ent_w", enc.encode("S1"));
		await a.appendTail("ent_w", enc.encode("u1"));

		const b = new FileSnapshotStore(dir); // restart
		const back = await b.readBackfill("ent_w");
		// wrap FIRST, then snapshot + tail — the cold device gets the DEK first.
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["W1", "S1", "u1"]);
	});

	test("a hostile entityId cannot traverse the storage root", async () => {
		const s = new FileSnapshotStore(dir);
		// base64url encoding makes the on-disk name safe; the data round-trips.
		await s.appendTail("../../etc/passwd", enc.encode("x"));
		const back = await s.readBackfill("../../etc/passwd");
		expect(back.frames.map((f) => new TextDecoder().decode(f))).toEqual(["x"]);
		// A different entity is isolated.
		expect((await s.readBackfill("other")).frames).toEqual([]);
	});

	test("empty entity backfills nothing, version 0", async () => {
		const s = new FileSnapshotStore(dir);
		const back = await s.readBackfill("nope");
		expect(back.frames).toEqual([]);
		expect(back.version).toBe(0);
		expect(await s.latestVersion("nope")).toBeNull();
	});
});

describe("server durable wiring (SYNC-2)", () => {
	let conn = 0;
	const mintConnId = () => `c${++conn}`;

	test("a cold subscriber's backfill carries the WrapBootstrap FIRST, then state (10.14)", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, store });
		const a = fakeWs();
		core.handlers.onOpen(a);
		// Owner emits the DEK wrap, then a snapshot — no one subscribed yet.
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_w", WireKind.WrapBootstrap), enc.encode("WR"))),
		);
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_w", WireKind.Snapshot), enc.encode("S1"))),
		);
		await flush();

		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_w"])));
		await flush();

		// The wrap arrives before the snapshot — the device installs the DEK,
		// then decrypts the state.
		expect(delivered(b).map((f) => new TextDecoder().decode(f.subarray(-2)))).toEqual(["WR", "S1"]);
	});

	test("a late/cold subscriber is backfilled snapshot ++ tail on subscribe", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, store });
		const a = fakeWs();
		core.handlers.onOpen(a);

		// Mira sends a snapshot then an update — no one is subscribed yet.
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_1", WireKind.Snapshot), enc.encode("S1"))),
		);
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_1", WireKind.Update), enc.encode("u1"))),
		);
		await flush();

		// A cold device connects + subscribes — it gets the durable state replayed.
		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_1"])));
		await flush();

		const got = delivered(b).map((f) => new TextDecoder().decode(f.subarray(-2)));
		// b received the snapshot frame then the tail update frame.
		expect(delivered(b).length).toBe(2);
		expect(got).toEqual(["S1", "u1"]);
	});

	test("a Snapshot frame compacts: a later subscriber gets snapshot + only the post-snapshot tail", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, store });
		const a = fakeWs();
		core.handlers.onOpen(a);
		const send = (k: WireKind, ct: string) =>
			core.handlers.onMessage(a, channel(FRAME_BYTE, frame(header("ent_2", k), enc.encode(ct))));

		send(WireKind.Update, "u0"); // pre-snapshot — should be subsumed
		send(WireKind.Snapshot, "S1");
		send(WireKind.Update, "u1");
		await flush();

		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_2"])));
		await flush();

		const got = delivered(b).map((f) => new TextDecoder().decode(f.subarray(-2)));
		expect(got).toEqual(["S1", "u1"]);
	});

	test("Awareness frames are NOT persisted (transient) — not backfilled", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, store });
		const a = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_3", WireKind.Awareness), enc.encode("a1"))),
		);
		await flush();

		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_3"])));
		await flush();
		expect(delivered(b)).toEqual([]);
	});

	test("forward-only (no store): a late subscriber gets NO backfill", async () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_4", WireKind.Update), enc.encode("u1"))),
		);
		await flush();
		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_4"])));
		await flush();
		expect(delivered(b)).toEqual([]);
	});

	test("a malformed frame is not persisted (no header → nothing to key on)", async () => {
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, store });
		const a = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onMessage(a, channel(FRAME_BYTE, new Uint8Array([1, 2, 3])));
		await flush();
		// Nothing keyed; a subscribe to anything yields no backfill.
		const b = fakeWs();
		core.handlers.onOpen(b);
		core.handlers.onMessage(b, channel(CONTROL_BYTE, subBody("subscribe", ["ent_1"])));
		await flush();
		expect(delivered(b)).toEqual([]);
	});
});
