/**
 * SYNC-4a — account catalog: the store contract, filesystem durability +
 * traversal-safety, and the server `catalog` control query. Zero-dep `bun test`.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ServerWebSocketLike, createRelayCore } from "../server";
import { PROTOCOL_VERSION, WireKind } from "../wire";
import { MemoryAccountCatalog } from "./account-catalog";
import { FileAccountCatalog } from "./file-account-catalog";
import { MemorySnapshotStore } from "./snapshot-store";

const FRAME_BYTE = 0x01;
const CONTROL_BYTE = 0x00;
const enc = new TextEncoder();
const dec = new TextDecoder();

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
	o += 2 + 64;
	view.setUint32(o, ciphertext.length, false);
	o += 4;
	out.set(ciphertext, o);
	return out;
}

const header = (entityId: string, kind: WireKind, sender: string) => ({
	v: PROTOCOL_VERSION,
	kind,
	entityId,
	sender,
	seq: 0,
	nonce: "n",
	ts: 1,
});

function channel(byte: number, body: Uint8Array): Uint8Array {
	const out = new Uint8Array(1 + body.length);
	out[0] = byte;
	out.set(body, 1);
	return out;
}

const flush = () => new Promise((r) => setTimeout(r, 10));

describe("MemoryAccountCatalog", () => {
	test("records + lists per account; dedups; isolates accounts", async () => {
		const c = new MemoryAccountCatalog();
		await c.record("acct-A", "ent_1");
		await c.record("acct-A", "ent_1"); // dup
		await c.record("acct-A", "ent_2");
		await c.record("acct-B", "ent_9");
		expect((await c.list("acct-A")).sort()).toEqual(["ent_1", "ent_2"]);
		expect(await c.list("acct-B")).toEqual(["ent_9"]);
		expect(await c.list("acct-unknown")).toEqual([]);
	});
});

describe("FileAccountCatalog", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "bs-sync-cat-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	test("persists across a fresh instance (durability) + dedups writes", async () => {
		const a = new FileAccountCatalog(dir);
		await a.record("acct-A", "ent_1");
		await a.record("acct-A", "ent_1");
		await a.record("acct-A", "ent_2");
		const b = new FileAccountCatalog(dir); // restart
		expect((await b.list("acct-A")).sort()).toEqual(["ent_1", "ent_2"]);
	});

	test("a hostile account string cannot traverse the root", async () => {
		const c = new FileAccountCatalog(dir);
		await c.record("../../etc/evil", "ent_1");
		expect(await c.list("../../etc/evil")).toEqual(["ent_1"]);
		expect(await c.list("other")).toEqual([]);
	});
});

describe("server catalog query (SYNC-4a)", () => {
	let conn = 0;
	const mintConnId = () => `c${++conn}`;

	test("records sender→entity on route + answers a catalog query with versions", async () => {
		const catalog = new MemoryAccountCatalog();
		const store = new MemorySnapshotStore();
		const core = createRelayCore({ mintConnId, catalog, store });
		const a = fakeWs();
		core.handlers.onOpen(a);

		// acct-A emits an update for ent_1 and a snapshot for ent_2.
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_1", WireKind.Update, "acct-A"), enc.encode("u1"))),
		);
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_2", WireKind.Snapshot, "acct-A"), enc.encode("S2"))),
		);
		// A different account's frame must NOT leak into acct-A's catalog.
		core.handlers.onMessage(
			a,
			channel(FRAME_BYTE, frame(header("ent_9", WireKind.Update, "acct-B"), enc.encode("x"))),
		);
		await flush();

		core.handlers.onMessage(
			a,
			channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "catalog", account: "acct-A" }))),
		);
		await flush();

		const replies = a.sent
			.filter((m) => m[0] === CONTROL_BYTE)
			.map((m) => JSON.parse(dec.decode(m.subarray(1))) as Record<string, unknown>);
		const result = replies.find((r) => r.op === "catalog-result") as {
			account: string;
			entities: Array<{ entityId: string; version: number }>;
		};
		expect(result.account).toBe("acct-A");
		expect(result.entities.map((e) => e.entityId).sort()).toEqual(["ent_1", "ent_2"]);
		// ent_2 had a snapshot → version 1; ent_1 (updates only) → 0.
		expect(result.entities.find((e) => e.entityId === "ent_2")?.version).toBe(1);
		expect(result.entities.find((e) => e.entityId === "ent_1")?.version).toBe(0);
	});

	test("no catalog configured ⇒ a catalog query is silently ignored", async () => {
		const core = createRelayCore({ mintConnId });
		const a = fakeWs();
		core.handlers.onOpen(a);
		core.handlers.onMessage(
			a,
			channel(CONTROL_BYTE, enc.encode(JSON.stringify({ op: "catalog", account: "acct-A" }))),
		);
		await flush();
		expect(a.sent.filter((m) => m[0] === CONTROL_BYTE)).toEqual([]);
	});
});
