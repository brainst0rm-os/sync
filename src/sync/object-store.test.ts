/**
 * SYNC-3 — object-storage snapshot+tail store + account catalog, plus the
 * `BunS3Bucket` adapter's not-found/pagination contract.
 */

import { describe, expect, test } from "bun:test";
import { BunS3Bucket, type S3ClientLike } from "./bun-s3-bucket";
import { MemoryBucket, ObjectAccountCatalog, ObjectSnapshotStore } from "./object-store";
import { WRAP_RETENTION } from "./snapshot-store";

const bytes = (...n: number[]) => new Uint8Array(n);

describe("ObjectSnapshotStore (SYNC-3)", () => {
	test("backfill replays wraps ++ snapshot ++ tail in order", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket);
		await store.appendWrap("e1", bytes(0xaa));
		await store.putSnapshot("e1", bytes(0x01));
		await store.appendTail("e1", bytes(0x02));
		await store.appendTail("e1", bytes(0x03));

		const { version, frames } = await store.readBackfill("e1");
		expect(version).toBe(1);
		expect(frames.map((f) => f[0])).toEqual([0xaa, 0x01, 0x02, 0x03]);
	});

	test("a Snapshot upload compacts: tail objects deleted, version bumped", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket);
		await store.appendTail("e1", bytes(1));
		await store.appendTail("e1", bytes(2));
		expect(bucket.size()).toBeGreaterThanOrEqual(2); // two tail objects on disk
		const v = await store.putSnapshot("e1", bytes(9));
		expect(v).toBe(1);
		const tailAfter = await store.readBackfill("e1");
		// Only the snapshot remains (no tail).
		expect(tailAfter.frames.map((f) => f[0])).toEqual([9]);

		await store.appendTail("e1", bytes(3));
		const v2 = await store.putSnapshot("e1", bytes(10));
		expect(v2).toBe(2);
		expect((await store.readBackfill("e1")).frames.map((f) => f[0])).toEqual([10]);
	});

	test("wrap retention is bounded at WRAP_RETENTION (oldest evicted)", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket);
		for (let i = 0; i < WRAP_RETENTION + 5; i++) await store.appendWrap("e1", bytes(i & 0xff));
		const { frames } = await store.readBackfill("e1");
		const wrapCount = frames.length; // no snapshot/tail → all wraps
		expect(wrapCount).toBe(WRAP_RETENTION);
		// The oldest five (0..4) were evicted; the newest survive.
		expect(frames[0]?.[0]).toBe(5);
	});

	test("tail seq is seeded from the bucket so a fresh store instance continues", async () => {
		const bucket = new MemoryBucket();
		await new ObjectSnapshotStore(bucket).appendTail("e1", bytes(1));
		await new ObjectSnapshotStore(bucket).appendTail("e1", bytes(2));
		// A third instance must not overwrite either prior tail object.
		const store3 = new ObjectSnapshotStore(bucket);
		await store3.appendTail("e1", bytes(3));
		expect((await store3.readBackfill("e1")).frames.map((f) => f[0])).toEqual([1, 2, 3]);
	});

	test("latestVersion is null before any snapshot", async () => {
		const store = new ObjectSnapshotStore(new MemoryBucket());
		expect(await store.latestVersion("e1")).toBeNull();
		await store.putSnapshot("e1", bytes(1));
		expect(await store.latestVersion("e1")).toBe(1);
	});

	test("a hostile entity id is base64url-namespaced (no key traversal)", async () => {
		const bucket = new MemoryBucket();
		const store = new ObjectSnapshotStore(bucket);
		await store.appendTail("../../escape", bytes(1));
		// Every written key stays under a base64url-safe segment.
		const keys = await bucket.list("");
		for (const k of keys) expect(k).not.toContain("..");
	});
});

describe("ObjectAccountCatalog (SYNC-3)", () => {
	test("record is idempotent; list returns the account's entities", async () => {
		const bucket = new MemoryBucket();
		const cat = new ObjectAccountCatalog(bucket);
		await cat.record("acctA", "e1");
		await cat.record("acctA", "e1"); // dup → no growth
		await cat.record("acctA", "e2");
		await cat.record("acctB", "e9");
		expect((await cat.list("acctA")).sort()).toEqual(["e1", "e2"]);
		expect(await cat.list("acctB")).toEqual(["e9"]);
		expect(await cat.list("nobody")).toEqual([]);
	});

	test("a fresh catalog instance reads what a prior one persisted", async () => {
		const bucket = new MemoryBucket();
		await new ObjectAccountCatalog(bucket).record("acctA", "e1");
		expect(await new ObjectAccountCatalog(bucket).list("acctA")).toEqual(["e1"]);
	});
});

describe("BunS3Bucket adapter (SYNC-3)", () => {
	function fakeClient(): { client: S3ClientLike; store: Map<string, Uint8Array> } {
		const store = new Map<string, Uint8Array>();
		const client: S3ClientLike = {
			file: (key) => ({
				async arrayBuffer() {
					const v = store.get(key);
					if (!v) {
						const err = new Error("not found") as Error & { code: string };
						err.code = "NoSuchKey";
						throw err;
					}
					return v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer;
				},
				async exists() {
					return store.has(key);
				},
			}),
			async write(key, data) {
				store.set(key, new Uint8Array(data));
				return data.byteLength;
			},
			async delete(key) {
				store.delete(key);
			},
			async list(input) {
				const all = [...store.keys()].filter((k) => k.startsWith(input.prefix ?? "")).sort();
				const start = input.continuationToken ? Number(input.continuationToken) : 0;
				const max = input.maxKeys ?? 1000;
				const page = all.slice(start, start + max);
				const end = start + page.length;
				const truncated = end < all.length;
				return {
					contents: page.map((key) => ({ key })),
					isTruncated: truncated,
					...(truncated ? { nextContinuationToken: String(end) } : {}),
				};
			},
		};
		return { client, store };
	}

	test("get returns null on NoSuchKey, bytes when present", async () => {
		const { client } = fakeClient();
		const bucket = new BunS3Bucket(client);
		expect(await bucket.get("missing")).toBeNull();
		await bucket.put("k", bytes(7));
		expect((await bucket.get("k"))?.[0]).toBe(7);
	});

	test("list pages through every continuation token", async () => {
		const { client } = fakeClient();
		const bucket = new BunS3Bucket(client);
		// Simulate a real S3 page cap by hammering a small page through the loop.
		for (let i = 0; i < 2500; i++)
			await bucket.put(`p/${String(i).padStart(5, "0")}`, bytes(i & 0xff));
		const keys = await bucket.list("p/");
		expect(keys.length).toBe(2500);
	});

	test("the object store works end-to-end over the S3 adapter", async () => {
		const { client } = fakeClient();
		const store = new ObjectSnapshotStore(new BunS3Bucket(client), "node1/");
		await store.appendWrap("e1", bytes(0xaa));
		await store.putSnapshot("e1", bytes(1));
		await store.appendTail("e1", bytes(2));
		const { frames } = await store.readBackfill("e1");
		expect(frames.map((f) => f[0])).toEqual([0xaa, 1, 2]);
	});
});
