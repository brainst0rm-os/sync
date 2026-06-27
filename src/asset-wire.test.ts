/**
 * Asset-B3 — the node's asset wire protocol (responder side). Zero-dep
 * `bun test`. Covers request decode + validation (hash format, bad kind,
 * malformed frames) and `handleAssetRequest` against an in-memory CAS,
 * including the metered byte counts.
 */

import { describe, expect, test } from "bun:test";
import {
	type AssetRequest,
	AssetWireKind,
	decodeAssetRequest,
	encodeAssetRequest,
	handleAssetRequest,
} from "./asset-wire";
import { MemoryAssetCas } from "./sync/asset-cas";

const HASH = "deadbeef".repeat(8);

describe("decodeAssetRequest validation", () => {
	test("round-trips a valid Has/Get/Put", () => {
		expect(decodeAssetRequest(encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH }))).toEqual(
			{
				kind: AssetWireKind.Has,
				hash: HASH,
			},
		);
		const chunk = crypto.getRandomValues(new Uint8Array(100));
		const put = decodeAssetRequest(
			encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk }),
		);
		expect(put.kind).toBe(AssetWireKind.Put);
		if (put.kind === AssetWireKind.Put) {
			expect(Buffer.from(put.chunk).equals(Buffer.from(chunk))).toBe(true);
		}
	});

	test("rejects a non-64-hex address (path-traversal / malformed)", () => {
		const bad = encodeAssetRequest({ kind: AssetWireKind.Get, hash: "../../escape" });
		expect(() => decodeAssetRequest(bad)).toThrow(/64-hex/);
		const short = encodeAssetRequest({ kind: AssetWireKind.Get, hash: "abc" });
		expect(() => decodeAssetRequest(short)).toThrow(/64-hex/);
	});

	test("rejects a bad kind / truncated / non-JSON frame", () => {
		expect(() => decodeAssetRequest(new Uint8Array([0, 0]))).toThrow();
		const bad = new Uint8Array(8);
		new DataView(bad.buffer).setUint32(0, 999, false);
		expect(() => decodeAssetRequest(bad)).toThrow();
		const bogus = encodeAssetRequest({ kind: "bogus", hash: HASH } as unknown as AssetRequest);
		expect(() => decodeAssetRequest(bogus)).toThrow(/bad kind/);
	});
});

describe("handleAssetRequest", () => {
	test("Has / Put / Get against the CAS, with metered bytes", async () => {
		const cas = new MemoryAssetCas();
		const chunk = crypto.getRandomValues(new Uint8Array(4096));

		const has0 = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Has, hash: HASH }),
		);
		expect(has0.meteredBytes).toBe(0);

		const put = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Put, hash: HASH, chunk }),
		);
		expect(put.meteredBytes).toBe(chunk.length); // ingress = chunk size
		expect(await cas.has(HASH)).toBe(true);

		const get = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Get, hash: HASH }),
		);
		expect(get.meteredBytes).toBe(chunk.length); // egress = chunk size

		const miss = await handleAssetRequest(
			cas,
			encodeAssetRequest({ kind: AssetWireKind.Get, hash: "f".repeat(64) }),
		);
		expect(miss.meteredBytes).toBe(0);
	});
});
