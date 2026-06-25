/**
 * SYNC-5 — token bucket, keyed limiter eviction, and the `Limits` facade with
 * its rejection counters. A fake clock drives refill deterministically.
 */

import { describe, expect, test } from "bun:test";
import { DEFAULT_LIMITS, KeyedRateLimiter, Limits, type LimitsConfig, TokenBucket } from "./limits";

function clock(start = 0): { now: () => number; advance: (ms: number) => void } {
	let t = start;
	return {
		now: () => t,
		advance: (ms) => {
			t += ms;
		},
	};
}

describe("TokenBucket", () => {
	test("burst is spent then refills at the configured rate", () => {
		const c = clock();
		const b = new TokenBucket(10, 5, c.now); // 10/s, burst 5
		for (let i = 0; i < 5; i++) expect(b.tryRemove()).toBe(true);
		expect(b.tryRemove()).toBe(false); // burst exhausted
		c.advance(100); // +1 token (10/s * 0.1s)
		expect(b.tryRemove()).toBe(true);
		expect(b.tryRemove()).toBe(false);
	});

	test("refill is capped at burst", () => {
		const c = clock();
		const b = new TokenBucket(1000, 3, c.now);
		c.advance(10_000); // would be 10000 tokens uncapped
		for (let i = 0; i < 3; i++) expect(b.tryRemove()).toBe(true);
		expect(b.tryRemove()).toBe(false);
	});
});

describe("KeyedRateLimiter", () => {
	test("buckets are independent per key", () => {
		const c = clock();
		const l = new KeyedRateLimiter(1, 1, c.now);
		expect(l.allow("a")).toBe(true);
		expect(l.allow("a")).toBe(false);
		expect(l.allow("b")).toBe(true); // b has its own bucket
	});

	test("idle buckets are eventually evicted to bound memory", () => {
		const c = clock();
		const l = new KeyedRateLimiter(1, 1, c.now);
		l.allow("old");
		c.advance(10 * 60_000); // well past the idle cutoff
		// Touch many fresh keys to trigger the periodic sweep.
		for (let i = 0; i < 1100; i++) l.allow(`fresh${i}`);
		// 1101 distinct keys created; "old" is idle and swept → fewer remain.
		expect(l.size()).toBeLessThanOrEqual(1100);
	});
});

describe("Limits facade", () => {
	const cfg: LimitsConfig = {
		...DEFAULT_LIMITS,
		maxFrameBytes: 100,
		maxControlBytes: 50,
		maxSubsPerConn: 2,
		msgPerConnPerSec: 1,
		msgPerConnBurst: 1,
	};

	test("frame / control size caps are enforced and counted", () => {
		const l = new Limits(cfg, clock().now);
		expect(l.frameTooLarge(101)).toBe(true);
		expect(l.frameTooLarge(100)).toBe(false);
		expect(l.controlTooLarge(51)).toBe(true);
		expect(l.stats()["frame-too-large"]).toBe(1);
		expect(l.stats()["control-too-large"]).toBe(1);
	});

	test("subscription cap", () => {
		const l = new Limits(cfg, clock().now);
		expect(l.subAllowed(0)).toBe(true);
		expect(l.subAllowed(1)).toBe(true);
		expect(l.subAllowed(2)).toBe(false); // at cap
		expect(l.stats()["too-many-subs"]).toBe(1);
	});

	test("per-connection message rate sheds the over-rate and counts it", () => {
		const c = clock();
		const l = new Limits(cfg, c.now);
		expect(l.allowMessage("c1", 10)).toBe(true);
		expect(l.allowMessage("c1", 10)).toBe(false); // 1/s burst 1 → second shed
		expect(l.stats()["msg-rate"]).toBe(1);
		c.advance(1000);
		expect(l.allowMessage("c1", 10)).toBe(true);
	});

	test("forgetConnection drops the connection's limiter state", () => {
		const c = clock();
		const l = new Limits(cfg, c.now);
		expect(l.allowMessage("c1", 1)).toBe(true);
		expect(l.allowMessage("c1", 1)).toBe(false);
		l.forgetConnection("c1");
		expect(l.allowMessage("c1", 1)).toBe(true); // fresh bucket
	});
});
