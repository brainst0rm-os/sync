/**
 * SYNC-5 (ops) — abuse caps, rate limits, and quotas.
 *
 * The node forwards opaque ciphertext for untrusted clients, so the abuse
 * surface is volume, not content: oversized frames, connection floods, per-
 * connection / per-account message storms. This module is the one place those
 * bounds live — a pure, injected-clock policy object so the thresholds are
 * unit-testable without a socket or wall-clock.
 *
 * Token buckets (not fixed windows) so a short burst is absorbed but a sustained
 * over-rate is shed. Keyed limiters evict idle buckets so a churn of IPs /
 * accounts can't grow memory without bound.
 *
 * **Relay-blind.** Counts bytes + events; never inspects payload. No crypto.
 */

export type LimitsConfig = {
	/** Hard cap on a single wire frame (drop oversize before routing). */
	maxFrameBytes: number;
	/** Hard cap on a control-channel JSON message. */
	maxControlBytes: number;
	/** Max simultaneous entity subscriptions per connection. */
	maxSubsPerConn: number;
	/** New connections per client IP: sustained rate + burst. */
	connPerIpPerSec: number;
	connPerIpBurst: number;
	/** Messages per connection: sustained rate + burst. */
	msgPerConnPerSec: number;
	msgPerConnBurst: number;
	/** Ingress bytes per connection: sustained rate + burst. */
	bytesPerConnPerSec: number;
	bytesPerConnBurst: number;
	/** Frames per authenticated account (across its connections): rate + burst. */
	framesPerAccountPerSec: number;
	framesPerAccountBurst: number;
};

/** Sensible production defaults. Generous enough for real co-editing, tight
 *  enough that a single hostile client can't saturate the node. */
export const DEFAULT_LIMITS: LimitsConfig = {
	maxFrameBytes: 1 << 20, // 1 MiB — a single CRDT update / snapshot chunk
	maxControlBytes: 64 << 10, // 64 KiB — subscribe lists, auth, catalog
	maxSubsPerConn: 4096,
	connPerIpPerSec: 10,
	connPerIpBurst: 40,
	msgPerConnPerSec: 200,
	msgPerConnBurst: 400,
	bytesPerConnPerSec: 4 << 20, // 4 MiB/s
	bytesPerConnBurst: 16 << 20,
	framesPerAccountPerSec: 400,
	framesPerAccountBurst: 800,
};

/** A classic token bucket. `tryRemove` refills lazily off the injected clock. */
export class TokenBucket {
	#tokens: number;
	#last: number;
	readonly #ratePerMs: number;
	readonly #burst: number;
	readonly #now: () => number;

	constructor(ratePerSec: number, burst: number, now: () => number) {
		this.#ratePerMs = ratePerSec / 1000;
		this.#burst = burst;
		this.#tokens = burst;
		this.#now = now;
		this.#last = now();
	}

	tryRemove(cost = 1): boolean {
		const t = this.#now();
		this.#tokens = Math.min(this.#burst, this.#tokens + (t - this.#last) * this.#ratePerMs);
		this.#last = t;
		if (this.#tokens < cost) return false;
		this.#tokens -= cost;
		return true;
	}

	/** Last-touch timestamp — used by the keyed limiter to evict idle buckets. */
	lastTouch(): number {
		return this.#last;
	}
}

const IDLE_EVICT_MS = 5 * 60_000;
const EVICT_SWEEP_EVERY = 1024;

/** A map of token buckets keyed by an opaque string, with idle eviction. */
export class KeyedRateLimiter {
	readonly #buckets = new Map<string, TokenBucket>();
	readonly #ratePerSec: number;
	readonly #burst: number;
	readonly #now: () => number;
	#sinceSweep = 0;

	constructor(ratePerSec: number, burst: number, now: () => number) {
		this.#ratePerSec = ratePerSec;
		this.#burst = burst;
		this.#now = now;
	}

	allow(key: string, cost = 1): boolean {
		let bucket = this.#buckets.get(key);
		if (!bucket) {
			bucket = new TokenBucket(this.#ratePerSec, this.#burst, this.#now);
			this.#buckets.set(key, bucket);
		}
		this.#maybeSweep();
		return bucket.tryRemove(cost);
	}

	forget(key: string): void {
		this.#buckets.delete(key);
	}

	#maybeSweep(): void {
		if (++this.#sinceSweep < EVICT_SWEEP_EVERY) return;
		this.#sinceSweep = 0;
		const cutoff = this.#now() - IDLE_EVICT_MS;
		for (const [key, bucket] of this.#buckets) {
			if (bucket.lastTouch() < cutoff) this.#buckets.delete(key);
		}
	}

	size(): number {
		return this.#buckets.size;
	}
}

export type LimitRejection =
	| "frame-too-large"
	| "control-too-large"
	| "too-many-subs"
	| "conn-rate"
	| "msg-rate"
	| "byte-rate"
	| "account-rate";

/** Aggregate rejection counters (exposed for ops dashboards / the audit sink). */
export type LimitStats = Record<LimitRejection, number>;

/**
 * The policy facade the server consults. Each method returns `true` when the
 * action is allowed; a `false` increments the matching rejection counter.
 */
export class Limits {
	readonly #config: LimitsConfig;
	readonly #connByIp: KeyedRateLimiter;
	readonly #msgByConn: KeyedRateLimiter;
	readonly #bytesByConn: KeyedRateLimiter;
	readonly #framesByAccount: KeyedRateLimiter;
	readonly #stats: LimitStats = {
		"frame-too-large": 0,
		"control-too-large": 0,
		"too-many-subs": 0,
		"conn-rate": 0,
		"msg-rate": 0,
		"byte-rate": 0,
		"account-rate": 0,
	};

	constructor(config: LimitsConfig, now: () => number = Date.now) {
		this.#config = config;
		this.#connByIp = new KeyedRateLimiter(config.connPerIpPerSec, config.connPerIpBurst, now);
		this.#msgByConn = new KeyedRateLimiter(config.msgPerConnPerSec, config.msgPerConnBurst, now);
		this.#bytesByConn = new KeyedRateLimiter(
			config.bytesPerConnPerSec,
			config.bytesPerConnBurst,
			now,
		);
		this.#framesByAccount = new KeyedRateLimiter(
			config.framesPerAccountPerSec,
			config.framesPerAccountBurst,
			now,
		);
	}

	allowConnection(ip: string): boolean {
		return this.#tally("conn-rate", this.#connByIp.allow(ip));
	}

	/** Per-connection message + ingress-byte rate (one call per inbound message). */
	allowMessage(connId: string, bytes: number): boolean {
		if (!this.#msgByConn.allow(connId)) return this.#tally("msg-rate", false);
		if (!this.#bytesByConn.allow(connId, Math.max(1, bytes)))
			return this.#tally("byte-rate", false);
		return true;
	}

	allowAccountFrame(account: string): boolean {
		return this.#tally("account-rate", this.#framesByAccount.allow(account));
	}

	frameTooLarge(bytes: number): boolean {
		return this.#flag("frame-too-large", bytes > this.#config.maxFrameBytes);
	}

	controlTooLarge(bytes: number): boolean {
		return this.#flag("control-too-large", bytes > this.#config.maxControlBytes);
	}

	/** Allowed to add one more subscription given the current count. */
	subAllowed(currentSubCount: number): boolean {
		return this.#tally("too-many-subs", currentSubCount < this.#config.maxSubsPerConn);
	}

	/** Drop per-connection limiter state on disconnect. */
	forgetConnection(connId: string): void {
		this.#msgByConn.forget(connId);
		this.#bytesByConn.forget(connId);
	}

	stats(): LimitStats {
		return { ...this.#stats };
	}

	/** Count a rejection when `allowed` is false; pass the boolean through. */
	#tally(kind: LimitRejection, allowed: boolean): boolean {
		if (!allowed) this.#stats[kind] += 1;
		return allowed;
	}

	/** Count a rejection when `rejected` is true; return the same boolean. */
	#flag(kind: LimitRejection, rejected: boolean): boolean {
		if (rejected) this.#stats[kind] += 1;
		return rejected;
	}
}
