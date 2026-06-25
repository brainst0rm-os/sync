/**
 * Routing table — `(entityId → Set<connId>)` subscriptions + blind fan-out.
 *
 * Pure data-flow class. On `route(connId, frame)` it peeks the routing header,
 * fans the untouched frame bytes out to every OTHER subscriber for that entity,
 * and appends one audit entry per delivery.
 *
 * **No echo.** A subscriber that's also the sender does NOT receive its own
 * frame back. Per-connection ids so a single device with two sockets gets
 * fan-out across both.
 *
 * **Malformed-header tolerance.** A frame whose header fails strict-shape
 * validation is dropped + counted; we do NOT close the connection (a malformed-
 * frame-as-DoS would be worse — the recipient is the last line of defense).
 *
 * **Relay-blind.** Zero crypto imports; never decodes the ciphertext body. See
 * CLAUDE.md.
 */

import type { AuditLog } from "./audit-log";
import { type RoutingHeader, peekRoutingHeader } from "./wire";

export type RouteResult = {
	delivered: number;
	dropped: 0 | 1;
	header: RoutingHeader | null;
};

export class FrameRouter {
	readonly #audit: AuditLog;
	readonly #connectionsByEntity = new Map<string, Set<string>>();
	readonly #entitiesByConnection = new Map<string, Set<string>>();
	#malformedDropped = 0;

	constructor(audit: AuditLog) {
		this.#audit = audit;
	}

	subscribe(connId: string, entityId: string): void {
		let set = this.#connectionsByEntity.get(entityId);
		if (!set) {
			set = new Set<string>();
			this.#connectionsByEntity.set(entityId, set);
		}
		set.add(connId);
		let entitySet = this.#entitiesByConnection.get(connId);
		if (!entitySet) {
			entitySet = new Set<string>();
			this.#entitiesByConnection.set(connId, entitySet);
		}
		entitySet.add(entityId);
	}

	unsubscribe(connId: string, entityId: string): void {
		const set = this.#connectionsByEntity.get(entityId);
		if (set) {
			set.delete(connId);
			if (set.size === 0) this.#connectionsByEntity.delete(entityId);
		}
		const entitySet = this.#entitiesByConnection.get(connId);
		if (entitySet) {
			entitySet.delete(entityId);
			if (entitySet.size === 0) this.#entitiesByConnection.delete(connId);
		}
	}

	dropConnection(connId: string): void {
		const entities = this.#entitiesByConnection.get(connId);
		if (!entities) return;
		for (const entityId of entities) {
			const set = this.#connectionsByEntity.get(entityId);
			if (set) {
				set.delete(connId);
				if (set.size === 0) this.#connectionsByEntity.delete(entityId);
			}
		}
		this.#entitiesByConnection.delete(connId);
	}

	/** Subscribers for `entityId` excluding `excludeConnId` (the sender). */
	subscribersFor(entityId: string, excludeConnId: string): string[] {
		const set = this.#connectionsByEntity.get(entityId);
		if (!set) return [];
		const out: string[] = [];
		for (const id of set) {
			if (id !== excludeConnId) out.push(id);
		}
		return out;
	}

	/**
	 * Peek the routing header, fan-out the (untouched) frame bytes to every
	 * OTHER subscriber, append one audit entry per delivery. The caller does the
	 * socket-write — the router is pure logic and returns the recipient count.
	 *
	 * `admit` (SYNC-4b) is an optional pre-fan-out guard on the parsed header
	 * (e.g. "the sender matches the connection's proven account", "the account
	 * is within its frame quota"). A `false` drops the frame WITHOUT fan-out,
	 * persistence, or audit — reported as `dropped: 1` so the caller skips its
	 * own persist/meter/catalog side-effects, exactly like a malformed frame.
	 */
	route(
		fromConnId: string,
		frame: Uint8Array,
		send: (toConnId: string, frame: Uint8Array) => void,
		admit?: (header: RoutingHeader) => boolean,
	): RouteResult {
		let header: RoutingHeader;
		try {
			const peeked = peekRoutingHeader(frame);
			header = peeked.header;
		} catch {
			this.#malformedDropped += 1;
			return { delivered: 0, dropped: 1, header: null };
		}
		if (admit && !admit(header)) {
			return { delivered: 0, dropped: 1, header };
		}
		const recipients = this.subscribersFor(header.entityId, fromConnId);
		let delivered = 0;
		for (const toConnId of recipients) {
			try {
				send(toConnId, frame);
				this.#audit.record({
					fromConnId,
					toConnId,
					entityId: header.entityId,
					kind: header.kind,
					bytes: frame.length,
				});
				delivered += 1;
			} catch {
				// A failed write must not block fan-out to siblings.
			}
		}
		return { delivered, dropped: 0, header };
	}

	malformedDropped(): number {
		return this.#malformedDropped;
	}

	subscriberCount(entityId: string): number {
		return this.#connectionsByEntity.get(entityId)?.size ?? 0;
	}

	connectionEntities(connId: string): readonly string[] {
		const set = this.#entitiesByConnection.get(connId);
		return set ? [...set] : [];
	}
}
