/**
 * Audit log — per-frame routing metadata, ciphertext-NEVER.
 *
 * **Ciphertext-only invariant.** The audit log records:
 *   - `fromConnId` / `toConnId` (opaque per-connection ids; assigned on
 *     handshake, no link to a user identity).
 *   - `entityId` (routing key; lives in the plaintext header).
 *   - `kind` (the `WireKind` from the header).
 *   - `bytes` (the wire-frame byte length).
 *   - `ts` (server-side ms timestamp).
 *
 * It MUST NOT accept the wire-frame payload bytes — the type system makes that
 * impossible (`AuditEntryInput` has no payload field). NDJSON output so an
 * external pipeline (logrotate / journald / an object-storage sink) can stream
 * events with a stable schema. See CLAUDE.md (relay-blind invariant).
 */

import type { WireKind } from "./wire";

export type AuditEntry = {
	ts: number;
	fromConnId: string;
	toConnId: string;
	entityId: string;
	kind: WireKind;
	bytes: number;
};

/** Constructor input — explicitly omits any payload-shaped field. */
export type AuditEntryInput = {
	fromConnId: string;
	toConnId: string;
	entityId: string;
	kind: WireKind;
	bytes: number;
};

export type AuditSink = (line: string) => void;

export class AuditLog {
	readonly #entries: AuditEntry[] = [];
	readonly #sink: AuditSink | null;
	readonly #now: () => number;

	constructor(opts: { sink?: AuditSink; now?: () => number } = {}) {
		this.#sink = opts.sink ?? null;
		this.#now = opts.now ?? Date.now;
	}

	record(input: AuditEntryInput): AuditEntry {
		const entry: AuditEntry = {
			ts: this.#now(),
			fromConnId: input.fromConnId,
			toConnId: input.toConnId,
			entityId: input.entityId,
			kind: input.kind,
			bytes: input.bytes,
		};
		this.#entries.push(entry);
		if (this.#sink) {
			this.#sink(JSON.stringify(entry));
		}
		return entry;
	}

	entries(): readonly AuditEntry[] {
		return this.#entries.slice();
	}

	/** NDJSON serialisation — one entry per line. */
	toJSONL(): string {
		return this.#entries.map((e) => JSON.stringify(e)).join("\n");
	}

	clear(): void {
		this.#entries.length = 0;
	}
}
