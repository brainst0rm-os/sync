/**
 * SYNC-4a — the account catalog: `account → {entityIds it has touched}`.
 *
 * doc-20 §Initial sync: a cold device, after recovering its identity, asks the
 * node for *"the list of entities the user has access to"* before it can fetch
 * snapshots. The blind node can't read access records (they're inside the
 * encrypted doc), but it DOES see the plaintext routing header — and the
 * `sender` of every frame is the emitting account's pubkey. So "entities this
 * account has emitted for" is a faithful, **crypto-free** catalog the node can
 * answer from metadata it already audit-logs. (A member who never wrote an
 * entity won't appear under it; that read-only-member edge resolves when the
 * verified-membership index lands with the full SYNC-4 admission.)
 *
 * **Relay-blind.** `sender` + `entityId` are routing metadata the node already
 * reads for fan-out + the audit log — no ciphertext, no crypto. Same posture as
 * `SnapshotStore`; the interface is storage-agnostic so SYNC-3 can swap the
 * backend.
 *
 * Account scoping is by the wire `sender` string (a base64url pubkey). The
 * verified-identity admission of SYNC-4b is what stops one connection asking for
 * another account's catalog; at SYNC-4a the entity ids are opaque metadata and
 * the open-admission dev node serves any requested account (OQ-SYNC-2).
 */

export interface AccountCatalog {
	/** Note that `account` has touched `entityId` (idempotent). */
	record(account: string, entityId: string): Promise<void>;
	/** The entity ids `account` has touched, in stable (insertion) order. */
	list(account: string): Promise<string[]>;
}

/** In-memory catalog — tests + ephemeral runs. */
export class MemoryAccountCatalog implements AccountCatalog {
	readonly #byAccount = new Map<string, Set<string>>();

	async record(account: string, entityId: string): Promise<void> {
		let set = this.#byAccount.get(account);
		if (!set) {
			set = new Set<string>();
			this.#byAccount.set(account, set);
		}
		set.add(entityId);
	}

	async list(account: string): Promise<string[]> {
		const set = this.#byAccount.get(account);
		return set ? [...set] : [];
	}
}
