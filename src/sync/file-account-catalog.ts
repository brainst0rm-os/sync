/**
 * SYNC-4a — filesystem-backed `AccountCatalog` (the local provider).
 *
 * Layout: `<root>/<base64url(account)>.json` = a JSON array of entity ids the
 * account has touched. `base64url` keeps a hostile `sender` string from
 * traversing the root (the wire is untrusted), exactly like
 * `FileSnapshotStore`. A small per-account in-memory set fronts the file so a
 * `record` of an already-known pair is a no-op (no write); a genuinely new pair
 * rewrites the account's file. Per-account write serialization avoids
 * interleaved writes.
 *
 * **Relay-blind.** Plaintext routing metadata only; zero crypto. See CLAUDE.md.
 */

import { Buffer } from "node:buffer";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { AccountCatalog } from "./account-catalog";

export class FileAccountCatalog implements AccountCatalog {
	readonly #root: string;
	readonly #cache = new Map<string, Set<string>>();
	readonly #queues = new Map<string, Promise<unknown>>();

	constructor(root: string) {
		this.#root = root;
	}

	record(account: string, entityId: string): Promise<void> {
		return this.#serial(account, async () => {
			const set = await this.#load(account);
			if (set.has(entityId)) return; // already known — no write
			set.add(entityId);
			await this.#persist(account, set);
		});
	}

	list(account: string): Promise<string[]> {
		return this.#serial(account, async () => [...(await this.#load(account))]);
	}

	async #load(account: string): Promise<Set<string>> {
		const cached = this.#cache.get(account);
		if (cached) return cached;
		let set = new Set<string>();
		try {
			const raw = await readFile(this.#pathFor(account), "utf8");
			const parsed = JSON.parse(raw);
			if (Array.isArray(parsed)) {
				set = new Set(parsed.filter((e): e is string => typeof e === "string"));
			}
		} catch {
			// Missing / malformed → empty (default-on-corrupt).
		}
		this.#cache.set(account, set);
		return set;
	}

	async #persist(account: string, set: Set<string>): Promise<void> {
		const path = this.#pathFor(account);
		const tmp = `${path}.tmp`;
		await mkdir(dirname(path), { recursive: true });
		await writeFile(tmp, JSON.stringify([...set]), "utf8");
		await rename(tmp, path);
	}

	#pathFor(account: string): string {
		const safe = Buffer.from(account, "utf8").toString("base64url");
		return join(this.#root, `${safe}.json`);
	}

	#serial<T>(account: string, op: () => Promise<T>): Promise<T> {
		const prior = this.#queues.get(account) ?? Promise.resolve();
		const next = prior.then(op, op);
		this.#queues.set(
			account,
			next.then(
				() => undefined,
				() => undefined,
			),
		);
		return next;
	}
}

/** Best-effort: how many accounts the catalog has on disk (ops / debugging). */
export async function countCatalogAccounts(root: string): Promise<number> {
	try {
		return (await readdir(root)).filter((f) => f.endsWith(".json")).length;
	} catch {
		return 0;
	}
}
