/**
 * SYNC-3 — `ObjectBucket` over Bun's built-in S3 client.
 *
 * The managed / self-hosted storage adapter: works against any S3-compatible
 * endpoint — our managed object storage, Cloudflare R2, AWS S3, or a
 * self-hoster's MinIO / bring-your-own bucket — with zero runtime deps (Bun
 * ships the S3 client). The snapshot+tail layout lives in `ObjectSnapshotStore`
 * (object-store.ts); this is the thin byte-shuttle behind its `ObjectBucket`
 * seam. A NoSuchKey read resolves to `null` (the store treats absence as "no
 * object yet"); `list` pages through every continuation token so a long tail
 * isn't silently truncated.
 *
 * **Relay-blind.** Opaque bytes only; no crypto. The S3 credentials are
 * transport auth to the bucket, not vault crypto — the node still holds no key
 * that can decrypt content. See CLAUDE.md.
 */

import type { ObjectBucket } from "./object-store";

export type S3BucketConfig = {
	bucket: string;
	accessKeyId: string;
	secretAccessKey: string;
	/** S3-compatible endpoint (R2 / MinIO / custom). Omit for AWS S3. */
	endpoint?: string;
	region?: string;
	/** Optional key prefix applied to every object (namespacing a shared bucket). */
	prefix?: string;
};

/** Minimal shape of `Bun.S3Client` we depend on (kept narrow + testable). */
type S3File = { arrayBuffer(): Promise<ArrayBuffer>; exists(): Promise<boolean> };
type S3ListResult = {
	contents?: Array<{ key: string }>;
	isTruncated?: boolean;
	nextContinuationToken?: string;
};
export interface S3ClientLike {
	file(key: string): S3File;
	write(key: string, data: Uint8Array): Promise<number>;
	delete(key: string): Promise<void>;
	list(input: {
		prefix?: string;
		maxKeys?: number;
		continuationToken?: string;
	}): Promise<S3ListResult>;
}

const LIST_PAGE = 1000;

function isNotFound(error: unknown): boolean {
	const e = error as { code?: string; name?: string; status?: number } | null;
	if (!e) return false;
	return (
		e.code === "NoSuchKey" || e.code === "ENOENT" || e.name === "NoSuchKey" || e.status === 404
	);
}

export class BunS3Bucket implements ObjectBucket {
	readonly #client: S3ClientLike;

	/** Construct from config (production) — opens a `Bun.S3Client`. */
	static fromConfig(config: S3BucketConfig): BunS3Bucket {
		const Bun = (globalThis as { Bun?: { S3Client: new (o: unknown) => S3ClientLike } }).Bun;
		if (!Bun?.S3Client) {
			throw new Error("BunS3Bucket: Bun.S3Client unavailable (must run under Bun)");
		}
		const client = new Bun.S3Client({
			bucket: config.bucket,
			accessKeyId: config.accessKeyId,
			secretAccessKey: config.secretAccessKey,
			...(config.endpoint ? { endpoint: config.endpoint } : {}),
			...(config.region ? { region: config.region } : {}),
		});
		return new BunS3Bucket(client);
	}

	/** Inject a client (tests / a pre-built `Bun.S3Client`). */
	constructor(client: S3ClientLike) {
		this.#client = client;
	}

	async get(key: string): Promise<Uint8Array | null> {
		try {
			return new Uint8Array(await this.#client.file(key).arrayBuffer());
		} catch (error) {
			if (isNotFound(error)) return null;
			throw error;
		}
	}

	async put(key: string, bytes: Uint8Array): Promise<void> {
		await this.#client.write(key, bytes);
	}

	async delete(key: string): Promise<void> {
		try {
			await this.#client.delete(key);
		} catch (error) {
			if (!isNotFound(error)) throw error;
		}
	}

	async list(prefix: string): Promise<string[]> {
		const keys: string[] = [];
		let continuationToken: string | undefined;
		do {
			const page: S3ListResult = await this.#client.list({
				prefix,
				maxKeys: LIST_PAGE,
				...(continuationToken ? { continuationToken } : {}),
			});
			for (const item of page.contents ?? []) keys.push(item.key);
			continuationToken = page.isTruncated ? page.nextContinuationToken : undefined;
		} while (continuationToken);
		return keys.sort();
	}
}
