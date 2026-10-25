import { Redis } from 'ioredis';
import { loadConfig } from '../config.js';
/**
 * Ephemeral store used for rate limiting, duplicate message detection, typing indicators,
 * and presence expiration. Uses Redis when REDIS_URL is configured, and falls back cleanly
 * to an in-memory TTL store in single-node development and test environments.
 */
export class EphemeralStore {
    redis = null;
    memory = new Map();
    constructor(redisUrl) {
        const url = redisUrl ?? loadConfig().redisUrl;
        if (url && url.trim().length > 0) {
            this.redis = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 2 });
        }
    }
    cleanExpired() {
        const now = Date.now();
        for (const [k, v] of this.memory.entries()) {
            if (v.expiresAt <= now) {
                this.memory.delete(k);
            }
        }
    }
    async setWithTtl(key, value, ttlSeconds) {
        if (this.redis) {
            await this.redis.set(key, value, 'EX', ttlSeconds);
            return;
        }
        this.cleanExpired();
        this.memory.set(key, {
            value,
            expiresAt: Date.now() + ttlSeconds * 1000,
        });
    }
    async get(key) {
        if (this.redis) {
            return await this.redis.get(key);
        }
        const entry = this.memory.get(key);
        if (!entry)
            return null;
        if (entry.expiresAt <= Date.now()) {
            this.memory.delete(key);
            return null;
        }
        return entry.value;
    }
    /**
     * Deterministic sliding window counter for rate limiting and spam prevention.
     */
    async incrementAndCheckLimit(bucketKey, maxRequests, windowSeconds) {
        const now = Date.now();
        if (this.redis) {
            const current = await this.redis.incr(bucketKey);
            if (current === 1) {
                await this.redis.expire(bucketKey, windowSeconds);
            }
            const ttl = await this.redis.ttl(bucketKey);
            return {
                allowed: current <= maxRequests,
                current,
                retryAfterSeconds: Math.max(1, ttl),
            };
        }
        this.cleanExpired();
        const existing = this.memory.get(bucketKey);
        if (!existing) {
            this.memory.set(bucketKey, {
                value: '1',
                expiresAt: now + windowSeconds * 1000,
            });
            return { allowed: true, current: 1, retryAfterSeconds: windowSeconds };
        }
        const nextCount = Number(existing.value) + 1;
        existing.value = String(nextCount);
        const retryAfterSeconds = Math.max(1, Math.ceil((existing.expiresAt - now) / 1000));
        return {
            allowed: nextCount <= maxRequests,
            current: nextCount,
            retryAfterSeconds,
        };
    }
    /**
     * Checks if an identical message content was sent by the same user in the same channel/DM within `windowSeconds`.
     */
    async isDuplicateSpamMessage(userId, scopeId, normalizedContent, windowSeconds = 5) {
        if (!normalizedContent)
            return false;
        const key = `dupmsg:${userId}:${scopeId}:${Buffer.from(normalizedContent).toString('base64').slice(0, 48)}`;
        const existing = await this.get(key);
        if (existing) {
            return true;
        }
        await this.setWithTtl(key, '1', windowSeconds);
        return false;
    }
    async close() {
        if (this.redis) {
            await this.redis.quit();
        }
        this.memory.clear();
    }
}
let sharedEphemeral = null;
export function getEphemeralStore() {
    if (!sharedEphemeral) {
        sharedEphemeral = new EphemeralStore();
    }
    return sharedEphemeral;
}
