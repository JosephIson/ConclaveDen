import { PGlite } from '@electric-sql/pglite';
import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import { loadConfig } from '../config.js';
class PgPoolAdapter {
    pool;
    constructor(connectionString) {
        this.pool = new pg.Pool({ connectionString, max: 20 });
    }
    async query(sql, params = []) {
        const res = await this.pool.query(sql, params);
        return {
            rows: res.rows,
            rowCount: res.rowCount ?? res.rows.length,
        };
    }
    async exec(sql) {
        await this.pool.query(sql);
    }
    async transaction(fn) {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');
            const txAdapter = {
                query: async (sql, params = []) => {
                    const res = await client.query(sql, params);
                    return { rows: res.rows, rowCount: res.rowCount ?? res.rows.length };
                },
                exec: async (sql) => {
                    await client.query(sql);
                },
            };
            const result = await fn(txAdapter);
            await client.query('COMMIT');
            return result;
        }
        catch (err) {
            await client.query('ROLLBACK');
            throw err;
        }
        finally {
            client.release();
        }
    }
    async close() {
        await this.pool.end();
    }
}
class PGliteAdapter {
    pglite;
    constructor(dataDir) {
        if (dataDir && dataDir !== 'memory://') {
            fs.mkdirSync(path.dirname(dataDir), { recursive: true });
            this.pglite = new PGlite(dataDir);
        }
        else {
            this.pglite = new PGlite();
        }
    }
    async query(sql, params = []) {
        const res = await this.pglite.query(sql, params);
        return {
            rows: res.rows,
            rowCount: res.affectedRows ?? res.rows.length,
        };
    }
    async exec(sql) {
        await this.pglite.exec(sql);
    }
    async transaction(fn) {
        return await this.pglite.transaction(async (tx) => {
            const txAdapter = {
                query: async (sql, params = []) => {
                    const res = await tx.query(sql, params);
                    return { rows: res.rows, rowCount: res.affectedRows ?? res.rows.length };
                },
                exec: async (sql) => {
                    await tx.exec(sql);
                },
            };
            return await fn(txAdapter);
        });
    }
    async close() {
        await this.pglite.close();
    }
}
let sharedDbInstance = null;
export function createDbClient(options) {
    const cfg = loadConfig();
    const dbUrl = options?.databaseUrl ?? cfg.databaseUrl;
    const pgliteDir = options?.pgliteDataDir ?? cfg.pgliteDataDir;
    if (dbUrl && dbUrl.trim().length > 0) {
        return new PgPoolAdapter(dbUrl);
    }
    return new PGliteAdapter(pgliteDir);
}
export function getDb() {
    if (!sharedDbInstance) {
        sharedDbInstance = createDbClient();
    }
    return sharedDbInstance;
}
export function setDb(client) {
    sharedDbInstance = client;
}
