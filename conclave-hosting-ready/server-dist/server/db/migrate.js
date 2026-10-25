import fs from 'node:fs';
import path from 'node:path';
import { getDb } from './client.js';
export async function runMigrations(customDb) {
    const db = customDb ?? getDb();
    const migrationsDir = path.resolve(process.cwd(), 'migrations');
    await db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version VARCHAR(128) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
    const files = fs
        .readdirSync(migrationsDir)
        .filter((f) => f.endsWith('.sql'))
        .sort();
    const appliedResult = await db.query('SELECT version FROM schema_migrations ORDER BY version ASC');
    const appliedSet = new Set(appliedResult.rows.map((r) => r.version));
    const newlyApplied = [];
    for (const file of files) {
        if (appliedSet.has(file))
            continue;
        const sqlPath = path.join(migrationsDir, file);
        const sql = fs.readFileSync(sqlPath, 'utf-8');
        await db.exec(sql);
        await db.query('INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING', [
            file,
        ]);
        newlyApplied.push(file);
    }
    return newlyApplied;
}
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
    runMigrations()
        .then((applied) => {
        console.log(applied.length > 0
            ? `[Conclave DB] Applied migrations: ${applied.join(', ')}`
            : '[Conclave DB] All migrations are already up to date.');
        process.exit(0);
    })
        .catch((err) => {
        console.error('[Conclave DB] Migration failed:', err);
        process.exit(1);
    });
}
