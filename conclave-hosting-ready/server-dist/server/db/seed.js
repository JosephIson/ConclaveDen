import { getDb } from './client.js';
import { runMigrations } from './migrate.js';
/**
 * Conclave starts with a clean, real-user-only database.
 * No fake users, fake activity feeds, or synthetic accounts are seeded.
 */
export async function seedInitialData(customDb) {
    const db = customDb ?? getDb();
    await runMigrations(db);
}
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
    seedInitialData()
        .then(() => {
        console.log('[Conclave DB] Schema ready (0 fake users seeded).');
        process.exit(0);
    })
        .catch((err) => {
        console.error('[Conclave DB] Initialization failed:', err);
        process.exit(1);
    });
}
