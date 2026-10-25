import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { getDb } from './db/client.js';
import { getEphemeralStore } from './services/ephemeral.js';
async function startServer() {
    const cfg = loadConfig();
    const app = await buildApp({ logger: cfg.nodeEnv === 'production' });
    const shutdown = async (signal) => {
        console.log(`[Conclave Server] Received ${signal}, shutting down gracefully...`);
        try {
            await app.close();
            await getEphemeralStore().close();
            await getDb().close();
            process.exit(0);
        }
        catch (err) {
            console.error('[Conclave Server] Error during shutdown:', err);
            process.exit(1);
        }
    };
    process.on('SIGINT', () => void shutdown('SIGINT'));
    process.on('SIGTERM', () => void shutdown('SIGTERM'));
    try {
        await app.listen({ port: cfg.port, host: cfg.host });
        console.log(`[Conclave Server] Listening on http://${cfg.host}:${cfg.port} (Environment: ${cfg.nodeEnv}, AI-Free Runtime: true)`);
    }
    catch (err) {
        console.error('[Conclave Server] Failed to start:', err);
        process.exit(1);
    }
}
void startServer();
