import Fastify from 'fastify';
import { buildApp } from './server-dist/server/app.js';
import { loadConfig } from './server-dist/server/config.js';
import { getDb } from './server-dist/server/db/client.js';
import { getEphemeralStore } from './server-dist/server/services/ephemeral.js';

// Reference Fastify for static framework detection scanners
void Fastify;

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
    } catch (err) {
      console.error('[Conclave Server] Error during shutdown:', err);
      process.exit(1);
    }
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  try {
    const port = Number(process.env.PORT) || cfg.port || 3000;
    const host = process.env.HOST || '0.0.0.0';
    await app.listen({ port, host });
    console.log(
      `[Conclave Server] Listening on http://${host}:${port} (Environment: ${cfg.nodeEnv}, AI-Free Runtime: true)`
    );
  } catch (err) {
    console.error('[Conclave Server] Failed to start:', err);
    process.exit(1);
  }
}

void startServer();
