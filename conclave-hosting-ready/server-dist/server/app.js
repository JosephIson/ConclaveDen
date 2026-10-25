import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import fastifyMultipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import fastifyWebsocket from '@fastify/websocket';
import path from 'node:path';
import fs from 'node:fs';
import { loadConfig } from './config.js';
import { getDb, setDb } from './db/client.js';
import { runMigrations } from './db/migrate.js';
import { authenticateToken } from './middleware/auth.js';
import { realtimeHub } from './services/realtime.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerProfileRoutes } from './routes/profiles.js';
import { registerCommunityRoutes } from './routes/communities.js';
import { registerMessageRoutes } from './routes/messages.js';
import { registerSocialAndModerationRoutes } from './routes/socialAndModeration.js';
export async function buildApp(options = {}) {
    const cfg = loadConfig();
    if (options.customDb) {
        setDb(options.customDb);
    }
    const db = getDb();
    await runMigrations(db);
    const app = Fastify({
        logger: options.logger ?? false,
        trustProxy: true,
        bodyLimit: cfg.maxUploadBytes + 1024 * 1024,
    });
    await app.register(fastifyHelmet, {
        contentSecurityPolicy: false,
        crossOriginResourcePolicy: { policy: 'cross-origin' },
    });
    await app.register(fastifyCors, {
        origin: true,
        credentials: true,
    });
    await app.register(fastifyCookie, {
        secret: cfg.sessionSecret,
    });
    await app.register(fastifyMultipart, {
        limits: {
            fileSize: cfg.maxUploadBytes,
            files: 1,
        },
    });
    await app.register(fastifyWebsocket);
    // Serve uploaded media files inside an isolated plugin scope with strict attachment headers
    fs.mkdirSync(cfg.uploadDir, { recursive: true });
    await app.register(async (uploadsPlugin) => {
        await uploadsPlugin.register(fastifyStatic, {
            root: path.resolve(cfg.uploadDir),
            prefix: '/uploads/',
            decorateReply: false,
            setHeaders(res) {
                res.setHeader('X-Content-Type-Options', 'nosniff');
                res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
            },
        });
    });
    // Health-check endpoint for hosting load balancers and container orchestrators
    app.get('/api/health', async () => {
        const dbCheck = await db.query('SELECT 1 AS ok');
        return {
            status: 'healthy',
            service: 'conclave-server',
            aiFreeRuntime: true,
            databaseConnected: dbCheck.rows[0]?.ok === 1,
            connectedRealtimeUsers: realtimeHub.getConnectedUserIds().length,
            timestamp: new Date().toISOString(),
        };
    });
    // WebSocket Real-Time Event & WebRTC Signaling Endpoint
    app.get('/ws', { websocket: true }, async (socket, request) => {
        const query = request.query;
        const rawToken = query.token ||
            request.cookies?.conclave_session ||
            (request.headers.authorization?.startsWith('Bearer ')
                ? request.headers.authorization.slice(7).trim()
                : '');
        if (!rawToken) {
            socket.close(4001, 'Authentication required');
            return;
        }
        const authUser = await authenticateToken(rawToken);
        if (!authUser) {
            socket.close(4001, 'Invalid or expired session');
            return;
        }
        const profRes = await db.query(`SELECT display_name, avatar_url FROM profiles WHERE user_id = $1`, [authUser.id]);
        const clientEntry = {
            ws: socket,
            userId: authUser.id,
            username: authUser.username,
            displayName: profRes.rows[0]?.display_name || authUser.username,
            avatarUrl: profRes.rows[0]?.avatar_url ?? null,
            connectedAt: Date.now(),
        };
        realtimeHub.registerClient(clientEntry);
        socket.on('message', async (rawBuffer) => {
            try {
                const msg = JSON.parse(rawBuffer.toString('utf-8'));
                if (msg.type === 'PING') {
                    socket.send(JSON.stringify({ type: 'PONG', payload: { ts: Date.now() } }));
                }
                else if (msg.type === 'WEBRTC_SIGNAL' && msg.payload) {
                    const { toUserId, channelId, signalType, data } = msg.payload;
                    if (typeof toUserId === 'string' &&
                        typeof channelId === 'string' &&
                        (signalType === 'offer' || signalType === 'answer' || signalType === 'ice-candidate')) {
                        realtimeHub.relayWebRtcSignal(authUser.id, toUserId, channelId, signalType, data);
                    }
                }
            }
            catch {
                // Ignore malformed client WS messages
            }
        });
        socket.on('close', () => {
            void realtimeHub.unregisterClient(clientEntry);
        });
    });
    // Register REST API route modules
    await registerAuthRoutes(app);
    await registerProfileRoutes(app);
    await registerCommunityRoutes(app);
    await registerMessageRoutes(app);
    await registerSocialAndModerationRoutes(app);
    // Serve built production frontend if dist/client or client-dist exists
    const primaryClientDir = path.resolve(process.cwd(), 'dist', 'client');
    const fallbackClientDir = path.resolve(process.cwd(), 'client-dist');
    const clientDistDir = fs.existsSync(primaryClientDir) ? primaryClientDir : fallbackClientDir;
    if (fs.existsSync(clientDistDir)) {
        await app.register(async (staticPlugin) => {
            await staticPlugin.register(fastifyStatic, {
                root: clientDistDir,
                prefix: '/',
                decorateReply: false,
                wildcard: false,
            });
        });
        app.setNotFoundHandler(async (request, reply) => {
            if (request.url.startsWith('/api/') || request.url.startsWith('/uploads/')) {
                return reply.code(404).send({ error: 'Endpoint not found.' });
            }
            const indexHtml = path.join(clientDistDir, 'index.html');
            if (fs.existsSync(indexHtml)) {
                const htmlContent = await fs.promises.readFile(indexHtml, 'utf-8');
                return reply.type('text/html; charset=utf-8').send(htmlContent);
            }
            return reply.code(404).send({ error: 'Not found.' });
        });
    }
    return app;
}
