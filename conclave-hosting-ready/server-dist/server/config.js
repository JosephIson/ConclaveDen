import path from 'node:path';
export function loadConfig() {
    const rootDir = process.cwd();
    const nodeEnv = process.env.NODE_ENV || 'development';
    return {
        port: Number(process.env.PORT || (nodeEnv === 'production' ? 3000 : 4000)),
        host: process.env.HOST || '0.0.0.0',
        nodeEnv,
        databaseUrl: process.env.DATABASE_URL || '',
        pgliteDataDir: process.env.PGLITE_DATA_DIR || path.join(rootDir, 'data', 'pgdata'),
        redisUrl: process.env.REDIS_URL || '',
        sessionSecret: process.env.SESSION_SECRET ||
            'conclave-local-dev-secret-change-in-production-64bytes-minimum-entropy',
        cookieSecure: process.env.COOKIE_SECURE !== undefined
            ? process.env.COOKIE_SECURE === 'true'
            : false,
        sessionTtlDays: Number(process.env.SESSION_TTL_DAYS || 30),
        uploadDir: process.env.UPLOAD_DIR || path.join(rootDir, 'data', 'uploads'),
        maxUploadBytes: Number(process.env.MAX_UPLOAD_BYTES || 15 * 1024 * 1024),
        stunUrls: (process.env.STUN_URLS || 'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        turnUrl: process.env.TURN_URL || '',
        turnUsername: process.env.TURN_USERNAME || '',
        turnCredential: process.env.TURN_CREDENTIAL || '',
    };
}
