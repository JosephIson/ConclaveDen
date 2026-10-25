import { getDb } from '../db/client.js';
import { hashSessionToken } from '../services/security.js';
export function extractRawSessionToken(request) {
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.slice(7).trim();
        if (token)
            return token;
    }
    const cookieToken = request.cookies?.conclave_session;
    if (cookieToken && cookieToken.trim()) {
        return cookieToken.trim();
    }
    return null;
}
export async function authenticateToken(rawToken) {
    const tokenHash = hashSessionToken(rawToken);
    const db = getDb();
    const res = await db.query(`SELECT
       s.id AS session_id,
       s.user_id,
       s.expires_at,
       s.revoked_at,
       u.username,
       u.normalized_username,
       u.email,
       u.is_deleted
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1`, [tokenHash]);
    const row = res.rows[0];
    if (!row)
        return null;
    if (row.is_deleted || row.revoked_at)
        return null;
    if (new Date(row.expires_at).getTime() <= Date.now()) {
        return null;
    }
    await db.query(`UPDATE sessions SET last_used_at = NOW() WHERE id = $1`, [row.session_id]);
    return {
        id: row.user_id,
        username: row.username,
        normalizedUsername: row.normalized_username,
        email: row.email,
        sessionId: row.session_id,
        tokenHash,
    };
}
export async function requireAuth(request, reply) {
    const rawToken = extractRawSessionToken(request);
    if (!rawToken) {
        reply.code(401).send({ error: 'Authentication required.' });
        return;
    }
    const user = await authenticateToken(rawToken);
    if (!user) {
        reply.clearCookie('conclave_session', { path: '/' });
        reply.code(401).send({ error: 'Invalid or expired session.' });
        return;
    }
    request.authUser = user;
}
