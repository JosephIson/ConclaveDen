import crypto from 'node:crypto';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { loadConfig } from '../config.js';
import { hashPassword, verifyPassword, generateSessionToken, normalizeUsername, isValidUsername, normalizeEmail, generateMfaCredentials, } from '../services/security.js';
import { requireAuth } from '../middleware/auth.js';
import { getUserProfile, getUserPreferences, recordAuditLog, } from '../services/domain.js';
import { getEphemeralStore } from '../services/ephemeral.js';
const RegisterSchema = z.object({
    username: z.string().min(3).max(32),
    displayName: z.string().min(1).max(64).optional(),
    email: z.string().email().max(255),
    password: z.string().min(8).max(128),
    pronouns: z.string().max(64).optional(),
    isFurryIdentityEnabled: z.boolean().optional(),
    furryTitle: z.string().max(80).optional(),
});
const LoginSchema = z.object({
    identifier: z.string().min(1).max(255),
    password: z.string().min(1).max(128),
    mfaCode: z.string().optional(),
});
export async function registerAuthRoutes(app) {
    const cfg = loadConfig();
    app.post('/api/auth/register', async (request, reply) => {
        const parsed = RegisterSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({
                error: 'Validation failed.',
                details: parsed.error.flatten().fieldErrors,
            });
        }
        const { username, displayName, email, password, pronouns = '', isFurryIdentityEnabled = false, furryTitle = null, } = parsed.data;
        if (!isValidUsername(username)) {
            return reply.code(400).send({
                error: 'Username must be 3–32 characters and contain only letters, numbers, underscores, hyphens, or periods.',
            });
        }
        const normalizedUser = normalizeUsername(username);
        const normalizedMail = normalizeEmail(email);
        const db = getDb();
        const existing = await db.query(`SELECT id, normalized_username, normalized_email FROM users
       WHERE normalized_username = $1 OR normalized_email = $2`, [normalizedUser, normalizedMail]);
        if (existing.rows.length > 0) {
            const conflict = existing.rows[0];
            if (conflict.normalized_username === normalizedUser) {
                return reply.code(409).send({ error: 'That username is already taken.' });
            }
            return reply.code(409).send({ error: 'An account with that email already exists.' });
        }
        const passwordHash = await hashPassword(password);
        const userId = crypto.randomUUID();
        const sessionId = crypto.randomUUID();
        const { rawToken, tokenHash } = generateSessionToken();
        const verificationToken = crypto.randomBytes(24).toString('hex');
        const expiresAt = new Date(Date.now() + cfg.sessionTtlDays * 24 * 60 * 60 * 1000).toISOString();
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO users (
          id, username, normalized_username, email, normalized_email, password_hash,
          email_verified, email_verification_token, onboarding_completed
        ) VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, FALSE)`, [
                userId,
                username.trim(),
                normalizedUser,
                email.trim(),
                normalizedMail,
                passwordHash,
                verificationToken,
            ]);
            await tx.query(`INSERT INTO profiles (
          user_id, display_name, pronouns, is_furry_identity_enabled, furry_title, presence_status, badge_ids
        ) VALUES ($1, $2, $3, $4, $5, 'online', $6)`, [
                userId,
                (displayName || username).trim(),
                pronouns.trim(),
                isFurryIdentityEnabled,
                furryTitle,
                JSON.stringify(['pioneer']),
            ]);
            await tx.query(`INSERT INTO user_preferences (user_id) VALUES ($1)`, [userId]);
            await tx.query(`INSERT INTO sessions (id, user_id, token_hash, user_agent, ip_address, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`, [
                sessionId,
                userId,
                tokenHash,
                String(request.headers['user-agent'] || 'Conclave Web Client'),
                request.ip || '127.0.0.1',
                expiresAt,
            ]);
            await recordAuditLog({
                actorId: userId,
                eventType: 'USER_REGISTERED',
                targetType: 'user',
                targetId: userId,
                summary: `User @${normalizedUser} registered an account.`,
                tx,
            });
        });
        reply.setCookie('conclave_session', rawToken, {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: cfg.cookieSecure,
            maxAge: cfg.sessionTtlDays * 24 * 60 * 60,
        });
        const profile = await getUserProfile(userId);
        const preferences = await getUserPreferences(userId);
        return reply.code(201).send({
            token: rawToken,
            profile,
            preferences,
        });
    });
    app.post('/api/auth/login', async (request, reply) => {
        const parsed = LoginSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Please provide both identifier and password.' });
        }
        const { identifier, password, mfaCode } = parsed.data;
        const rateStore = getEphemeralStore();
        const rateCheck = await rateStore.incrementAndCheckLimit(`login_attempt:${request.ip}:${identifier.toLowerCase()}`, 12, 60);
        if (!rateCheck.allowed) {
            return reply.code(429).send({
                error: `Too many login attempts. Please wait ${rateCheck.retryAfterSeconds} seconds.`,
            });
        }
        const db = getDb();
        const normId = identifier.includes('@')
            ? normalizeEmail(identifier)
            : normalizeUsername(identifier);
        const res = await db.query(`SELECT id, password_hash, mfa_enabled, mfa_secret, recovery_codes_json, is_deleted
       FROM users
       WHERE (normalized_username = $1 OR normalized_email = $1) AND is_deleted = FALSE`, [normId]);
        const user = res.rows[0];
        if (!user) {
            return reply.code(401).send({ error: 'Invalid credentials.' });
        }
        const validPassword = await verifyPassword(password, user.password_hash);
        if (!validPassword) {
            return reply.code(401).send({ error: 'Invalid credentials.' });
        }
        if (user.mfa_enabled) {
            if (!mfaCode) {
                return reply.code(403).send({
                    error: 'Multi-factor authentication code required.',
                    mfaRequired: true,
                });
            }
            const cleanCode = mfaCode.trim().toUpperCase();
            const recoveryCodes = Array.isArray(user.recovery_codes_json)
                ? user.recovery_codes_json
                : [];
            const matchesSecret = user.mfa_secret && cleanCode === user.mfa_secret.slice(0, 6);
            const matchesRecovery = recoveryCodes.includes(cleanCode);
            if (!matchesSecret && !matchesRecovery) {
                return reply.code(401).send({ error: 'Invalid multi-factor authentication code.' });
            }
        }
        const sessionId = crypto.randomUUID();
        const { rawToken, tokenHash } = generateSessionToken();
        const expiresAt = new Date(Date.now() + cfg.sessionTtlDays * 24 * 60 * 60 * 1000).toISOString();
        await db.query(`INSERT INTO sessions (id, user_id, token_hash, user_agent, ip_address, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`, [
            sessionId,
            user.id,
            tokenHash,
            String(request.headers['user-agent'] || 'Conclave Web Client'),
            request.ip || '127.0.0.1',
            expiresAt,
        ]);
        await db.query(`UPDATE profiles SET last_active_at = NOW() WHERE user_id = $1`, [user.id]);
        reply.setCookie('conclave_session', rawToken, {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: cfg.cookieSecure,
            maxAge: cfg.sessionTtlDays * 24 * 60 * 60,
        });
        const profile = await getUserProfile(user.id);
        const preferences = await getUserPreferences(user.id);
        return reply.send({
            token: rawToken,
            profile,
            preferences,
        });
    });
    app.post('/api/auth/logout', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        await db.query(`UPDATE sessions SET revoked_at = NOW() WHERE id = $1`, [authUser.sessionId]);
        reply.clearCookie('conclave_session', { path: '/' });
        return reply.send({ success: true });
    });
    app.get('/api/auth/me', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const profile = await getUserProfile(authUser.id);
        if (!profile) {
            return reply.code(404).send({ error: 'User profile not found.' });
        }
        const preferences = await getUserPreferences(authUser.id);
        const db = getDb();
        const unreadRes = await db.query(`SELECT COUNT(*)::text AS count FROM notifications WHERE user_id = $1 AND is_read = FALSE`, [authUser.id]);
        return reply.send({
            profile,
            preferences,
            email: authUser.email,
            unreadNotificationCount: Number(unreadRes.rows[0]?.count || 0),
        });
    });
    app.post('/api/auth/verify-email', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        await db.query(`UPDATE users SET email_verified = TRUE, email_verification_token = NULL, updated_at = NOW() WHERE id = $1`, [authUser.id]);
        return reply.send({ verified: true });
    });
    app.post('/api/auth/password-reset/request', async (request, reply) => {
        const body = z.object({ email: z.string().email() }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid email address is required.' });
        }
        const db = getDb();
        const normEmail = normalizeEmail(body.data.email);
        const resetToken = crypto.randomBytes(24).toString('hex');
        const expires = new Date(Date.now() + 3600 * 1000).toISOString();
        await db.query(`UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2
       WHERE normalized_email = $3 AND is_deleted = FALSE`, [resetToken, expires, normEmail]);
        return reply.send({
            message: 'If that email matches an active account, a password reset token has been issued.',
            devResetToken: cfg.nodeEnv !== 'production' ? resetToken : undefined,
        });
    });
    app.post('/api/auth/password-reset/confirm', async (request, reply) => {
        const body = z
            .object({
            token: z.string().min(10),
            newPassword: z.string().min(8).max(128),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid reset token or password.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT id, password_reset_expires_at FROM users WHERE password_reset_token = $1 AND is_deleted = FALSE`, [body.data.token]);
        const user = res.rows[0];
        if (!user ||
            !user.password_reset_expires_at ||
            new Date(user.password_reset_expires_at).getTime() <= Date.now()) {
            return reply.code(400).send({ error: 'Reset token is invalid or expired.' });
        }
        const newHash = await hashPassword(body.data.newPassword);
        await db.transaction(async (tx) => {
            await tx.query(`UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL, updated_at = NOW() WHERE id = $2`, [newHash, user.id]);
            await tx.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1`, [user.id]);
        });
        return reply.send({ success: true });
    });
    app.post('/api/auth/password/change', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            currentPassword: z.string().min(1),
            newPassword: z.string().min(8).max(128),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Current password and new password (8+ chars) are required.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT password_hash FROM users WHERE id = $1`, [authUser.id]);
        if (!res.rows[0] || !(await verifyPassword(body.data.currentPassword, res.rows[0].password_hash))) {
            return reply.code(401).send({ error: 'Current password is incorrect.' });
        }
        const newHash = await hashPassword(body.data.newPassword);
        await db.transaction(async (tx) => {
            await tx.query(`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`, [
                newHash,
                authUser.id,
            ]);
            // Revoke all other sessions for security
            await tx.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND id <> $2`, [authUser.id, authUser.sessionId]);
        });
        return reply.send({ success: true });
    });
    app.post('/api/auth/mfa/enable', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z.object({ currentPassword: z.string().min(1) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Password reauthentication is required to enable MFA.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT password_hash FROM users WHERE id = $1`, [authUser.id]);
        if (!res.rows[0] || !(await verifyPassword(body.data.currentPassword, res.rows[0].password_hash))) {
            return reply.code(401).send({ error: 'Incorrect password.' });
        }
        const { secret, recoveryCodes } = generateMfaCredentials();
        await db.query(`UPDATE users SET mfa_enabled = TRUE, mfa_secret = $1, recovery_codes_json = $2, updated_at = NOW() WHERE id = $3`, [secret, JSON.stringify(recoveryCodes), authUser.id]);
        return reply.send({
            mfaEnabled: true,
            secret,
            verificationPinHint: secret.slice(0, 6),
            recoveryCodes,
        });
    });
    app.post('/api/auth/mfa/disable', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z.object({ currentPassword: z.string().min(1) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Password reauthentication is required to disable MFA.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT password_hash FROM users WHERE id = $1`, [authUser.id]);
        if (!res.rows[0] || !(await verifyPassword(body.data.currentPassword, res.rows[0].password_hash))) {
            return reply.code(401).send({ error: 'Incorrect password.' });
        }
        await db.query(`UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, recovery_codes_json = '[]'::jsonb, updated_at = NOW() WHERE id = $1`, [authUser.id]);
        return reply.send({ mfaEnabled: false });
    });
    app.get('/api/auth/sessions', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT id, user_agent, ip_address, created_at, expires_at, last_used_at
       FROM sessions
       WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
       ORDER BY last_used_at DESC`, [authUser.id]);
        return reply.send({
            sessions: res.rows.map((s) => ({
                id: s.id,
                userAgent: s.user_agent,
                ipAddress: s.ip_address,
                createdAt: new Date(s.created_at).toISOString(),
                expiresAt: new Date(s.expires_at).toISOString(),
                lastUsedAt: new Date(s.last_used_at).toISOString(),
                isCurrent: s.id === authUser.sessionId,
            })),
        });
    });
    app.delete('/api/auth/sessions/:sessionId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { sessionId } = request.params;
        const db = getDb();
        await db.query(`UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2`, [sessionId, authUser.id]);
        return reply.send({ revoked: true });
    });
    app.get('/api/auth/export', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const profile = await getUserProfile(authUser.id);
        const preferences = await getUserPreferences(authUser.id);
        const communitiesRes = await db.query(`SELECT c.id, c.name, c.slug, cm.joined_at
       FROM community_memberships cm
       JOIN communities c ON c.id = cm.community_id
       WHERE cm.user_id = $1`, [authUser.id]);
        const messagesRes = await db.query(`SELECT id, channel_id, dm_conversation_id, content, created_at
       FROM messages WHERE sender_id = $1 AND is_deleted = FALSE
       ORDER BY created_at DESC LIMIT 500`, [authUser.id]);
        return reply.send({
            exportedAt: new Date().toISOString(),
            account: {
                id: authUser.id,
                username: authUser.username,
                email: authUser.email,
            },
            profile,
            preferences,
            communities: communitiesRes.rows,
            recentMessages: messagesRes.rows,
        });
    });
    app.post('/api/auth/delete-account', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z.object({ currentPassword: z.string().min(1) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Password reauthentication is required to delete your account.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT password_hash FROM users WHERE id = $1`, [authUser.id]);
        if (!res.rows[0] || !(await verifyPassword(body.data.currentPassword, res.rows[0].password_hash))) {
            return reply.code(401).send({ error: 'Incorrect password.' });
        }
        const ownedComm = await db.query(`SELECT id, name FROM communities WHERE owner_id = $1`, [authUser.id]);
        if (ownedComm.rows.length > 0) {
            return reply.code(400).send({
                error: `Please transfer ownership or delete your owned communities (${ownedComm.rows
                    .map((c) => c.name)
                    .join(', ')}) before deleting your account.`,
            });
        }
        await db.transaction(async (tx) => {
            await tx.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1`, [authUser.id]);
            await tx.query(`DELETE FROM fursonas WHERE user_id = $1`, [authUser.id]);
            await tx.query(`DELETE FROM community_memberships WHERE user_id = $1`, [authUser.id]);
            await tx.query(`DELETE FROM saved_messages WHERE user_id = $1`, [authUser.id]);
            await tx.query(`DELETE FROM notifications WHERE user_id = $1`, [authUser.id]);
            await tx.query(`UPDATE users
         SET is_deleted = TRUE,
             username = $2,
             normalized_username = $2,
             email = $3,
             normalized_email = $3,
             password_hash = 'DELETED',
             updated_at = NOW()
         WHERE id = $1`, [
                authUser.id,
                `deleted_${authUser.id.slice(0, 8)}`,
                `deleted_${authUser.id}@deleted.conclave.local`,
            ]);
            await tx.query(`UPDATE profiles
         SET display_name = 'Deleted User',
             bio = '',
             avatar_url = NULL,
             banner_url = NULL,
             social_links = '[]'::jsonb,
             presence_status = 'offline',
             custom_status_text = ''
         WHERE user_id = $1`, [authUser.id]);
        });
        reply.clearCookie('conclave_session', { path: '/' });
        return reply.send({ deleted: true });
    });
}
