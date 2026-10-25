import crypto from 'node:crypto';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { loadConfig } from '../config.js';
import { requireAuth } from '../middleware/auth.js';
import { PERMISSIONS, canActorModerateMember } from '../../shared/permissions.js';
import { getMemberPermissionsAndRoles, isBlockedBetween, getUserPreferences, createNotification, recordAuditLog, } from '../services/domain.js';
import { normalizeUsername } from '../services/security.js';
import { realtimeHub } from '../services/realtime.js';
export async function registerSocialAndModerationRoutes(app) {
    const cfg = loadConfig();
    // ============================================================================
    // FRIENDS & PRESENCE
    // ============================================================================
    app.get('/api/friends', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT
         fr.*,
         u1.username AS req_username,
         p1.display_name AS req_display_name,
         p1.avatar_url AS req_avatar_url,
         p1.pronouns AS req_pronouns,
         p1.presence_status AS req_presence_status,
         p1.custom_status_text AS req_custom_status_text,
         p1.last_active_at AS req_last_active_at,
         p1.furry_title AS req_furry_title,
         pref1.show_online_status AS req_show_online,
         pref1.show_last_active AS req_show_last_active,
         u2.username AS add_username,
         p2.display_name AS add_display_name,
         p2.avatar_url AS add_avatar_url,
         p2.pronouns AS add_pronouns,
         p2.presence_status AS add_presence_status,
         p2.custom_status_text AS add_custom_status_text,
         p2.last_active_at AS add_last_active_at,
         p2.furry_title AS add_furry_title,
         pref2.show_online_status AS add_show_online,
         pref2.show_last_active AS add_show_last_active
       FROM friend_relationships fr
       JOIN users u1 ON u1.id = fr.requester_id
       JOIN profiles p1 ON p1.user_id = fr.requester_id
       JOIN user_preferences pref1 ON pref1.user_id = fr.requester_id
       JOIN users u2 ON u2.id = fr.addressee_id
       JOIN profiles p2 ON p2.user_id = fr.addressee_id
       JOIN user_preferences pref2 ON pref2.user_id = fr.addressee_id
       WHERE (fr.requester_id = $1 OR fr.addressee_id = $1)
         AND fr.status <> 'declined'
       ORDER BY fr.updated_at DESC`, [authUser.id]);
        const relationships = res.rows.map((r) => {
            const isRequester = String(r.requester_id) === authUser.id;
            const showOnline = isRequester ? Boolean(r.add_show_online) : Boolean(r.req_show_online);
            const showLastActive = isRequester
                ? Boolean(r.add_show_last_active)
                : Boolean(r.req_show_last_active);
            const friend = isRequester
                ? {
                    id: String(r.addressee_id),
                    username: String(r.add_username),
                    displayName: String(r.add_display_name),
                    avatarUrl: r.add_avatar_url ? String(r.add_avatar_url) : null,
                    pronouns: String(r.add_pronouns || ''),
                    presenceStatus: showOnline
                        ? (r.add_presence_status ||
                            'online')
                        : 'offline',
                    customStatusText: showOnline ? String(r.add_custom_status_text || '') : '',
                    lastActiveAt: showLastActive && r.add_last_active_at
                        ? new Date(String(r.add_last_active_at)).toISOString()
                        : null,
                    furryTitle: r.add_furry_title ? String(r.add_furry_title) : null,
                }
                : {
                    id: String(r.requester_id),
                    username: String(r.req_username),
                    displayName: String(r.req_display_name),
                    avatarUrl: r.req_avatar_url ? String(r.req_avatar_url) : null,
                    pronouns: String(r.req_pronouns || ''),
                    presenceStatus: showOnline
                        ? (r.req_presence_status ||
                            'online')
                        : 'offline',
                    customStatusText: showOnline ? String(r.req_custom_status_text || '') : '',
                    lastActiveAt: showLastActive && r.req_last_active_at
                        ? new Date(String(r.req_last_active_at)).toISOString()
                        : null,
                    furryTitle: r.req_furry_title ? String(r.req_furry_title) : null,
                };
            return {
                id: String(r.id),
                requesterId: String(r.requester_id),
                addresseeId: String(r.addressee_id),
                status: r.status,
                createdAt: new Date(String(r.created_at)).toISOString(),
                updatedAt: new Date(String(r.updated_at)).toISOString(),
                friend,
                direction: r.status === 'accepted' ? 'mutual' : isRequester ? 'outgoing' : 'incoming',
            };
        });
        return reply.send({ relationships });
    });
    app.post('/api/friends/request', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            username: z.string().min(1).optional(),
            targetUserId: z.string().uuid().optional(),
        })
            .safeParse(request.body);
        if (!body.success || (!body.data.username && !body.data.targetUserId)) {
            return reply.code(400).send({ error: 'Username or targetUserId is required.' });
        }
        const db = getDb();
        let targetId = body.data.targetUserId || '';
        if (!targetId && body.data.username) {
            const uRes = await db.query(`SELECT id FROM users WHERE normalized_username = $1 AND is_deleted = FALSE`, [normalizeUsername(body.data.username.replace(/^@/, ''))]);
            targetId = uRes.rows[0]?.id || '';
        }
        if (!targetId) {
            return reply.code(404).send({ error: 'User not found.' });
        }
        if (targetId === authUser.id) {
            return reply.code(400).send({ error: 'You cannot send a friend request to yourself.' });
        }
        const blockState = await isBlockedBetween(authUser.id, targetId);
        if (blockState.blocked) {
            return reply.code(403).send({ error: 'Cannot send friend request due to an active block.' });
        }
        const targetPrefs = await getUserPreferences(targetId);
        if (targetPrefs.allowFriendRequestsFrom === 'nobody') {
            return reply.code(403).send({ error: 'This user has disabled incoming friend requests.' });
        }
        if (targetPrefs.allowFriendRequestsFrom === 'community_members') {
            const sharedRes = await db.query(`SELECT cm1.id
         FROM community_memberships cm1
         JOIN community_memberships cm2 ON cm2.community_id = cm1.community_id
         WHERE cm1.user_id = $1 AND cm2.user_id = $2
         LIMIT 1`, [authUser.id, targetId]);
            if (!sharedRes.rows[0]) {
                return reply.code(403).send({
                    error: 'This user only accepts friend requests from shared community members.',
                });
            }
        }
        const existing = await db.query(`SELECT id, requester_id, addressee_id, status FROM friend_relationships
       WHERE (requester_id = $1 AND addressee_id = $2)
          OR (requester_id = $2 AND addressee_id = $1)`, [authUser.id, targetId]);
        if (existing.rows[0]) {
            const row = existing.rows[0];
            if (row.status === 'accepted') {
                return reply.code(409).send({ error: 'You are already friends with this user.' });
            }
            if (row.status === 'pending' && row.requester_id === targetId) {
                // Mutual request — accept automatically
                await db.query(`UPDATE friend_relationships SET status = 'accepted', updated_at = NOW() WHERE id = $1`, [row.id]);
                return reply.send({ status: 'accepted', id: row.id });
            }
            if (row.status === 'declined') {
                await db.query(`UPDATE friend_relationships SET requester_id = $1, addressee_id = $2, status = 'pending', updated_at = NOW() WHERE id = $3`, [authUser.id, targetId, row.id]);
                return reply.send({ status: 'pending', id: row.id });
            }
            return reply.code(409).send({ error: 'A friend request is already pending.' });
        }
        const id = crypto.randomUUID();
        await db.query(`INSERT INTO friend_relationships (id, requester_id, addressee_id, status) VALUES ($1, $2, $3, 'pending')`, [id, authUser.id, targetId]);
        await createNotification({
            userId: targetId,
            type: 'friend_request',
            title: `New friend request from @${authUser.username}`,
            body: `@${authUser.username} wants to connect with you on Conclave.`,
            actorId: authUser.id,
        });
        return reply.code(201).send({ status: 'pending', id });
    });
    app.post('/api/friends/:id/respond', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const body = z
            .object({ action: z.enum(['accept', 'decline']) })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid action (accept | decline) required.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT requester_id, addressee_id, status FROM friend_relationships WHERE id = $1`, [id]);
        const rel = res.rows[0];
        if (!rel || rel.addressee_id !== authUser.id) {
            return reply.code(404).send({ error: 'Incoming friend request not found.' });
        }
        const nextStatus = body.data.action === 'accept' ? 'accepted' : 'declined';
        await db.query(`UPDATE friend_relationships SET status = $1, updated_at = NOW() WHERE id = $2`, [nextStatus, id]);
        if (nextStatus === 'accepted') {
            await createNotification({
                userId: rel.requester_id,
                type: 'friend_accepted',
                title: `@${authUser.username} accepted your friend request`,
                body: `You and @${authUser.username} are now friends.`,
                actorId: authUser.id,
            });
        }
        return reply.send({ status: nextStatus });
    });
    app.delete('/api/friends/:id', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const db = getDb();
        await db.query(`DELETE FROM friend_relationships
       WHERE (id = $1 OR requester_id = $1 OR addressee_id = $1)
         AND (requester_id = $2 OR addressee_id = $2)`, [id, authUser.id]);
        return reply.send({ removed: true });
    });
    // ============================================================================
    // BLOCKS
    // ============================================================================
    app.get('/api/blocks', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT b.*, u.username, p.display_name, p.avatar_url
       FROM blocks b
       JOIN users u ON u.id = b.blocked_user_id
       JOIN profiles p ON p.user_id = b.blocked_user_id
       WHERE b.blocker_id = $1
       ORDER BY b.created_at DESC`, [authUser.id]);
        const blocks = res.rows.map((r) => ({
            id: String(r.id),
            blockerId: String(r.blocker_id),
            blockedUserId: String(r.blocked_user_id),
            reason: r.reason ? String(r.reason) : null,
            createdAt: new Date(String(r.created_at)).toISOString(),
            blockedUser: {
                id: String(r.blocked_user_id),
                username: String(r.username),
                displayName: String(r.display_name),
                avatarUrl: r.avatar_url ? String(r.avatar_url) : null,
            },
        }));
        return reply.send({ blocks });
    });
    app.post('/api/blocks', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            targetUserId: z.string().uuid().optional(),
            targetUsername: z.string().optional(),
            reason: z.string().max(300).optional(),
        })
            .safeParse(request.body);
        if (!body.success || (!body.data.targetUserId && !body.data.targetUsername)) {
            return reply.code(400).send({ error: 'targetUserId or targetUsername is required.' });
        }
        const db = getDb();
        let targetId = body.data.targetUserId || '';
        if (!targetId && body.data.targetUsername) {
            const uRes = await db.query(`SELECT id FROM users WHERE normalized_username = $1`, [normalizeUsername(body.data.targetUsername.replace(/^@/, ''))]);
            targetId = uRes.rows[0]?.id || '';
        }
        if (!targetId || targetId === authUser.id) {
            return reply.code(400).send({ error: 'Invalid target user to block.' });
        }
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO blocks (id, blocker_id, blocked_user_id, reason)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (blocker_id, blocked_user_id) DO NOTHING`, [crypto.randomUUID(), authUser.id, targetId, body.data.reason ?? null]);
            // Remove any existing friendship
            await tx.query(`DELETE FROM friend_relationships
         WHERE (requester_id = $1 AND addressee_id = $2)
            OR (requester_id = $2 AND addressee_id = $1)`, [authUser.id, targetId]);
        });
        return reply.code(201).send({ blocked: true });
    });
    app.delete('/api/blocks/:blockedUserId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { blockedUserId } = request.params;
        const db = getDb();
        await db.query(`DELETE FROM blocks WHERE blocker_id = $1 AND blocked_user_id = $2`, [authUser.id, blockedUserId]);
        return reply.send({ unblocked: true });
    });
    // ============================================================================
    // HUMAN-OPERATED MODERATION, REPORTS & APPEALS
    // ============================================================================
    app.post('/api/reports', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            communityId: z.string().uuid().nullable().optional(),
            targetType: z.enum(['user', 'message', 'community', 'artwork_theft', 'impersonation']),
            targetUserId: z.string().uuid().nullable().optional(),
            targetMessageId: z.string().uuid().nullable().optional(),
            category: z.enum([
                'harassment',
                'spam',
                'stolen_artwork',
                'impersonation',
                'rule_violation',
                'hate_speech',
                'other',
            ]),
            reason: z.string().min(5).max(2000),
            evidenceUrls: z.array(z.string().max(500)).max(5).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({
                error: 'Please provide a valid report category and detailed reason (at least 5 characters).',
            });
        }
        const d = body.data;
        const db = getDb();
        const reportId = crypto.randomUUID();
        await db.query(`INSERT INTO reports (
        id, community_id, reporter_id, target_type, target_user_id, target_message_id,
        category, reason, evidence_urls, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open')`, [
            reportId,
            d.communityId ?? null,
            authUser.id,
            d.targetType,
            d.targetUserId ?? null,
            d.targetMessageId ?? null,
            d.category,
            d.reason.trim(),
            JSON.stringify(d.evidenceUrls || []),
        ]);
        if (d.communityId) {
            await recordAuditLog({
                communityId: d.communityId,
                actorId: authUser.id,
                eventType: 'REPORT_SUBMITTED',
                targetType: d.targetType,
                targetId: reportId,
                summary: `Submitted ${d.category} report (${d.targetType}).`,
            });
        }
        return reply.code(201).send({
            report: {
                id: reportId,
                communityId: d.communityId ?? null,
                reporterId: authUser.id,
                reporterUsername: authUser.username,
                targetType: d.targetType,
                targetUserId: d.targetUserId ?? null,
                targetMessageId: d.targetMessageId ?? null,
                category: d.category,
                reason: d.reason.trim(),
                evidenceUrls: d.evidenceUrls || [],
                status: 'open',
                resolutionNotes: null,
                resolvedByUserId: null,
                createdAt: new Date().toISOString(),
                resolvedAt: null,
            },
        });
    });
    app.get('/api/communities/:communityId/reports', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        const canReview = memberState.permissions.has(PERMISSIONS.VIEW_AUDIT_LOG) ||
            memberState.permissions.has(PERMISSIONS.KICK_MEMBERS) ||
            memberState.permissions.has(PERMISSIONS.BAN_MEMBERS) ||
            memberState.permissions.has(PERMISSIONS.MANAGE_MESSAGES);
        if (!canReview) {
            return reply.code(403).send({ error: 'Moderator permissions required to view reports.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT
           r.*,
           rep_u.username AS reporter_username,
           tgt_u.username AS target_user_username,
           res_u.username AS resolved_by_username,
           m.content AS target_message_content
         FROM reports r
         JOIN users rep_u ON rep_u.id = r.reporter_id
         LEFT JOIN users tgt_u ON tgt_u.id = r.target_user_id
         LEFT JOIN users res_u ON res_u.id = r.resolved_by_user_id
         LEFT JOIN messages m ON m.id = r.target_message_id
         WHERE r.community_id = $1
         ORDER BY r.created_at DESC`, [communityId]);
        const reports = res.rows.map((r) => ({
            id: String(r.id),
            communityId: r.community_id ? String(r.community_id) : null,
            reporterId: String(r.reporter_id),
            reporterUsername: String(r.reporter_username),
            targetType: r.target_type,
            targetUserId: r.target_user_id ? String(r.target_user_id) : null,
            targetUserUsername: r.target_user_username ? String(r.target_user_username) : null,
            targetMessageId: r.target_message_id ? String(r.target_message_id) : null,
            targetMessageContent: r.target_message_content ? String(r.target_message_content) : null,
            category: r.category,
            reason: String(r.reason),
            evidenceUrls: Array.isArray(r.evidence_urls) ? r.evidence_urls : [],
            status: r.status,
            resolutionNotes: r.resolution_notes ? String(r.resolution_notes) : null,
            resolvedByUserId: r.resolved_by_user_id ? String(r.resolved_by_user_id) : null,
            resolvedByUsername: r.resolved_by_username ? String(r.resolved_by_username) : null,
            createdAt: new Date(String(r.created_at)).toISOString(),
            resolvedAt: r.resolved_at ? new Date(String(r.resolved_at)).toISOString() : null,
        }));
        return reply.send({ reports });
    });
    app.patch('/api/communities/:communityId/reports/:reportId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, reportId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        const canReview = memberState.permissions.has(PERMISSIONS.VIEW_AUDIT_LOG) ||
            memberState.permissions.has(PERMISSIONS.KICK_MEMBERS) ||
            memberState.permissions.has(PERMISSIONS.BAN_MEMBERS) ||
            memberState.permissions.has(PERMISSIONS.MANAGE_MESSAGES);
        if (!canReview) {
            return reply.code(403).send({ error: 'Moderator permissions required to resolve reports.' });
        }
        const body = z
            .object({
            status: z.enum(['under_review', 'resolved', 'dismissed']),
            resolutionNotes: z.string().max(1500).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid report resolution payload.' });
        }
        const db = getDb();
        const resolvedAt = body.data.status === 'resolved' || body.data.status === 'dismissed'
            ? new Date().toISOString()
            : null;
        await db.query(`UPDATE reports
         SET status = $1,
             resolution_notes = $2,
             resolved_by_user_id = $3,
             resolved_at = $4
         WHERE id = $5 AND community_id = $6`, [
            body.data.status,
            body.data.resolutionNotes ?? null,
            authUser.id,
            resolvedAt,
            reportId,
            communityId,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'REPORT_REVIEWED',
            targetType: 'report',
            targetId: reportId,
            summary: `Marked report ${reportId.slice(0, 8)} as ${body.data.status}.`,
            metadata: { resolutionNotes: body.data.resolutionNotes ?? '' },
        });
        return reply.send({ updated: true, status: body.data.status });
    });
    // Execute human-operated moderation action (warn, timeout, untimeout, kick, ban, unban, note)
    app.post('/api/communities/:communityId/moderation/actions', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const body = z
            .object({
            targetUserId: z.string().uuid(),
            actionType: z.enum(['warn', 'timeout', 'untimeout', 'kick', 'ban', 'unban', 'note']),
            reason: z.string().min(2).max(1500),
            durationSeconds: z.number().int().min(60).max(2419200).nullable().optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid moderation action parameters.' });
        }
        const { targetUserId, actionType, reason, durationSeconds } = body.data;
        const actorState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        const targetState = await getMemberPermissionsAndRoles(communityId, targetUserId);
        const requiredPerm = actionType === 'ban' || actionType === 'unban'
            ? PERMISSIONS.BAN_MEMBERS
            : PERMISSIONS.KICK_MEMBERS;
        if (actionType !== 'unban') {
            const allowed = canActorModerateMember(authUser.id, targetUserId, actorState.communityOwnerId, actorState.assignedRoles, targetState.assignedRoles, requiredPerm);
            if (!allowed) {
                return reply.code(403).send({
                    error: 'Insufficient permissions or target member has an equal/higher role than you.',
                });
            }
        }
        else if (!actorState.permissions.has(PERMISSIONS.BAN_MEMBERS)) {
            return reply.code(403).send({ error: 'Missing BAN_MEMBERS permission.' });
        }
        const db = getDb();
        const actionId = crypto.randomUUID();
        await db.transaction(async (tx) => {
            if (actionType === 'timeout') {
                const secs = durationSeconds || 600;
                const until = new Date(Date.now() + secs * 1000).toISOString();
                await tx.query(`UPDATE community_memberships SET timeout_until = $1 WHERE community_id = $2 AND user_id = $3`, [until, communityId, targetUserId]);
            }
            else if (actionType === 'untimeout') {
                await tx.query(`UPDATE community_memberships SET timeout_until = NULL WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
            }
            else if (actionType === 'kick') {
                await tx.query(`DELETE FROM role_assignments WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
                await tx.query(`DELETE FROM community_memberships WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
            }
            else if (actionType === 'ban') {
                const exp = durationSeconds
                    ? new Date(Date.now() + durationSeconds * 1000).toISOString()
                    : null;
                await tx.query(`INSERT INTO community_bans (id, community_id, user_id, actor_id, reason, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (community_id, user_id)
             DO UPDATE SET reason = EXCLUDED.reason, actor_id = EXCLUDED.actor_id, expires_at = EXCLUDED.expires_at`, [crypto.randomUUID(), communityId, targetUserId, authUser.id, reason.trim(), exp]);
                await tx.query(`DELETE FROM role_assignments WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
                await tx.query(`DELETE FROM community_memberships WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
            }
            else if (actionType === 'unban') {
                await tx.query(`DELETE FROM community_bans WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
            }
            await tx.query(`INSERT INTO moderation_actions (
            id, community_id, actor_id, target_user_id, action_type, reason, duration_seconds
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)`, [
                actionId,
                communityId,
                authUser.id,
                targetUserId,
                actionType,
                reason.trim(),
                durationSeconds ?? null,
            ]);
            await recordAuditLog({
                communityId,
                actorId: authUser.id,
                eventType: `MOD_${actionType.toUpperCase()}`,
                targetType: 'user',
                targetId: targetUserId,
                summary: `Moderator executed ${actionType.toUpperCase()} on user ${targetUserId}: ${reason.trim()}`,
                tx,
            });
        });
        if (actionType !== 'note') {
            await createNotification({
                userId: targetUserId,
                type: 'moderation',
                title: `Moderation action: ${actionType.toUpperCase()}`,
                body: `Reason: ${reason.trim()}`,
                communityId,
                actorId: authUser.id,
            });
        }
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MEMBER_UPDATED',
            payload: { communityId, userId: targetUserId },
        });
        return reply.code(201).send({ actionId, actionType });
    });
    // List community moderation actions & bans
    app.get('/api/communities/:communityId/moderation/actions', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.VIEW_AUDIT_LOG) &&
            !memberState.permissions.has(PERMISSIONS.KICK_MEMBERS) &&
            !memberState.permissions.has(PERMISSIONS.BAN_MEMBERS)) {
            return reply.code(403).send({ error: 'Moderator permissions required.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT
           ma.*,
           act_u.username AS actor_username,
           tgt_u.username AS target_username
         FROM moderation_actions ma
         JOIN users act_u ON act_u.id = ma.actor_id
         JOIN users tgt_u ON tgt_u.id = ma.target_user_id
         WHERE ma.community_id = $1
         ORDER BY ma.created_at DESC
         LIMIT 100`, [communityId]);
        const bansRes = await db.query(`SELECT cb.*, u.username AS banned_username, p.display_name AS banned_display_name
         FROM community_bans cb
         JOIN users u ON u.id = cb.user_id
         JOIN profiles p ON p.user_id = cb.user_id
         WHERE cb.community_id = $1
         ORDER BY cb.created_at DESC`, [communityId]);
        const actions = res.rows.map((r) => ({
            id: String(r.id),
            communityId: String(r.community_id),
            actorId: String(r.actor_id),
            actorUsername: String(r.actor_username),
            targetUserId: String(r.target_user_id),
            targetUsername: String(r.target_username),
            actionType: r.action_type,
            reason: String(r.reason),
            durationSeconds: r.duration_seconds ? Number(r.duration_seconds) : null,
            appealStatus: r.appeal_status || 'none',
            appealText: r.appeal_text ? String(r.appeal_text) : null,
            createdAt: new Date(String(r.created_at)).toISOString(),
        }));
        return reply.send({
            actions,
            bans: bansRes.rows.map((b) => ({
                id: String(b.id),
                userId: String(b.user_id),
                username: String(b.banned_username),
                displayName: String(b.banned_display_name),
                reason: String(b.reason),
                createdAt: new Date(String(b.created_at)).toISOString(),
            })),
        });
    });
    // Submit an appeal for a significant moderation action
    app.post('/api/moderation/actions/:actionId/appeal', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { actionId } = request.params;
        const body = z.object({ appealText: z.string().min(10).max(1500) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Appeal explanation (10+ characters) is required.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT target_user_id, community_id FROM moderation_actions WHERE id = $1`, [actionId]);
        if (!res.rows[0] || res.rows[0].target_user_id !== authUser.id) {
            return reply.code(404).send({ error: 'Moderation action not found for your account.' });
        }
        await db.query(`UPDATE moderation_actions SET appeal_status = 'submitted', appeal_text = $1 WHERE id = $2`, [body.data.appealText.trim(), actionId]);
        return reply.send({ appealStatus: 'submitted' });
    });
    // Moderator review of an appeal
    app.patch('/api/communities/:communityId/moderation/actions/:actionId/appeal', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, actionId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.BAN_MEMBERS)) {
            return reply.code(403).send({ error: 'Missing BAN_MEMBERS permission to review appeals.' });
        }
        const body = z
            .object({ decision: z.enum(['approved', 'rejected']) })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Decision must be approved or rejected.' });
        }
        const db = getDb();
        const actRes = await db.query(`SELECT target_user_id, action_type FROM moderation_actions WHERE id = $1 AND community_id = $2`, [actionId, communityId]);
        if (!actRes.rows[0]) {
            return reply.code(404).send({ error: 'Moderation action not found.' });
        }
        await db.transaction(async (tx) => {
            await tx.query(`UPDATE moderation_actions SET appeal_status = $1 WHERE id = $2`, [body.data.decision, actionId]);
            if (body.data.decision === 'approved') {
                await tx.query(`DELETE FROM community_bans WHERE community_id = $1 AND user_id = $2`, [communityId, actRes.rows[0].target_user_id]);
                await tx.query(`UPDATE community_memberships SET timeout_until = NULL WHERE community_id = $1 AND user_id = $2`, [communityId, actRes.rows[0].target_user_id]);
            }
        });
        return reply.send({ appealStatus: body.data.decision });
    });
    // Community Audit Logs
    app.get('/api/communities/:communityId/audit-logs', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.VIEW_AUDIT_LOG)) {
            return reply.code(403).send({ error: 'Missing VIEW_AUDIT_LOG permission.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT ae.*, u.username AS actor_username
         FROM audit_events ae
         JOIN users u ON u.id = ae.actor_id
         WHERE ae.community_id = $1
         ORDER BY ae.created_at DESC
         LIMIT 150`, [communityId]);
        const logs = res.rows.map((r) => ({
            id: String(r.id),
            communityId: r.community_id ? String(r.community_id) : null,
            actorId: String(r.actor_id),
            actorUsername: String(r.actor_username),
            eventType: String(r.event_type),
            targetType: String(r.target_type),
            targetId: String(r.target_id),
            summary: String(r.summary),
            metadata: r.metadata || {},
            createdAt: new Date(String(r.created_at)).toISOString(),
        }));
        return reply.send({ logs });
    });
    // ============================================================================
    // NOTIFICATIONS
    // ============================================================================
    app.get('/api/notifications', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT
         n.*,
         p.display_name AS actor_display_name,
         p.avatar_url AS actor_avatar_url
       FROM notifications n
       LEFT JOIN profiles p ON p.user_id = n.actor_id
       WHERE n.user_id = $1
       ORDER BY n.created_at DESC
       LIMIT 80`, [authUser.id]);
        const notifications = res.rows.map((r) => ({
            id: String(r.id),
            userId: String(r.user_id),
            type: r.type,
            title: String(r.title),
            body: String(r.body),
            communityId: r.community_id ? String(r.community_id) : null,
            channelId: r.channel_id ? String(r.channel_id) : null,
            dmConversationId: r.dm_conversation_id ? String(r.dm_conversation_id) : null,
            messageId: r.message_id ? String(r.message_id) : null,
            actorId: r.actor_id ? String(r.actor_id) : null,
            actorDisplayName: r.actor_display_name ? String(r.actor_display_name) : null,
            actorAvatarUrl: r.actor_avatar_url ? String(r.actor_avatar_url) : null,
            isRead: Boolean(r.is_read),
            createdAt: new Date(String(r.created_at)).toISOString(),
        }));
        return reply.send({ notifications });
    });
    app.post('/api/notifications/:id/read', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const db = getDb();
        await db.query(`UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2`, [
            id,
            authUser.id,
        ]);
        return reply.send({ read: true });
    });
    app.post('/api/notifications/read-all', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        await db.query(`UPDATE notifications SET is_read = TRUE WHERE user_id = $1`, [authUser.id]);
        return reply.send({ readAll: true });
    });
    app.put('/api/communities/:communityId/notification-prefs', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const body = z
            .object({
            isMuted: z.boolean(),
            notifyLevel: z.enum(['all', 'mentions', 'nothing']).default('all'),
            suppressEveryone: z.boolean().default(false),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid notification preferences.' });
        }
        const db = getDb();
        await db.query(`INSERT INTO community_notification_prefs (id, user_id, community_id, is_muted, notify_level, suppress_everyone)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, community_id)
         DO UPDATE SET is_muted = EXCLUDED.is_muted, notify_level = EXCLUDED.notify_level, suppress_everyone = EXCLUDED.suppress_everyone`, [
            crypto.randomUUID(),
            authUser.id,
            communityId,
            body.data.isMuted,
            body.data.notifyLevel,
            body.data.suppressEveryone,
        ]);
        return reply.send({ updated: true });
    });
    // ============================================================================
    // VOICE, VIDEO & SCREEN SHARING (WEBRTC SIGNALING & ROOM COORDINATION)
    // ============================================================================
    app.get('/api/voice/config', { preHandler: [requireAuth] }, async (_request, reply) => {
        const iceServers = [
            { urls: cfg.stunUrls },
        ];
        if (cfg.turnUrl) {
            iceServers.push({
                urls: cfg.turnUrl,
                username: cfg.turnUsername || undefined,
                credential: cfg.turnCredential || undefined,
            });
        }
        return reply.send({
            iceServers,
            turnConfigured: Boolean(cfg.turnUrl),
        });
    });
    app.post('/api/channels/:channelId/voice/join', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const db = getDb();
        const chRes = await db.query(`SELECT community_id, type FROM channels WHERE id = $1`, [channelId]);
        if (!chRes.rows[0]) {
            return reply.code(404).send({ error: 'Voice channel not found.' });
        }
        const communityId = chRes.rows[0].community_id;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id, channelId);
        if (!memberState.permissions.has(PERMISSIONS.VOICE_CONNECT)) {
            return reply.code(403).send({ error: 'Missing VOICE_CONNECT permission.' });
        }
        const profRes = await db.query(`SELECT display_name, avatar_url FROM profiles WHERE user_id = $1`, [authUser.id]);
        const canSpeak = memberState.permissions.has(PERMISSIONS.VOICE_SPEAK);
        const participants = await realtimeHub.joinVoiceChannel({
            userId: authUser.id,
            username: authUser.username,
            displayName: profRes.rows[0]?.display_name || authUser.username,
            avatarUrl: profRes.rows[0]?.avatar_url ?? null,
            channelId,
            communityId,
            isMuted: !canSpeak,
            isDeafened: false,
            isServerMuted: !canSpeak,
            isCameraOn: false,
            isScreenSharing: false,
            isSpeaking: false,
            connectionQuality: 'excellent',
            joinedAt: new Date().toISOString(),
        });
        return reply.send({ participants });
    });
    app.post('/api/channels/:channelId/voice/state', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const body = z
            .object({
            isMuted: z.boolean().optional(),
            isDeafened: z.boolean().optional(),
            isCameraOn: z.boolean().optional(),
            isScreenSharing: z.boolean().optional(),
            isSpeaking: z.boolean().optional(),
            connectionQuality: z.enum(['excellent', 'good', 'fair', 'poor']).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid voice state update.' });
        }
        const participants = await realtimeHub.updateVoiceParticipant(channelId, authUser.id, body.data);
        return reply.send({ participants: participants ?? [] });
    });
    app.post('/api/channels/:channelId/voice/leave', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        await realtimeHub.leaveVoiceChannel(channelId, authUser.id);
        return reply.send({ left: true });
    });
    app.post('/api/channels/:channelId/voice/signal', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const body = z
            .object({
            toUserId: z.string().uuid(),
            signalType: z.enum(['offer', 'answer', 'ice-candidate']),
            data: z.unknown(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid WebRTC signal payload.' });
        }
        realtimeHub.relayWebRtcSignal(authUser.id, body.data.toUserId, channelId, body.data.signalType, body.data.data);
        return reply.send({ relayed: true });
    });
    app.post('/api/channels/:channelId/voice/moderate', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const body = z
            .object({
            targetUserId: z.string().uuid(),
            serverMuted: z.boolean(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid voice moderation payload.' });
        }
        const db = getDb();
        const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [channelId]);
        if (!chRes.rows[0]) {
            return reply.code(404).send({ error: 'Voice channel not found.' });
        }
        const memberState = await getMemberPermissionsAndRoles(chRes.rows[0].community_id, authUser.id, channelId);
        if (!memberState.permissions.has(PERMISSIONS.VOICE_MUTE_MEMBERS)) {
            return reply.code(403).send({ error: 'Missing VOICE_MUTE_MEMBERS permission.' });
        }
        const participants = await realtimeHub.updateVoiceParticipant(channelId, body.data.targetUserId, {
            isServerMuted: body.data.serverMuted,
            isMuted: body.data.serverMuted ? true : undefined,
        });
        return reply.send({ participants: participants ?? [] });
    });
}
