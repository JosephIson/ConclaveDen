import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { loadConfig } from '../config.js';
import { requireAuth } from '../middleware/auth.js';
import { PERMISSIONS } from '../../shared/permissions.js';
import { getMemberPermissionsAndRoles, hydrateMessages, isBlockedBetween, getUserPreferences, createNotification, recordAuditLog, } from '../services/domain.js';
import { validateFileMagicBytes, sanitizeFileName, extractSafeLinkPreviews, normalizeUsername, } from '../services/security.js';
import { getEphemeralStore } from '../services/ephemeral.js';
import { realtimeHub } from '../services/realtime.js';
const SendMessageSchema = z.object({
    content: z.string().max(4000).optional().default(''),
    replyToMessageId: z.string().uuid().nullable().optional(),
    clientNonce: z.string().max(128).nullable().optional(),
    attachmentIds: z.array(z.string().uuid()).max(10).optional().default([]),
});
async function verifyMessageAccess(userId, messageId) {
    const db = getDb();
    const msgRes = await db.query(`SELECT id, channel_id, dm_conversation_id, is_deleted FROM messages WHERE id = $1`, [
        messageId,
    ]);
    const msg = msgRes.rows[0];
    if (!msg || msg.is_deleted) {
        return {
            exists: false,
            allowed: false,
            reason: 'Message not found.',
            channelId: null,
            dmConversationId: null,
            communityId: null,
        };
    }
    if (msg.channel_id) {
        const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [msg.channel_id]);
        const communityId = chRes.rows[0]?.community_id;
        if (!communityId) {
            return {
                exists: false,
                allowed: false,
                reason: 'Channel not found.',
                channelId: msg.channel_id,
                dmConversationId: null,
                communityId: null,
            };
        }
        const memberState = await getMemberPermissionsAndRoles(communityId, userId, msg.channel_id);
        if (!memberState.permissions.has(PERMISSIONS.VIEW_CHANNELS)) {
            return {
                exists: true,
                allowed: false,
                reason: 'You do not have permission to view this channel.',
                channelId: msg.channel_id,
                dmConversationId: null,
                communityId,
            };
        }
        return {
            exists: true,
            allowed: true,
            channelId: msg.channel_id,
            dmConversationId: null,
            communityId,
        };
    }
    if (msg.dm_conversation_id) {
        const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [msg.dm_conversation_id]);
        const dm = dmRes.rows[0];
        if (!dm || (dm.participant_one_id !== userId && dm.participant_two_id !== userId)) {
            return {
                exists: true,
                allowed: false,
                reason: 'Access denied to this direct message conversation.',
                channelId: null,
                dmConversationId: msg.dm_conversation_id,
                communityId: null,
            };
        }
        return {
            exists: true,
            allowed: true,
            channelId: null,
            dmConversationId: msg.dm_conversation_id,
            communityId: null,
        };
    }
    return {
        exists: false,
        allowed: false,
        reason: 'Message scope not found.',
        channelId: null,
        dmConversationId: null,
        communityId: null,
    };
}
export async function registerMessageRoutes(app) {
    const cfg = loadConfig();
    fs.mkdirSync(cfg.uploadDir, { recursive: true });
    // 1. Multipart File Upload with Magic-Byte Validation & Optional Artwork Attribution
    app.post('/api/uploads', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const data = await request.file({
            limits: { fileSize: cfg.maxUploadBytes },
        });
        if (!data) {
            return reply.code(400).send({ error: 'No file provided in multipart upload.' });
        }
        const chunks = [];
        let totalBytes = 0;
        for await (const chunk of data.file) {
            totalBytes += chunk.length;
            if (totalBytes > cfg.maxUploadBytes) {
                return reply.code(413).send({ error: 'File exceeds maximum allowed upload size (15 MB).' });
            }
            chunks.push(chunk);
        }
        const buffer = Buffer.concat(chunks);
        const cleanOriginalName = sanitizeFileName(data.filename || 'upload');
        const magicInfo = validateFileMagicBytes(buffer, cleanOriginalName);
        if (!magicInfo.valid) {
            return reply.code(415).send({
                error: magicInfo.reason || 'Unsupported or unsafe file content.',
            });
        }
        // Parse optional artwork metadata from multipart fields
        const fields = data.fields;
        let artworkMeta = null;
        if (fields?.artworkMeta?.value) {
            try {
                const parsedMeta = JSON.parse(fields.artworkMeta.value);
                artworkMeta = {
                    isArtwork: Boolean(parsedMeta.isArtwork),
                    title: parsedMeta.title ? String(parsedMeta.title).slice(0, 120) : undefined,
                    artistName: parsedMeta.artistName ? String(parsedMeta.artistName).slice(0, 120) : undefined,
                    artistUrl: parsedMeta.artistUrl ? String(parsedMeta.artistUrl).slice(0, 400) : undefined,
                    isReferenceSheet: Boolean(parsedMeta.isReferenceSheet),
                    commissionInfo: parsedMeta.commissionInfo
                        ? String(parsedMeta.commissionInfo).slice(0, 300)
                        : undefined,
                    contentWarning: parsedMeta.contentWarning
                        ? String(parsedMeta.contentWarning).slice(0, 100)
                        : null,
                };
            }
            catch {
                artworkMeta = null;
            }
        }
        const attachmentId = crypto.randomUUID();
        const storedName = `${attachmentId}${magicInfo.extension}`;
        const storedPath = path.join(cfg.uploadDir, storedName);
        fs.writeFileSync(storedPath, buffer);
        const url = `/uploads/${storedName}`;
        const thumbnailUrl = magicInfo.isImage ? url : null;
        const db = getDb();
        await db.query(`INSERT INTO attachments (
        id, uploader_id, file_name, stored_name, mime_type, size_bytes,
        url, thumbnail_url, width, height, artwork_meta
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, [
            attachmentId,
            authUser.id,
            cleanOriginalName,
            storedName,
            magicInfo.detectedMime,
            buffer.length,
            url,
            thumbnailUrl,
            magicInfo.width ?? null,
            magicInfo.height ?? null,
            artworkMeta ? JSON.stringify(artworkMeta) : null,
        ]);
        const attachment = {
            id: attachmentId,
            messageId: null,
            uploaderId: authUser.id,
            fileName: cleanOriginalName,
            mimeType: magicInfo.detectedMime,
            sizeBytes: buffer.length,
            url,
            thumbnailUrl,
            width: magicInfo.width ?? null,
            height: magicInfo.height ?? null,
            artworkMeta,
            createdAt: new Date().toISOString(),
        };
        return reply.code(201).send({ attachment });
    });
    // 2. Get paginated channel messages
    app.get('/api/channels/:channelId/messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const query = request.query;
        const limit = Math.min(Math.max(Number(query.limit || 50), 1), 100);
        const db = getDb();
        const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [channelId]);
        const communityId = chRes.rows[0]?.community_id;
        if (!communityId) {
            return reply.code(404).send({ error: 'Channel not found.' });
        }
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id, channelId);
        if (!memberState.permissions.has(PERMISSIONS.VIEW_CHANNELS)) {
            return reply.code(403).send({ error: 'You do not have permission to view this channel.' });
        }
        const params = [channelId, limit];
        let beforeClause = '';
        if (query.before) {
            params.push(query.before);
            beforeClause = `AND m.created_at < $${params.length}`;
        }
        const rowsRes = await db.query(`SELECT
           m.*,
           u.username AS sender_username,
           p.display_name AS sender_display_name,
           p.avatar_url AS sender_avatar_url,
           p.pronouns AS sender_pronouns,
           p.furry_title AS sender_furry_title
         FROM messages m
         JOIN users u ON u.id = m.sender_id
         JOIN profiles p ON p.user_id = m.sender_id
         WHERE m.channel_id = $1 ${beforeClause}
         ORDER BY m.created_at DESC
         LIMIT $2`, params);
        // Reverse to chronological ascending order for chat display
        const chronological = [...rowsRes.rows].reverse();
        const messages = await hydrateMessages(chronological, authUser.id, communityId);
        return reply.send({
            messages,
            hasMore: rowsRes.rows.length === limit,
        });
    });
    // 3. Send message in a community channel (Server-Authoritative)
    app.post('/api/channels/:channelId/messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { channelId } = request.params;
        const parsed = SendMessageSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid message payload.' });
        }
        const { content, replyToMessageId, clientNonce, attachmentIds } = parsed.data;
        const trimmedContent = content.trim();
        if (!trimmedContent && attachmentIds.length === 0) {
            return reply.code(400).send({ error: 'Message must contain text or attachments.' });
        }
        const db = getDb();
        const chRes = await db.query(`SELECT community_id, name, is_announcement, slowmode_seconds FROM channels WHERE id = $1`, [channelId]);
        const chRow = chRes.rows[0];
        if (!chRow) {
            return reply.code(404).send({ error: 'Channel not found.' });
        }
        const communityId = chRow.community_id;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id, channelId);
        if (!memberState.permissions.has(PERMISSIONS.VIEW_CHANNELS)) {
            return reply.code(403).send({ error: 'You cannot access this channel.' });
        }
        if (!memberState.permissions.has(PERMISSIONS.SEND_MESSAGES)) {
            return reply.code(403).send({
                error: memberState.timeoutUntil
                    ? `You are currently timed out until ${new Date(memberState.timeoutUntil).toLocaleString()}.`
                    : 'You do not have permission to send messages in this channel.',
            });
        }
        if (attachmentIds.length > 0 &&
            !memberState.permissions.has(PERMISSIONS.UPLOAD_FILES)) {
            return reply.code(403).send({ error: 'Missing UPLOAD_FILES permission in this channel.' });
        }
        // Idempotent duplicate-send protection via clientNonce
        if (clientNonce) {
            const existingNonce = await db.query(`SELECT
             m.*,
             u.username AS sender_username,
             p.display_name AS sender_display_name,
             p.avatar_url AS sender_avatar_url,
             p.pronouns AS sender_pronouns,
             p.furry_title AS sender_furry_title
           FROM messages m
           JOIN users u ON u.id = m.sender_id
           JOIN profiles p ON p.user_id = m.sender_id
           WHERE m.sender_id = $1 AND m.client_nonce = $2`, [authUser.id, clientNonce]);
            if (existingNonce.rows[0]) {
                const [hydrated] = await hydrateMessages(existingNonce.rows, authUser.id, communityId);
                return reply.send({ message: hydrated, deduplicated: true });
            }
        }
        // Deterministic rate limit & duplicate-message spam check
        const eph = getEphemeralStore();
        const rateCheck = await eph.incrementAndCheckLimit(`msg_rate:${authUser.id}`, 15, 10);
        if (!rateCheck.allowed) {
            return reply.code(429).send({
                error: `Sending messages too quickly. Please wait ${rateCheck.retryAfterSeconds}s.`,
            });
        }
        if (trimmedContent.length > 0 &&
            (await eph.isDuplicateSpamMessage(authUser.id, channelId, trimmedContent, 4))) {
            return reply.code(429).send({
                error: 'Duplicate message detected. Please avoid repeating identical messages.',
            });
        }
        // Enforce configurable community word filters
        const commRes = await db.query(`SELECT name, word_filters FROM communities WHERE id = $1`, [communityId]);
        const wordFilters = Array.isArray(commRes.rows[0]?.word_filters)
            ? commRes.rows[0].word_filters
            : [];
        const lowerContent = trimmedContent.toLowerCase();
        for (const word of wordFilters) {
            const cleanWord = word.trim().toLowerCase();
            if (cleanWord && lowerContent.includes(cleanWord)) {
                return reply.code(422).send({
                    error: `Message blocked by community word filter rule ("${word}").`,
                });
            }
        }
        const linkPreviews = extractSafeLinkPreviews(trimmedContent);
        const messageId = crypto.randomUUID();
        const createdAt = new Date().toISOString();
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO messages (
            id, channel_id, sender_id, content, reply_to_message_id, client_nonce, link_previews, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
                messageId,
                channelId,
                authUser.id,
                trimmedContent,
                replyToMessageId ?? null,
                clientNonce ?? null,
                JSON.stringify(linkPreviews),
                createdAt,
            ]);
            if (attachmentIds.length > 0) {
                await tx.query(`UPDATE attachments SET message_id = $1 WHERE id = ANY($2::uuid[]) AND uploader_id = $3`, [messageId, attachmentIds, authUser.id]);
            }
        });
        const msgRows = await db.query(`SELECT
           m.*,
           u.username AS sender_username,
           p.display_name AS sender_display_name,
           p.avatar_url AS sender_avatar_url,
           p.pronouns AS sender_pronouns,
           p.furry_title AS sender_furry_title
         FROM messages m
         JOIN users u ON u.id = m.sender_id
         JOIN profiles p ON p.user_id = m.sender_id
         WHERE m.id = $1`, [messageId]);
        const [message] = await hydrateMessages(msgRows.rows, authUser.id, communityId);
        // Broadcast real-time event to community members
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MESSAGE_CREATED',
            payload: { message },
        });
        // Handle notifications for replies and @mentions
        if (replyToMessageId) {
            const replyTarget = await db.query(`SELECT sender_id FROM messages WHERE id = $1`, [replyToMessageId]);
            const targetUid = replyTarget.rows[0]?.sender_id;
            if (targetUid && targetUid !== authUser.id) {
                await createNotification({
                    userId: targetUid,
                    type: 'reply',
                    title: `${message.sender.displayName} replied to you in #${chRow.name}`,
                    body: trimmedContent.slice(0, 140),
                    communityId,
                    channelId,
                    messageId,
                    actorId: authUser.id,
                });
            }
        }
        const mentionMatches = trimmedContent.match(/@([a-zA-Z0-9_.-]{3,32})/g) || [];
        for (const rawMention of mentionMatches) {
            const uname = normalizeUsername(rawMention.slice(1));
            const mentionedRes = await db.query(`SELECT u.id
           FROM users u
           JOIN community_memberships cm ON cm.user_id = u.id AND cm.community_id = $2
           WHERE u.normalized_username = $1`, [uname, communityId]);
            const mentionedUid = mentionedRes.rows[0]?.id;
            if (mentionedUid && mentionedUid !== authUser.id) {
                await createNotification({
                    userId: mentionedUid,
                    type: 'mention',
                    title: `${message.sender.displayName} mentioned you in #${chRow.name}`,
                    body: trimmedContent.slice(0, 140),
                    communityId,
                    channelId,
                    messageId,
                    actorId: authUser.id,
                });
            }
        }
        return reply.code(201).send({ message });
    });
    // 4. Edit a message & record edit history
    app.patch('/api/messages/:messageId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { messageId } = request.params;
        const body = z.object({ content: z.string().min(1).max(4000) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Updated message content is required.' });
        }
        const db = getDb();
        const existingRes = await db.query(`SELECT id, sender_id, channel_id, dm_conversation_id, content, is_deleted FROM messages WHERE id = $1`, [
            messageId,
        ]);
        const existing = existingRes.rows[0];
        if (!existing || existing.is_deleted) {
            return reply.code(404).send({ error: 'Message not found.' });
        }
        if (existing.sender_id !== authUser.id) {
            return reply.code(403).send({ error: 'Only the message author can edit its content.' });
        }
        const nextContent = body.data.content.trim();
        const linkPreviews = extractSafeLinkPreviews(nextContent);
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO message_edit_history (id, message_id, previous_content) VALUES ($1, $2, $3)`, [crypto.randomUUID(), messageId, existing.content]);
            await tx.query(`UPDATE messages
         SET content = $1, link_previews = $2, is_edited = TRUE, edited_at = NOW()
         WHERE id = $3`, [nextContent, JSON.stringify(linkPreviews), messageId]);
        });
        let communityId = null;
        if (existing.channel_id) {
            const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [existing.channel_id]);
            communityId = chRes.rows[0]?.community_id ?? null;
        }
        const msgRows = await db.query(`SELECT
         m.*,
         u.username AS sender_username,
         p.display_name AS sender_display_name,
         p.avatar_url AS sender_avatar_url,
         p.pronouns AS sender_pronouns,
         p.furry_title AS sender_furry_title
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       JOIN profiles p ON p.user_id = m.sender_id
       WHERE m.id = $1`, [messageId]);
        const [message] = await hydrateMessages(msgRows.rows, authUser.id, communityId);
        if (communityId) {
            await realtimeHub.broadcastToCommunity(communityId, {
                type: 'MESSAGE_UPDATED',
                payload: { message },
            });
        }
        else if (existing.dm_conversation_id) {
            const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [existing.dm_conversation_id]);
            if (dmRes.rows[0]) {
                realtimeHub.sendToUsers([dmRes.rows[0].participant_one_id, dmRes.rows[0].participant_two_id], { type: 'MESSAGE_UPDATED', payload: { message } });
            }
        }
        return reply.send({ message });
    });
    // 5. Get message edit history
    app.get('/api/messages/:messageId/history', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { messageId } = request.params;
        const access = await verifyMessageAccess(authUser.id, messageId);
        if (!access.exists) {
            return reply.code(404).send({ error: access.reason || 'Message not found.' });
        }
        if (!access.allowed) {
            return reply.code(403).send({ error: access.reason || 'Access denied.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT id, message_id, previous_content, edited_at
         FROM message_edit_history
         WHERE message_id = $1
         ORDER BY edited_at DESC`, [messageId]);
        return reply.send({
            history: res.rows.map((r) => ({
                id: r.id,
                messageId: r.message_id,
                previousContent: r.previous_content,
                editedAt: new Date(r.edited_at).toISOString(),
            })),
        });
    });
    // 6. Delete a message (Author or Moderator with MANAGE_MESSAGES)
    app.delete('/api/messages/:messageId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { messageId } = request.params;
        const db = getDb();
        const existingRes = await db.query(`SELECT id, sender_id, channel_id, dm_conversation_id FROM messages WHERE id = $1`, [
            messageId,
        ]);
        const existing = existingRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Message not found.' });
        }
        let communityId = null;
        if (existing.channel_id) {
            const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [existing.channel_id]);
            communityId = chRes.rows[0]?.community_id ?? null;
        }
        if (existing.sender_id !== authUser.id) {
            if (!communityId) {
                return reply.code(403).send({ error: 'Cannot delete another user’s direct message.' });
            }
            const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id, existing.channel_id);
            if (!memberState.permissions.has(PERMISSIONS.MANAGE_MESSAGES)) {
                return reply.code(403).send({ error: 'Missing MANAGE_MESSAGES permission.' });
            }
            await recordAuditLog({
                communityId,
                actorId: authUser.id,
                eventType: 'MESSAGE_MODERATOR_DELETED',
                targetType: 'message',
                targetId: messageId,
                summary: `Moderator deleted message ${messageId} by user ${existing.sender_id}.`,
            });
        }
        await db.query(`UPDATE messages SET is_deleted = TRUE, content = '', link_previews = '[]'::jsonb WHERE id = $1`, [messageId]);
        const eventPayload = {
            messageId,
            channelId: existing.channel_id,
            dmConversationId: existing.dm_conversation_id,
        };
        if (communityId) {
            await realtimeHub.broadcastToCommunity(communityId, {
                type: 'MESSAGE_DELETED',
                payload: eventPayload,
            });
        }
        else if (existing.dm_conversation_id) {
            const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [existing.dm_conversation_id]);
            if (dmRes.rows[0]) {
                realtimeHub.sendToUsers([dmRes.rows[0].participant_one_id, dmRes.rows[0].participant_two_id], { type: 'MESSAGE_DELETED', payload: eventPayload });
            }
        }
        return reply.send({ deleted: true });
    });
    // 7. Toggle emoji reaction
    app.post('/api/messages/:messageId/reactions', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { messageId } = request.params;
        const body = z.object({ emoji: z.string().min(1).max(32) }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid emoji required.' });
        }
        const access = await verifyMessageAccess(authUser.id, messageId);
        if (!access.exists) {
            return reply.code(404).send({ error: access.reason || 'Message not found.' });
        }
        if (!access.allowed) {
            return reply.code(403).send({ error: access.reason || 'Access denied.' });
        }
        const emoji = body.data.emoji.trim();
        const db = getDb();
        const existing = await db.query(`SELECT id FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3`, [messageId, authUser.id, emoji]);
        if (existing.rows[0]) {
            await db.query(`DELETE FROM reactions WHERE id = $1`, [existing.rows[0].id]);
        }
        else {
            await db.query(`INSERT INTO reactions (id, message_id, user_id, emoji) VALUES ($1, $2, $3, $4)`, [crypto.randomUUID(), messageId, authUser.id, emoji]);
        }
        const allReactionsRes = await db.query(`SELECT user_id, emoji FROM reactions WHERE message_id = $1 ORDER BY created_at ASC`, [messageId]);
        const summaryList = [];
        for (const r of allReactionsRes.rows) {
            let entry = summaryList.find((s) => s.emoji === r.emoji);
            if (!entry) {
                entry = { emoji: r.emoji, count: 0, userIds: [], me: false };
                summaryList.push(entry);
            }
            entry.count += 1;
            entry.userIds.push(r.user_id);
            if (r.user_id === authUser.id)
                entry.me = true;
        }
        if (access.channelId && access.communityId) {
            await realtimeHub.broadcastToCommunity(access.communityId, {
                type: 'REACTION_UPDATED',
                payload: {
                    messageId,
                    channelId: access.channelId,
                    dmConversationId: null,
                    reactions: summaryList,
                },
            });
        }
        else if (access.dmConversationId) {
            const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [access.dmConversationId]);
            if (dmRes.rows[0]) {
                realtimeHub.sendToUsers([dmRes.rows[0].participant_one_id, dmRes.rows[0].participant_two_id], {
                    type: 'REACTION_UPDATED',
                    payload: {
                        messageId,
                        channelId: null,
                        dmConversationId: access.dmConversationId,
                        reactions: summaryList,
                    },
                });
            }
        }
        return reply.send({ reactions: summaryList });
    });
    // 8. Ephemeral typing indicator
    app.post('/api/typing', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            channelId: z.string().uuid().optional(),
            dmConversationId: z.string().uuid().optional(),
            isTyping: z.boolean().default(true),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid typing payload.' });
        }
        const db = getDb();
        const profRes = await db.query(`SELECT display_name FROM profiles WHERE user_id = $1`, [authUser.id]);
        const displayName = profRes.rows[0]?.display_name || authUser.username;
        if (body.data.channelId) {
            const chRes = await db.query(`SELECT community_id FROM channels WHERE id = $1`, [body.data.channelId]);
            if (chRes.rows[0]) {
                await realtimeHub.broadcastToCommunity(chRes.rows[0].community_id, {
                    type: 'TYPING_UPDATE',
                    payload: {
                        scopeId: body.data.channelId,
                        userId: authUser.id,
                        displayName,
                        isTyping: body.data.isTyping,
                    },
                });
            }
        }
        else if (body.data.dmConversationId) {
            const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [body.data.dmConversationId]);
            if (dmRes.rows[0]) {
                const otherId = dmRes.rows[0].participant_one_id === authUser.id
                    ? dmRes.rows[0].participant_two_id
                    : dmRes.rows[0].participant_one_id;
                realtimeHub.sendToUser(otherId, {
                    type: 'TYPING_UPDATE',
                    payload: {
                        scopeId: body.data.dmConversationId,
                        userId: authUser.id,
                        displayName,
                        isTyping: body.data.isTyping,
                    },
                });
            }
        }
        return reply.send({ ok: true });
    });
    // 9. Direct Message Conversations List
    app.get('/api/dms', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT
         d.*,
         u1.username AS u1_username,
         p1.display_name AS u1_display_name,
         p1.avatar_url AS u1_avatar_url,
         p1.pronouns AS u1_pronouns,
         p1.presence_status AS u1_presence_status,
         p1.custom_status_text AS u1_custom_status_text,
         p1.furry_title AS u1_furry_title,
         u2.username AS u2_username,
         p2.display_name AS u2_display_name,
         p2.avatar_url AS u2_avatar_url,
         p2.pronouns AS u2_pronouns,
         p2.presence_status AS u2_presence_status,
         p2.custom_status_text AS u2_custom_status_text,
         p2.furry_title AS u2_furry_title
       FROM dm_conversations d
       JOIN users u1 ON u1.id = d.participant_one_id
       JOIN profiles p1 ON p1.user_id = d.participant_one_id
       JOIN users u2 ON u2.id = d.participant_two_id
       JOIN profiles p2 ON p2.user_id = d.participant_two_id
       WHERE d.participant_one_id = $1 OR d.participant_two_id = $1
       ORDER BY COALESCE(d.last_message_at, d.created_at) DESC`, [authUser.id]);
        const conversations = res.rows.map((r) => {
            const isP1 = String(r.participant_one_id) === authUser.id;
            const otherUser = isP1
                ? {
                    id: String(r.participant_two_id),
                    username: String(r.u2_username),
                    displayName: String(r.u2_display_name),
                    avatarUrl: r.u2_avatar_url ? String(r.u2_avatar_url) : null,
                    pronouns: String(r.u2_pronouns || ''),
                    presenceStatus: r.u2_presence_status || 'online',
                    customStatusText: String(r.u2_custom_status_text || ''),
                    furryTitle: r.u2_furry_title ? String(r.u2_furry_title) : null,
                }
                : {
                    id: String(r.participant_one_id),
                    username: String(r.u1_username),
                    displayName: String(r.u1_display_name),
                    avatarUrl: r.u1_avatar_url ? String(r.u1_avatar_url) : null,
                    pronouns: String(r.u1_pronouns || ''),
                    presenceStatus: r.u1_presence_status || 'online',
                    customStatusText: String(r.u1_custom_status_text || ''),
                    furryTitle: r.u1_furry_title ? String(r.u1_furry_title) : null,
                };
            return {
                id: String(r.id),
                participantOneId: String(r.participant_one_id),
                participantTwoId: String(r.participant_two_id),
                otherUser,
                lastMessageAt: r.last_message_at ? new Date(String(r.last_message_at)).toISOString() : null,
                lastMessagePreview: r.last_message_preview ? String(r.last_message_preview) : null,
                unreadCount: 0,
                isMuted: isP1 ? Boolean(r.participant_one_muted) : Boolean(r.participant_two_muted),
                otherUserLastReadMessageId: isP1
                    ? r.participant_two_last_read_id
                        ? String(r.participant_two_last_read_id)
                        : null
                    : r.participant_one_last_read_id
                        ? String(r.participant_one_last_read_id)
                        : null,
                createdAt: new Date(String(r.created_at)).toISOString(),
            };
        });
        return reply.send({ conversations });
    });
    // 10. Open or create a 1-to-1 Direct Message conversation
    app.post('/api/dms', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            targetUserId: z.string().uuid().optional(),
            targetUsername: z.string().optional(),
        })
            .safeParse(request.body);
        if (!body.success || (!body.data.targetUserId && !body.data.targetUsername)) {
            return reply.code(400).send({ error: 'Target user ID or username is required.' });
        }
        const db = getDb();
        let targetId = body.data.targetUserId || '';
        if (!targetId && body.data.targetUsername) {
            const uRes = await db.query(`SELECT id FROM users WHERE normalized_username = $1 AND is_deleted = FALSE`, [normalizeUsername(body.data.targetUsername)]);
            targetId = uRes.rows[0]?.id || '';
        }
        if (!targetId) {
            return reply.code(404).send({ error: 'Recipient user not found.' });
        }
        if (targetId === authUser.id) {
            return reply.code(400).send({ error: 'Cannot start a direct message with yourself.' });
        }
        const blockState = await isBlockedBetween(authUser.id, targetId);
        if (blockState.blocked) {
            return reply.code(403).send({
                error: 'Direct messages cannot be opened due to an active block between accounts.',
            });
        }
        // Check recipient's DM privacy preference
        const targetPrefs = await getUserPreferences(targetId);
        if (targetPrefs.allowDirectMessagesFrom === 'friends_only') {
            const friendRes = await db.query(`SELECT id FROM friend_relationships
         WHERE status = 'accepted'
           AND ((requester_id = $1 AND addressee_id = $2) OR (requester_id = $2 AND addressee_id = $1))`, [authUser.id, targetId]);
            if (!friendRes.rows[0]) {
                return reply.code(403).send({
                    error: 'This user only accepts direct messages from friends.',
                });
            }
        }
        else if (targetPrefs.allowDirectMessagesFrom === 'community_members') {
            const sharedRes = await db.query(`SELECT cm1.id
         FROM community_memberships cm1
         JOIN community_memberships cm2 ON cm2.community_id = cm1.community_id
         WHERE cm1.user_id = $1 AND cm2.user_id = $2
         LIMIT 1`, [authUser.id, targetId]);
            const friendRes = await db.query(`SELECT id FROM friend_relationships
         WHERE status = 'accepted'
           AND ((requester_id = $1 AND addressee_id = $2) OR (requester_id = $2 AND addressee_id = $1))`, [authUser.id, targetId]);
            if (!sharedRes.rows[0] && !friendRes.rows[0]) {
                return reply.code(403).send({
                    error: 'This user only accepts direct messages from friends or shared community members.',
                });
            }
        }
        const [p1, p2] = [authUser.id, targetId].sort();
        const existingDm = await db.query(`SELECT id FROM dm_conversations WHERE participant_one_id = $1 AND participant_two_id = $2`, [p1, p2]);
        let dmId = existingDm.rows[0]?.id;
        if (!dmId) {
            dmId = crypto.randomUUID();
            await db.query(`INSERT INTO dm_conversations (id, participant_one_id, participant_two_id) VALUES ($1, $2, $3)`, [dmId, p1, p2]);
        }
        return reply.send({ dmConversationId: dmId });
    });
    // 11. Get Direct Message history
    app.get('/api/dms/:dmId/messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { dmId } = request.params;
        const query = request.query;
        const limit = Math.min(Math.max(Number(query.limit || 50), 1), 100);
        const db = getDb();
        const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [dmId]);
        const dm = dmRes.rows[0];
        if (!dm || (dm.participant_one_id !== authUser.id && dm.participant_two_id !== authUser.id)) {
            return reply.code(403).send({ error: 'Access denied to this conversation.' });
        }
        const params = [dmId, limit];
        let beforeClause = '';
        if (query.before) {
            params.push(query.before);
            beforeClause = `AND m.created_at < $${params.length}`;
        }
        const rowsRes = await db.query(`SELECT
         m.*,
         u.username AS sender_username,
         p.display_name AS sender_display_name,
         p.avatar_url AS sender_avatar_url,
         p.pronouns AS sender_pronouns,
         p.furry_title AS sender_furry_title
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       JOIN profiles p ON p.user_id = m.sender_id
       WHERE m.dm_conversation_id = $1 ${beforeClause}
       ORDER BY m.created_at DESC
       LIMIT $2`, params);
        const chronological = [...rowsRes.rows].reverse();
        const messages = await hydrateMessages(chronological, authUser.id, null);
        return reply.send({
            messages,
            hasMore: rowsRes.rows.length === limit,
        });
    });
    // 12. Send a Direct Message
    app.post('/api/dms/:dmId/messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { dmId } = request.params;
        const parsed = SendMessageSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid message payload.' });
        }
        const { content, replyToMessageId, clientNonce, attachmentIds } = parsed.data;
        const trimmedContent = content.trim();
        if (!trimmedContent && attachmentIds.length === 0) {
            return reply.code(400).send({ error: 'Message must contain text or attachments.' });
        }
        const db = getDb();
        const dmRes = await db.query(`SELECT * FROM dm_conversations WHERE id = $1`, [dmId]);
        const dm = dmRes.rows[0];
        if (!dm || (dm.participant_one_id !== authUser.id && dm.participant_two_id !== authUser.id)) {
            return reply.code(403).send({ error: 'Access denied to this conversation.' });
        }
        const recipientId = dm.participant_one_id === authUser.id ? dm.participant_two_id : dm.participant_one_id;
        const blockState = await isBlockedBetween(authUser.id, recipientId);
        if (blockState.blocked) {
            return reply.code(403).send({
                error: 'Cannot send direct messages while a block is active between participants.',
            });
        }
        const linkPreviews = extractSafeLinkPreviews(trimmedContent);
        const messageId = crypto.randomUUID();
        const createdAt = new Date().toISOString();
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO messages (
          id, dm_conversation_id, sender_id, content, reply_to_message_id, client_nonce, link_previews, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
                messageId,
                dmId,
                authUser.id,
                trimmedContent,
                replyToMessageId ?? null,
                clientNonce ?? null,
                JSON.stringify(linkPreviews),
                createdAt,
            ]);
            if (attachmentIds.length > 0) {
                await tx.query(`UPDATE attachments SET message_id = $1 WHERE id = ANY($2::uuid[]) AND uploader_id = $3`, [messageId, attachmentIds, authUser.id]);
            }
            await tx.query(`UPDATE dm_conversations SET last_message_at = $1, last_message_preview = $2 WHERE id = $3`, [createdAt, trimmedContent.slice(0, 120) || '[Attachment]', dmId]);
        });
        const msgRows = await db.query(`SELECT
         m.*,
         u.username AS sender_username,
         p.display_name AS sender_display_name,
         p.avatar_url AS sender_avatar_url,
         p.pronouns AS sender_pronouns,
         p.furry_title AS sender_furry_title
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       JOIN profiles p ON p.user_id = m.sender_id
       WHERE m.id = $1`, [messageId]);
        const [message] = await hydrateMessages(msgRows.rows, authUser.id, null);
        realtimeHub.sendToUsers([authUser.id, recipientId], {
            type: 'MESSAGE_CREATED',
            payload: { message },
        });
        const recipientMuted = dm.participant_one_id === recipientId ? dm.participant_one_muted : dm.participant_two_muted;
        if (!recipientMuted) {
            await createNotification({
                userId: recipientId,
                type: 'dm',
                title: `Direct message from ${message.sender.displayName}`,
                body: trimmedContent.slice(0, 140) || 'Sent an attachment',
                dmConversationId: dmId,
                messageId,
                actorId: authUser.id,
            });
        }
        return reply.code(201).send({ message });
    });
    // 13. Mark DM as read (with optional read receipt) & toggle mute
    app.post('/api/dms/:dmId/read', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { dmId } = request.params;
        const body = z.object({ lastReadMessageId: z.string().uuid() }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'lastReadMessageId is required.' });
        }
        const db = getDb();
        const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [dmId]);
        const dm = dmRes.rows[0];
        if (!dm || (dm.participant_one_id !== authUser.id && dm.participant_two_id !== authUser.id)) {
            return reply.code(403).send({ error: 'Access denied.' });
        }
        const isP1 = dm.participant_one_id === authUser.id;
        await db.query(isP1
            ? `UPDATE dm_conversations SET participant_one_last_read_id = $1 WHERE id = $2`
            : `UPDATE dm_conversations SET participant_two_last_read_id = $1 WHERE id = $2`, [body.data.lastReadMessageId, dmId]);
        const prefs = await getUserPreferences(authUser.id);
        if (prefs.sendReadReceipts) {
            const otherId = isP1 ? dm.participant_two_id : dm.participant_one_id;
            realtimeHub.sendToUser(otherId, {
                type: 'DM_READ_RECEIPT',
                payload: {
                    dmConversationId: dmId,
                    userId: authUser.id,
                    lastReadMessageId: body.data.lastReadMessageId,
                },
            });
        }
        return reply.send({ read: true });
    });
    app.post('/api/dms/:dmId/mute', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { dmId } = request.params;
        const body = z.object({ muted: z.boolean() }).safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'muted boolean is required.' });
        }
        const db = getDb();
        const dmRes = await db.query(`SELECT participant_one_id, participant_two_id FROM dm_conversations WHERE id = $1`, [dmId]);
        const dm = dmRes.rows[0];
        if (!dm || (dm.participant_one_id !== authUser.id && dm.participant_two_id !== authUser.id)) {
            return reply.code(403).send({ error: 'Access denied.' });
        }
        const isP1 = dm.participant_one_id === authUser.id;
        await db.query(isP1
            ? `UPDATE dm_conversations SET participant_one_muted = $1 WHERE id = $2`
            : `UPDATE dm_conversations SET participant_two_muted = $1 WHERE id = $2`, [body.data.muted, dmId]);
        return reply.send({ muted: body.data.muted });
    });
    // 14. Conventional, permission-scoped Search across Messages, Communities, Channels, and Users
    app.get('/api/search', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const query = request.query;
        const q = (query.q || '').trim().toLowerCase();
        const db = getDb();
        // Determine channels the user is authorized to view
        const membershipsRes = await db.query(`SELECT community_id FROM community_memberships WHERE user_id = $1`, [authUser.id]);
        const joinedCommIds = membershipsRes.rows.map((r) => r.community_id);
        const allowedChannelIds = [];
        for (const cid of joinedCommIds) {
            if (query.communityId && cid !== query.communityId)
                continue;
            const chRes = await db.query(`SELECT id FROM channels WHERE community_id = $1`, [cid]);
            for (const ch of chRes.rows) {
                if (query.channelId && ch.id !== query.channelId)
                    continue;
                const permState = await getMemberPermissionsAndRoles(cid, authUser.id, ch.id);
                if (permState.permissions.has(PERMISSIONS.VIEW_CHANNELS)) {
                    allowedChannelIds.push(ch.id);
                }
            }
        }
        // Also include user's own DM conversations if not filtering by community/channel
        let allowedDmIds = [];
        if (!query.communityId && !query.channelId) {
            const dmRes = await db.query(`SELECT id FROM dm_conversations WHERE participant_one_id = $1 OR participant_two_id = $1`, [authUser.id]);
            allowedDmIds = dmRes.rows.map((d) => d.id);
        }
        let messages = [];
        if (allowedChannelIds.length > 0 || allowedDmIds.length > 0) {
            const msgParams = [allowedChannelIds, allowedDmIds];
            const msgConds = [
                `m.is_deleted = FALSE`,
                `(m.channel_id = ANY($1::uuid[]) OR m.dm_conversation_id = ANY($2::uuid[]))`,
            ];
            if (q) {
                msgParams.push(`%${q}%`);
                msgConds.push(`LOWER(m.content) LIKE $${msgParams.length}`);
            }
            if (query.sender && query.sender.trim()) {
                msgParams.push(normalizeUsername(query.sender.replace(/^@/, '')));
                msgConds.push(`u.normalized_username = $${msgParams.length}`);
            }
            if (query.dateFrom) {
                msgParams.push(query.dateFrom);
                msgConds.push(`m.created_at >= $${msgParams.length}`);
            }
            if (query.dateTo) {
                msgParams.push(query.dateTo);
                msgConds.push(`m.created_at <= $${msgParams.length}`);
            }
            if (query.hasAttachments === 'true') {
                msgConds.push(`EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id)`);
            }
            const msgRows = await db.query(`SELECT
           m.*,
           u.username AS sender_username,
           p.display_name AS sender_display_name,
           p.avatar_url AS sender_avatar_url,
           p.pronouns AS sender_pronouns,
           p.furry_title AS sender_furry_title
         FROM messages m
         JOIN users u ON u.id = m.sender_id
         JOIN profiles p ON p.user_id = m.sender_id
         WHERE ${msgConds.join(' AND ')}
         ORDER BY m.created_at DESC
         LIMIT 40`, msgParams);
            messages = await hydrateMessages(msgRows.rows, authUser.id, query.communityId || null);
        }
        // Users search (respecting discoverable_by_search privacy setting)
        let users = [];
        if (q) {
            const uRes = await db.query(`SELECT u.id, u.username, p.display_name, p.avatar_url, p.furry_title
         FROM users u
         JOIN profiles p ON p.user_id = u.id
         JOIN user_preferences pref ON pref.user_id = u.id
         WHERE u.is_deleted = FALSE
           AND pref.discoverable_by_search = TRUE
           AND (LOWER(u.username) LIKE $1 OR LOWER(p.display_name) LIKE $1)
         LIMIT 20`, [`%${q}%`]);
            users = uRes.rows.map((r) => ({
                id: String(r.id),
                username: String(r.username),
                displayName: String(r.display_name),
                avatarUrl: r.avatar_url ? String(r.avatar_url) : null,
                furryTitle: r.furry_title ? String(r.furry_title) : null,
            }));
        }
        return reply.send({
            messages,
            users,
        });
    });
    // 15. Saved Messages / Bookmarks
    app.get('/api/saved-messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const savedRes = await db.query(`SELECT
         sm.id AS bookmark_id,
         sm.folder_name,
         sm.note,
         sm.created_at AS bookmarked_at,
         m.*,
         u.username AS sender_username,
         p.display_name AS sender_display_name,
         p.avatar_url AS sender_avatar_url,
         p.pronouns AS sender_pronouns,
         p.furry_title AS sender_furry_title,
         ch.name AS channel_name,
         c.name AS community_name
       FROM saved_messages sm
       JOIN messages m ON m.id = sm.message_id
       JOIN users u ON u.id = m.sender_id
       JOIN profiles p ON p.user_id = m.sender_id
       LEFT JOIN channels ch ON ch.id = m.channel_id
       LEFT JOIN communities c ON c.id = ch.community_id
       WHERE sm.user_id = $1 AND m.is_deleted = FALSE
       ORDER BY sm.created_at DESC`, [authUser.id]);
        const hydrated = await hydrateMessages(savedRes.rows, authUser.id, null);
        const bookmarks = savedRes.rows.map((row, idx) => ({
            id: String(row.bookmark_id),
            userId: authUser.id,
            messageId: String(row.id),
            folderName: String(row.folder_name || 'General'),
            note: String(row.note || ''),
            createdAt: new Date(String(row.bookmarked_at)).toISOString(),
            message: hydrated[idx],
            communityName: row.community_name ? String(row.community_name) : null,
            channelName: row.channel_name ? String(row.channel_name) : null,
        }));
        return reply.send({ bookmarks });
    });
    app.post('/api/saved-messages', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const body = z
            .object({
            messageId: z.string().uuid(),
            folderName: z.string().min(1).max(64).optional(),
            note: z.string().max(500).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid messageId required.' });
        }
        const access = await verifyMessageAccess(authUser.id, body.data.messageId);
        if (!access.exists) {
            return reply.code(404).send({ error: access.reason || 'Message not found.' });
        }
        if (!access.allowed) {
            return reply.code(403).send({ error: access.reason || 'Access denied.' });
        }
        const db = getDb();
        const id = crypto.randomUUID();
        await db.query(`INSERT INTO saved_messages (id, user_id, message_id, folder_name, note)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, message_id)
       DO UPDATE SET folder_name = EXCLUDED.folder_name, note = EXCLUDED.note`, [
            id,
            authUser.id,
            body.data.messageId,
            (body.data.folderName || 'General').trim(),
            (body.data.note || '').trim(),
        ]);
        return reply.code(201).send({ saved: true });
    });
    app.delete('/api/saved-messages/:id', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const db = getDb();
        await db.query(`DELETE FROM saved_messages WHERE (id = $1 OR message_id = $1) AND user_id = $2`, [
            id,
            authUser.id,
        ]);
        return reply.send({ removed: true });
    });
}
