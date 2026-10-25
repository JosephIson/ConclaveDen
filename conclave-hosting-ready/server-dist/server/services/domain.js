import crypto from 'node:crypto';
import { getDb } from '../db/client.js';
import { computeEffectivePermissions, } from '../../shared/permissions.js';
import { realtimeHub } from './realtime.js';
export async function recordAuditLog(params) {
    const db = params.tx ?? getDb();
    await db.query(`INSERT INTO audit_events (id, community_id, actor_id, event_type, target_type, target_id, summary, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
        crypto.randomUUID(),
        params.communityId ?? null,
        params.actorId,
        params.eventType,
        params.targetType,
        params.targetId,
        params.summary,
        JSON.stringify(params.metadata ?? {}),
    ]);
}
export async function createNotification(params) {
    if (params.actorId && params.actorId === params.userId) {
        return null;
    }
    const db = getDb();
    // Check user notification preferences
    const prefRes = await db.query(`SELECT * FROM user_preferences WHERE user_id = $1`, [params.userId]);
    const prefs = prefRes.rows[0];
    if (prefs) {
        if (params.type === 'dm' && !prefs.notify_on_direct_messages)
            return null;
        if (params.type === 'mention' && !prefs.notify_on_mentions)
            return null;
        if (params.type === 'reply' && !prefs.notify_on_replies)
            return null;
        if (params.type === 'friend_request' && !prefs.notify_on_friend_requests)
            return null;
        if (params.type === 'announcement' && !prefs.notify_on_announcements)
            return null;
    }
    if (params.communityId) {
        const commPref = await db.query(`SELECT is_muted FROM community_notification_prefs WHERE user_id = $1 AND community_id = $2`, [params.userId, params.communityId]);
        if (commPref.rows[0]?.is_muted && params.type !== 'moderation') {
            return null;
        }
    }
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    await db.query(`INSERT INTO notifications (
      id, user_id, type, title, body, community_id, channel_id, dm_conversation_id, message_id, actor_id, is_read, created_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, $11)`, [
        id,
        params.userId,
        params.type,
        params.title,
        params.body,
        params.communityId ?? null,
        params.channelId ?? null,
        params.dmConversationId ?? null,
        params.messageId ?? null,
        params.actorId ?? null,
        createdAt,
    ]);
    let actorDisplayName = null;
    let actorAvatarUrl = null;
    if (params.actorId) {
        const actorRes = await db.query(`SELECT display_name, avatar_url FROM profiles WHERE user_id = $1`, [params.actorId]);
        if (actorRes.rows[0]) {
            actorDisplayName = actorRes.rows[0].display_name;
            actorAvatarUrl = actorRes.rows[0].avatar_url;
        }
    }
    const notification = {
        id,
        userId: params.userId,
        type: params.type,
        title: params.title,
        body: params.body,
        communityId: params.communityId ?? null,
        channelId: params.channelId ?? null,
        dmConversationId: params.dmConversationId ?? null,
        messageId: params.messageId ?? null,
        actorId: params.actorId ?? null,
        actorDisplayName,
        actorAvatarUrl,
        isRead: false,
        createdAt,
    };
    if (!prefs?.do_not_disturb) {
        realtimeHub.sendToUser(params.userId, {
            type: 'NOTIFICATION_CREATED',
            payload: { notification },
        });
    }
    return notification;
}
export async function isBlockedBetween(userA, userB) {
    const db = getDb();
    const res = await db.query(`SELECT blocker_id, blocked_user_id FROM blocks
     WHERE (blocker_id = $1 AND blocked_user_id = $2)
        OR (blocker_id = $2 AND blocked_user_id = $1)`, [userA, userB]);
    const aBlockedB = res.rows.some((r) => r.blocker_id === userA && r.blocked_user_id === userB);
    const bBlockedA = res.rows.some((r) => r.blocker_id === userB && r.blocked_user_id === userA);
    return {
        blocked: aBlockedB || bBlockedA,
        aBlockedB,
        bBlockedA,
    };
}
export async function getUserProfile(userId) {
    const db = getDb();
    const res = await db.query(`SELECT
       u.id AS user_id,
       u.username,
       u.normalized_username,
       u.email_verified,
       u.mfa_enabled,
       u.onboarding_completed,
       u.created_at,
       p.display_name,
       p.avatar_url,
       p.banner_url,
       p.accent_color,
       p.profile_gradient,
       p.badge_ids,
       p.bio,
       p.pronouns,
       p.interests,
       p.favorite_games,
       p.social_links,
       p.is_furry_identity_enabled,
       p.furry_title,
       p.presence_status,
       p.custom_status_text,
       p.last_active_at
     FROM users u
     JOIN profiles p ON p.user_id = u.id
     WHERE u.id = $1 AND u.is_deleted = FALSE`, [userId]);
    const row = res.rows[0];
    if (!row)
        return null;
    const fursonaRes = await db.query(`SELECT * FROM fursonas WHERE user_id = $1 ORDER BY is_primary DESC, created_at ASC`, [userId]);
    const fursonas = fursonaRes.rows.map((f) => ({
        id: String(f.id),
        userId: String(f.user_id),
        name: String(f.name),
        species: String(f.species),
        pronouns: String(f.pronouns || ''),
        description: String(f.description || ''),
        colors: Array.isArray(f.colors) ? f.colors : [],
        traits: Array.isArray(f.traits) ? f.traits : [],
        avatarUrl: f.avatar_url ? String(f.avatar_url) : null,
        refSheetUrl: f.ref_sheet_url ? String(f.ref_sheet_url) : null,
        artistCreditName: f.artist_credit_name ? String(f.artist_credit_name) : null,
        artistCreditUrl: f.artist_credit_url ? String(f.artist_credit_url) : null,
        portfolioUrl: f.portfolio_url ? String(f.portfolio_url) : null,
        commissionStatus: f.commission_status || 'not_applicable',
        commissionInfo: f.commission_info ? String(f.commission_info) : null,
        isPrimary: Boolean(f.is_primary),
        createdAt: new Date(String(f.created_at)).toISOString(),
        updatedAt: new Date(String(f.updated_at)).toISOString(),
    }));
    return {
        userId: String(row.user_id),
        username: String(row.username),
        normalizedUsername: String(row.normalized_username),
        displayName: String(row.display_name),
        avatarUrl: row.avatar_url ? String(row.avatar_url) : null,
        bannerUrl: row.banner_url ? String(row.banner_url) : null,
        accentColor: String(row.accent_color || '#8B5CF6'),
        profileGradient: row.profile_gradient ? String(row.profile_gradient) : null,
        badgeIds: Array.isArray(row.badge_ids) ? row.badge_ids : [],
        bio: String(row.bio || ''),
        pronouns: String(row.pronouns || ''),
        interests: Array.isArray(row.interests) ? row.interests : [],
        favoriteGames: Array.isArray(row.favorite_games) ? row.favorite_games : [],
        socialLinks: Array.isArray(row.social_links) ? row.social_links : [],
        isFurryIdentityEnabled: Boolean(row.is_furry_identity_enabled),
        furryTitle: row.furry_title ? String(row.furry_title) : null,
        fursonas,
        presenceStatus: row.presence_status || 'online',
        customStatusText: String(row.custom_status_text || ''),
        lastActiveAt: row.last_active_at ? new Date(String(row.last_active_at)).toISOString() : null,
        emailVerified: Boolean(row.email_verified),
        mfaEnabled: Boolean(row.mfa_enabled),
        onboardingCompleted: Boolean(row.onboarding_completed),
        createdAt: new Date(String(row.created_at)).toISOString(),
    };
}
export async function getUserPreferences(userId) {
    const db = getDb();
    const res = await db.query(`SELECT * FROM user_preferences WHERE user_id = $1`, [userId]);
    const row = res.rows[0];
    if (!row) {
        return {
            userId,
            theme: 'dark',
            reducedMotion: false,
            highContrast: false,
            fontScale: 'md',
            compactMessages: false,
            allowDirectMessagesFrom: 'everyone',
            allowFriendRequestsFrom: 'everyone',
            showOnlineStatus: true,
            showLastActive: true,
            showSharedCommunities: true,
            sendReadReceipts: true,
            discoverableBySearch: true,
            doNotDisturb: false,
            notifyOnDirectMessages: true,
            notifyOnMentions: true,
            notifyOnReplies: true,
            notifyOnFriendRequests: true,
            notifyOnAnnouncements: true,
            matureContentFilter: 'blur_with_warning',
        };
    }
    return {
        userId,
        theme: row.theme || 'dark',
        reducedMotion: Boolean(row.reduced_motion),
        highContrast: Boolean(row.high_contrast),
        fontScale: row.font_scale || 'md',
        compactMessages: Boolean(row.compact_messages),
        allowDirectMessagesFrom: row.allow_direct_messages_from || 'everyone',
        allowFriendRequestsFrom: row.allow_friend_requests_from || 'everyone',
        showOnlineStatus: Boolean(row.show_online_status),
        showLastActive: Boolean(row.show_last_active),
        showSharedCommunities: Boolean(row.show_shared_communities),
        sendReadReceipts: Boolean(row.send_read_receipts),
        discoverableBySearch: Boolean(row.discoverable_by_search),
        doNotDisturb: Boolean(row.do_not_disturb),
        notifyOnDirectMessages: Boolean(row.notify_on_direct_messages),
        notifyOnMentions: Boolean(row.notify_on_mentions),
        notifyOnReplies: Boolean(row.notify_on_replies),
        notifyOnFriendRequests: Boolean(row.notify_on_friend_requests),
        notifyOnAnnouncements: Boolean(row.notify_on_announcements),
        matureContentFilter: row.mature_content_filter || 'blur_with_warning',
    };
}
export async function getMemberPermissionsAndRoles(communityId, userId, channelId) {
    const db = getDb();
    const commRes = await db.query(`SELECT owner_id FROM communities WHERE id = $1`, [communityId]);
    if (!commRes.rows[0]) {
        return {
            isMember: false,
            isBanned: false,
            communityOwnerId: '',
            assignedRoles: [],
            defaultRole: null,
            timeoutUntil: null,
            permissions: new Set(),
        };
    }
    const communityOwnerId = commRes.rows[0].owner_id;
    const banRes = await db.query(`SELECT id, expires_at FROM community_bans WHERE community_id = $1 AND user_id = $2`, [communityId, userId]);
    if (banRes.rows[0]) {
        const exp = banRes.rows[0].expires_at;
        if (!exp || new Date(exp).getTime() > Date.now()) {
            return {
                isMember: false,
                isBanned: true,
                communityOwnerId,
                assignedRoles: [],
                defaultRole: null,
                timeoutUntil: null,
                permissions: new Set(),
            };
        }
    }
    const memRes = await db.query(`SELECT id, timeout_until FROM community_memberships WHERE community_id = $1 AND user_id = $2`, [communityId, userId]);
    if (!memRes.rows[0]) {
        return {
            isMember: false,
            isBanned: false,
            communityOwnerId,
            assignedRoles: [],
            defaultRole: null,
            timeoutUntil: null,
            permissions: new Set(),
        };
    }
    const timeoutUntil = memRes.rows[0].timeout_until
        ? new Date(memRes.rows[0].timeout_until).toISOString()
        : null;
    const allRolesRes = await db.query(`SELECT * FROM roles WHERE community_id = $1 ORDER BY position DESC`, [communityId]);
    const allRoles = allRolesRes.rows.map((r) => ({
        id: String(r.id),
        communityId: String(r.community_id),
        name: String(r.name),
        slug: String(r.slug),
        color: String(r.color),
        position: Number(r.position),
        isDefault: Boolean(r.is_default),
        isSystem: Boolean(r.is_system),
        permissions: Array.isArray(r.permissions) ? r.permissions : [],
        denyPermissions: Array.isArray(r.deny_permissions)
            ? r.deny_permissions
            : [],
    }));
    const defaultRole = allRoles.find((r) => r.isDefault) ?? null;
    const assignedIdsRes = await db.query(`SELECT role_id FROM role_assignments WHERE community_id = $1 AND user_id = $2`, [communityId, userId]);
    const assignedIdSet = new Set(assignedIdsRes.rows.map((r) => r.role_id));
    const assignedRoles = allRoles.filter((r) => assignedIdSet.has(r.id));
    let channelData = null;
    let channelOverrides = [];
    let isChannelExplicitMember = false;
    if (channelId) {
        const chRes = await db.query(`SELECT id, is_private, is_announcement, is_archived FROM channels WHERE id = $1 AND community_id = $2`, [channelId, communityId]);
        if (chRes.rows[0]) {
            channelData = {
                id: String(chRes.rows[0].id),
                isPrivate: Boolean(chRes.rows[0].is_private),
                isAnnouncement: Boolean(chRes.rows[0].is_announcement),
                isArchived: Boolean(chRes.rows[0].is_archived),
            };
            const ovRes = await db.query(`SELECT * FROM permission_overrides WHERE channel_id = $1`, [channelId]);
            channelOverrides = ovRes.rows.map((o) => ({
                id: String(o.id),
                channelId: String(o.channel_id),
                targetType: o.target_type,
                targetId: String(o.target_id),
                allow: Array.isArray(o.allow_permissions) ? o.allow_permissions : [],
                deny: Array.isArray(o.deny_permissions) ? o.deny_permissions : [],
            }));
            const chMemRes = await db.query(`SELECT id FROM channel_memberships WHERE channel_id = $1 AND user_id = $2`, [channelId, userId]);
            isChannelExplicitMember = Boolean(chMemRes.rows[0]);
        }
    }
    const permissions = computeEffectivePermissions({
        userId,
        communityOwnerId,
        assignedRoles,
        defaultRole,
        timeoutUntil,
        channel: channelData,
        channelOverrides,
        isChannelExplicitMember,
    });
    return {
        isMember: true,
        isBanned: false,
        communityOwnerId,
        assignedRoles,
        defaultRole,
        timeoutUntil,
        permissions,
    };
}
export async function hydrateMessages(rows, viewerUserId, communityId) {
    if (rows.length === 0)
        return [];
    const db = getDb();
    const messageIds = rows.map((r) => String(r.id));
    // Fetch attachments
    const attRes = await db.query(`SELECT * FROM attachments WHERE message_id = ANY($1::uuid[]) ORDER BY created_at ASC`, [messageIds]);
    const attachmentsByMsg = new Map();
    for (const a of attRes.rows) {
        const msgId = String(a.message_id);
        const list = attachmentsByMsg.get(msgId) ?? [];
        list.push({
            id: String(a.id),
            messageId: msgId,
            uploaderId: String(a.uploader_id),
            fileName: String(a.file_name),
            mimeType: String(a.mime_type),
            sizeBytes: Number(a.size_bytes),
            url: String(a.url),
            thumbnailUrl: a.thumbnail_url ? String(a.thumbnail_url) : null,
            width: a.width ? Number(a.width) : null,
            height: a.height ? Number(a.height) : null,
            artworkMeta: a.artwork_meta ?? null,
            createdAt: new Date(String(a.created_at)).toISOString(),
        });
        attachmentsByMsg.set(msgId, list);
    }
    // Fetch reactions
    const reactRes = await db.query(`SELECT message_id, user_id, emoji FROM reactions WHERE message_id = ANY($1::uuid[]) ORDER BY created_at ASC`, [messageIds]);
    const reactionsByMsg = new Map();
    for (const r of reactRes.rows) {
        const msgId = String(r.message_id);
        const emoji = String(r.emoji);
        const uid = String(r.user_id);
        const list = reactionsByMsg.get(msgId) ?? [];
        let summary = list.find((s) => s.emoji === emoji);
        if (!summary) {
            summary = { emoji, count: 0, userIds: [], me: false };
            list.push(summary);
        }
        summary.count += 1;
        summary.userIds.push(uid);
        if (uid === viewerUserId) {
            summary.me = true;
        }
        reactionsByMsg.set(msgId, list);
    }
    // Fetch reply targets if any
    const replyIds = Array.from(new Set(rows.map((r) => (r.reply_to_message_id ? String(r.reply_to_message_id) : '')).filter(Boolean)));
    const replyMap = new Map();
    if (replyIds.length > 0) {
        const repRes = await db.query(`SELECT m.id, m.content, m.is_deleted, u.username, p.display_name
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       JOIN profiles p ON p.user_id = m.sender_id
       WHERE m.id = ANY($1::uuid[])`, [replyIds]);
        for (const rep of repRes.rows) {
            replyMap.set(String(rep.id), {
                id: String(rep.id),
                senderDisplayName: String(rep.display_name),
                senderUsername: String(rep.username),
                content: rep.is_deleted ? '[Message deleted]' : String(rep.content).slice(0, 140),
            });
        }
    }
    // Fetch sender role colors if inside a community
    const roleColorByUser = new Map();
    if (communityId) {
        const senderIds = Array.from(new Set(rows.map((r) => String(r.sender_id))));
        if (senderIds.length > 0) {
            const roleRes = await db.query(`SELECT ra.user_id, r.color, r.name, r.position
         FROM role_assignments ra
         JOIN roles r ON r.id = ra.role_id
         WHERE ra.community_id = $1 AND ra.user_id = ANY($2::uuid[])
         ORDER BY r.position DESC`, [communityId, senderIds]);
            for (const rr of roleRes.rows) {
                const uid = String(rr.user_id);
                if (!roleColorByUser.has(uid)) {
                    roleColorByUser.set(uid, {
                        color: String(rr.color),
                        name: String(rr.name),
                    });
                }
            }
        }
    }
    return rows.map((row) => {
        const id = String(row.id);
        const senderId = String(row.sender_id);
        const roleMeta = roleColorByUser.get(senderId);
        const isDeleted = Boolean(row.is_deleted);
        return {
            id,
            channelId: row.channel_id ? String(row.channel_id) : null,
            dmConversationId: row.dm_conversation_id ? String(row.dm_conversation_id) : null,
            senderId,
            content: isDeleted ? '' : String(row.content || ''),
            replyToMessageId: row.reply_to_message_id ? String(row.reply_to_message_id) : null,
            replyPreview: row.reply_to_message_id
                ? replyMap.get(String(row.reply_to_message_id)) ?? null
                : null,
            clientNonce: row.client_nonce ? String(row.client_nonce) : null,
            attachments: isDeleted ? [] : attachmentsByMsg.get(id) ?? [],
            reactions: isDeleted ? [] : reactionsByMsg.get(id) ?? [],
            linkPreviews: !isDeleted && Array.isArray(row.link_previews)
                ? row.link_previews
                : [],
            isEdited: Boolean(row.is_edited),
            isDeleted,
            editedAt: row.edited_at ? new Date(String(row.edited_at)).toISOString() : null,
            createdAt: new Date(String(row.created_at)).toISOString(),
            sender: {
                id: senderId,
                username: String(row.sender_username || 'user'),
                displayName: String(row.sender_display_name || row.sender_username || 'Member'),
                avatarUrl: row.sender_avatar_url ? String(row.sender_avatar_url) : null,
                pronouns: String(row.sender_pronouns || ''),
                roleColor: roleMeta?.color ?? null,
                highestRoleName: roleMeta?.name ?? null,
                furryTitle: row.sender_furry_title ? String(row.sender_furry_title) : null,
            },
        };
    });
}
