import crypto from 'node:crypto';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { requireAuth } from '../middleware/auth.js';
import { PERMISSIONS, ALL_PERMISSIONS, DEFAULT_COMMUNITY_ROLES, canActorManageTargetRole, getHighestRolePosition, } from '../../shared/permissions.js';
import { getMemberPermissionsAndRoles, recordAuditLog, } from '../services/domain.js';
import { realtimeHub } from '../services/realtime.js';
const CreateCommunitySchema = z.object({
    name: z.string().min(2).max(80),
    slug: z
        .string()
        .min(2)
        .max(64)
        .regex(/^[a-z0-9-]+$/),
    description: z.string().max(1000).optional(),
    iconUrl: z.string().max(1000).nullable().optional(),
    bannerUrl: z.string().max(1000).nullable().optional(),
    accentColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
    categories: z.array(z.string().max(40)).max(8).optional(),
    tags: z.array(z.string().max(32)).max(12).optional(),
    primaryLanguage: z.string().min(2).max(16).optional(),
    visibility: z.enum(['public', 'private']).optional(),
    isListedInDiscovery: z.boolean().optional(),
    membershipPolicy: z.enum(['open', 'invite_only']).optional(),
    invitePolicy: z.enum(['everyone', 'role_based', 'admins_only']).optional(),
    rulesText: z.string().max(4000).optional(),
    wordFilters: z.array(z.string().max(64)).max(100).optional(),
});
const ChannelInputSchema = z.object({
    name: z.string().min(1).max(64),
    topic: z.string().max(500).optional(),
    categoryName: z.string().min(1).max(64).optional(),
    type: z
        .enum(['text', 'announcement', 'art_gallery', 'media', 'introductions', 'staff', 'voice'])
        .optional(),
    position: z.number().int().min(0).max(10000).optional(),
    isPrivate: z.boolean().optional(),
    isAnnouncement: z.boolean().optional(),
    isArchived: z.boolean().optional(),
    slowmodeSeconds: z.number().int().min(0).max(3600).optional(),
});
function formatSlug(name) {
    return (name
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 60) || 'general');
}
async function mapCommunityRow(row, db) {
    const communityId = String(row.id);
    const countRes = await db.query(`SELECT
       COUNT(*)::text AS total,
       COUNT(*) FILTER (WHERE p.presence_status <> 'offline')::text AS online
     FROM community_memberships cm
     JOIN profiles p ON p.user_id = cm.user_id
     WHERE cm.community_id = $1`, [communityId]);
    return {
        id: communityId,
        name: String(row.name),
        slug: String(row.slug),
        description: String(row.description || ''),
        iconUrl: row.icon_url ? String(row.icon_url) : null,
        bannerUrl: row.banner_url ? String(row.banner_url) : null,
        accentColor: String(row.accent_color || '#8B5CF6'),
        categories: Array.isArray(row.categories) ? row.categories : [],
        tags: Array.isArray(row.tags) ? row.tags : [],
        primaryLanguage: String(row.primary_language || 'en'),
        visibility: row.visibility || 'public',
        isListedInDiscovery: Boolean(row.is_listed_in_discovery),
        membershipPolicy: row.membership_policy || 'open',
        invitePolicy: row.invite_policy || 'everyone',
        rulesText: String(row.rules_text || ''),
        wordFilters: Array.isArray(row.word_filters) ? row.word_filters : [],
        ownerId: String(row.owner_id),
        memberCount: Number(countRes.rows[0]?.total || 0),
        onlineCount: Number(countRes.rows[0]?.online || 0),
        createdAt: new Date(String(row.created_at)).toISOString(),
        updatedAt: new Date(String(row.updated_at)).toISOString(),
    };
}
export async function registerCommunityRoutes(app) {
    // List communities the authenticated user belongs to
    app.get('/api/communities', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const db = getDb();
        const res = await db.query(`SELECT c.*
       FROM communities c
       JOIN community_memberships cm ON cm.community_id = c.id
       WHERE cm.user_id = $1
       ORDER BY cm.joined_at ASC`, [authUser.id]);
        const communities = [];
        for (const row of res.rows) {
            communities.push(await mapCommunityRow(row, db));
        }
        return reply.send({ communities });
    });
    // Conventional, deterministic Community Discovery
    app.get('/api/communities/discover', { preHandler: [requireAuth] }, async (request, reply) => {
        const query = request.query;
        const db = getDb();
        const conditions = [`c.visibility = 'public'`, `c.is_listed_in_discovery = TRUE`];
        const params = [];
        if (query.q && query.q.trim()) {
            params.push(`%${query.q.trim().toLowerCase()}%`);
            const idx = params.length;
            conditions.push(`(LOWER(c.name) LIKE $${idx} OR LOWER(c.description) LIKE $${idx} OR LOWER(c.slug) LIKE $${idx})`);
        }
        if (query.language && query.language.trim() && query.language !== 'all') {
            params.push(query.language.trim());
            conditions.push(`c.primary_language = $${params.length}`);
        }
        const sql = `
      SELECT c.*, COUNT(cm.id)::int AS member_count
      FROM communities c
      LEFT JOIN community_memberships cm ON cm.community_id = c.id
      WHERE ${conditions.join(' AND ')}
      GROUP BY c.id
      ORDER BY ${query.sort === 'newest'
            ? 'c.created_at DESC'
            : query.sort === 'alphabetical'
                ? 'c.name ASC'
                : 'member_count DESC, c.created_at DESC'}
      LIMIT 60
    `;
        const res = await db.query(sql, params);
        let list = [];
        for (const row of res.rows) {
            list.push(await mapCommunityRow(row, db));
        }
        if (query.category && query.category !== 'all') {
            const catLower = query.category.toLowerCase();
            list = list.filter((c) => c.categories.some((cat) => cat.toLowerCase() === catLower));
        }
        if (query.tag && query.tag.trim()) {
            const tagLower = query.tag.trim().toLowerCase();
            list = list.filter((c) => c.tags.some((t) => t.toLowerCase().includes(tagLower)));
        }
        return reply.send({ communities: list });
    });
    // Create a new community with default roles & channels
    app.post('/api/communities', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const parsed = CreateCommunitySchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({
                error: 'Invalid community configuration.',
                details: parsed.error.flatten().fieldErrors,
            });
        }
        const d = parsed.data;
        const db = getDb();
        const existingSlug = await db.query(`SELECT id FROM communities WHERE slug = $1`, [d.slug.toLowerCase()]);
        if (existingSlug.rows.length > 0) {
            return reply.code(409).send({ error: 'A community with that slug identifier already exists.' });
        }
        const communityId = crypto.randomUUID();
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO communities (
          id, name, slug, description, icon_url, banner_url, accent_color,
          categories, tags, primary_language, visibility, is_listed_in_discovery,
          membership_policy, invite_policy, rules_text, word_filters, owner_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`, [
                communityId,
                d.name.trim(),
                d.slug.toLowerCase().trim(),
                (d.description || '').trim(),
                d.iconUrl ?? null,
                d.bannerUrl ?? null,
                d.accentColor || '#8B5CF6',
                JSON.stringify(d.categories || ['General']),
                JSON.stringify(d.tags || []),
                d.primaryLanguage || 'en',
                d.visibility || 'public',
                d.isListedInDiscovery ?? true,
                d.membershipPolicy || 'open',
                d.invitePolicy || 'everyone',
                d.rulesText ||
                    '1. Treat every member with respect.\n2. Credit artists when sharing artwork or reference sheets.\n3. No harassment, impersonation, or spam.',
                JSON.stringify(d.wordFilters || []),
                authUser.id,
            ]);
            // Insert membership for creator
            await tx.query(`INSERT INTO community_memberships (id, community_id, user_id) VALUES ($1, $2, $3)`, [crypto.randomUUID(), communityId, authUser.id]);
            // Create all 9 default roles
            let ownerRoleId = '';
            for (const tpl of DEFAULT_COMMUNITY_ROLES) {
                const rId = crypto.randomUUID();
                if (tpl.slug === 'owner')
                    ownerRoleId = rId;
                await tx.query(`INSERT INTO roles (
            id, community_id, name, slug, color, position, is_default, is_system, permissions, deny_permissions
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, [
                    rId,
                    communityId,
                    tpl.name,
                    tpl.slug,
                    tpl.color,
                    tpl.position,
                    tpl.isDefault,
                    tpl.isSystem,
                    JSON.stringify(tpl.permissions),
                    JSON.stringify(tpl.denyPermissions),
                ]);
            }
            if (ownerRoleId) {
                await tx.query(`INSERT INTO role_assignments (id, community_id, user_id, role_id) VALUES ($1, $2, $3, $4)`, [crypto.randomUUID(), communityId, authUser.id, ownerRoleId]);
            }
            // Create default channels
            const defaultChannels = [
                {
                    name: 'announcements',
                    topic: 'Official community updates and announcements.',
                    categoryName: 'Information',
                    type: 'announcement',
                    position: 10,
                    isPrivate: false,
                    isAnnouncement: true,
                },
                {
                    name: 'introductions',
                    topic: 'Introduce yourself, your interests, or your fursona!',
                    categoryName: 'Information',
                    type: 'introductions',
                    position: 20,
                    isPrivate: false,
                    isAnnouncement: false,
                },
                {
                    name: 'general',
                    topic: 'Main community hangout and daily conversation.',
                    categoryName: 'Community Spaces',
                    type: 'text',
                    position: 30,
                    isPrivate: false,
                    isAnnouncement: false,
                },
                {
                    name: 'art-gallery',
                    topic: 'Share original artwork, reference sheets, and commission openings.',
                    categoryName: 'Creative & Media',
                    type: 'art_gallery',
                    position: 40,
                    isPrivate: false,
                    isAnnouncement: false,
                },
                {
                    name: 'gaming-and-dev',
                    topic: 'Co-op sessions, game nights, and programming projects.',
                    categoryName: 'Community Spaces',
                    type: 'text',
                    position: 50,
                    isPrivate: false,
                    isAnnouncement: false,
                },
                {
                    name: 'staff-lounge',
                    topic: 'Private coordination channel for moderators and community managers.',
                    categoryName: 'Staff Only',
                    type: 'staff',
                    position: 60,
                    isPrivate: true,
                    isAnnouncement: false,
                },
                {
                    name: 'General Lounge',
                    topic: 'Voice, video, and screen sharing lounge.',
                    categoryName: 'Voice Channels',
                    type: 'voice',
                    position: 70,
                    isPrivate: false,
                    isAnnouncement: false,
                },
            ];
            for (const ch of defaultChannels) {
                await tx.query(`INSERT INTO channels (
            id, community_id, name, slug, topic, category_name, type, position, is_private, is_announcement
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, [
                    crypto.randomUUID(),
                    communityId,
                    ch.name,
                    formatSlug(ch.name),
                    ch.topic,
                    ch.categoryName,
                    ch.type,
                    ch.position,
                    ch.isPrivate,
                    ch.isAnnouncement,
                ]);
            }
            await recordAuditLog({
                communityId,
                actorId: authUser.id,
                eventType: 'COMMUNITY_CREATED',
                targetType: 'community',
                targetId: communityId,
                summary: `Created community "${d.name.trim()}" (${d.slug}).`,
                tx,
            });
        });
        const rowRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        const community = await mapCommunityRow(rowRes.rows[0], db);
        return reply.code(201).send({ community });
    });
    // Get full community details, channels visible to member, roles, members, and effective permissions
    app.get('/api/communities/:communityId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const db = getDb();
        const commRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        if (!commRes.rows[0]) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (memberState.isBanned) {
            return reply.code(403).send({ error: 'You are banned from this community.' });
        }
        if (!memberState.isMember) {
            return reply.code(403).send({ error: 'You must be a member to access this community.' });
        }
        const community = await mapCommunityRow(commRes.rows[0], db);
        // Fetch channels and filter by per-channel VIEW_CHANNELS permission
        const chanRes = await db.query(`SELECT * FROM channels WHERE community_id = $1 ORDER BY position ASC, created_at ASC`, [communityId]);
        const visibleChannels = [];
        for (const chRow of chanRes.rows) {
            const chId = String(chRow.id);
            const chEval = await getMemberPermissionsAndRoles(communityId, authUser.id, chId);
            if (!chEval.permissions.has(PERMISSIONS.VIEW_CHANNELS)) {
                continue;
            }
            const ovRes = await db.query(`SELECT * FROM permission_overrides WHERE channel_id = $1`, [chId]);
            visibleChannels.push({
                id: chId,
                communityId,
                name: String(chRow.name),
                slug: String(chRow.slug),
                topic: String(chRow.topic || ''),
                categoryName: String(chRow.category_name || 'Text Channels'),
                type: chRow.type || 'text',
                position: Number(chRow.position || 0),
                isPrivate: Boolean(chRow.is_private),
                isAnnouncement: Boolean(chRow.is_announcement),
                isArchived: Boolean(chRow.is_archived),
                slowmodeSeconds: Number(chRow.slowmode_seconds || 0),
                createdAt: new Date(String(chRow.created_at)).toISOString(),
                updatedAt: new Date(String(chRow.updated_at)).toISOString(),
                overrides: ovRes.rows.map((o) => ({
                    id: String(o.id),
                    channelId: String(o.channel_id),
                    targetType: o.target_type,
                    targetId: String(o.target_id),
                    allow: Array.isArray(o.allow_permissions) ? o.allow_permissions : [],
                    deny: Array.isArray(o.deny_permissions) ? o.deny_permissions : [],
                })),
            });
        }
        // Fetch all roles
        const rolesRes = await db.query(`SELECT * FROM roles WHERE community_id = $1 ORDER BY position DESC`, [communityId]);
        const roles = rolesRes.rows.map((r) => ({
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
        const roleById = new Map(roles.map((r) => [r.id, r]));
        // Fetch members and their role assignments
        const membersRes = await db.query(`SELECT
           cm.id,
           cm.community_id,
           cm.user_id,
           cm.nickname,
           cm.timeout_until,
           cm.joined_at,
           u.username,
           p.display_name,
           p.avatar_url,
           p.pronouns,
           p.presence_status,
           p.custom_status_text,
           p.furry_title,
           p.badge_ids
         FROM community_memberships cm
         JOIN users u ON u.id = cm.user_id
         JOIN profiles p ON p.user_id = cm.user_id
         WHERE cm.community_id = $1 AND u.is_deleted = FALSE
         ORDER BY p.display_name ASC`, [communityId]);
        const assignRes = await db.query(`SELECT user_id, role_id FROM role_assignments WHERE community_id = $1`, [communityId]);
        const rolesByUser = new Map();
        for (const a of assignRes.rows) {
            const role = roleById.get(a.role_id);
            if (!role)
                continue;
            const list = rolesByUser.get(a.user_id) ?? [];
            list.push(role);
            rolesByUser.set(a.user_id, list);
        }
        const members = membersRes.rows.map((m) => {
            const uid = String(m.user_id);
            const userRoles = (rolesByUser.get(uid) ?? []).sort((a, b) => b.position - a.position);
            return {
                id: String(m.id),
                communityId: String(m.community_id),
                userId: uid,
                nickname: m.nickname ? String(m.nickname) : null,
                joinedAt: new Date(String(m.joined_at)).toISOString(),
                timeoutUntil: m.timeout_until ? new Date(String(m.timeout_until)).toISOString() : null,
                roles: userRoles,
                user: {
                    id: uid,
                    username: String(m.username),
                    displayName: String(m.display_name),
                    avatarUrl: m.avatar_url ? String(m.avatar_url) : null,
                    pronouns: String(m.pronouns || ''),
                    presenceStatus: m.presence_status || 'online',
                    customStatusText: String(m.custom_status_text || ''),
                    furryTitle: m.furry_title ? String(m.furry_title) : null,
                    badgeIds: Array.isArray(m.badge_ids) ? m.badge_ids : [],
                },
            };
        });
        // Voice states for voice channels in this community
        const voiceStatesByChannel = {};
        for (const ch of visibleChannels) {
            if (ch.type === 'voice') {
                voiceStatesByChannel[ch.id] = realtimeHub.getVoiceParticipants(ch.id);
            }
        }
        return reply.send({
            community,
            channels: visibleChannels,
            roles,
            members,
            myPermissions: Array.from(memberState.permissions),
            myTimeoutUntil: memberState.timeoutUntil,
            voiceStatesByChannel,
        });
    });
    // Update community settings
    app.patch('/api/communities/:communityId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_COMMUNITY)) {
            return reply.code(403).send({ error: 'Missing MANAGE_COMMUNITY permission.' });
        }
        const parsed = CreateCommunitySchema.partial().safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid community update fields.' });
        }
        const db = getDb();
        const existingRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        const existing = existingRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        const d = parsed.data;
        await db.query(`UPDATE communities
         SET name = $1,
             description = $2,
             icon_url = $3,
             banner_url = $4,
             accent_color = $5,
             categories = $6,
             tags = $7,
             primary_language = $8,
             visibility = $9,
             is_listed_in_discovery = $10,
             membership_policy = $11,
             invite_policy = $12,
             rules_text = $13,
             word_filters = $14,
             updated_at = NOW()
         WHERE id = $15`, [
            d.name !== undefined ? d.name.trim() : existing.name,
            d.description !== undefined ? d.description.trim() : existing.description,
            d.iconUrl !== undefined ? d.iconUrl : existing.icon_url,
            d.bannerUrl !== undefined ? d.bannerUrl : existing.banner_url,
            d.accentColor !== undefined ? d.accentColor : existing.accent_color,
            JSON.stringify(d.categories !== undefined ? d.categories : existing.categories),
            JSON.stringify(d.tags !== undefined ? d.tags : existing.tags),
            d.primaryLanguage !== undefined ? d.primaryLanguage : existing.primary_language,
            d.visibility !== undefined ? d.visibility : existing.visibility,
            d.isListedInDiscovery !== undefined
                ? d.isListedInDiscovery
                : existing.is_listed_in_discovery,
            d.membershipPolicy !== undefined ? d.membershipPolicy : existing.membership_policy,
            d.invitePolicy !== undefined ? d.invitePolicy : existing.invite_policy,
            d.rulesText !== undefined ? d.rulesText : existing.rules_text,
            JSON.stringify(d.wordFilters !== undefined ? d.wordFilters : existing.word_filters),
            communityId,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'COMMUNITY_UPDATED',
            targetType: 'community',
            targetId: communityId,
            summary: `Updated community configuration and rules.`,
        });
        const updatedRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        return reply.send({ community: await mapCommunityRow(updatedRes.rows[0], db) });
    });
    // Transfer community ownership (Owner only)
    app.post('/api/communities/:communityId/transfer-ownership', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const body = z
            .object({
            newOwnerUserId: z.string().uuid(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid newOwnerUserId is required.' });
        }
        const db = getDb();
        const commRes = await db.query(`SELECT id, name, owner_id FROM communities WHERE id = $1`, [communityId]);
        const comm = commRes.rows[0];
        if (!comm) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        if (comm.owner_id !== authUser.id) {
            return reply.code(403).send({ error: 'Only the current community owner can transfer ownership.' });
        }
        const targetUserId = body.data.newOwnerUserId;
        if (targetUserId === authUser.id) {
            return reply.code(400).send({ error: 'You are already the owner of this community.' });
        }
        const memberCheck = await db.query(`SELECT id FROM community_memberships WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
        if (!memberCheck.rows[0]) {
            return reply.code(400).send({ error: 'New owner must already be a member of this community.' });
        }
        await db.transaction(async (tx) => {
            await tx.query(`UPDATE communities SET owner_id = $1, updated_at = NOW() WHERE id = $2`, [targetUserId, communityId]);
            const ownerRoleRes = await tx.query(`SELECT id FROM roles WHERE community_id = $1 AND slug = 'owner' LIMIT 1`, [communityId]);
            const ownerRoleId = ownerRoleRes.rows[0]?.id;
            if (ownerRoleId) {
                await tx.query(`DELETE FROM role_assignments WHERE community_id = $1 AND user_id = $2 AND role_id = $3`, [communityId, authUser.id, ownerRoleId]);
                await tx.query(`INSERT INTO role_assignments (id, community_id, user_id, role_id)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (community_id, user_id, role_id) DO NOTHING`, [crypto.randomUUID(), communityId, targetUserId, ownerRoleId]);
            }
            await recordAuditLog({
                communityId,
                actorId: authUser.id,
                eventType: 'COMMUNITY_OWNERSHIP_TRANSFERRED',
                targetType: 'user',
                targetId: targetUserId,
                summary: `Transferred community ownership to user ${targetUserId}.`,
                tx,
            });
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MEMBER_UPDATED',
            payload: { communityId, userId: targetUserId },
        });
        const updatedRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        return reply.send({
            transferred: true,
            community: await mapCommunityRow(updatedRes.rows[0], db),
        });
    });
    // Delete community (Owner only)
    app.delete('/api/communities/:communityId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const db = getDb();
        const commRes = await db.query(`SELECT id, owner_id FROM communities WHERE id = $1`, [communityId]);
        const comm = commRes.rows[0];
        if (!comm) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        if (comm.owner_id !== authUser.id) {
            return reply.code(403).send({ error: 'Only the community owner can delete a community.' });
        }
        await db.query(`DELETE FROM communities WHERE id = $1`, [communityId]);
        return reply.send({ deleted: true });
    });
    // Join a public community directly
    app.post('/api/communities/:communityId/join', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const db = getDb();
        const commRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        const comm = commRes.rows[0];
        if (!comm) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        const state = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (state.isBanned) {
            return reply.code(403).send({ error: 'You are banned from joining this community.' });
        }
        if (state.isMember) {
            return reply.send({ joined: true, community: await mapCommunityRow(comm, db) });
        }
        if (comm.visibility === 'private' || comm.membership_policy === 'invite_only') {
            return reply
                .code(403)
                .send({ error: 'This community requires a valid invitation code to join.' });
        }
        await db.transaction(async (tx) => {
            await tx.query(`INSERT INTO community_memberships (id, community_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [crypto.randomUUID(), communityId, authUser.id]);
            const defRole = await tx.query(`SELECT id FROM roles WHERE community_id = $1 AND is_default = TRUE LIMIT 1`, [communityId]);
            if (defRole.rows[0]) {
                await tx.query(`INSERT INTO role_assignments (id, community_id, user_id, role_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, [crypto.randomUUID(), communityId, authUser.id, defRole.rows[0].id]);
            }
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MEMBER_UPDATED',
            payload: { communityId, userId: authUser.id },
        });
        return reply.send({ joined: true, community: await mapCommunityRow(comm, db) });
    });
    // Leave community
    app.post('/api/communities/:communityId/leave', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const db = getDb();
        const commRes = await db.query(`SELECT owner_id FROM communities WHERE id = $1`, [communityId]);
        if (!commRes.rows[0]) {
            return reply.code(404).send({ error: 'Community not found.' });
        }
        if (commRes.rows[0].owner_id === authUser.id) {
            return reply.code(400).send({ error: 'Community owner cannot leave without transferring ownership.' });
        }
        await db.transaction(async (tx) => {
            await tx.query(`DELETE FROM role_assignments WHERE community_id = $1 AND user_id = $2`, [communityId, authUser.id]);
            await tx.query(`DELETE FROM community_memberships WHERE community_id = $1 AND user_id = $2`, [communityId, authUser.id]);
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MEMBER_UPDATED',
            payload: { communityId, userId: authUser.id },
        });
        return reply.send({ left: true });
    });
    // Create channel
    app.post('/api/communities/:communityId/channels', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_CHANNELS)) {
            return reply.code(403).send({ error: 'Missing MANAGE_CHANNELS permission.' });
        }
        const parsed = ChannelInputSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid channel parameters.' });
        }
        const d = parsed.data;
        const db = getDb();
        const channelId = crypto.randomUUID();
        const isAnnouncement = d.isAnnouncement ?? d.type === 'announcement';
        const isPrivate = d.isPrivate ?? d.type === 'staff';
        await db.query(`INSERT INTO channels (
          id, community_id, name, slug, topic, category_name, type, position,
          is_private, is_announcement, is_archived, slowmode_seconds
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, [
            channelId,
            communityId,
            d.name.trim(),
            formatSlug(d.name),
            (d.topic || '').trim(),
            (d.categoryName || 'Text Channels').trim(),
            d.type || 'text',
            d.position ?? 100,
            isPrivate,
            isAnnouncement,
            Boolean(d.isArchived),
            d.slowmodeSeconds ?? 0,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'CHANNEL_CREATED',
            targetType: 'channel',
            targetId: channelId,
            summary: `Created channel #${d.name.trim()}.`,
        });
        const chRes = await db.query(`SELECT * FROM channels WHERE id = $1`, [channelId]);
        const chRow = chRes.rows[0];
        const channel = {
            id: channelId,
            communityId,
            name: String(chRow.name),
            slug: String(chRow.slug),
            topic: String(chRow.topic || ''),
            categoryName: String(chRow.category_name),
            type: chRow.type,
            position: Number(chRow.position),
            isPrivate: Boolean(chRow.is_private),
            isAnnouncement: Boolean(chRow.is_announcement),
            isArchived: Boolean(chRow.is_archived),
            slowmodeSeconds: Number(chRow.slowmode_seconds),
            createdAt: new Date(String(chRow.created_at)).toISOString(),
            updatedAt: new Date(String(chRow.updated_at)).toISOString(),
            overrides: [],
        };
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'CHANNEL_UPDATED',
            payload: { communityId, channel },
        });
        return reply.code(201).send({ channel });
    });
    // Update channel (rename, reorder, archive, privacy, topic)
    app.patch('/api/communities/:communityId/channels/:channelId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, channelId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_CHANNELS)) {
            return reply.code(403).send({ error: 'Missing MANAGE_CHANNELS permission.' });
        }
        const parsed = ChannelInputSchema.partial().safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid channel update parameters.' });
        }
        const db = getDb();
        const existingRes = await db.query(`SELECT * FROM channels WHERE id = $1 AND community_id = $2`, [channelId, communityId]);
        const existing = existingRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Channel not found.' });
        }
        const d = parsed.data;
        const nextName = d.name !== undefined ? d.name.trim() : String(existing.name);
        await db.query(`UPDATE channels
         SET name = $1,
             slug = $2,
             topic = $3,
             category_name = $4,
             type = $5,
             position = $6,
             is_private = $7,
             is_announcement = $8,
             is_archived = $9,
             slowmode_seconds = $10,
             updated_at = NOW()
         WHERE id = $11 AND community_id = $12`, [
            nextName,
            formatSlug(nextName),
            d.topic !== undefined ? d.topic.trim() : existing.topic,
            d.categoryName !== undefined ? d.categoryName.trim() : existing.category_name,
            d.type !== undefined ? d.type : existing.type,
            d.position !== undefined ? d.position : existing.position,
            d.isPrivate !== undefined ? d.isPrivate : existing.is_private,
            d.isAnnouncement !== undefined ? d.isAnnouncement : existing.is_announcement,
            d.isArchived !== undefined ? d.isArchived : existing.is_archived,
            d.slowmodeSeconds !== undefined ? d.slowmodeSeconds : existing.slowmode_seconds,
            channelId,
            communityId,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'CHANNEL_UPDATED',
            targetType: 'channel',
            targetId: channelId,
            summary: `Updated channel #${nextName}.`,
        });
        const chRes = await db.query(`SELECT * FROM channels WHERE id = $1`, [channelId]);
        const chRow = chRes.rows[0];
        const channel = {
            id: channelId,
            communityId,
            name: String(chRow.name),
            slug: String(chRow.slug),
            topic: String(chRow.topic || ''),
            categoryName: String(chRow.category_name),
            type: chRow.type,
            position: Number(chRow.position),
            isPrivate: Boolean(chRow.is_private),
            isAnnouncement: Boolean(chRow.is_announcement),
            isArchived: Boolean(chRow.is_archived),
            slowmodeSeconds: Number(chRow.slowmode_seconds),
            createdAt: new Date(String(chRow.created_at)).toISOString(),
            updatedAt: new Date(String(chRow.updated_at)).toISOString(),
        };
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'CHANNEL_UPDATED',
            payload: { communityId, channel },
        });
        return reply.send({ channel });
    });
    // Delete channel
    app.delete('/api/communities/:communityId/channels/:channelId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, channelId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_CHANNELS)) {
            return reply.code(403).send({ error: 'Missing MANAGE_CHANNELS permission.' });
        }
        const db = getDb();
        await db.query(`DELETE FROM channels WHERE id = $1 AND community_id = $2`, [
            channelId,
            communityId,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'CHANNEL_DELETED',
            targetType: 'channel',
            targetId: channelId,
            summary: `Deleted channel (${channelId}).`,
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'CHANNEL_DELETED',
            payload: { communityId, channelId },
        });
        return reply.send({ deleted: true });
    });
    // Set channel permission override for role or user
    app.put('/api/communities/:communityId/channels/:channelId/overrides', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, channelId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_CHANNELS)) {
            return reply.code(403).send({ error: 'Missing MANAGE_CHANNELS permission.' });
        }
        const body = z
            .object({
            targetType: z.enum(['role', 'user']),
            targetId: z.string().uuid(),
            allow: z.array(z.string()),
            deny: z.array(z.string()),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid channel override payload.' });
        }
        const allowValid = body.data.allow.filter((p) => ALL_PERMISSIONS.includes(p));
        const denyValid = body.data.deny.filter((p) => ALL_PERMISSIONS.includes(p));
        // Prevent granting a permission the actor does not possess
        for (const p of allowValid) {
            if (!memberState.permissions.has(p)) {
                return reply.code(403).send({
                    error: `Cannot grant channel override permission ${p} that you do not possess.`,
                });
            }
        }
        const db = getDb();
        await db.query(`INSERT INTO permission_overrides (id, channel_id, target_type, target_id, allow_permissions, deny_permissions)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (channel_id, target_type, target_id)
         DO UPDATE SET allow_permissions = EXCLUDED.allow_permissions, deny_permissions = EXCLUDED.deny_permissions`, [
            crypto.randomUUID(),
            channelId,
            body.data.targetType,
            body.data.targetId,
            JSON.stringify(allowValid),
            JSON.stringify(denyValid),
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'CHANNEL_OVERRIDE_UPDATED',
            targetType: 'channel',
            targetId: channelId,
            summary: `Updated channel permission overrides for ${body.data.targetType} ${body.data.targetId}.`,
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'ROLE_UPDATED',
            payload: { communityId },
        });
        return reply.send({ updated: true });
    });
    // Create custom role
    app.post('/api/communities/:communityId/roles', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_ROLES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_ROLES permission.' });
        }
        const body = z
            .object({
            name: z.string().min(1).max(64),
            color: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
            position: z.number().int().min(1).max(899).optional(),
            permissions: z.array(z.string()).optional(),
            denyPermissions: z.array(z.string()).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid role definition.' });
        }
        const requestedPerms = (body.data.permissions || []).filter((p) => ALL_PERMISSIONS.includes(p));
        const requestedDeny = (body.data.denyPermissions || []).filter((p) => ALL_PERMISSIONS.includes(p));
        const targetPos = body.data.position ?? 250;
        if (!canActorManageTargetRole(authUser.id, memberState.communityOwnerId, memberState.assignedRoles, targetPos, requestedPerms)) {
            return reply.code(403).send({
                error: 'Privilege escalation prevented: cannot create a role at or above your highest role position or grant permissions you lack.',
            });
        }
        const db = getDb();
        const roleId = crypto.randomUUID();
        const slug = `${formatSlug(body.data.name)}-${roleId.slice(0, 4)}`;
        await db.query(`INSERT INTO roles (
          id, community_id, name, slug, color, position, is_default, is_system, permissions, deny_permissions
        ) VALUES ($1, $2, $3, $4, $5, $6, FALSE, FALSE, $7, $8)`, [
            roleId,
            communityId,
            body.data.name.trim(),
            slug,
            body.data.color || '#C4B5FD',
            targetPos,
            JSON.stringify(requestedPerms),
            JSON.stringify(requestedDeny),
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'ROLE_CREATED',
            targetType: 'role',
            targetId: roleId,
            summary: `Created role "${body.data.name.trim()}".`,
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'ROLE_UPDATED',
            payload: { communityId },
        });
        return reply.code(201).send({
            role: {
                id: roleId,
                communityId,
                name: body.data.name.trim(),
                slug,
                color: body.data.color || '#C4B5FD',
                position: targetPos,
                isDefault: false,
                isSystem: false,
                permissions: requestedPerms,
                denyPermissions: requestedDeny,
            },
        });
    });
    // Update role permissions, name, color, or position
    app.patch('/api/communities/:communityId/roles/:roleId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, roleId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_ROLES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_ROLES permission.' });
        }
        const db = getDb();
        const roleRes = await db.query(`SELECT * FROM roles WHERE id = $1 AND community_id = $2`, [roleId, communityId]);
        const existing = roleRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Role not found.' });
        }
        const body = z
            .object({
            name: z.string().min(1).max(64).optional(),
            color: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
            position: z.number().int().min(1).max(899).optional(),
            permissions: z.array(z.string()).optional(),
            denyPermissions: z.array(z.string()).optional(),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Invalid role update fields.' });
        }
        const nextPerms = body.data.permissions !== undefined
            ? body.data.permissions.filter((p) => ALL_PERMISSIONS.includes(p))
            : existing.permissions;
        const nextDeny = body.data.denyPermissions !== undefined
            ? body.data.denyPermissions.filter((p) => ALL_PERMISSIONS.includes(p))
            : existing.deny_permissions;
        const nextPos = body.data.position !== undefined ? body.data.position : Number(existing.position);
        if (!canActorManageTargetRole(authUser.id, memberState.communityOwnerId, memberState.assignedRoles, Math.max(Number(existing.position), nextPos), nextPerms)) {
            return reply.code(403).send({
                error: 'Privilege escalation prevented: cannot modify a role at or above your highest role position or grant permissions you lack.',
            });
        }
        await db.query(`UPDATE roles
         SET name = $1,
             color = $2,
             position = $3,
             permissions = $4,
             deny_permissions = $5
         WHERE id = $6 AND community_id = $7`, [
            body.data.name !== undefined ? body.data.name.trim() : existing.name,
            body.data.color !== undefined ? body.data.color : existing.color,
            nextPos,
            JSON.stringify(nextPerms),
            JSON.stringify(nextDeny),
            roleId,
            communityId,
        ]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'ROLE_UPDATED',
            targetType: 'role',
            targetId: roleId,
            summary: `Updated permissions/settings for role "${body.data.name !== undefined ? body.data.name.trim() : String(existing.name)}".`,
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'ROLE_UPDATED',
            payload: { communityId },
        });
        return reply.send({
            role: {
                id: roleId,
                communityId,
                name: body.data.name !== undefined ? body.data.name.trim() : String(existing.name),
                slug: String(existing.slug),
                color: body.data.color !== undefined ? body.data.color : String(existing.color),
                position: nextPos,
                isDefault: Boolean(existing.is_default),
                isSystem: Boolean(existing.is_system),
                permissions: nextPerms,
                denyPermissions: nextDeny,
            },
        });
    });
    // Delete custom role
    app.delete('/api/communities/:communityId/roles/:roleId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, roleId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_ROLES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_ROLES permission.' });
        }
        const db = getDb();
        const roleRes = await db.query(`SELECT * FROM roles WHERE id = $1 AND community_id = $2`, [roleId, communityId]);
        const existing = roleRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Role not found.' });
        }
        if (existing.is_system || existing.is_default) {
            return reply.code(400).send({ error: 'Default system roles cannot be deleted.' });
        }
        if (!canActorManageTargetRole(authUser.id, memberState.communityOwnerId, memberState.assignedRoles, Number(existing.position))) {
            return reply.code(403).send({ error: 'Cannot delete a role at or above your position.' });
        }
        await db.query(`DELETE FROM roles WHERE id = $1 AND community_id = $2`, [roleId, communityId]);
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'ROLE_UPDATED',
            payload: { communityId },
        });
        return reply.send({ deleted: true });
    });
    // Assign / update a member's roles with hierarchy protection
    app.put('/api/communities/:communityId/members/:targetUserId/roles', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, targetUserId } = request.params;
        const actorState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!actorState.permissions.has(PERMISSIONS.MANAGE_ROLES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_ROLES permission.' });
        }
        const body = z
            .object({
            roleIds: z.array(z.string().uuid()),
        })
            .safeParse(request.body);
        if (!body.success) {
            return reply.code(400).send({ error: 'Valid roleIds array required.' });
        }
        const db = getDb();
        const allRolesRes = await db.query(`SELECT * FROM roles WHERE community_id = $1`, [communityId]);
        const roleMap = new Map();
        for (const r of allRolesRes.rows) {
            roleMap.set(String(r.id), {
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
            });
        }
        const actorMaxPos = getHighestRolePosition(authUser.id, actorState.communityOwnerId, actorState.assignedRoles);
        // Verify actor can manage all newly added/removed roles
        const targetState = await getMemberPermissionsAndRoles(communityId, targetUserId);
        const currentRoleIds = new Set(targetState.assignedRoles.map((r) => r.id));
        const nextRoleIds = new Set(body.data.roleIds);
        for (const rid of new Set([...currentRoleIds, ...nextRoleIds])) {
            const changed = currentRoleIds.has(rid) !== nextRoleIds.has(rid);
            if (!changed)
                continue;
            const role = roleMap.get(rid);
            if (!role) {
                return reply.code(400).send({ error: 'Invalid role ID for this community.' });
            }
            if (authUser.id !== actorState.communityOwnerId && role.position >= actorMaxPos) {
                return reply.code(403).send({
                    error: `Privilege escalation prevented: cannot assign or revoke role "${role.name}" at or above your highest role position.`,
                });
            }
        }
        await db.transaction(async (tx) => {
            await tx.query(`DELETE FROM role_assignments WHERE community_id = $1 AND user_id = $2`, [communityId, targetUserId]);
            for (const rid of nextRoleIds) {
                await tx.query(`INSERT INTO role_assignments (id, community_id, user_id, role_id) VALUES ($1, $2, $3, $4)`, [crypto.randomUUID(), communityId, targetUserId, rid]);
            }
        });
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'MEMBER_ROLES_UPDATED',
            targetType: 'user',
            targetId: targetUserId,
            summary: `Updated assigned roles for member ${targetUserId}.`,
        });
        await realtimeHub.broadcastToCommunity(communityId, {
            type: 'MEMBER_UPDATED',
            payload: { communityId, userId: targetUserId },
        });
        return reply.send({ updated: true });
    });
    // Create community invitation
    app.post('/api/communities/:communityId/invites', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.isMember) {
            return reply.code(403).send({ error: 'Only members can create invitations.' });
        }
        const db = getDb();
        const commRes = await db.query(`SELECT invite_policy FROM communities WHERE id = $1`, [communityId]);
        const invitePolicy = commRes.rows[0]?.invite_policy || 'everyone';
        if (invitePolicy === 'admins_only' &&
            !memberState.permissions.has(PERMISSIONS.MANAGE_COMMUNITY)) {
            return reply.code(403).send({ error: 'Only administrators can create invitations in this community.' });
        }
        if (invitePolicy !== 'everyone' &&
            !memberState.permissions.has(PERMISSIONS.MANAGE_INVITES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_INVITES permission.' });
        }
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_INVITES)) {
            return reply.code(403).send({ error: 'Your role does not permit creating invitations.' });
        }
        const body = z
            .object({
            maxUses: z.number().int().min(1).max(1000).nullable().optional(),
            expiresInHours: z.number().int().min(1).max(720).nullable().optional(),
        })
            .safeParse(request.body || {});
        const maxUses = body.success ? body.data.maxUses ?? null : null;
        const expiresAt = body.success && body.data.expiresInHours
            ? new Date(Date.now() + body.data.expiresInHours * 3600 * 1000).toISOString()
            : null;
        const inviteId = crypto.randomUUID();
        const code = crypto.randomBytes(5).toString('hex');
        await db.query(`INSERT INTO invitations (id, community_id, code, creator_id, max_uses, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`, [inviteId, communityId, code, authUser.id, maxUses, expiresAt]);
        await recordAuditLog({
            communityId,
            actorId: authUser.id,
            eventType: 'INVITE_CREATED',
            targetType: 'invitation',
            targetId: inviteId,
            summary: `Created invitation code ${code}.`,
        });
        return reply.code(201).send({
            invitation: {
                id: inviteId,
                communityId,
                code,
                creatorId: authUser.id,
                creatorUsername: authUser.username,
                maxUses,
                usesCount: 0,
                expiresAt,
                isRevoked: false,
                createdAt: new Date().toISOString(),
            },
        });
    });
    // List community invitations
    app.get('/api/communities/:communityId/invites', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_INVITES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_INVITES permission.' });
        }
        const db = getDb();
        const res = await db.query(`SELECT i.*, u.username AS creator_username
         FROM invitations i
         JOIN users u ON u.id = i.creator_id
         WHERE i.community_id = $1 AND i.is_revoked = FALSE
         ORDER BY i.created_at DESC`, [communityId]);
        return reply.send({
            invitations: res.rows.map((r) => ({
                id: String(r.id),
                communityId: String(r.community_id),
                code: String(r.code),
                creatorId: String(r.creator_id),
                creatorUsername: String(r.creator_username),
                maxUses: r.max_uses ? Number(r.max_uses) : null,
                usesCount: Number(r.uses_count),
                expiresAt: r.expires_at ? new Date(String(r.expires_at)).toISOString() : null,
                isRevoked: Boolean(r.is_revoked),
                createdAt: new Date(String(r.created_at)).toISOString(),
            })),
        });
    });
    // Revoke invitation
    app.delete('/api/communities/:communityId/invites/:inviteId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { communityId, inviteId } = request.params;
        const memberState = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (!memberState.permissions.has(PERMISSIONS.MANAGE_INVITES)) {
            return reply.code(403).send({ error: 'Missing MANAGE_INVITES permission.' });
        }
        const db = getDb();
        await db.query(`UPDATE invitations SET is_revoked = TRUE WHERE id = $1 AND community_id = $2`, [inviteId, communityId]);
        return reply.send({ revoked: true });
    });
    // Accept invitation code
    app.post('/api/invites/:code/accept', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { code } = request.params;
        const db = getDb();
        const invRes = await db.query(`SELECT * FROM invitations WHERE code = $1 AND is_revoked = FALSE`, [code.trim()]);
        const inv = invRes.rows[0];
        if (!inv) {
            return reply.code(404).send({ error: 'Invalid or revoked invitation code.' });
        }
        if (inv.expires_at && new Date(String(inv.expires_at)).getTime() <= Date.now()) {
            return reply.code(410).send({ error: 'This invitation has expired.' });
        }
        if (inv.max_uses && Number(inv.uses_count) >= Number(inv.max_uses)) {
            return reply.code(410).send({ error: 'This invitation has reached its maximum number of uses.' });
        }
        const communityId = String(inv.community_id);
        const state = await getMemberPermissionsAndRoles(communityId, authUser.id);
        if (state.isBanned) {
            return reply.code(403).send({ error: 'You are banned from this community.' });
        }
        if (!state.isMember) {
            await db.transaction(async (tx) => {
                await tx.query(`INSERT INTO community_memberships (id, community_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [crypto.randomUUID(), communityId, authUser.id]);
                const defRole = await tx.query(`SELECT id FROM roles WHERE community_id = $1 AND is_default = TRUE LIMIT 1`, [communityId]);
                if (defRole.rows[0]) {
                    await tx.query(`INSERT INTO role_assignments (id, community_id, user_id, role_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, [crypto.randomUUID(), communityId, authUser.id, defRole.rows[0].id]);
                }
                await tx.query(`UPDATE invitations SET uses_count = uses_count + 1 WHERE id = $1`, [inv.id]);
            });
            await realtimeHub.broadcastToCommunity(communityId, {
                type: 'MEMBER_UPDATED',
                payload: { communityId, userId: authUser.id },
            });
        }
        const commRes = await db.query(`SELECT * FROM communities WHERE id = $1`, [communityId]);
        return reply.send({
            joined: true,
            community: await mapCommunityRow(commRes.rows[0], db),
        });
    });
}
