import crypto from 'node:crypto';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { requireAuth } from '../middleware/auth.js';
import { getUserProfile, getUserPreferences, isBlockedBetween, } from '../services/domain.js';
import { normalizeUsername } from '../services/security.js';
import { realtimeHub } from '../services/realtime.js';
const UpdateProfileSchema = z.object({
    displayName: z.string().min(1).max(64).optional(),
    avatarUrl: z.string().max(1000).nullable().optional(),
    bannerUrl: z.string().max(1000).nullable().optional(),
    accentColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
    profileGradient: z.string().max(64).nullable().optional(),
    bio: z.string().max(1200).optional(),
    pronouns: z.string().max(64).optional(),
    interests: z.array(z.string().max(48)).max(20).optional(),
    favoriteGames: z.array(z.string().max(64)).max(20).optional(),
    socialLinks: z
        .array(z.object({
        platform: z.string().min(1).max(40),
        label: z.string().min(1).max(80),
        url: z.string().url().max(400),
    }))
        .max(10)
        .optional(),
    isFurryIdentityEnabled: z.boolean().optional(),
    furryTitle: z.string().max(80).nullable().optional(),
    presenceStatus: z.enum(['online', 'idle', 'busy', 'offline']).optional(),
    customStatusText: z.string().max(128).optional(),
    onboardingCompleted: z.boolean().optional(),
});
const UpdatePreferencesSchema = z.object({
    theme: z.enum(['dark', 'light', 'midnight-indigo', 'crimson-den', 'forest-canopy']).optional(),
    reducedMotion: z.boolean().optional(),
    highContrast: z.boolean().optional(),
    fontScale: z.enum(['sm', 'md', 'lg', 'xl']).optional(),
    compactMessages: z.boolean().optional(),
    allowDirectMessagesFrom: z.enum(['everyone', 'community_members', 'friends_only']).optional(),
    allowFriendRequestsFrom: z.enum(['everyone', 'community_members', 'nobody']).optional(),
    showOnlineStatus: z.boolean().optional(),
    showLastActive: z.boolean().optional(),
    showSharedCommunities: z.boolean().optional(),
    sendReadReceipts: z.boolean().optional(),
    discoverableBySearch: z.boolean().optional(),
    doNotDisturb: z.boolean().optional(),
    notifyOnDirectMessages: z.boolean().optional(),
    notifyOnMentions: z.boolean().optional(),
    notifyOnReplies: z.boolean().optional(),
    notifyOnFriendRequests: z.boolean().optional(),
    notifyOnAnnouncements: z.boolean().optional(),
    matureContentFilter: z.enum(['hide', 'blur_with_warning', 'show']).optional(),
});
const FursonaInputSchema = z.object({
    name: z.string().min(1).max(64),
    species: z.string().min(1).max(80),
    pronouns: z.string().max(64).optional(),
    description: z.string().max(2000).optional(),
    colors: z.array(z.string().regex(/^#[0-9a-fA-F]{6}$/)).max(12).optional(),
    traits: z
        .array(z.object({
        label: z.string().min(1).max(48),
        value: z.string().min(1).max(120),
    }))
        .max(16)
        .optional(),
    avatarUrl: z.string().max(1000).nullable().optional(),
    refSheetUrl: z.string().max(1000).nullable().optional(),
    artistCreditName: z.string().max(120).nullable().optional(),
    artistCreditUrl: z.string().max(500).nullable().optional(),
    portfolioUrl: z.string().max(500).nullable().optional(),
    commissionStatus: z.enum(['open', 'closed', 'ask', 'not_applicable']).optional(),
    commissionInfo: z.string().max(500).nullable().optional(),
    isPrimary: z.boolean().optional(),
});
export async function registerProfileRoutes(app) {
    app.get('/api/users/:usernameOrId', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { usernameOrId } = request.params;
        const db = getDb();
        const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(usernameOrId);
        const userRes = await db.query(isUuid
            ? `SELECT id FROM users WHERE id = $1 AND is_deleted = FALSE`
            : `SELECT id FROM users WHERE normalized_username = $1 AND is_deleted = FALSE`, [isUuid ? usernameOrId : normalizeUsername(usernameOrId)]);
        const targetId = userRes.rows[0]?.id;
        if (!targetId) {
            return reply.code(404).send({ error: 'User not found.' });
        }
        const blockInfo = await isBlockedBetween(authUser.id, targetId);
        const profile = await getUserProfile(targetId);
        if (!profile) {
            return reply.code(404).send({ error: 'Profile not found.' });
        }
        const targetPrefs = await getUserPreferences(targetId);
        // Apply target user's privacy preferences when viewed by someone else
        if (targetId !== authUser.id) {
            if (!targetPrefs.showOnlineStatus) {
                profile.presenceStatus = 'offline';
                profile.customStatusText = '';
            }
            if (!targetPrefs.showLastActive) {
                profile.lastActiveAt = null;
            }
        }
        let sharedCommunities = [];
        if (targetId === authUser.id || targetPrefs.showSharedCommunities) {
            const sharedRes = await db.query(`SELECT c.id, c.name, c.slug, c.icon_url
           FROM communities c
           JOIN community_memberships cm1 ON cm1.community_id = c.id AND cm1.user_id = $1
           JOIN community_memberships cm2 ON cm2.community_id = c.id AND cm2.user_id = $2
           ORDER BY c.name ASC`, [authUser.id, targetId]);
            sharedCommunities = sharedRes.rows.map((r) => ({
                id: r.id,
                name: r.name,
                slug: r.slug,
                iconUrl: r.icon_url,
            }));
        }
        return reply.send({
            profile,
            sharedCommunities,
            blockInfo,
        });
    });
    app.patch('/api/profile', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const parsed = UpdateProfileSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({
                error: 'Invalid profile fields.',
                details: parsed.error.flatten().fieldErrors,
            });
        }
        const data = parsed.data;
        const db = getDb();
        const existing = await getUserProfile(authUser.id);
        if (!existing) {
            return reply.code(404).send({ error: 'Profile not found.' });
        }
        await db.transaction(async (tx) => {
            if (data.onboardingCompleted !== undefined) {
                await tx.query(`UPDATE users SET onboarding_completed = $1, updated_at = NOW() WHERE id = $2`, [data.onboardingCompleted, authUser.id]);
            }
            await tx.query(`UPDATE profiles
         SET display_name = $1,
             avatar_url = $2,
             banner_url = $3,
             accent_color = $4,
             profile_gradient = $5,
             bio = $6,
             pronouns = $7,
             interests = $8,
             favorite_games = $9,
             social_links = $10,
             is_furry_identity_enabled = $11,
             furry_title = $12,
             presence_status = $13,
             custom_status_text = $14,
             updated_at = NOW()
         WHERE user_id = $15`, [
                data.displayName !== undefined ? data.displayName.trim() : existing.displayName,
                data.avatarUrl !== undefined ? data.avatarUrl : existing.avatarUrl,
                data.bannerUrl !== undefined ? data.bannerUrl : existing.bannerUrl,
                data.accentColor !== undefined ? data.accentColor : existing.accentColor,
                data.profileGradient !== undefined ? data.profileGradient : existing.profileGradient,
                data.bio !== undefined ? data.bio : existing.bio,
                data.pronouns !== undefined ? data.pronouns.trim() : existing.pronouns,
                JSON.stringify(data.interests !== undefined ? data.interests : existing.interests),
                JSON.stringify(data.favoriteGames !== undefined ? data.favoriteGames : existing.favoriteGames),
                JSON.stringify(data.socialLinks !== undefined ? data.socialLinks : existing.socialLinks),
                data.isFurryIdentityEnabled !== undefined
                    ? data.isFurryIdentityEnabled
                    : existing.isFurryIdentityEnabled,
                data.furryTitle !== undefined ? data.furryTitle : existing.furryTitle,
                data.presenceStatus !== undefined ? data.presenceStatus : existing.presenceStatus,
                data.customStatusText !== undefined ? data.customStatusText : existing.customStatusText,
                authUser.id,
            ]);
        });
        const updated = await getUserProfile(authUser.id);
        if (updated && (data.presenceStatus !== undefined || data.customStatusText !== undefined)) {
            realtimeHub.broadcastAll({
                type: 'PRESENCE_UPDATE',
                payload: {
                    userId: authUser.id,
                    status: updated.presenceStatus,
                    customStatusText: updated.customStatusText,
                },
            });
        }
        return reply.send({ profile: updated });
    });
    app.patch('/api/preferences', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const parsed = UpdatePreferencesSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({
                error: 'Invalid preference settings.',
                details: parsed.error.flatten().fieldErrors,
            });
        }
        const current = await getUserPreferences(authUser.id);
        const next = { ...current, ...parsed.data };
        const db = getDb();
        await db.query(`UPDATE user_preferences
       SET theme = $1,
           reduced_motion = $2,
           high_contrast = $3,
           font_scale = $4,
           compact_messages = $5,
           allow_direct_messages_from = $6,
           allow_friend_requests_from = $7,
           show_online_status = $8,
           show_last_active = $9,
           show_shared_communities = $10,
           send_read_receipts = $11,
           discoverable_by_search = $12,
           do_not_disturb = $13,
           notify_on_direct_messages = $14,
           notify_on_mentions = $15,
           notify_on_replies = $16,
           notify_on_friend_requests = $17,
           notify_on_announcements = $18,
           mature_content_filter = $19,
           updated_at = NOW()
       WHERE user_id = $20`, [
            next.theme,
            next.reducedMotion,
            next.highContrast,
            next.fontScale,
            next.compactMessages,
            next.allowDirectMessagesFrom,
            next.allowFriendRequestsFrom,
            next.showOnlineStatus,
            next.showLastActive,
            next.showSharedCommunities,
            next.sendReadReceipts,
            next.discoverableBySearch,
            next.doNotDisturb,
            next.notifyOnDirectMessages,
            next.notifyOnMentions,
            next.notifyOnReplies,
            next.notifyOnFriendRequests,
            next.notifyOnAnnouncements,
            next.matureContentFilter,
            authUser.id,
        ]);
        const preferences = await getUserPreferences(authUser.id);
        return reply.send({ preferences });
    });
    // Fursona Profile Endpoints (Optional Furry-Friendly Feature)
    app.post('/api/fursonas', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const parsed = FursonaInputSchema.safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({
                error: 'Invalid fursona profile data.',
                details: parsed.error.flatten().fieldErrors,
            });
        }
        const d = parsed.data;
        const db = getDb();
        const id = crypto.randomUUID();
        await db.transaction(async (tx) => {
            if (d.isPrimary) {
                await tx.query(`UPDATE fursonas SET is_primary = FALSE WHERE user_id = $1`, [authUser.id]);
            }
            await tx.query(`INSERT INTO fursonas (
          id, user_id, name, species, pronouns, description, colors, traits,
          avatar_url, ref_sheet_url, artist_credit_name, artist_credit_url,
          portfolio_url, commission_status, commission_info, is_primary
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`, [
                id,
                authUser.id,
                d.name.trim(),
                d.species.trim(),
                (d.pronouns || '').trim(),
                (d.description || '').trim(),
                JSON.stringify(d.colors || ['#8B5CF6', '#35D9FF']),
                JSON.stringify(d.traits || []),
                d.avatarUrl ?? null,
                d.refSheetUrl ?? null,
                d.artistCreditName ?? null,
                d.artistCreditUrl ?? null,
                d.portfolioUrl ?? null,
                d.commissionStatus || 'not_applicable',
                d.commissionInfo ?? null,
                Boolean(d.isPrimary),
            ]);
            await tx.query(`UPDATE profiles SET is_furry_identity_enabled = TRUE, updated_at = NOW() WHERE user_id = $1`, [authUser.id]);
        });
        const profile = await getUserProfile(authUser.id);
        return reply.code(201).send({ profile });
    });
    app.patch('/api/fursonas/:id', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const parsed = FursonaInputSchema.partial().safeParse(request.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: 'Invalid fursona update fields.' });
        }
        const db = getDb();
        const existingRes = await db.query(`SELECT * FROM fursonas WHERE id = $1 AND user_id = $2`, [id, authUser.id]);
        const existing = existingRes.rows[0];
        if (!existing) {
            return reply.code(404).send({ error: 'Fursona profile not found.' });
        }
        const d = parsed.data;
        await db.transaction(async (tx) => {
            if (d.isPrimary) {
                await tx.query(`UPDATE fursonas SET is_primary = FALSE WHERE user_id = $1`, [authUser.id]);
            }
            await tx.query(`UPDATE fursonas
         SET name = $1,
             species = $2,
             pronouns = $3,
             description = $4,
             colors = $5,
             traits = $6,
             avatar_url = $7,
             ref_sheet_url = $8,
             artist_credit_name = $9,
             artist_credit_url = $10,
             portfolio_url = $11,
             commission_status = $12,
             commission_info = $13,
             is_primary = $14,
             updated_at = NOW()
         WHERE id = $15 AND user_id = $16`, [
                d.name !== undefined ? d.name.trim() : existing.name,
                d.species !== undefined ? d.species.trim() : existing.species,
                d.pronouns !== undefined ? d.pronouns.trim() : existing.pronouns,
                d.description !== undefined ? d.description.trim() : existing.description,
                JSON.stringify(d.colors !== undefined ? d.colors : existing.colors),
                JSON.stringify(d.traits !== undefined ? d.traits : existing.traits),
                d.avatarUrl !== undefined ? d.avatarUrl : existing.avatar_url,
                d.refSheetUrl !== undefined ? d.refSheetUrl : existing.ref_sheet_url,
                d.artistCreditName !== undefined ? d.artistCreditName : existing.artist_credit_name,
                d.artistCreditUrl !== undefined ? d.artistCreditUrl : existing.artist_credit_url,
                d.portfolioUrl !== undefined ? d.portfolioUrl : existing.portfolio_url,
                d.commissionStatus !== undefined ? d.commissionStatus : existing.commission_status,
                d.commissionInfo !== undefined ? d.commissionInfo : existing.commission_info,
                d.isPrimary !== undefined ? d.isPrimary : existing.is_primary,
                id,
                authUser.id,
            ]);
        });
        const profile = await getUserProfile(authUser.id);
        return reply.send({ profile });
    });
    app.delete('/api/fursonas/:id', { preHandler: [requireAuth] }, async (request, reply) => {
        const authUser = request.authUser;
        const { id } = request.params;
        const db = getDb();
        await db.query(`DELETE FROM fursonas WHERE id = $1 AND user_id = $2`, [id, authUser.id]);
        const profile = await getUserProfile(authUser.id);
        return reply.send({ profile });
    });
}
