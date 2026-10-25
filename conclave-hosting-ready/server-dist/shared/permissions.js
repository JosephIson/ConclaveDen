export const PERMISSIONS = {
    VIEW_CHANNELS: 'VIEW_CHANNELS',
    SEND_MESSAGES: 'SEND_MESSAGES',
    MANAGE_MESSAGES: 'MANAGE_MESSAGES',
    UPLOAD_FILES: 'UPLOAD_FILES',
    MANAGE_CHANNELS: 'MANAGE_CHANNELS',
    MANAGE_ROLES: 'MANAGE_ROLES',
    MANAGE_INVITES: 'MANAGE_INVITES',
    KICK_MEMBERS: 'KICK_MEMBERS',
    BAN_MEMBERS: 'BAN_MEMBERS',
    MANAGE_COMMUNITY: 'MANAGE_COMMUNITY',
    VIEW_AUDIT_LOG: 'VIEW_AUDIT_LOG',
    MANAGE_INTEGRATIONS: 'MANAGE_INTEGRATIONS',
    VOICE_CONNECT: 'VOICE_CONNECT',
    VOICE_SPEAK: 'VOICE_SPEAK',
    VOICE_MUTE_MEMBERS: 'VOICE_MUTE_MEMBERS',
};
export const ALL_PERMISSIONS = Object.values(PERMISSIONS);
export const DEFAULT_COMMUNITY_ROLES = [
    {
        name: 'Owner',
        slug: 'owner',
        color: '#F5B94C',
        position: 900,
        isDefault: false,
        isSystem: true,
        permissions: [...ALL_PERMISSIONS],
        denyPermissions: [],
    },
    {
        name: 'Administrator',
        slug: 'administrator',
        color: '#8B5CF6',
        position: 800,
        isDefault: false,
        isSystem: true,
        permissions: [...ALL_PERMISSIONS],
        denyPermissions: [],
    },
    {
        name: 'Community Manager',
        slug: 'community-manager',
        color: '#35D9FF',
        position: 700,
        isDefault: false,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.MANAGE_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_CHANNELS,
            PERMISSIONS.MANAGE_ROLES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.KICK_MEMBERS,
            PERMISSIONS.MANAGE_COMMUNITY,
            PERMISSIONS.VIEW_AUDIT_LOG,
            PERMISSIONS.MANAGE_INTEGRATIONS,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
            PERMISSIONS.VOICE_MUTE_MEMBERS,
        ],
        denyPermissions: [],
    },
    {
        name: 'Moderator',
        slug: 'moderator',
        color: '#35D49A',
        position: 600,
        isDefault: false,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.MANAGE_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.KICK_MEMBERS,
            PERMISSIONS.BAN_MEMBERS,
            PERMISSIONS.VIEW_AUDIT_LOG,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
            PERMISSIONS.VOICE_MUTE_MEMBERS,
        ],
        denyPermissions: [],
    },
    {
        name: 'Verified Creator',
        slug: 'verified-creator',
        color: '#C4B5FD',
        position: 500,
        isDefault: false,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
        ],
        denyPermissions: [],
    },
    {
        name: 'Artist',
        slug: 'artist',
        color: '#F472B6',
        position: 400,
        isDefault: false,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
        ],
        denyPermissions: [],
    },
    {
        name: 'Member',
        slug: 'member',
        color: '#A7ADBF',
        position: 300,
        isDefault: true,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
        ],
        denyPermissions: [],
    },
    {
        name: 'New Member',
        slug: 'new-member',
        color: '#94A3B8',
        position: 200,
        isDefault: false,
        isSystem: true,
        permissions: [
            PERMISSIONS.VIEW_CHANNELS,
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.VOICE_CONNECT,
            PERMISSIONS.VOICE_SPEAK,
        ],
        denyPermissions: [],
    },
    {
        name: 'Restricted Member',
        slug: 'restricted-member',
        color: '#F87171',
        position: 100,
        isDefault: false,
        isSystem: true,
        permissions: [PERMISSIONS.VIEW_CHANNELS],
        denyPermissions: [
            PERMISSIONS.SEND_MESSAGES,
            PERMISSIONS.UPLOAD_FILES,
            PERMISSIONS.MANAGE_INVITES,
            PERMISSIONS.VOICE_SPEAK,
        ],
    },
];
/**
 * Deterministically computes effective permissions for a member in a community and optional channel.
 */
export function computeEffectivePermissions(input) {
    const { userId, communityOwnerId, assignedRoles, defaultRole, timeoutUntil, channel, channelOverrides = [], isChannelExplicitMember = false, } = input;
    // 1. Community Owner always has all permissions.
    if (userId === communityOwnerId) {
        return new Set(ALL_PERMISSIONS);
    }
    const sortedRoles = [...assignedRoles].sort((a, b) => a.position - b.position);
    if (sortedRoles.some((r) => r.slug === 'owner' || r.slug === 'administrator')) {
        return new Set(ALL_PERMISSIONS);
    }
    // 2. Start with default role permissions if present, then apply assigned roles in ascending position order.
    const effective = new Set();
    if (defaultRole && sortedRoles.length === 0) {
        for (const p of defaultRole.permissions) {
            effective.add(p);
        }
    }
    for (const role of sortedRoles) {
        for (const p of role.permissions) {
            effective.add(p);
        }
    }
    // Apply explicit role-level denyPermissions (e.g. Restricted Member role)
    for (const role of sortedRoles) {
        if (role.denyPermissions && role.denyPermissions.length > 0) {
            for (const d of role.denyPermissions) {
                effective.delete(d);
            }
        }
    }
    // 3. Channel-specific evaluation
    if (channel) {
        const roleIds = new Set(sortedRoles.map((r) => r.id));
        if (defaultRole)
            roleIds.add(defaultRole.id);
        // Private channel enforcement
        if (channel.isPrivate) {
            const canManageChannels = effective.has(PERMISSIONS.MANAGE_CHANNELS) ||
                effective.has(PERMISSIONS.MANAGE_COMMUNITY);
            const hasExplicitOverrideAllow = channelOverrides.some((ov) => ((ov.targetType === 'user' && ov.targetId === userId) ||
                (ov.targetType === 'role' && roleIds.has(ov.targetId))) &&
                ov.allow.includes(PERMISSIONS.VIEW_CHANNELS));
            if (!canManageChannels && !isChannelExplicitMember && !hasExplicitOverrideAllow) {
                effective.clear();
                return effective;
            }
        }
        // Apply role-targeted channel overrides
        for (const ov of channelOverrides) {
            if (ov.targetType === 'role' && roleIds.has(ov.targetId)) {
                for (const d of ov.deny)
                    effective.delete(d);
                for (const a of ov.allow)
                    effective.add(a);
            }
        }
        // Apply user-targeted channel overrides (highest specificity)
        for (const ov of channelOverrides) {
            if (ov.targetType === 'user' && ov.targetId === userId) {
                for (const d of ov.deny)
                    effective.delete(d);
                for (const a of ov.allow)
                    effective.add(a);
            }
        }
        // Read-only announcement channel enforcement
        if (channel.isAnnouncement) {
            const canPostAnnouncement = effective.has(PERMISSIONS.MANAGE_CHANNELS) ||
                effective.has(PERMISSIONS.MANAGE_COMMUNITY) ||
                effective.has(PERMISSIONS.MANAGE_MESSAGES);
            if (!canPostAnnouncement) {
                effective.delete(PERMISSIONS.SEND_MESSAGES);
            }
        }
        // Archived channel enforcement
        if (channel.isArchived) {
            effective.delete(PERMISSIONS.SEND_MESSAGES);
            effective.delete(PERMISSIONS.UPLOAD_FILES);
        }
        // If user cannot view the channel, they have no channel actions
        if (!effective.has(PERMISSIONS.VIEW_CHANNELS)) {
            effective.clear();
            return effective;
        }
    }
    // 4. Active timeout enforcement
    if (timeoutUntil) {
        const untilMs = new Date(timeoutUntil).getTime();
        if (!Number.isNaN(untilMs) && untilMs > Date.now()) {
            effective.delete(PERMISSIONS.SEND_MESSAGES);
            effective.delete(PERMISSIONS.UPLOAD_FILES);
            effective.delete(PERMISSIONS.VOICE_SPEAK);
            effective.delete(PERMISSIONS.MANAGE_INVITES);
        }
    }
    return effective;
}
export function getHighestRolePosition(userId, communityOwnerId, roles) {
    if (userId === communityOwnerId)
        return 1000;
    if (roles.length === 0)
        return 0;
    return Math.max(...roles.map((r) => r.position));
}
export function canActorManageTargetRole(actorUserId, communityOwnerId, actorRoles, targetRolePosition, requestedPermissions = []) {
    if (actorUserId === communityOwnerId)
        return true;
    const effective = computeEffectivePermissions({
        userId: actorUserId,
        communityOwnerId,
        assignedRoles: actorRoles,
    });
    if (!effective.has(PERMISSIONS.MANAGE_ROLES))
        return false;
    const actorMaxPos = getHighestRolePosition(actorUserId, communityOwnerId, actorRoles);
    if (targetRolePosition >= actorMaxPos)
        return false;
    // Actor cannot grant permissions they do not possess themselves
    for (const perm of requestedPermissions) {
        if (!effective.has(perm))
            return false;
    }
    return true;
}
export function canActorModerateMember(actorUserId, targetUserId, communityOwnerId, actorRoles, targetRoles, requiredPermission) {
    if (actorUserId === targetUserId)
        return false;
    if (targetUserId === communityOwnerId)
        return false;
    if (actorUserId === communityOwnerId)
        return true;
    const effective = computeEffectivePermissions({
        userId: actorUserId,
        communityOwnerId,
        assignedRoles: actorRoles,
    });
    if (!effective.has(requiredPermission))
        return false;
    const actorPos = getHighestRolePosition(actorUserId, communityOwnerId, actorRoles);
    const targetPos = getHighestRolePosition(targetUserId, communityOwnerId, targetRoles);
    return actorPos > targetPos;
}
