import { getDb } from '../db/client.js';
class RealtimeHub {
    clientsByUser = new Map();
    voiceChannelParticipants = new Map();
    registerClient(client) {
        let set = this.clientsByUser.get(client.userId);
        if (!set) {
            set = new Set();
            this.clientsByUser.set(client.userId, set);
        }
        set.add(client);
        this.sendToSocket(client.ws, {
            type: 'CONNECTED',
            payload: {
                userId: client.userId,
                serverTime: new Date().toISOString(),
            },
        });
    }
    async unregisterClient(client) {
        const set = this.clientsByUser.get(client.userId);
        if (set) {
            set.delete(client);
            if (set.size === 0) {
                this.clientsByUser.delete(client.userId);
                // Clean up any active voice channel participation on full disconnect
                await this.leaveAllVoiceChannels(client.userId);
                // Update last_active_at in database
                try {
                    const db = getDb();
                    await db.query(`UPDATE profiles SET last_active_at = NOW() WHERE user_id = $1`, [client.userId]);
                }
                catch {
                    // Ignore DB closed during test teardown
                }
            }
        }
    }
    isUserConnected(userId) {
        const set = this.clientsByUser.get(userId);
        return Boolean(set && set.size > 0);
    }
    getConnectedUserIds() {
        return Array.from(this.clientsByUser.keys());
    }
    sendToSocket(ws, event) {
        if (ws.readyState === 1) {
            ws.send(JSON.stringify(event));
        }
    }
    sendToUser(userId, event) {
        const set = this.clientsByUser.get(userId);
        if (!set)
            return;
        const payload = JSON.stringify(event);
        for (const client of set) {
            if (client.ws.readyState === 1) {
                client.ws.send(payload);
            }
        }
    }
    sendToUsers(userIds, event) {
        const seen = new Set();
        for (const uid of userIds) {
            if (seen.has(uid))
                continue;
            seen.add(uid);
            this.sendToUser(uid, event);
        }
    }
    async broadcastToCommunity(communityId, event) {
        const db = getDb();
        const res = await db.query(`SELECT user_id FROM community_memberships WHERE community_id = $1`, [communityId]);
        this.sendToUsers(res.rows.map((r) => r.user_id), event);
    }
    broadcastAll(event) {
        const payload = JSON.stringify(event);
        for (const set of this.clientsByUser.values()) {
            for (const client of set) {
                if (client.ws.readyState === 1) {
                    client.ws.send(payload);
                }
            }
        }
    }
    // Voice & Video Room Management + WebRTC Signaling
    getVoiceParticipants(channelId) {
        const room = this.voiceChannelParticipants.get(channelId);
        if (!room)
            return [];
        return Array.from(room.values());
    }
    async joinVoiceChannel(state) {
        // Remove user from any other voice channel first
        await this.leaveAllVoiceChannels(state.userId);
        let room = this.voiceChannelParticipants.get(state.channelId);
        if (!room) {
            room = new Map();
            this.voiceChannelParticipants.set(state.channelId, room);
        }
        room.set(state.userId, state);
        const participants = Array.from(room.values());
        await this.broadcastToCommunity(state.communityId, {
            type: 'VOICE_STATE_SYNC',
            payload: {
                channelId: state.channelId,
                communityId: state.communityId,
                participants,
            },
        });
        return participants;
    }
    async updateVoiceParticipant(channelId, userId, updates) {
        const room = this.voiceChannelParticipants.get(channelId);
        if (!room)
            return null;
        const existing = room.get(userId);
        if (!existing)
            return null;
        const updated = {
            ...existing,
            ...updates,
        };
        room.set(userId, updated);
        const participants = Array.from(room.values());
        await this.broadcastToCommunity(existing.communityId, {
            type: 'VOICE_STATE_SYNC',
            payload: {
                channelId,
                communityId: existing.communityId,
                participants,
            },
        });
        return participants;
    }
    async leaveVoiceChannel(channelId, userId) {
        const room = this.voiceChannelParticipants.get(channelId);
        if (!room)
            return;
        const existing = room.get(userId);
        if (!existing)
            return;
        room.delete(userId);
        if (room.size === 0) {
            this.voiceChannelParticipants.delete(channelId);
        }
        const participants = Array.from(room.values());
        await this.broadcastToCommunity(existing.communityId, {
            type: 'VOICE_STATE_SYNC',
            payload: {
                channelId,
                communityId: existing.communityId,
                participants,
            },
        });
    }
    async leaveAllVoiceChannels(userId) {
        for (const [channelId, room] of this.voiceChannelParticipants.entries()) {
            if (room.has(userId)) {
                await this.leaveVoiceChannel(channelId, userId);
            }
        }
    }
    relayWebRtcSignal(fromUserId, toUserId, channelId, signalType, data) {
        this.sendToUser(toUserId, {
            type: 'WEBRTC_SIGNAL',
            payload: {
                fromUserId,
                toUserId,
                channelId,
                signalType,
                data,
            },
        });
    }
}
export const realtimeHub = new RealtimeHub();
