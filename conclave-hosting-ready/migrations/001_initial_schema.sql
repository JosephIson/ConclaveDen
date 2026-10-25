-- Conclave PostgreSQL Schema Migration 001
-- Conventional, normalized human-to-human communication platform database schema.
-- Strictly zero AI tables, embeddings, or model analytics.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(128) PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 1. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username VARCHAR(32) NOT NULL UNIQUE,
  normalized_username VARCHAR(32) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  normalized_email VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  email_verification_token TEXT,
  password_reset_token TEXT,
  password_reset_expires_at TIMESTAMPTZ,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret TEXT,
  recovery_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  onboarding_completed BOOLEAN NOT NULL DEFAULT FALSE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_normalized_username ON users(normalized_username);
CREATE INDEX IF NOT EXISTS idx_users_normalized_email ON users(normalized_email);

-- 2. External Auth Identities (Optional OAuth)
CREATE TABLE IF NOT EXISTS auth_identities (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(64) NOT NULL,
  provider_user_id VARCHAR(255) NOT NULL,
  provider_username VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_user_id)
);

-- 3. Sessions
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(128) NOT NULL UNIQUE,
  user_agent TEXT NOT NULL DEFAULT '',
  ip_address VARCHAR(64) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

-- 4. Profiles
CREATE TABLE IF NOT EXISTS profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  display_name VARCHAR(64) NOT NULL,
  avatar_url TEXT,
  banner_url TEXT,
  accent_color VARCHAR(16) NOT NULL DEFAULT '#8B5CF6',
  profile_gradient VARCHAR(64),
  badge_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  bio TEXT NOT NULL DEFAULT '',
  pronouns VARCHAR(64) NOT NULL DEFAULT '',
  interests JSONB NOT NULL DEFAULT '[]'::jsonb,
  favorite_games JSONB NOT NULL DEFAULT '[]'::jsonb,
  social_links JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_furry_identity_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  furry_title VARCHAR(80),
  presence_status VARCHAR(16) NOT NULL DEFAULT 'online',
  custom_status_text VARCHAR(128) NOT NULL DEFAULT '',
  last_active_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Fursona Profiles (Optional Furry-Friendly Feature)
CREATE TABLE IF NOT EXISTS fursonas (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(64) NOT NULL,
  species VARCHAR(80) NOT NULL,
  pronouns VARCHAR(64) NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  colors JSONB NOT NULL DEFAULT '[]'::jsonb,
  traits JSONB NOT NULL DEFAULT '[]'::jsonb,
  avatar_url TEXT,
  ref_sheet_url TEXT,
  artist_credit_name VARCHAR(120),
  artist_credit_url TEXT,
  portfolio_url TEXT,
  commission_status VARCHAR(32) NOT NULL DEFAULT 'not_applicable',
  commission_info TEXT,
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fursonas_user_id ON fursonas(user_id);

-- 6. User Preferences & Privacy Controls
CREATE TABLE IF NOT EXISTS user_preferences (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  theme VARCHAR(32) NOT NULL DEFAULT 'dark',
  reduced_motion BOOLEAN NOT NULL DEFAULT FALSE,
  high_contrast BOOLEAN NOT NULL DEFAULT FALSE,
  font_scale VARCHAR(8) NOT NULL DEFAULT 'md',
  compact_messages BOOLEAN NOT NULL DEFAULT FALSE,
  allow_direct_messages_from VARCHAR(32) NOT NULL DEFAULT 'everyone',
  allow_friend_requests_from VARCHAR(32) NOT NULL DEFAULT 'everyone',
  show_online_status BOOLEAN NOT NULL DEFAULT TRUE,
  show_last_active BOOLEAN NOT NULL DEFAULT TRUE,
  show_shared_communities BOOLEAN NOT NULL DEFAULT TRUE,
  send_read_receipts BOOLEAN NOT NULL DEFAULT TRUE,
  discoverable_by_search BOOLEAN NOT NULL DEFAULT TRUE,
  do_not_disturb BOOLEAN NOT NULL DEFAULT FALSE,
  notify_on_direct_messages BOOLEAN NOT NULL DEFAULT TRUE,
  notify_on_mentions BOOLEAN NOT NULL DEFAULT TRUE,
  notify_on_replies BOOLEAN NOT NULL DEFAULT TRUE,
  notify_on_friend_requests BOOLEAN NOT NULL DEFAULT TRUE,
  notify_on_announcements BOOLEAN NOT NULL DEFAULT TRUE,
  mature_content_filter VARCHAR(32) NOT NULL DEFAULT 'blur_with_warning',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Friend Relationships
CREATE TABLE IF NOT EXISTS friend_relationships (
  id UUID PRIMARY KEY,
  requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  addressee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(16) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(requester_id, addressee_id),
  CHECK (requester_id <> addressee_id)
);

CREATE INDEX IF NOT EXISTS idx_friends_requester ON friend_relationships(requester_id, status);
CREATE INDEX IF NOT EXISTS idx_friends_addressee ON friend_relationships(addressee_id, status);

-- 8. Blocks
CREATE TABLE IF NOT EXISTS blocks (
  id UUID PRIMARY KEY,
  blocker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(blocker_id, blocked_user_id),
  CHECK (blocker_id <> blocked_user_id)
);

CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks(blocker_id);
CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_user_id);

-- 9. Communities
CREATE TABLE IF NOT EXISTS communities (
  id UUID PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  slug VARCHAR(64) NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  icon_url TEXT,
  banner_url TEXT,
  accent_color VARCHAR(16) NOT NULL DEFAULT '#8B5CF6',
  categories JSONB NOT NULL DEFAULT '[]'::jsonb,
  tags JSONB NOT NULL DEFAULT '[]'::jsonb,
  primary_language VARCHAR(16) NOT NULL DEFAULT 'en',
  visibility VARCHAR(16) NOT NULL DEFAULT 'public',
  is_listed_in_discovery BOOLEAN NOT NULL DEFAULT TRUE,
  membership_policy VARCHAR(24) NOT NULL DEFAULT 'open',
  invite_policy VARCHAR(24) NOT NULL DEFAULT 'everyone',
  rules_text TEXT NOT NULL DEFAULT '',
  word_filters JSONB NOT NULL DEFAULT '[]'::jsonb,
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_communities_slug ON communities(slug);
CREATE INDEX IF NOT EXISTS idx_communities_discovery ON communities(visibility, is_listed_in_discovery);

-- 10. Community Memberships
CREATE TABLE IF NOT EXISTS community_memberships (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nickname VARCHAR(64),
  timeout_until TIMESTAMPTZ,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(community_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_community_memberships_community ON community_memberships(community_id);
CREATE INDEX IF NOT EXISTS idx_community_memberships_user ON community_memberships(user_id);

-- 11. Community Bans
CREATE TABLE IF NOT EXISTS community_bans (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(community_id, user_id)
);

-- 12. Roles
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  name VARCHAR(64) NOT NULL,
  slug VARCHAR(64) NOT NULL,
  color VARCHAR(16) NOT NULL DEFAULT '#A7ADBF',
  position INTEGER NOT NULL DEFAULT 100,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  deny_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(community_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_roles_community ON roles(community_id, position DESC);

-- 13. Role Assignments
CREATE TABLE IF NOT EXISTS role_assignments (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(community_id, user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_member ON role_assignments(community_id, user_id);

-- 14. Channels
CREATE TABLE IF NOT EXISTS channels (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  name VARCHAR(64) NOT NULL,
  slug VARCHAR(64) NOT NULL,
  topic TEXT NOT NULL DEFAULT '',
  category_name VARCHAR(64) NOT NULL DEFAULT 'Text Channels',
  type VARCHAR(32) NOT NULL DEFAULT 'text',
  position INTEGER NOT NULL DEFAULT 0,
  is_private BOOLEAN NOT NULL DEFAULT FALSE,
  is_announcement BOOLEAN NOT NULL DEFAULT FALSE,
  is_archived BOOLEAN NOT NULL DEFAULT FALSE,
  slowmode_seconds INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_channels_community ON channels(community_id, position ASC);

-- 15. Permission Overrides (Channel-specific role or user overrides)
CREATE TABLE IF NOT EXISTS permission_overrides (
  id UUID PRIMARY KEY,
  channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  target_type VARCHAR(16) NOT NULL CHECK (target_type IN ('role', 'user')),
  target_id UUID NOT NULL,
  allow_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  deny_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(channel_id, target_type, target_id)
);

CREATE INDEX IF NOT EXISTS idx_permission_overrides_channel ON permission_overrides(channel_id);

-- 16. Channel Memberships & Read State (for private channels and unread indicators)
CREATE TABLE IF NOT EXISTS channel_memberships (
  id UUID PRIMARY KEY,
  channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_read_message_id UUID,
  last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_muted BOOLEAN NOT NULL DEFAULT FALSE,
  notify_preference VARCHAR(24) NOT NULL DEFAULT 'all',
  UNIQUE(channel_id, user_id)
);

-- 17. Direct Message Conversations
CREATE TABLE IF NOT EXISTS dm_conversations (
  id UUID PRIMARY KEY,
  participant_one_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  participant_two_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  participant_one_last_read_id UUID,
  participant_two_last_read_id UUID,
  participant_one_muted BOOLEAN NOT NULL DEFAULT FALSE,
  participant_two_muted BOOLEAN NOT NULL DEFAULT FALSE,
  last_message_at TIMESTAMPTZ,
  last_message_preview TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(participant_one_id, participant_two_id)
);

CREATE INDEX IF NOT EXISTS idx_dm_participant_one ON dm_conversations(participant_one_id);
CREATE INDEX IF NOT EXISTS idx_dm_participant_two ON dm_conversations(participant_two_id);

-- 18. Messages
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY,
  channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
  dm_conversation_id UUID REFERENCES dm_conversations(id) ON DELETE CASCADE,
  sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL DEFAULT '',
  reply_to_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
  client_nonce VARCHAR(128),
  link_previews JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_edited BOOLEAN NOT NULL DEFAULT FALSE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  edited_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (channel_id IS NOT NULL AND dm_conversation_id IS NULL) OR
    (channel_id IS NULL AND dm_conversation_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_dm_created ON messages(dm_conversation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender_nonce ON messages(sender_id, client_nonce);

-- 19. Message Edit History
CREATE TABLE IF NOT EXISTS message_edit_history (
  id UUID PRIMARY KEY,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  previous_content TEXT NOT NULL,
  edited_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_message_edit_history_msg ON message_edit_history(message_id, edited_at DESC);

-- 20. Reactions
CREATE TABLE IF NOT EXISTS reactions (
  id UUID PRIMARY KEY,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  emoji VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id);

-- 21. Attachments
CREATE TABLE IF NOT EXISTS attachments (
  id UUID PRIMARY KEY,
  message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
  uploader_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_name VARCHAR(255) NOT NULL,
  stored_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(128) NOT NULL,
  size_bytes INTEGER NOT NULL,
  url TEXT NOT NULL,
  thumbnail_url TEXT,
  width INTEGER,
  height INTEGER,
  artwork_meta JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);

-- 22. Invitations
CREATE TABLE IF NOT EXISTS invitations (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  code VARCHAR(32) NOT NULL UNIQUE,
  creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  max_uses INTEGER,
  uses_count INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(code);
CREATE INDEX IF NOT EXISTS idx_invitations_community ON invitations(community_id);

-- 23. Reports (User, Message, Community, Artwork Theft, Impersonation)
CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY,
  community_id UUID REFERENCES communities(id) ON DELETE CASCADE,
  reporter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type VARCHAR(32) NOT NULL,
  target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  target_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
  category VARCHAR(64) NOT NULL,
  reason TEXT NOT NULL,
  evidence_urls JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'open',
  resolution_notes TEXT,
  resolved_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_reports_community_status ON reports(community_id, status);

-- 24. Moderation Actions & Appeals
CREATE TABLE IF NOT EXISTS moderation_actions (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action_type VARCHAR(32) NOT NULL,
  reason TEXT NOT NULL,
  duration_seconds INTEGER,
  appeal_status VARCHAR(32) NOT NULL DEFAULT 'none',
  appeal_text TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_moderation_actions_community ON moderation_actions(community_id, created_at DESC);

-- 25. Notifications & Per-Community Notification Preferences
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(32) NOT NULL,
  title VARCHAR(160) NOT NULL,
  body TEXT NOT NULL,
  community_id UUID REFERENCES communities(id) ON DELETE CASCADE,
  channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
  dm_conversation_id UUID REFERENCES dm_conversations(id) ON DELETE CASCADE,
  message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
  actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications(user_id, is_read, created_at DESC);

CREATE TABLE IF NOT EXISTS community_notification_prefs (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  is_muted BOOLEAN NOT NULL DEFAULT FALSE,
  notify_level VARCHAR(24) NOT NULL DEFAULT 'all',
  suppress_everyone BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE(user_id, community_id)
);

-- 26. Saved Messages / Bookmarks
CREATE TABLE IF NOT EXISTS saved_messages (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  folder_name VARCHAR(64) NOT NULL DEFAULT 'General',
  note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_saved_messages_user ON saved_messages(user_id, created_at DESC);

-- 27. Voice Session Metadata
CREATE TABLE IF NOT EXISTS voice_session_metadata (
  id UUID PRIMARY KEY,
  channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_muted BOOLEAN NOT NULL DEFAULT FALSE,
  is_deafened BOOLEAN NOT NULL DEFAULT FALSE,
  is_server_muted BOOLEAN NOT NULL DEFAULT FALSE,
  is_camera_on BOOLEAN NOT NULL DEFAULT FALSE,
  is_screen_sharing BOOLEAN NOT NULL DEFAULT FALSE,
  connection_quality VARCHAR(24) NOT NULL DEFAULT 'good',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(channel_id, user_id)
);

-- 28. Audit Events
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY,
  community_id UUID REFERENCES communities(id) ON DELETE CASCADE,
  actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_type VARCHAR(64) NOT NULL,
  target_type VARCHAR(64) NOT NULL,
  target_id VARCHAR(128) NOT NULL,
  summary TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_community ON audit_events(community_id, created_at DESC);

-- 29. Webhooks & Integrations
CREATE TABLE IF NOT EXISTS webhooks (
  id UUID PRIMARY KEY,
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(80) NOT NULL,
  token VARCHAR(128) NOT NULL UNIQUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
