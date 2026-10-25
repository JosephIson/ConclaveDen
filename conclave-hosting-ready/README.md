# CONCLAVE

**Your community. Your identity. Your space.**

Conclave is a professional, human-centered, real-time messaging, community management, voice/video communication, and social networking platform built to compete with Discord while welcoming furry communities, artists, fursuit makers, gamers, developers, and general-interest organizations.

---

## 1. Strictly 100% AI-Free Runtime Guarantee

Conclave is engineered exclusively with conventional, deterministic software engineering:
- **Zero AI SDKs or Model APIs** in runtime dependencies (`npm run audit:no-ai`).
- **Zero AI Chatbots, Virtual Assistants, or Auto-Replies**.
- **Zero AI Moderation, Sentiment Scoring, or Behavioral Profiling** — all moderation is human-operated with explicit, deterministic word filters and rate limits.
- **Zero AI Artwork Generation or Model Training** — user-uploaded artwork and reference sheets are never analyzed, classified, or transmitted to external AI providers.
- **Zero Semantic Embeddings or Algorithmic Feeds** — community discovery and message search use standard indexed PostgreSQL queries and chronological ordering.

---

## 2. Directory Structure

```text
conclave/
├── migrations/
│   └── 001_initial_schema.sql          # Normalized PostgreSQL schema (29 tables + indexes)
├── public/
│   └── favicon.svg                     # Original Conclave geometric crest icon
├── scripts/
│   └── audit-no-ai.ts                  # Automated AI-exclusion audit script
├── src/
│   ├── shared/
│   │   ├── permissions.ts              # Deterministic permission & role hierarchy engine
│   │   └── types.ts                    # Shared TypeScript API & WebSocket contracts
│   ├── server/
│   │   ├── config.ts                   # Validated environment configuration
│   │   ├── app.ts                      # Fastify application & WebSocket (/ws) builder
│   │   ├── index.ts                    # Server entrypoint
│   │   ├── db/
│   │   │   ├── client.ts               # PostgreSQL (pg.Pool / persistent PGlite) adapter
│   │   │   ├── migrate.ts              # Idempotent SQL migration runner
│   │   │   └── seed.ts                 # Starter communities & test accounts seeder
│   │   ├── middleware/
│   │   │   └── auth.ts                 # Session token & HttpOnly cookie authentication
│   │   ├── services/
│   │   │   ├── domain.ts               # Audit logging, notifications, hydration, permissions
│   │   │   ├── ephemeral.ts            # Redis / TTL store for rate limits & spam protection
│   │   │   ├── realtime.ts             # WebSocket event hub & WebRTC signaling coordinator
│   │   │   └── security.ts             # scrypt hashing, magic-byte file validator, SSRF guard
│   │   └── routes/
│   │       ├── auth.ts                 # Registration, login, MFA, sessions, export, deletion
│   │       ├── profiles.ts             # User profiles, preferences, Fursona Studio CRUD
│   │       ├── communities.ts          # Communities, discovery, channels, roles, invites
│   │       ├── messages.ts             # Channel/DM messages, uploads, reactions, search, saved
│   │       └── socialAndModeration.ts  # Friends, blocks, reports, mod actions, audit, WebRTC
│   └── client/
│       ├── App.tsx                     # Responsive desktop & mobile application shell
│       ├── main.tsx                    # React 19 entrypoint
│       ├── index.css                   # Brand design tokens, themes, and accessibility rules
│       ├── lib/
│       │   └── api.ts                  # Typed REST & multipart XHR upload client
│       └── components/
│           ├── BrandPrimitives.tsx     # ConclaveLogo, AvatarWithPresence, ModalDialog, Badges
│           ├── AuthScreen.tsx          # Sign in, Registration, Password Reset, Seeded Switcher
│           ├── UserProfileModal.tsx    # Profile inspector, Fursona cards, DM/Friend/Block/Report
│           ├── MessageStreamAndComposer.tsx # Real-time chat, replies, edits, reactions, art uploads
│           ├── VoiceVideoStage.tsx     # WebRTC voice, video, screen share & device diagnostics
│           ├── CommunityAdminModal.tsx # Channels, Roles, Invites, Reports, Bans, Audit Log
│           ├── SettingsAndFursonaView.tsx # Profile, Fursona Studio, Themes, Privacy, Security
│           └── DiscoverySearchAndSavedViews.tsx # Discovery, Friends, Notifications, Search, Saved
├── tests/
│   ├── unit/
│   │   └── permissionsAndSecurity.test.ts
│   └── integration/
│       └── conclaveWorkflow.test.ts
├── docker-compose.yml                  # PostgreSQL 16 + Redis 7 production-ready compose stack
├── .env.example                        # Documented environment variables
└── package.json
```

---

## 3. Local Setup & Development Guide

### Prerequisites
- **Node.js** 20+ (tested on Node.js v24.14.0)
- **PostgreSQL 16+** & **Redis 7+** (Optional in local dev: when `DATABASE_URL` is omitted, Conclave automatically runs an embedded persistent PostgreSQL 16 engine on disk at `./data/pgdata` via `@electric-sql/pglite` so migrations and persistence work out of the box without external daemon setup).

### Quick Start
1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy `.env.example` to `.env` (optional for local development):
   ```bash
   cp .env.example .env
   ```
3. Run database migrations and seed initial communities:
   ```bash
   npm run db:migrate
   npm run db:seed
   ```
4. Start the development servers (Fastify API + WebSocket on `:4000`, Vite HMR frontend on `:5173`):
   ```bash
   npm run dev
   ```
   Or build and run the unified single-port production server on `http://127.0.0.1:4000`:
   ```bash
   npm run build
   npm start
   ```

### Seeded Accounts for Multi-Account Testing
- `@koda_fennec` / Password: `ConclavePass!2026` (Owner of *Starlight Den & Art Sanctuary*, Verified Artist)
- `@lyra_lynx` / Password: `ConclavePass!2026` (Moderator, Boreal Lynx Audio Crafter)
- `@milo_dev` / Password: `ConclavePass!2026` (Owner of *Conclave Builders & Co-Op Lounge*)

---

## 4. Verification & Testing Commands

```bash
# Strict TypeScript verification
npm run typecheck

# ESLint verification
npm run lint

# Automated AI-Exclusion Audit
npm run audit:no-ai

# Unit & 13-Step Multi-Account Integration Tests
npm test

# Production Bundle Build
npm run build
```

---

## 5. Production Deployment & External Credentials

For multi-node production deployments:
1. Launch PostgreSQL 16 and Redis 7 (e.g., `docker compose up -d`).
2. Configure `.env`:
   - `NODE_ENV=production`
   - `DATABASE_URL=postgresql://conclave:password@localhost:5432/conclave`
   - `REDIS_URL=redis://localhost:6379`
   - `SESSION_SECRET=<64-byte-cryptographic-random-hex>`
   - `COOKIE_SECURE=true`
   - `STUN_URLS=stun:stun.l.google.com:19302`
   - `TURN_URL=turn:turn.yourdomain.com:3478` (Required for reliable WebRTC relay across symmetric NATs)
   - `TURN_USERNAME=<turn-user>`
   - `TURN_CREDENTIAL=<turn-secret>`
3. Run `npm run db:migrate && npm run build && npm start`.
