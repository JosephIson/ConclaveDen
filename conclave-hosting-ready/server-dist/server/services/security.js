import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scryptAsync = promisify(crypto.scrypt);
const SCRYPT_KEYLEN = 64;
/**
 * Hashes a plaintext password using memory-hard scrypt with a 16-byte random salt.
 * Never stores plaintext passwords.
 */
export async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = (await scryptAsync(password, salt, SCRYPT_KEYLEN));
    return `scrypt$${salt}$${derivedKey.toString('hex')}`;
}
/**
 * Verifies a plaintext password against a stored scrypt hash using constant-time comparison.
 */
export async function verifyPassword(password, storedHash) {
    const parts = storedHash.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') {
        return false;
    }
    const [, salt, keyHex] = parts;
    const expectedBuffer = Buffer.from(keyHex, 'hex');
    const derivedKey = (await scryptAsync(password, salt, SCRYPT_KEYLEN));
    if (expectedBuffer.length !== derivedKey.length) {
        return false;
    }
    return crypto.timingSafeEqual(expectedBuffer, derivedKey);
}
/**
 * Generates a high-entropy session token and its SHA-256 database hash.
 */
export function generateSessionToken() {
    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashSessionToken(rawToken);
    return { rawToken, tokenHash };
}
export function hashSessionToken(rawToken) {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
}
/**
 * Documented Username Normalization Policy:
 * 1. Unicode NFKC normalization
 * 2. Trim leading/trailing whitespace
 * 3. Lowercase ASCII characters
 * 4. Must match ^[a-z0-9_.-]{3,32}$
 */
export function normalizeUsername(username) {
    return username.normalize('NFKC').trim().toLowerCase();
}
export function isValidUsername(username) {
    const trimmed = username.trim();
    return /^[a-zA-Z0-9_.-]{3,32}$/.test(trimmed);
}
export function normalizeEmail(email) {
    return email.normalize('NFKC').trim().toLowerCase();
}
/**
 * Generates recovery codes and MFA secret for account security.
 */
export function generateMfaCredentials() {
    const secret = crypto.randomBytes(16).toString('hex').toUpperCase();
    const recoveryCodes = Array.from({ length: 8 }, () => `${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto
        .randomBytes(3)
        .toString('hex')
        .toUpperCase()}`);
    return { secret, recoveryCodes };
}
export function validateFileMagicBytes(buffer, originalName) {
    if (buffer.length < 4) {
        return {
            valid: false,
            detectedMime: 'application/octet-stream',
            extension: '',
            isImage: false,
            reason: 'File is empty or too small.',
        };
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (buffer.length >= 24 &&
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47) {
        const width = buffer.readUInt32BE(16);
        const height = buffer.readUInt32BE(20);
        return {
            valid: true,
            detectedMime: 'image/png',
            extension: '.png',
            isImage: true,
            width,
            height,
        };
    }
    // JPEG: FF D8 FF
    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
        return {
            valid: true,
            detectedMime: 'image/jpeg',
            extension: '.jpg',
            isImage: true,
        };
    }
    // GIF: 47 49 46 38 (GIF87a or GIF89a)
    if (buffer.length >= 10 &&
        buffer[0] === 0x47 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x38) {
        const width = buffer.readUInt16LE(6);
        const height = buffer.readUInt16LE(8);
        return {
            valid: true,
            detectedMime: 'image/gif',
            extension: '.gif',
            isImage: true,
            width,
            height,
        };
    }
    // WEBP: RIFF....WEBP
    if (buffer.length >= 16 &&
        buffer.toString('ascii', 0, 4) === 'RIFF' &&
        buffer.toString('ascii', 8, 12) === 'WEBP') {
        return {
            valid: true,
            detectedMime: 'image/webp',
            extension: '.webp',
            isImage: true,
        };
    }
    // PDF: %PDF-
    if (buffer.length >= 5 && buffer.toString('ascii', 0, 5) === '%PDF-') {
        return {
            valid: true,
            detectedMime: 'application/pdf',
            extension: '.pdf',
            isImage: false,
        };
    }
    // Plain text (.txt or .md) — verify no null bytes and no <script / <svg tags
    const ext = originalName.toLowerCase();
    if (ext.endsWith('.txt') || ext.endsWith('.md') || ext.endsWith('.json')) {
        const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
        if (sample.includes(0x00)) {
            return {
                valid: false,
                detectedMime: 'application/octet-stream',
                extension: '',
                isImage: false,
                reason: 'Binary content disguised as text.',
            };
        }
        const textSample = sample.toString('utf-8').toLowerCase();
        if (textSample.includes('<script') || textSample.includes('<svg') || textSample.includes('<!doctype html')) {
            return {
                valid: false,
                detectedMime: 'text/html',
                extension: '',
                isImage: false,
                reason: 'Executable HTML/SVG scripts are prohibited in attachments.',
            };
        }
        return {
            valid: true,
            detectedMime: 'text/plain',
            extension: ext.endsWith('.md') ? '.md' : '.txt',
            isImage: false,
        };
    }
    return {
        valid: false,
        detectedMime: 'application/octet-stream',
        extension: '',
        isImage: false,
        reason: 'Unsupported or unrecognized file signature. Allowed formats: PNG, JPEG, GIF, WEBP, PDF, TXT, MD.',
    };
}
/**
 * Sanitizes filenames to prevent path traversal and control characters.
 */
export function sanitizeFileName(fileName) {
    const base = fileName.replace(/^.*[\\/]/, '').replace(/[^\w.\- ()]/g, '_');
    return base.slice(0, 120) || 'attachment';
}
/**
 * SSRF-Safe Link Preview Extractor.
 * Extracts public HTTPS links from message text and rejects localhost, loopback, link-local,
 * and RFC1918 private network addresses so internal network resources can never be probed.
 */
export function extractSafeLinkPreviews(content) {
    const urlRegex = /https?:\/\/[^\s<>()"]+/gi;
    const matches = content.match(urlRegex) || [];
    const results = [];
    const seen = new Set();
    for (const rawUrl of matches.slice(0, 3)) {
        try {
            const parsed = new URL(rawUrl);
            if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
                continue;
            const host = parsed.hostname.toLowerCase();
            if (isInternalOrPrivateHost(host)) {
                continue;
            }
            const normalizedUrl = parsed.toString();
            if (seen.has(normalizedUrl))
                continue;
            seen.add(normalizedUrl);
            const pathParts = parsed.pathname.split('/').filter(Boolean);
            const readableSlug = pathParts.length > 0
                ? decodeURIComponent(pathParts[pathParts.length - 1]).replace(/[-_]/g, ' ')
                : parsed.hostname;
            results.push({
                url: normalizedUrl,
                domain: parsed.hostname,
                siteName: parsed.hostname.replace(/^www\./, ''),
                title: readableSlug.slice(0, 90) || parsed.hostname,
            });
        }
        catch {
            // Ignore malformed URLs
        }
    }
    return results;
}
export function isInternalOrPrivateHost(hostname) {
    const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (h === 'localhost' ||
        h.endsWith('.localhost') ||
        h.endsWith('.local') ||
        h.endsWith('.internal') ||
        h === '0.0.0.0' ||
        h === '::1' ||
        h.startsWith('127.') ||
        h.startsWith('10.') ||
        h.startsWith('192.168.') ||
        h.startsWith('169.254.') ||
        h.startsWith('fe80:') ||
        h.startsWith('fc00:') ||
        h.startsWith('fd00:')) {
        return true;
    }
    // Check 172.16.0.0/12
    const ipv4Parts = h.split('.');
    if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d+$/.test(p))) {
        const first = Number(ipv4Parts[0]);
        const second = Number(ipv4Parts[1]);
        if (first === 172 && second >= 16 && second <= 31) {
            return true;
        }
    }
    return false;
}
