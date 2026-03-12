// TOTAL FOOTY - COMPLETE BACKEND API V2
// Core functionality - Ready to deploy

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
require('dotenv').config();

// Nodemailer Gmail setup for password reset emails
const nodemailer = require('nodemailer');
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'totalfooty19@gmail.com',
        pass: process.env.GMAIL_APP_PASSWORD,
    },
});



// Push notifications are sent via the Expo Push API (https://exp.host/--/api/v2/push/send).
// The mobile app uses Expo's getExpoPushTokenAsync() which returns ExponentPushToken[...] tokens.
// These tokens only work with the Expo Push API — NOT with Firebase Admin directly.
// No extra packages needed: native fetch is available in Node >= 18 (enforced in package.json).

const app = express();
const PORT = process.env.PORT || 3000;

// FIX-054: Required for correct client IP on Render (behind load balancer)
app.set('trust proxy', 1);

// CORS MUST be first — before rate limiters, before helmet, before everything.
// If CORS comes after rate limiters, any 429 response has no CORS headers and
// the browser treats it as a CORS failure, blocking ALL subsequent requests.
const CORS_ORIGINS = ['https://totalfooty.co.uk', 'https://www.totalfooty.co.uk'];
app.use(cors({
    origin: CORS_ORIGINS,
    credentials: true,
    optionsSuccessStatus: 200, // Some browsers (IE11) choke on 204
}));
// Explicitly handle OPTIONS preflight for all routes so rate limiters never intercept it
app.options('*', cors({ origin: CORS_ORIGINS, credentials: true, optionsSuccessStatus: 200 }));

// FIX-011: Security headers — SEC-003: HSTS enabled, SEC-004: referrerPolicy added
const helmet = require('helmet');
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,       // 1 year
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.disable('x-powered-by');
app.use(cookieParser()); // CRIT-2: Parse httpOnly cookies on every request

// SEC-005: Enforce JSON Content-Type on all API responses
app.use('/api', (req, res, next) => {
    if (req.method === 'OPTIONS') return next(); // Don't override preflight Content-Type
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    next();
});

// FIX-010: Rate limiting on auth routes
const rateLimit = require('express-rate-limit');
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skip: (req) => req.method === 'OPTIONS', // Never rate-limit preflight requests
});
// SEC-001: Registration rate limit — prevents bulk account farming
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: { error: 'Too many accounts created. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
});
// SEC-002: Stricter limit for password reset to prevent token enumeration
const resetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many reset requests. Please try again in an hour.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', registerLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', resetLimiter);

// FIX-036: Global 500kb body limit (photo upload route overrides to 5mb below)
app.use((req, res, next) => {
    if (req.path === '/api/players/me/photo') return next();
    express.json({ limit: '500kb' })(req, res, next);
});
app.post('/api/players/me/photo', express.json({ limit: '5mb' }));

// FIX-055: No-cache headers on all API responses
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// SEC-007: CSRF — reject state-changing requests from unexpected origins
// CRIT-33: Use URL().origin for exact match — startsWith() was spoofable via https://totalfooty.co.uk.evil.com
const ALLOWED_ORIGINS = ['https://totalfooty.co.uk', 'https://www.totalfooty.co.uk'];
const csrfProtect = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const raw = req.headers['origin'] || req.headers['referer'] || '';
    let originToCheck = raw;
    try { originToCheck = new URL(raw).origin; } catch (_) { /* not a valid URL — block it */ }
    if (!ALLOWED_ORIGINS.includes(originToCheck)) {
        return res.status(403).json({ error: 'Request origin not permitted' });
    }
    next();
};
app.use('/api', csrfProtect);

// SEC-008: Audit log — tamper-evident record of privileged actions

// BST/DST helper: add N weeks to a game date while preserving wall-clock time in Europe/London.
// Standard Date.setDate() operates in UTC, so crossing a DST boundary shifts the stored hour by 1.
// This function extracts the London local hour/minute from the original date, adds weeks to the
// calendar date, then returns the UTC instant that gives the same wall-clock time in London.
// N2: Reject any social URL that doesn't start with https:// — prevents javascript: URI stored XSS
function validateSocialUrl(url) {
    if (!url) return null;
    const trimmed = String(url).trim();
    if (!trimmed.startsWith('https://')) return null;
    return trimmed;
}

// CRIT-8/10/15/N8: htmlEncode for user-supplied values inside HTML email bodies
function htmlEncode(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// wrapEmailHtml: consistent dark-theme email wrapper used by signup + topup emails
function wrapEmailHtml(inner) {
    return `<div style="background:#0d0d0d;padding:40px;font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
        <img src="https://totalfooty.co.uk/assets/logo.png" width="80" style="margin-bottom:24px"/>
        ${inner}
        <p style="color:#333;font-size:11px;margin-top:32px;letter-spacing:1px;">TOTALFOOTY — COVENTRY FOOTBALL COMMUNITY</p>
    </div>`;
}

function addWeeksLondon(isoDateStr, weeks) {
    const orig = new Date(isoDateStr);
    const fmt = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Europe/London',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false
    });
    const parts = fmt.formatToParts(orig);
    const get = (type) => parseInt(parts.find(p => p.type === type)?.value || '0');
    const year = get('year'), month = get('month'), day = get('day');
    const hour = get('hour'), minute = get('minute'), second = get('second');

    // Build target date: same wall-clock time but weeks * 7 days later (JS Date handles month overflow)
    const target = new Date(Date.UTC(year, month - 1, day + weeks * 7, hour, minute, second));

    // Check what London hour this UTC instant corresponds to (may differ across DST boundary)
    const checkParts = fmt.formatToParts(target);
    const checkHour = parseInt(checkParts.find(p => p.type === 'hour')?.value || '0');

    // Correct for DST shift (±1 hour at boundary)
    const hourDiff = checkHour - hour;
    if (hourDiff !== 0) {
        return new Date(target.getTime() - hourDiff * 3600 * 1000);
    }
    return target;
}
async function auditLog(pool, adminId, action, targetId, detail = '') {
    try {
        await pool.query(
            `INSERT INTO audit_logs (admin_id, action, target_id, detail, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT DO NOTHING`,
            [adminId, action, targetId, detail]
        );
    } catch (e) {
        console.warn('audit_log insert failed (non-critical):', e.message);
    }
}

async function gameAuditLog(pool, gameId, adminId, action, detail = '') {
    try {
        await pool.query(
            `INSERT INTO game_audit_log (game_id, admin_id, action, detail, created_at)
             VALUES ($1, $2, $3, $4, NOW())`,
            [gameId, adminId || null, action, detail]
        );
    } catch (e) {
        console.warn('game_audit_log insert failed (non-critical):', e.message);
    }
}

async function registrationEvent(pool, gameId, playerId, eventType, detail = '') {
    try {
        await pool.query(
            `INSERT INTO registration_events (game_id, player_id, event_type, detail, created_at)
             VALUES ($1, $2, $3, $4, NOW())`,
            [gameId, playerId, eventType, detail]
        );
    } catch (e) {
        console.warn('registration_event insert failed (non-critical):', e.message);
    }
}

async function statHistory(pool, playerId, changedBy, stats, tier = null) {
    try {
        await pool.query(
            `INSERT INTO player_stat_history 
             (player_id, changed_by, overall_rating, defending_rating, strength_rating,
              fitness_rating, pace_rating, decisions_rating, assisting_rating, shooting_rating,
              goalkeeper_rating, reliability_tier, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())`,
            [playerId, changedBy || null,
             stats.overall || null, stats.defending || null, stats.strength || null,
             stats.fitness || null, stats.pace || null, stats.decisions || null,
             stats.assisting || null, stats.shooting || null, stats.goalkeeper || null,
             tier || null]
        );
    } catch (e) {
        console.warn('stat_history insert failed (non-critical):', e.message);
    }
}



// ── PUSH NOTIFICATIONS ───────────────────────────────────────────────────────
// getGameDataForNotification: fetch minimal game info for push payloads
async function getGameDataForNotification(gameId) {
    const result = await pool.query(
        `SELECT g.game_date, g.game_url, g.format, g.cost_per_player,
                v.name as venue_name
         FROM games g LEFT JOIN venues v ON v.id = g.venue_id
         WHERE g.id = $1`,
        [gameId]
    );
    if (result.rows.length === 0) return {};
    const row = result.rows[0];
    const d = new Date(row.game_date);
    return {
        gameId,
        game_url: row.game_url,
        day:      d.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'Europe/London' }),
        time:     d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/London' }),
        venue:    row.venue_name || 'TBC',
        format:   row.format || '',
        cost:     parseFloat(row.cost_per_player || 0),
    };
}

// Push notification title/body templates per type
const NOTIF_TEMPLATES = {
    game_registered:   d => ({ title: 'Signed Up! ⚽',          body: `You're in for ${d.day} at ${d.venue}. £${(d.cost||0).toFixed(2)} deducted.` }),
    backup_added:      d => ({ title: 'On the Backup List ⏳',  body: `You're on backup for ${d.day} at ${d.venue}.` }),
    dropout_confirmed: d => ({ title: 'Dropped Out ✅',          body: `You've been removed from ${d.day} at ${d.venue}.` }),
    backup_promoted:   d => ({ title: "You're In! 🟢",           body: `A spot opened — you're confirmed for ${d.day} at ${d.venue}!` }),
    teams_created:     d => ({ title: 'Teams Are Live! 🏟️',     body: `Teams set for ${d.day} at ${d.venue}. Check the app!` }),
    game_cancelled:    d => ({ title: 'Game Cancelled ❌',       body: `The game on ${d.day} at ${d.venue} has been cancelled. Refund issued.` }),
    cost_changed:      d => ({ title: 'Price Updated 💰',        body: `Game cost changed: was £${d.oldCost}, now £${d.newCost}.` }),
    game_reminder:     d => ({ title: 'Game Tomorrow! ⚽',       body: `You're playing ${d.day} at ${d.time}, ${d.venue}.` }),
    motm_voting_open:  d => ({ title: 'Vote for MOTM 🏆',       body: `Voting is open for ${d.day}. Cast your vote now!` }),
    motm_winner:       d => ({ title: 'MOTM Winner 🌟',          body: `${d.winnerName} has won Man of the Match for ${d.day}!` }),
    signup:            _d => ({ title: 'Welcome to TotalFooty! ⚽', body: "Your account is ready. Find a game and sign up!" }),
    badge_awarded:     _d => ({ title: 'New Badge! 🏅',          body: "You've earned a new badge. Check your profile!" }),
    balance_updated:   _d => ({ title: 'Balance Updated 💳',    body: 'Your TotalFooty credit balance has been updated.' }),
};

// sendNotification: send an Expo push notification to a player's registered devices.
// Silently no-ops if the player has no tokens. Never throws.
async function sendNotification(type, playerId, data = {}) {
    try {
        const tokenResult = await pool.query(
            'SELECT fcm_token FROM fcm_tokens WHERE player_id = $1 ORDER BY last_used_at DESC LIMIT 5',
            [playerId]
        );
        if (tokenResult.rows.length === 0) return;

        const tmpl = NOTIF_TEMPLATES[type];
        if (!tmpl) { console.warn('sendNotification: unknown type ' + type); return; }
        const { title, body } = tmpl(data);

        const messages = tokenResult.rows.map(row => ({
            to: row.fcm_token, sound: 'default', title, body,
            data: { type, gameId: data.gameId || null },
        }));

        const response = await fetch('https://exp.host/--/api/v2/push/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(messages),
        });

        if (!response.ok) {
            console.warn('Expo push API error: ' + response.status);
            return;
        }
        // Prune DeviceNotRegistered tokens
        const json = await response.json();
        const tickets = Array.isArray(json.data) ? json.data : [];
        for (let i = 0; i < tickets.length; i++) {
            if (tickets[i]?.details?.error === 'DeviceNotRegistered') {
                const stale = tokenResult.rows[i]?.fcm_token;
                if (stale) pool.query('DELETE FROM fcm_tokens WHERE fcm_token = $1', [stale]).catch(() => {});
            }
        }
    } catch (e) {
        console.warn('sendNotification(' + type + ', ' + playerId + ') failed (non-critical):', e.message);
    }
}

// ── SUPERADMIN EMAIL ALERTS ──────────────────────────────────────────────────
// notifyAdmin: fire-and-forget email to SUPERADMIN_EMAIL. Never throws.
// rows: array of [label, value] pairs to render as a table.
async function notifyAdmin(subject, rows) {
    if (!SUPERADMIN_EMAIL) return;
    try {
        const tableRows = rows.map(([label, value]) =>
            `<tr><td style="padding:6px 0;color:#888;width:140px;vertical-align:top;">${htmlEncode(String(label))}</td>` +
            `<td style="font-weight:700;color:#fff;">${htmlEncode(String(value))}</td></tr>`
        ).join('');
        await emailTransporter.sendMail({
            from: '"TotalFooty" <totalfooty19@gmail.com>',
            to:   SUPERADMIN_EMAIL,
            subject,
            html: wrapEmailHtml(
                `<p style="color:#888;font-size:14px;margin:0 0 16px">${htmlEncode(subject)}</p>` +
                `<table style="width:100%;border-collapse:collapse;font-size:14px;">${tableRows}</table>`
            ),
        });
    } catch (e) {
        console.warn('notifyAdmin email failed (non-critical):', e.message);
    }
}


// SEC-009: Rate limiter for DM sends — prevents spam/flooding
const dmSendLimiter = rateLimit({
    windowMs: 60 * 1000,   // 1 minute
    max: 30,
    message: { error: 'Too many messages. Please slow down.' },
    keyGenerator: (req) => req.user?.playerId || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
});

// SEC-010: Rate limiter for fairness votes
const fairnessLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Too many votes. Please slow down.' },
    keyGenerator: (req) => req.user?.playerId || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-30: Rate limit all /api/public/* routes — game_url is brute-forceable without this
const publicEndpointLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-21: Rate limit public player profile — prevents full squad enumeration in 99 requests
const publicPlayerLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-13: Rate limit player lookup/search endpoints
const playerLookupLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-32: Rate limit game registration and dropout — prevents slot-camping scripts
const registrationLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: 'Too many registration attempts. Please wait and try again.' },
    keyGenerator: (req) => req.user?.playerId || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-34: Rate limit top-up requests — prevents admin inbox flood
const topupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: 'Too many top-up requests. Please wait before requesting again.' },
    keyGenerator: (req) => req.user?.playerId || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
});

// CRIT-30: One-line rate limit covers all 8+ /api/public/* routes — must be after limiter definitions
app.use('/api/public/', publicEndpointLimiter);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // SEC-011: rejectUnauthorized true enforces valid server cert — prevents MITM on DB connection
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

pool.connect((err, client, done) => {
    if (err) console.error('❌ Database error:', err);
    else { console.log('✅ Database connected'); done(); }
});

// FIX-030: Fail fast if JWT_SECRET missing — never fall back to hardcoded string
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL: JWT_SECRET environment variable not set.');
    process.exit(1);
}

// FIX-034: Superadmin email from env var — never hardcoded in source
const SUPERADMIN_EMAIL = process.env.SUPERADMIN_EMAIL;
if (!SUPERADMIN_EMAIL) console.warn('WARNING: SUPERADMIN_EMAIL not set — auto-assign disabled');

// ==========================================
// MIDDLEWARE
// ==========================================

const authenticateToken = async (req, res, next) => {
    // CRIT-2: Read JWT from httpOnly cookie — not Authorization header
    const token = req.cookies?.tf_token;
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        // FIX-075: Verify player still exists (deleted players should lose access immediately)
        try {
            const playerExists = await pool.query(
                'SELECT p.id, p.is_clm_admin, p.is_organiser, u.token_version, u.role FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                [user.playerId]
            );
            if (playerExists.rows.length === 0) {
                return res.status(401).json({ error: 'Account no longer exists' });
            }
            // SEC-016: JWT revocation via token_version
            const dbVersion = playerExists.rows[0].token_version || 0;
            const tokenVersion = user.tokenVersion || 0;
            if (tokenVersion < dbVersion) {
                return res.status(401).json({ error: 'Session expired. Please log in again.' });
            }
            // SEC-ROLE: Always use role from DB, not JWT — prevents stale elevated roles
            user.role = playerExists.rows[0].role;
            user.isCLMAdmin = playerExists.rows[0].is_clm_admin || false;
            user.isOrganiser = playerExists.rows[0].is_organiser || false;
        } catch (e) {
            return res.status(500).json({ error: 'Authentication error' });
        }
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// SEC-026: Optional auth — attaches user if token present but never blocks unauthenticated requests.
// Used for endpoints where general content is public but personalised content requires auth.
const optionalAuth = async (req, res, next) => {
    // CRIT-2: Read JWT from httpOnly cookie — not Authorization header
    const token = req.cookies?.tf_token;
    if (!token) return next();
    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (!err) {
            try {
                const row = await pool.query(
                    'SELECT p.id, u.token_version, u.role FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                    [user.playerId]
                );
                if (row.rows.length > 0) {
                    const dbVer = row.rows[0].token_version || 0;
                    if ((user.tokenVersion || 0) >= dbVer) {
                        user.role = row.rows[0].role; // SEC-ROLE: always use role from DB
                        req.user = user;
                    }
                }
            } catch (_) { /* ignore — treat as guest */ }
        }
        next();
    });
};

const requireSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Super admin access required' });
    }
    next();
};

// CLM Admin: is_clm_admin flag, only operates on CLM-exclusive games
const requireCLMAdmin = async (req, res, next) => {
    try {
        if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
        const result = await pool.query('SELECT is_clm_admin FROM players WHERE id = $1', [req.user.playerId]);
        if (!result.rows[0]?.is_clm_admin) return res.status(403).json({ error: 'CLM admin access required' });
        const gameId = req.params.gameId || req.params.id;
        if (gameId) {
            const gc = await pool.query('SELECT exclusivity FROM games WHERE id = $1', [gameId]);
            if (gc.rows.length > 0 && gc.rows[0].exclusivity !== 'clm') {
                return res.status(403).json({ error: 'CLM admins can only manage CLM games' });
            }
        }
        next();
    } catch (error) {
        console.error('CLM admin check error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
    }
};

// Organiser: is_organiser flag, must be registered for the game
const requireOrganiser = async (req, res, next) => {
    try {
        if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
        const result = await pool.query('SELECT is_organiser FROM players WHERE id = $1', [req.user.playerId]);
        if (!result.rows[0]?.is_organiser) return res.status(403).json({ error: 'Organiser access required' });
        const gameId = req.params.gameId || req.params.id;
        if (gameId) {
            const rc = await pool.query(
                "SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'",
                [gameId, req.user.playerId]
            );
            if (rc.rows.length === 0) {
                return res.status(403).json({ error: 'Organisers can only manage games they are registered for' });
            }
        }
        next();
    } catch (error) {
        console.error('Organiser check error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
    }
};

// Either admin, CLM admin (CLM games), or organiser (registered games)
const requireGameManager = async (req, res, next) => {
    try {
        if (req.user.role === 'admin' || req.user.role === 'superadmin') {
            req.managerRole = 'admin';
            return next();
        }
        const pr = await pool.query('SELECT is_clm_admin, is_organiser FROM players WHERE id = $1', [req.user.playerId]);
        const player = pr.rows[0];
        if (!player) return res.status(403).json({ error: 'Access denied' });
        const gameId = req.params.gameId || req.params.id;
        if (gameId) {
            const gc = await pool.query('SELECT exclusivity FROM games WHERE id = $1', [gameId]);
            const game = gc.rows[0];
            if (!game) return res.status(404).json({ error: 'Game not found' });
            if (player.is_clm_admin && game.exclusivity === 'clm') {
                req.managerRole = 'clm_admin';
                return next();
            }
            if (player.is_organiser) {
                const rc = await pool.query(
                    "SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'",
                    [gameId, req.user.playerId]
                );
                if (rc.rows.length > 0) {
                    req.managerRole = 'organiser';
                    return next();
                }
            }
        }
        return res.status(403).json({ error: 'You do not have permission to manage this game' });
    } catch (error) {
        console.error('Game manager check error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
    }
};

// ==========================================
// AUTHENTICATION
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, alias, email, password, phone, ref } = req.body;

        // Validate required fields
        if (!fullName || !email || !password || !phone) {
            return res.status(400).json({ error: 'Full name, email, password, and phone are required' });
        }

        // FIX-009: Minimum password length
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // SEC-013: Basic email format check
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        // SEC-039: Block registration with reserved internal import domain
        if (email.toLowerCase().endsWith('@totalfooty.import')) {
            return res.status(400).json({ error: 'Invalid email address' });
        }

        // Check if email already exists
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12); // SEC-014: bcrypt cost 12 (was 10)

        // MED-2: All new accounts start as 'player' — superadmin must be set directly in DB
        const role = 'player';

        // Create user
        const userResult = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [email.toLowerCase(), passwordHash, role]
        );
        const userId = userResult.rows[0].id;

        // Extract first and last name
        const nameParts = fullName.trim().split(/\s+/);
        const firstName = nameParts[0];
        const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : firstName;
        const playerAlias = alias?.trim() || firstName;

        // Create player with default stats (GK=84, all outfield stats=12, overall=84)
        const playerResult = await pool.query(
            `INSERT INTO players (user_id, full_name, first_name, last_name, alias, phone, position, reliability_tier,
                goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
                pace_rating, decisions_rating, assisting_rating, shooting_rating, overall_rating)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'silver', 84, 12, 12, 12, 12, 12, 12, 12, 84) RETURNING id`,
            [userId, fullName.trim(), firstName, lastName, playerAlias, phone.trim(), 'outfield']
        );
        const playerId = playerResult.rows[0].id;

        // Create credits record
        await pool.query('INSERT INTO credits (player_id, balance) VALUES ($1, 0.00)', [playerId]);

        // Generate referral code (TF + 8 hex chars) on players table + referrals table (backward compat)
        const referralCode = 'TF' + crypto.randomBytes(4).toString('hex').toUpperCase();
        await pool.query('UPDATE players SET referral_code = $1 WHERE id = $2', [referralCode, playerId]);
        try {
            await pool.query(
                'INSERT INTO referrals (referrer_id, referral_code) VALUES ($1, $2)',
                [playerId, referralCode]
            );
        } catch (refErr) {
            console.error('Referrals table insert (non-critical):', refErr.message);
        }
        
        // Handle referral: look up referrer by code
        // N6: ref=clm and ref=misfits badge auto-assignment REMOVED — exclusive badges must be admin-granted only.
        // Any user who reads the source could self-assign restricted badges via ?ref=clm on the register URL.
        if (ref) {
            try {
                if (ref.toLowerCase() === 'clm' || ref.toLowerCase() === 'misfits') {
                    // Silently ignore — no longer auto-assigns badges from URL param
                    console.log(`N6: ref=${ref} badge auto-assign blocked for player ${playerId}`);
                } else {
                    let referrerId = null;
                    const pRef = await pool.query('SELECT id FROM players WHERE referral_code = $1', [ref.toUpperCase()]);
                    if (pRef.rows.length > 0) {
                        referrerId = pRef.rows[0].id;
                    } else {
                        const rRef = await pool.query('SELECT referrer_id FROM referrals WHERE referral_code = $1', [ref.toUpperCase()]);
                        if (rRef.rows.length > 0) referrerId = rRef.rows[0].referrer_id;
                    }
                    
                    if (referrerId) {
                        // FIX-065: Block self-referral
                        if (referrerId === playerId) {
                            console.log('Referral skipped: self-referral detected for player ' + playerId);
                        } else {
                            // FIX-065: Block circular chain (referrer was referred by this new player)
                            const circularCheck = await pool.query('SELECT referred_by FROM players WHERE id = $1', [referrerId]);
                            if (circularCheck.rows[0]?.referred_by === playerId) {
                                console.log('Referral skipped: circular chain detected');
                            } else {
                                // Set referred_by on new player
                                await pool.query('UPDATE players SET referred_by = $1 WHERE id = $2', [referrerId, playerId]);

                                // CLM badge inheritance via referral chain
                                const referrerCLM = await pool.query(
                                    "SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = $1 AND b.name = 'CLM'",
                                    [referrerId]
                                );
                                if (referrerCLM.rows.length > 0) {
                                    const clmBadge = await pool.query("SELECT id FROM badges WHERE name = 'CLM'");
                                    if (clmBadge.rows.length > 0) {
                                        await pool.query(
                                            'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                                            [playerId, clmBadge.rows[0].id]
                                        );
                                        await auditLog(pool, null, 'badge_auto_awarded', playerId, `badge: CLM (inherited via referral from player ${referrerId})`);
                                    }
                                }

                                // Misfits badge inheritance (social group, kept intentionally)
                                const referrerMisfits = await pool.query(
                                    "SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = $1 AND b.name = 'Misfits'",
                                    [referrerId]
                                );
                                if (referrerMisfits.rows.length > 0) {
                                    const misfitsBadge = await pool.query("SELECT id FROM badges WHERE name = 'Misfits'");
                                    if (misfitsBadge.rows.length > 0) {
                                        await pool.query(
                                            'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                                            [playerId, misfitsBadge.rows[0].id]
                                        );
                                        await auditLog(pool, null, 'badge_auto_awarded', playerId, `badge: Misfits (inherited via referral from player ${referrerId})`);
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (refErr) {
                console.error('Referral processing (non-critical):', refErr.message);
            }
        }
        
        // Auto-allocate badges immediately (assigns "New" badge)
        try {
            await autoAllocateBadges(playerId);
        } catch (badgeErr) {
            console.error('Failed to auto-allocate badges on registration:', badgeErr.message);
        }

        res.status(201).json({ 
            message: 'Account created successfully', 
            userId,
            playerId 
        });

        // Non-critical: send welcome email after response
        setImmediate(async () => {
            try {
                await sendNotification('signup', playerId, {});
            } catch (e) {
                console.error('Signup notification failed (non-critical):', e.message);
            }
            try {
                await auditLog(pool, playerId, 'player_created', playerId, `email:${email} name:${fullName}`);
            } catch (e) { /* non-critical */ }
            // #14: Notify admin of new signup
            try {
                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to: SUPERADMIN_EMAIL || 'totalfooty19@gmail.com',
                    subject: '🆕 New Player Signup — TotalFooty',
                    html: wrapEmailHtml(`
                        <p style="color:#888;font-size:14px;margin:0 0 16px">New account created</p>
                        <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;">
                            <tr><td style="padding:6px 0;color:#888;width:120px;">Full Name</td><td style="font-weight:900;">${htmlEncode(fullName.trim())}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Alias</td><td>${htmlEncode(playerAlias)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Email</td><td>${htmlEncode(email)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Mobile</td><td>${htmlEncode(phone.trim())}</td></tr>
                            ${ref ? `<tr><td style="padding:6px 0;color:#888;">Referral</td><td>${htmlEncode(ref)}</td></tr>` : ''}
                        </table>
                    `)
                });
            } catch (e) {
                console.error('Admin signup notification failed (non-critical):', e.message);
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        // FIX-008: Guard against empty/null body
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];

        // MED-4: Check if account is currently locked out
        const failureRecord = await pool.query(
            'SELECT failed_count, locked_until FROM login_failures WHERE user_id = $1',
            [user.id]
        );
        if (failureRecord.rows.length > 0) {
            const { locked_until } = failureRecord.rows[0];
            if (locked_until && new Date(locked_until) > new Date()) {
                const minutesLeft = Math.ceil((new Date(locked_until) - new Date()) / 60000);
                return res.status(429).json({
                    error: `Account temporarily locked due to too many failed attempts. Try again in ${minutesLeft} minute${minutesLeft !== 1 ? 's' : ''}.`
                });
            }
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            // MED-4: Record failed attempt — lock after 10 failures for 15 minutes
            await pool.query(`
                INSERT INTO login_failures (user_id, failed_count, last_failed_at)
                VALUES ($1, 1, NOW())
                ON CONFLICT (user_id) DO UPDATE
                SET failed_count = login_failures.failed_count + 1,
                    last_failed_at = NOW(),
                    locked_until = CASE
                        WHEN login_failures.failed_count + 1 >= 10
                        THEN NOW() + INTERVAL '15 minutes'
                        ELSE NULL
                    END
            `, [user.id]);
            console.warn(`Failed login: ${email.toLowerCase()} at ${new Date().toISOString()}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // MED-4: Successful login — clear failure record
        await pool.query('DELETE FROM login_failures WHERE user_id = $1', [user.id]);

        const playerResult = await pool.query(
            `SELECT p.*, c.balance as credits,
             (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
              FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
             p.referral_code,
             u.token_version
             FROM players p 
             LEFT JOIN credits c ON c.player_id = p.id 
             LEFT JOIN users u ON u.id = p.user_id
             WHERE p.user_id = $1`,
            [user.id]
        );

        const player = playerResult.rows[0];

        // SEC-017: Include token_version so revocation works (see authenticateToken)
        const token = jwt.sign(
            {
                userId: user.id,
                playerId: player.id,
                email: user.email,
                role: user.role,
                isCLMAdmin: player.is_clm_admin || false,
                isOrganiser: player.is_organiser || false,
                tokenVersion: player.token_version || 0
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // CRIT-2: Set JWT as httpOnly cookie — not in response body
        // SameSite=None required for cross-origin (totalfooty.co.uk → totalfooty-api.onrender.com)
        res.cookie('tf_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
        });

        res.json({
            user: {
                id: player.id,
                userId: user.id,
                email: user.email,
                fullName: player.full_name,
                alias: player.alias,
                role: user.role,
                isAdmin: user.role === 'admin' || user.role === 'superadmin',
                isSuperAdmin: user.role === 'superadmin',
                isCLMAdmin: player.is_clm_admin || false,
                isOrganiser: player.is_organiser || false,
                squadNumber: player.squad_number,
                phone: player.phone,
                photoUrl: player.photo_url,
                tier: player.reliability_tier,
                credits: parseFloat(player.credits || 0),
                appearances: player.total_appearances || 0,
                motmWins: player.motm_wins || 0,
                wins: player.total_wins || 0,
                badges: player.badges || [],
                referralCode: player.referral_code,
                stats: {
                    overall: player.overall_rating || 0,
                    defending: player.defending_rating || 0,
                    strength: player.strength_rating || 0,
                    fitness: player.fitness_rating || 0,
                    pace: player.pace_rating || 0,
                    decisions: player.decisions_rating || 0,
                    assisting: player.assisting_rating || 0,
                    shooting: player.shooting_rating || 0,
                    goalkeeper: player.goalkeeper_rating || 0
                }
            }
        });

        // Audit login event (non-critical, after response)
        setImmediate(() => auditLog(pool, player.id, 'login', player.id,
            `email:${user.email} role:${user.role}`).catch(() => {}));
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// CRIT-2: Logout — clear the httpOnly cookie
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('tf_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
    });
    res.json({ message: 'Logged out' });
});

// Get current user info (for game.html auth check)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const playerResult = await pool.query(
            `SELECT p.id, p.full_name, p.alias, p.squad_number, p.referral_code, u.role,
             COALESCE(p.is_clm_admin, false) as is_clm_admin,
             COALESCE(p.is_organiser, false) as is_organiser
             FROM players p
             JOIN users u ON u.id = p.user_id
             WHERE p.id = $1`,
            [req.user.playerId]
        );
        
        if (playerResult.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        const player = playerResult.rows[0];
        res.json({
            playerId: player.id,
            fullName: player.full_name,
            alias: player.alias,
            squadNumber: player.squad_number,
            referralCode: player.referral_code,
            role: player.role,
            isCLMAdmin: player.is_clm_admin || false,
            isOrganiser: player.is_organiser || false
        });
    } catch (error) {
        console.error('Auth me error:', error);
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

// ==========================================
// PLAYERS
// ==========================================

// ==========================================
// PLAYERS - Get current user's player data
// ==========================================

app.get('/api/players/me', authenticateToken, async (req, res) => {
    try {
        
        // Start with absolute basics
        const result = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.phone
            FROM players p
            WHERE p.id = $1
        `, [req.user.playerId]);
        
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        const player = result.rows[0];
        
        // Add other fields one by one
        try {
            const detailsResult = await pool.query(`
                SELECT 
                    p.squad_number, 
                    p.player_number, 
                    p.photo_url, 
                    p.reliability_tier, 
                    p.total_appearances, 
                    p.motm_wins, 
                    p.total_wins,
                    p.is_clm_admin,
                    p.is_organiser,
                    p.referred_by,
                    c.balance as credits,
                    u.email,
                    u.role,
                    (SELECT COALESCE(alias, full_name)
                     FROM players WHERE id = p.referred_by) AS referred_by_name,
                    (SELECT COUNT(*) FROM registrations r2
                     JOIN games g2 ON g2.id = r2.game_id
                     JOIN team_players tp2 ON tp2.player_id = r2.player_id
                     JOIN teams t2 ON t2.id = tp2.team_id AND t2.game_id = g2.id
                     WHERE r2.player_id = p.id AND r2.status = 'confirmed'
                       AND g2.game_status = 'completed'
                       AND g2.team_selection_type = 'tournament'
                       AND LOWER(g2.winning_team) = LOWER(t2.team_name))::int AS tournament_wins,
                    (SELECT COUNT(*) FROM registrations r3
                     JOIN games g3 ON g3.id = r3.game_id
                     JOIN team_players tp3 ON tp3.player_id = r3.player_id
                     JOIN teams t3 ON t3.id = tp3.team_id AND t3.game_id = g3.id
                     WHERE r3.player_id = p.id AND r3.status = 'confirmed'
                       AND g3.game_status = 'completed'
                       AND g3.team_selection_type = 'vs_external'
                       AND LOWER(g3.winning_team) = LOWER(t3.team_name))::int AS external_game_wins
                FROM players p
                LEFT JOIN credits c ON c.player_id = p.id
                LEFT JOIN users u ON u.id = p.user_id
                WHERE p.id = $1
            `, [req.user.playerId]);
            
            if (detailsResult.rows.length > 0) {
                Object.assign(player, detailsResult.rows[0]);
                // Add frontend-friendly role flags
                player.isAdmin = player.role === 'admin' || player.role === 'superadmin';
                player.isSuperAdmin = player.role === 'superadmin';
                player.isCLMAdmin = player.is_clm_admin || false;
                player.isOrganiser = player.is_organiser || false;
            }
        } catch (detailsError) {
            console.error('Error fetching details:', detailsError.message);
            // Continue with basic info
        }
        
        // Fetch badges
        try {
            const badgeResult = await pool.query(`
                SELECT b.id, b.name, b.color, b.icon
                FROM player_badges pb JOIN badges b ON pb.badge_id = b.id
                WHERE pb.player_id = $1
                ORDER BY b.name
            `, [req.user.playerId]);
            player.badges = badgeResult.rows;
        } catch (badgeErr) {
            console.error('Badge fetch error:', badgeErr.message);
            player.badges = [];
        }
        
        // Ensure role flags always have defaults
        if (player.isCLMAdmin === undefined) player.isCLMAdmin = false;
        if (player.isOrganiser === undefined) player.isOrganiser = false;
        if (player.isAdmin === undefined) player.isAdmin = false;
        if (player.isSuperAdmin === undefined) player.isSuperAdmin = false;
        
        res.json(player);
    } catch (error) {
        console.error('Error fetching player data:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ error: 'Failed to fetch player data' });
    }
});

app.get('/api/players', authenticateToken, playerLookupLimiter, async (req, res) => {
    try {
        const result = await pool.query(`
            WITH player_stats AS (
                SELECT
                    r.player_id,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.game_date >= NOW() - INTERVAL '3 months') AS apps_3m,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.game_date >= DATE_TRUNC('year', NOW()))   AS apps_year
                FROM registrations r
                JOIN games g ON g.id = r.game_id
                WHERE r.status = 'confirmed' AND g.game_status = 'completed'
                GROUP BY r.player_id
            ),
            motm_stats AS (
                SELECT
                    motm_winner_id AS player_id,
                    COUNT(*) FILTER (WHERE game_date >= NOW() - INTERVAL '3 months')     AS motm_3m,
                    COUNT(*) FILTER (WHERE game_date >= DATE_TRUNC('year', NOW()))        AS motm_year
                FROM games WHERE motm_winner_id IS NOT NULL
                GROUP BY motm_winner_id
            ),
            win_stats AS (
                SELECT
                    r.player_id,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.game_date >= NOW() - INTERVAL '3 months') AS wins_3m,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.game_date >= DATE_TRUNC('year', NOW()))   AS wins_year,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.team_selection_type = 'tournament') AS tournament_wins,
                    COUNT(DISTINCT r.game_id) FILTER (WHERE g.team_selection_type = 'vs_external') AS external_game_wins
                FROM registrations r
                JOIN games g ON g.id = r.game_id
                JOIN team_players tp ON tp.player_id = r.player_id
                JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                WHERE r.status = 'confirmed' AND g.game_status = 'completed'
                  AND LOWER(g.winning_team) = LOWER(t.team_name)
                GROUP BY r.player_id
            )
            SELECT 
                p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                p.reliability_tier, p.total_appearances, p.motm_wins, p.total_wins,
                p.phone, u.email,
                p.is_clm_admin, p.is_organiser,
                c.balance as credits,
                p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                p.goalkeeper_rating,
                COALESCE(p.is_featured, false) AS is_featured,
                p.social_tiktok, p.social_instagram, p.social_youtube, p.social_facebook,
                (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
                COALESCE(ps.apps_3m, 0)   AS apps_3m,
                COALESCE(ms.motm_3m, 0)   AS motm_3m,
                COALESCE(ws.wins_3m, 0)   AS wins_3m,
                COALESCE(ps.apps_year, 0) AS apps_year,
                COALESCE(ms.motm_year, 0) AS motm_year,
                COALESCE(ws.wins_year, 0) AS wins_year,
                COALESCE(ws.tournament_wins, 0)   AS tournament_wins,
                COALESCE(ws.external_game_wins, 0) AS external_game_wins,
                CASE WHEN p.total_appearances > 0
                     THEN ROUND(p.total_wins::numeric / p.total_appearances * 100, 1)
                     ELSE 0 END AS win_percent,
                CASE WHEN p.total_appearances > 0
                     THEN ROUND(p.motm_wins::numeric / p.total_appearances * 100, 1)
                     ELSE 0 END AS motm_percent
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            LEFT JOIN player_stats ps ON ps.player_id = p.id
            LEFT JOIN motm_stats ms ON ms.player_id = p.id
            LEFT JOIN win_stats ws ON ws.player_id = p.id
            ORDER BY p.squad_number NULLS LAST, p.full_name
            LIMIT 500
        `);
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        if (isAdmin) {
            res.json(result.rows);
        } else {
            // Strip sensitive fields for non-admin users
            const safeRows = result.rows.map(p => {
                const { phone, email, credits, is_clm_admin, is_organiser,
                    overall_rating, defending_rating, strength_rating, fitness_rating,
                    pace_rating, decisions_rating, assisting_rating, shooting_rating, goalkeeper_rating,
                    ...safe } = p;
                // safe includes: id, alias, full_name, squad_number, photo_url, reliability_tier,
                //   total_appearances, motm_wins, total_wins, badges, stats, is_featured, social_*
                return safe;
            });
            res.json(safeRows);
        }
    } catch (error) {
        console.error('Error fetching players:', error);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

// ==========================================
// ADMIN PLAYERS GRID — all data for manage-players.html
// ==========================================
app.get('/api/admin/players/grid', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                p.reliability_tier, p.phone,
                p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                p.goalkeeper_rating,
                p.is_clm_admin, p.is_organiser,
                u.role as user_role, u.email,
                c.balance as credits,

                -- Badges with IDs
                (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,

                -- GAME STATS: all time
                p.total_appearances, p.total_wins, p.motm_wins,

                -- GAME STATS: last 3 months
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND g.game_date >= NOW() - INTERVAL '3 months') as apps_3m,

                (SELECT COUNT(*) FROM games g WHERE g.motm_winner_id = p.id
                 AND g.game_status = 'completed'
                 AND g.game_date >= NOW() - INTERVAL '3 months') as motm_3m,

                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r JOIN games g ON g.id = r.game_id
                 JOIN team_players tp ON tp.player_id = r.player_id
                 JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND LOWER(g.winning_team) = LOWER(t.team_name)
                 AND g.game_date >= NOW() - INTERVAL '3 months') as wins_3m,

                -- GAME STATS: calendar year
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as apps_year,

                (SELECT COUNT(*) FROM games g WHERE g.motm_winner_id = p.id
                 AND g.game_status = 'completed'
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as motm_year,

                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r JOIN games g ON g.id = r.game_id
                 JOIN team_players tp ON tp.player_id = r.player_id
                 JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND LOWER(g.winning_team) = LOWER(t.team_name)
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as wins_year,

                -- FINANCIAL: all time
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'admin_adjustment' AND ct.amount > 0), 0) as topped_up,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'game_fee'), 0) as spent,

                (SELECT COUNT(*) FROM game_guests gg WHERE gg.invited_by = p.id) as guests_invited,

                (SELECT COUNT(*) FROM players ref WHERE ref.referred_by = p.id) as players_referred,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 JOIN players ref ON ct.player_id = ref.id
                 WHERE ref.referred_by = p.id AND ct.type = 'game_fee'), 0) as referred_spend,

                -- CLM REVENUE per player: their fees at CLM games + their guests' fees at CLM games
                COALESCE((SELECT SUM(g.cost_per_player) FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.exclusivity = 'clm' AND g.game_status = 'completed'), 0)
                +
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg
                 JOIN games g ON g.id = gg.game_id
                 WHERE gg.invited_by = p.id AND g.exclusivity = 'clm'), 0) as clm_revenue,

                -- FINANCIAL: last 3 months
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'admin_adjustment' AND ct.amount > 0
                 AND ct.created_at >= NOW() - INTERVAL '3 months'), 0) as topped_up_3m,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'game_fee'
                 AND ct.created_at >= NOW() - INTERVAL '3 months'), 0) as spent_3m,

                (SELECT COUNT(*) FROM game_guests gg
                 JOIN games g ON g.id = gg.game_id
                 WHERE gg.invited_by = p.id
                 AND g.game_date >= NOW() - INTERVAL '3 months') as guests_invited_3m,

                (SELECT COUNT(*) FROM players ref WHERE ref.referred_by = p.id
                 AND ref.created_at >= NOW() - INTERVAL '3 months') as players_referred_3m,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 JOIN players ref ON ct.player_id = ref.id
                 WHERE ref.referred_by = p.id AND ct.type = 'game_fee'
                 AND ct.created_at >= NOW() - INTERVAL '3 months'), 0) as referred_spend_3m,

                COALESCE((SELECT SUM(g.cost_per_player) FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.exclusivity = 'clm' AND g.game_status = 'completed'
                 AND g.game_date >= NOW() - INTERVAL '3 months'), 0)
                +
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg
                 JOIN games g ON g.id = gg.game_id
                 WHERE gg.invited_by = p.id AND g.exclusivity = 'clm'
                 AND g.game_date >= NOW() - INTERVAL '3 months'), 0) as clm_revenue_3m,

                -- FINANCIAL: calendar year
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'admin_adjustment' AND ct.amount > 0
                 AND ct.created_at >= DATE_TRUNC('year', NOW())), 0) as topped_up_year,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'game_fee'
                 AND ct.created_at >= DATE_TRUNC('year', NOW())), 0) as spent_year,

                (SELECT COUNT(*) FROM game_guests gg
                 JOIN games g ON g.id = gg.game_id
                 WHERE gg.invited_by = p.id
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as guests_invited_year,

                (SELECT COUNT(*) FROM players ref WHERE ref.referred_by = p.id
                 AND ref.created_at >= DATE_TRUNC('year', NOW())) as players_referred_year,

                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct
                 JOIN players ref ON ct.player_id = ref.id
                 WHERE ref.referred_by = p.id AND ct.type = 'game_fee'
                 AND ct.created_at >= DATE_TRUNC('year', NOW())), 0) as referred_spend_year,

                COALESCE((SELECT SUM(g.cost_per_player) FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id AND r.status = 'confirmed'
                 AND g.exclusivity = 'clm' AND g.game_status = 'completed'
                 AND g.game_date >= DATE_TRUNC('year', NOW())), 0)
                +
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg
                 JOIN games g ON g.id = gg.game_id
                 WHERE gg.invited_by = p.id AND g.exclusivity = 'clm'
                 AND g.game_date >= DATE_TRUNC('year', NOW())), 0) as clm_revenue_year,

                -- FEATURED PROFILE & SOCIALS
                COALESCE(p.is_featured, false) as is_featured,
                p.social_tiktok,
                p.social_instagram,
                p.social_youtube,
                p.social_facebook,

                -- DISCIPLINE: all-time total points
                COALESCE((
                    SELECT SUM(dr.points) FROM discipline_records dr WHERE dr.player_id = p.id
                ), 0) as disc_points_total,

                -- DISCIPLINE: revolving — last 10 completed games only (not manual entries)
                COALESCE((
                    SELECT SUM(dr.points)
                    FROM discipline_records dr
                    WHERE dr.player_id = p.id
                    AND dr.game_id IN (
                        SELECT r.game_id FROM registrations r
                        JOIN games g2 ON g2.id = r.game_id
                        WHERE r.player_id = p.id AND r.status = 'confirmed'
                        AND g2.game_status = 'completed'
                        ORDER BY g2.game_date DESC LIMIT 10
                    )
                ), 0) as disc_points_revolving,

                -- DISCIPLINE: most recent offense type
                (SELECT dr.offense_type FROM discipline_records dr
                 WHERE dr.player_id = p.id AND dr.game_id IS NOT NULL
                 ORDER BY dr.id DESC LIMIT 1) as last_offense

            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.squad_number NULLS LAST, p.full_name
            LIMIT 200
        `);

        // All badges for the badge matrix headers
        const badgesResult = await pool.query('SELECT id, name, color, icon FROM badges ORDER BY name');

        // CLM totals (platform-wide) — all time, last 3 months, calendar year
        const clmTotals = await pool.query(`
            SELECT
                COALESCE(SUM(g.cost_per_player * sub.player_count + COALESCE(sub.guest_revenue, 0)), 0) as clm_total,
                COALESCE(SUM(CASE WHEN g.game_date >= NOW() - INTERVAL '3 months'
                    THEN g.cost_per_player * sub.player_count + COALESCE(sub.guest_revenue, 0) ELSE 0 END), 0) as clm_total_3m,
                COALESCE(SUM(CASE WHEN g.game_date >= DATE_TRUNC('year', NOW())
                    THEN g.cost_per_player * sub.player_count + COALESCE(sub.guest_revenue, 0) ELSE 0 END), 0) as clm_total_year
            FROM games g
            JOIN (
                SELECT r.game_id,
                    COUNT(*) as player_count,
                    (SELECT COALESCE(SUM(gg.amount_paid), 0) FROM game_guests gg WHERE gg.game_id = r.game_id) as guest_revenue
                FROM registrations r
                WHERE r.status = 'confirmed'
                GROUP BY r.game_id
            ) sub ON sub.game_id = g.id
            WHERE g.exclusivity = 'clm' AND g.game_status = 'completed'
        `);

        res.json({
            players: result.rows,
            allBadges: badgesResult.rows,
            clmTotals: clmTotals.rows[0] || { clm_total: 0, clm_total_3m: 0, clm_total_year: 0 }
        });
    } catch (error) {
        console.error('Error fetching admin players grid:', error);
        res.status(500).json({ error: 'Failed to fetch players grid data' });
    }
});

app.get('/api/players/:id', authenticateToken, playerLookupLimiter, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.*, c.balance as credits, u.email,
            (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
             FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
            COALESCE((SELECT SUM(dr.points) FROM discipline_records dr WHERE dr.player_id = p.id), 0) as disc_points_total,
            COALESCE((
                SELECT SUM(dr.points) FROM discipline_records dr
                WHERE dr.player_id = p.id
                AND dr.game_id IN (
                    SELECT r.game_id FROM registrations r
                    JOIN games g2 ON g2.id = r.game_id
                    WHERE r.player_id = p.id AND r.status = 'confirmed'
                    AND g2.game_status = 'completed'
                    ORDER BY g2.game_date DESC LIMIT 10
                )
            ), 0) as disc_points_revolving,
            (SELECT dr.offense_type FROM discipline_records dr
             WHERE dr.player_id = p.id AND dr.game_id IS NOT NULL
             ORDER BY dr.id DESC LIMIT 1) as last_offense
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            WHERE p.id = $1
        `, [req.params.id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        const player = result.rows[0];
        
        // Return different data based on viewer
        const isOwnProfile = player.user_id === req.user.userId;
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        // Derive computed stats
        const apps = parseInt(player.total_appearances || 0);
        const wins = parseInt(player.total_wins || 0);
        const motm = parseInt(player.motm_wins || 0);
        const win_percent  = apps > 0 ? parseFloat((wins / apps * 100).toFixed(1)) : 0;
        const motm_percent = apps > 0 ? parseFloat((motm / apps * 100).toFixed(1)) : 0;

        // Derived: tournament wins and external game wins
        const tourneyResult = await pool.query(`
            SELECT COUNT(*) AS cnt FROM registrations r
            JOIN games g ON g.id = r.game_id
            JOIN team_players tp ON tp.player_id = r.player_id
            JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
            WHERE r.player_id = $1 AND r.status = 'confirmed'
              AND g.game_status = 'completed' AND g.team_selection_type = 'tournament'
              AND LOWER(g.winning_team) = LOWER(t.team_name)
        `, [player.id]);
        const extResult = await pool.query(`
            SELECT COUNT(*) AS cnt FROM registrations r
            JOIN games g ON g.id = r.game_id
            JOIN team_players tp ON tp.player_id = r.player_id
            JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
            WHERE r.player_id = $1 AND r.status = 'confirmed'
              AND g.game_status = 'completed' AND g.team_selection_type = 'vs_external'
              AND LOWER(g.winning_team) = LOWER(t.team_name)
        `, [player.id]);

        const tournament_wins   = parseInt(tourneyResult.rows[0].cnt) || 0;
        const external_game_wins = parseInt(extResult.rows[0].cnt) || 0;

        if (isOwnProfile || isAdmin) {
            res.json({ ...player, win_percent, motm_percent, tournament_wins, external_game_wins });
        } else {
            // Public view — limited data per visibility matrix
            res.json({
                id:               player.id,
                alias:            player.alias,
                full_name:        player.full_name,
                squad_number:     player.squad_number,
                photo_url:        player.photo_url,
                reliability_tier: player.reliability_tier,
                total_appearances: player.total_appearances,
                total_wins:       player.total_wins,
                motm_wins:        player.motm_wins,
                overall_rating:   player.overall_rating,
                win_percent,
                motm_percent,
                tournament_wins,
                external_game_wins,
                badges:           player.badges,
                // Socials are public — players opt in by adding them
                social_tiktok:    player.social_tiktok,
                social_instagram: player.social_instagram,
                social_youtube:   player.social_youtube,
                social_facebook:  player.social_facebook,
            });
        }
    } catch (error) {
        console.error('Error fetching player:', error);
        res.status(500).json({ error: 'Failed to fetch player' });
    }
});

// Get player's games (upcoming and completed)
app.get('/api/players/:playerId/games', authenticateToken, async (req, res) => {
    try {
        const { playerId } = req.params;

        // CRIT-9: Prevent IDOR — only the player themselves or an admin can view game history
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (!isAdmin && req.user.playerId !== playerId) {
            return res.status(403).json({ error: 'You can only view your own game history' });
        }
        // Get upcoming games (registered and not completed)
        const upcomingResult = await pool.query(`
            SELECT g.id, g.game_date, g.cost_per_player, g.max_players, g.format, g.game_url,
                   v.name as venue_name,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players
            FROM registrations r
            JOIN games g ON g.id = r.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE r.player_id = $1 
            AND r.status = 'confirmed'
            AND g.game_status IN ('available', 'confirmed')
            AND g.game_date >= CURRENT_TIMESTAMP
            ORDER BY g.game_date ASC
        `, [playerId]);
        
        // Get completed games
        const completedResult = await pool.query(`
            SELECT g.id, g.game_date, g.game_url, g.winning_team,
                   v.name as venue_name
            FROM registrations r
            JOIN games g ON g.id = r.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE r.player_id = $1
            AND r.status = 'confirmed'
            AND g.game_status = 'completed'
            ORDER BY g.game_date DESC
            LIMIT 20
        `, [playerId]);
        
        res.json({
            upcomingGames: upcomingResult.rows,
            completedGames: completedResult.rows
        });
        
    } catch (error) {
        console.error('Get player games error:', error);
        res.status(500).json({ error: 'Failed to get player games' });
    }
});

app.put('/api/players/me', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const { fullName, alias, email, phone, currentPassword } = req.body;

        // FIX-078: Guard against undefined/null fullName (was crashing with TypeError)
        if (!fullName?.trim()) return res.status(400).json({ error: 'Full name is required' });

        // FIX-079: Field length validation
        if (fullName.trim().length > 100) return res.status(400).json({ error: 'Full name: max 100 characters' });
        if (alias?.length > 50) return res.status(400).json({ error: 'Alias: max 50 characters' });
        if (phone?.length > 20) return res.status(400).json({ error: 'Phone: max 20 characters' });
        
        // Split name into first and last
        const nameParts = fullName.trim().split(/\s+/);
        const firstName = nameParts[0];
        const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : firstName;

        // FIX-014: Check email uniqueness before updating
        if (email) {
            const emailCheck = await pool.query(
                'SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2',
                [email, req.user.userId]
            );
            if (emailCheck.rows.length > 0) {
                return res.status(400).json({ error: 'Email already in use by another account' });
            }

            // N5: Require current password to change email — prevents account takeover via stolen session
            if (!currentPassword) {
                return res.status(400).json({ error: 'Current password is required to change your email address' });
            }
            const userResult = await pool.query('SELECT password_hash, email FROM users WHERE id = $1', [req.user.userId]);
            const valid = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
            if (!valid) {
                return res.status(403).json({ error: 'Current password is incorrect' });
            }
        }

        // N10: Fetch old email before update so we can alert it afterwards
        const oldEmailRow = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.userId]);
        const oldEmail = oldEmailRow.rows[0]?.email || null;

        // FIX-091: Wrap both UPDATEs in a transaction — prevents partial profile update
        await client.query('BEGIN');
        
        // Update player
        await client.query(
            `UPDATE players SET 
             full_name = $1, 
             first_name = $2, 
             last_name = $3, 
             alias = $4, 
             phone = $5, 
             updated_at = CURRENT_TIMESTAMP
             WHERE id = $6`,
            [fullName.trim(), firstName, lastName, alias?.trim(), phone?.trim(), req.user.playerId]
        );
        
        // Update email in users table
        if (email) {
            await client.query(
                'UPDATE users SET email = $1 WHERE id = $2',
                [email.toLowerCase(), req.user.userId]
            );
        }

        await client.query('COMMIT');
        res.json({ message: 'Profile updated successfully' });

        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'account_updated', req.user.playerId,
                `name:${fullName?.trim()} alias:${alias?.trim() || '-'} email:${email || '-'} phone:${phone ? 'updated' : '-'}`);

            // N10: Alert old email address when email is changed — lets player spot unauthorised takeover
            if (email && oldEmail && email.toLowerCase() !== oldEmail.toLowerCase()) {
                try {
                    await emailTransporter.sendMail({
                        from: '"TotalFooty" <totalfooty19@gmail.com>',
                        to: oldEmail,
                        subject: '⚠️ Your TotalFooty email address was changed',
                        html: wrapEmailHtml(`
                            <p style="color:#ccc;font-size:15px;margin:0 0 16px;">
                                The email address on your TotalFooty account was just changed to
                                <strong>${htmlEncode(email)}</strong>.
                            </p>
                            <p style="color:#ccc;font-size:15px;margin:0 0 16px;">
                                If you made this change, you can ignore this message.
                            </p>
                            <p style="color:#ff4444;font-size:15px;margin:0;">
                                If you did <strong>not</strong> make this change, contact us immediately at
                                <a href="mailto:totalfooty19@gmail.com" style="color:#ff4444;">totalfooty19@gmail.com</a>.
                            </p>
                        `)
                    });
                } catch (e) {
                    console.error('Email change alert failed (non-critical):', e.message);
                }
            }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Update failed' });
    } finally {
        client.release();
    }
});

// Upload profile photo (base64)
app.post('/api/players/me/photo', authenticateToken, async (req, res) => {
    try {
        const { photoData } = req.body; // Base64 string
        
        if (!photoData) {
            return res.status(400).json({ error: 'No photo data provided' });
        }

        // FIX-015: Guard against huge base64 payloads
        if (photoData.length > 2_000_000) {
            return res.status(400).json({ error: 'Photo too large. Max ~1.5MB.' });
        }

        // FIX-046: Check MIME prefix first
        const VALID_PREFIXES = {
            'data:image/jpeg;base64,': { magic: [0xFF, 0xD8, 0xFF], label: 'JPEG' },
            'data:image/png;base64,':  { magic: [0x89, 0x50, 0x4E, 0x47], label: 'PNG' },
            'data:image/webp;base64,': { magic: [0x52, 0x49, 0x46, 0x46], label: 'WebP' },
        };
        const matchedPrefix = Object.keys(VALID_PREFIXES).find(p => photoData.startsWith(p));
        if (!matchedPrefix) {
            return res.status(400).json({ error: 'Invalid image format. Only JPEG, PNG, and WebP are allowed.' });
        }

        // SEC-027: Validate magic bytes — prevents polyglot files that pass MIME-prefix-only checks
        const b64Data = photoData.slice(matchedPrefix.length);
        const rawBytes = Buffer.from(b64Data, 'base64');
        const expectedMagic = VALID_PREFIXES[matchedPrefix].magic;
        const actualBytes = [...rawBytes.slice(0, expectedMagic.length)];
        const magicOk = expectedMagic.every((byte, i) => actualBytes[i] === byte);
        if (!magicOk) {
            return res.status(400).json({ error: 'File contents do not match declared image type.' });
        }
        
        await pool.query(
            'UPDATE players SET photo_url = $1 WHERE id = $2',
            [photoData, req.user.playerId]
        );
        
        res.json({ message: 'Photo uploaded successfully' });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.put('/api/admin/players/:id/stats', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { overall, defending, strength, fitness, pace, decisions, assisting, shooting, goalkeeper } = req.body;
        
        await pool.query(
            `UPDATE players SET 
             overall_rating = $1, defending_rating = $2, strength_rating = $3,
             fitness_rating = $4, pace_rating = $5, decisions_rating = $6,
             assisting_rating = $7, shooting_rating = $8, goalkeeper_rating = $9,
             updated_at = CURRENT_TIMESTAMP
             WHERE id = $10`,
            [overall, defending, strength, fitness, pace, decisions, assisting, shooting, goalkeeper, req.params.id]
        );
        
        res.json({ message: 'Stats updated' });

        setImmediate(async () => {
            await statHistory(pool, req.params.id, req.user.playerId,
                { overall, defending, strength, fitness, pace, decisions, assisting, shooting, goalkeeper });
            await auditLog(pool, req.user.playerId, 'stats_updated', req.params.id,
                `OVR:${overall} DEF:${defending} STR:${strength} FIT:${fitness} PAC:${pace} DEC:${decisions} AST:${assisting} SHT:${shooting} GK:${goalkeeper}`);
        });
    } catch (error) {
        console.error('Update stats error:', error);
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/admin/players/:id/credits', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { amount, description } = req.body;

        // FIX-024: Validate amount and description
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount)) return res.status(400).json({ error: 'Amount must be a number' });
        if (!description?.trim()) return res.status(400).json({ error: 'Description is required' });
        if (Math.abs(parsedAmount) > 500) return res.status(400).json({ error: 'Amount too large — max ±£500' });

        await pool.query(
            'UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2',
            [parsedAmount, req.params.id]
        );
        
        await pool.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description, admin_id) VALUES ($1, $2, $3, $4, $5)',
            [req.params.id, amount, 'admin_adjustment', description, req.user.userId]
        );
        
        res.json({ message: 'Credits adjusted' });

        // Non-critical: notify player their balance was updated
        setImmediate(async () => {
            try {
                await sendNotification('balance_updated', req.params.id, {});
            } catch (e) {
                console.error('Balance notification failed (non-critical):', e.message);
            }
        });
    } catch (error) {
        console.error('Credit adjustment error:', error);
        res.status(500).json({ error: 'Adjustment failed' });
    }
});

// Update player (admin)
app.put('/api/admin/players/:playerId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        const {
            goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            total_wins, squad_number, phone, balance, alias,
            is_featured, social_tiktok, social_instagram, social_youtube, social_facebook
        } = req.body;
        
        // Calculate overall rating
        const overall_rating = (defending_rating || 0) + (strength_rating || 0) + (fitness_rating || 0) + 
                              (pace_rating || 0) + (decisions_rating || 0) + (assisting_rating || 0) + (shooting_rating || 0);
        
        // FIX-090: Check squad number uniqueness before updating
        if (squad_number !== undefined && squad_number !== null) {
            const squadCheck = await pool.query(
                'SELECT id FROM players WHERE squad_number = $1 AND id != $2',
                [squad_number, playerId]
            );
            if (squadCheck.rows.length > 0) {
                return res.status(400).json({ error: `Squad number ${squad_number} is already assigned to another player` });
            }
        }

        // Update player ratings and stats
        await pool.query(`
            UPDATE players SET
                goalkeeper_rating = $1,
                defending_rating = $2,
                strength_rating = $3,
                fitness_rating = $4,
                pace_rating = $5,
                decisions_rating = $6,
                assisting_rating = $7,
                shooting_rating = $8,
                overall_rating = $9,
                total_wins = $10,
                squad_number = $11,
                phone = $12,
                alias = COALESCE($13, alias),
                is_featured = COALESCE($14, is_featured),
                social_tiktok = $15,
                social_instagram = $16,
                social_youtube = $17,
                social_facebook = $18
            WHERE id = $19
        `, [goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            overall_rating, total_wins, squad_number, phone, alias || null,
            is_featured !== undefined ? is_featured : null,
            validateSocialUrl(social_tiktok), validateSocialUrl(social_instagram),
            validateSocialUrl(social_youtube), validateSocialUrl(social_facebook),
            playerId]);
        
        // FIX-053: Update balance with audit trail if changed
        if (balance !== undefined) {
            const prevResult = await pool.query('SELECT balance FROM credits WHERE player_id = $1', [playerId]);
            const prevBalance = prevResult.rows.length > 0 ? parseFloat(prevResult.rows[0].balance) : 0;
            const newBalance = parseFloat(balance);
            const diff = parseFloat((newBalance - prevBalance).toFixed(2));
            await pool.query('UPDATE credits SET balance = $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2', [newBalance, playerId]);
            if (diff !== 0) {
                await pool.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description, admin_id) VALUES ($1, $2, $3, $4, $5)',
                    [playerId, diff, 'admin_adjustment', `Direct balance set to £${newBalance.toFixed(2)} by admin`, req.user.userId]
                );
                // SEC-028: Audit log every balance change — tamper-evident record for disputes
                await auditLog(pool, req.user.playerId, 'balance_adjustment',
                    playerId, `prev=£${prevBalance.toFixed(2)} new=£${newBalance.toFixed(2)} diff=£${diff}`);
            }
        }
        
        res.json({ message: 'Player updated successfully' });

        setImmediate(async () => {
            await statHistory(pool, playerId, req.user.playerId,
                { overall: overall_rating, defending: defending_rating, strength: strength_rating,
                  fitness: fitness_rating, pace: pace_rating, decisions: decisions_rating,
                  assisting: assisting_rating, shooting: shooting_rating, goalkeeper: goalkeeper_rating });
            await auditLog(pool, req.user.playerId, 'player_updated', playerId,
                `OVR:${overall_rating} squad:${squad_number ?? '-'} alias:${alias ?? '-'}`);
        });
    } catch (error) {
        console.error('Update player error:', error);
        res.status(500).json({ error: 'Failed to update player' });
    }
});
app.delete('/api/admin/players/:playerId', authenticateToken, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { playerId } = req.params;
        
        await client.query('BEGIN');

        await client.query('UPDATE registrations SET registered_by_player_id = NULL WHERE registered_by_player_id = $1', [playerId]);
        await client.query('DELETE FROM registration_preferences WHERE registration_id IN (SELECT id FROM registrations WHERE player_id = $1)', [playerId]);
        await client.query('DELETE FROM registration_preferences WHERE target_player_id = $1', [playerId]);
        await client.query('DELETE FROM team_players WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM registrations WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM notifications WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM game_guests WHERE invited_by = $1', [playerId]);
        await client.query('DELETE FROM player_fixed_teams WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM player_badges WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM credit_transactions WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM credits WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM discipline_records WHERE player_id = $1', [playerId]);
        await client.query('DELETE FROM whatsapp_logs WHERE player_id = $1', [playerId]);
        await client.query('UPDATE players SET referred_by = NULL WHERE referred_by = $1', [playerId]);
        await client.query('UPDATE games SET motm_winner_id = NULL WHERE motm_winner_id = $1', [playerId]);
        
        // Delete player (cascade will handle remaining user record link)
        const result = await client.query('DELETE FROM players WHERE id = $1 RETURNING full_name, alias', [playerId]);
        
        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Player not found' });
        }
        
        await client.query('COMMIT');

        // SEC-030: Audit player deletion — permanent and irreversible, must always be traceable
        await auditLog(pool, req.user.playerId, 'player_deleted', playerId,
            `name="${result.rows[0].full_name}" alias="${result.rows[0].alias}"`);
        
        res.json({ 
            message: 'Player deleted successfully',
            player: result.rows[0]
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Delete player error:', error);
        res.status(500).json({ error: 'Failed to delete player' });
    } finally {
        client.release();
    }
});

// ==========================================
// BADGES SYSTEM
// ==========================================

// Get all badges
app.get('/api/badges', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM badges ORDER BY name'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get badges error:', error);
        res.status(500).json({ error: 'Failed to get badges' });
    }
});

// Update player badges (admin only)
app.put('/api/admin/players/:playerId/badges', authenticateToken, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { playerId } = req.params;
        const { badgeIds } = req.body;
        
        await client.query('BEGIN');

        // Capture before state for audit
        const beforeResult = await client.query(
            'SELECT b.name FROM player_badges pb JOIN badges b ON b.id = pb.badge_id WHERE pb.player_id = $1 ORDER BY b.name',
            [playerId]
        );
        const beforeNames = beforeResult.rows.map(r => r.name);
        
        // Remove all existing badges
        await client.query('DELETE FROM player_badges WHERE player_id = $1', [playerId]);
        
        // Add new badges
        let afterNames = [];
        for (const badgeId of badgeIds) {
            await client.query(
                'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2)',
                [playerId, badgeId]
            );
        }

        // Capture after state for audit
        if (badgeIds.length > 0) {
            const afterResult = await client.query(
                'SELECT b.name FROM player_badges pb JOIN badges b ON b.id = pb.badge_id WHERE pb.player_id = $1 ORDER BY b.name',
                [playerId]
            );
            afterNames = afterResult.rows.map(r => r.name);
        }
        
        await client.query('COMMIT');

        // Audit: log what changed
        const added = afterNames.filter(n => !beforeNames.includes(n));
        const removed = beforeNames.filter(n => !afterNames.includes(n));
        const detail = [
            added.length   ? 'added: ' + added.join(', ')   : '',
            removed.length ? 'removed: ' + removed.join(', ') : ''
        ].filter(Boolean).join(' | ') || 'no change';
        await auditLog(pool, req.user.playerId, 'badges_updated', playerId, detail);
        
        res.json({ message: 'Badges updated successfully' });

        // Non-critical: notify player of new badge
        setImmediate(async () => {
            try {
                await sendNotification('badge_awarded', playerId, {});
            } catch (e) {
                console.error('Badge notification failed (non-critical):', e.message);
            }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Update badges error:', error);
        res.status(500).json({ error: 'Failed to update badges' });
    } finally {
        client.release();
    }
});


// Auto-allocate badges based on player stats

async function autoAllocateBadges(playerId) {
    try {
        // Get player stats
        const playerResult = await pool.query(`
            SELECT 
                p.id,
                p.total_appearances,
                p.motm_wins,
                p.created_at,
                (SELECT json_agg(badge_id) FROM player_badges WHERE player_id = p.id) as current_badge_ids
            FROM players p
            WHERE p.id = $1
        `, [playerId]);
        
        if (playerResult.rows.length === 0) return;
        
        const player = playerResult.rows[0];
        const currentBadgeIds = player.current_badge_ids || [];
        
        // Get all auto-allocated badges
        const badgesResult = await pool.query(`
            SELECT id, name FROM badges WHERE is_auto_allocated = TRUE
        `);
        
        const badgesToAward = [];
        const badgesToRemove = [];
        
        for (const badge of badgesResult.rows) {
            const shouldHave = await checkBadgeCriteria(badge.name, player);
            const hasNow = currentBadgeIds.includes(badge.id);
            
            // Award badges if criteria met
            if (shouldHave && !hasNow) {
                badgesToAward.push(badge.id);
            }
            
            // ONLY remove "New" badge - preserve all other badges
            if (!shouldHave && hasNow && badge.name === 'New') {
                badgesToRemove.push(badge.id);
            }
        }
        
        // Award new badges
        for (const badgeId of badgesToAward) {
            await pool.query(
                'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [playerId, badgeId]
            );
            const badgeName = badgesResult.rows.find(b => b.id === badgeId)?.name || badgeId;
            await auditLog(pool, null, 'badge_auto_awarded', playerId, `badge: ${badgeName} (auto)`);
        }
        
        // Remove "New" badge if no longer applicable
        for (const badgeId of badgesToRemove) {
            await pool.query(
                'DELETE FROM player_badges WHERE player_id = $1 AND badge_id = $2',
                [playerId, badgeId]
            );
            const badgeName = badgesResult.rows.find(b => b.id === badgeId)?.name || badgeId;
            await auditLog(pool, null, 'badge_auto_removed', playerId, `badge: ${badgeName} (auto-expired)`);
        }
        
        return { awarded: badgesToAward.length, removed: badgesToRemove.length };
        
    } catch (error) {
        console.error('Auto allocate badges error:', error);
        return null;
    }
}

async function checkBadgeCriteria(badgeName, player) {
    switch (badgeName) {
        case '100 Apps':
            return player.total_appearances >= 100;
            
        case '250 Apps':
            return player.total_appearances >= 250;
            
        case '15 MOTM':
            return player.motm_wins >= 15;
            
        case 'MOTM Streak':
            // Won MOTM in 3 consecutive completed games they played in
            try {
                const streakResult = await pool.query(`
                    SELECT g.id, g.motm_winner_id
                    FROM games g
                    JOIN team_players tp ON tp.player_id = $1
                    JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                    WHERE g.game_status = 'completed' AND g.motm_winner_id IS NOT NULL
                    ORDER BY g.game_date DESC
                    LIMIT 3
                `, [player.id]);
                
                if (streakResult.rows.length < 3) return false;
                return streakResult.rows.every(row => row.motm_winner_id === player.id);
            } catch (err) {
                console.error('MOTM streak check error:', err.message);
                return false;
            }
            
        case 'New':
            // Less than 30 days since account creation
            if (!player.created_at) return false;
            const accountAge = (Date.now() - new Date(player.created_at)) / (1000 * 60 * 60 * 24);
            return accountAge < 30;
            
        default:
            return false;
    }
}

// Endpoint to trigger badge auto-allocation
app.post('/api/admin/players/:playerId/auto-badges', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        const result = await autoAllocateBadges(playerId);
        
        if (result) {
            res.json({ 
                message: 'Badges updated',
                awarded: result.awarded,
                removed: result.removed
            });
        } else {
            res.status(500).json({ error: 'Failed to allocate badges' });
        }
    } catch (error) {
        console.error('Auto badge allocation error:', error);
        res.status(500).json({ error: 'Failed to allocate badges' });
    }
});

// Auto-allocate badges for all players
app.post('/api/admin/badges/auto-allocate-all', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const playersResult = await pool.query('SELECT id FROM players');
        let totalAwarded = 0;
        let totalRemoved = 0;
        
        for (const player of playersResult.rows) {
            const result = await autoAllocateBadges(player.id);
            if (result) {
                totalAwarded += result.awarded;
                totalRemoved += result.removed;
            }
        }
        
        res.json({ 
            message: 'All players processed',
            totalAwarded,
            totalRemoved,
            playersProcessed: playersResult.rows.length
        });
    } catch (error) {
        console.error('Auto allocate all error:', error);
        res.status(500).json({ error: 'Failed to allocate badges' });
    }
});

// Admin: manually link a player's referrer
app.put('/api/admin/players/:playerId/referral', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        const { referredBy } = req.body;
        
        if (!referredBy) {
            return res.status(400).json({ error: 'referredBy (player ID) is required' });
        }
        
        // Verify both players exist
        const playerCheck = await pool.query('SELECT id, alias, full_name, referred_by FROM players WHERE id = $1', [playerId]);
        if (playerCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        const referrerCheck = await pool.query('SELECT id, alias, full_name FROM players WHERE id = $1', [referredBy]);
        if (referrerCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Referrer not found' });
        }
        
        // Prevent self-referral
        if (playerId === referredBy) {
            return res.status(400).json({ error: 'A player cannot refer themselves' });
        }
        
        // Update referred_by
        await pool.query('UPDATE players SET referred_by = $1 WHERE id = $2', [referredBy, playerId]);
        
        const player = playerCheck.rows[0];
        const referrer = referrerCheck.rows[0];
        console.log(`Admin manually linked referral: ${player.alias || player.full_name} referred by ${referrer.alias || referrer.full_name}`);
        
        res.json({ 
            message: `${player.alias || player.full_name} is now linked as referred by ${referrer.alias || referrer.full_name}`,
            player: { id: playerId, name: player.alias || player.full_name },
            referrer: { id: referredBy, name: referrer.alias || referrer.full_name }
        });
    } catch (error) {
        console.error('Admin set referral error:', error);
        res.status(500).json({ error: 'Failed to set referral' });
    }
});


// ==========================================
// VENUES API
// ==========================================

app.get('/api/venues', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, address, pitch_location, facilities, notes FROM venues ORDER BY name ASC'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching venues:', error);
        res.status(500).json({ error: 'Failed to fetch venues' });
    }
});

// ==========================================
// GAMES API
// ==========================================

app.get('/api/games', authenticateToken, async (req, res) => {
    try {
        const playerResult = await pool.query(
            'SELECT reliability_tier FROM players WHERE id = $1',
            [req.user.playerId]
        );
        
        const tier = playerResult.rows[0]?.reliability_tier || 'silver';
        
        // Check if player has TF All Star badge
        const allStarBadgeResult = await pool.query(`
            SELECT 1 FROM player_badges pb
            JOIN badges b ON b.id = pb.badge_id
            WHERE pb.player_id = $1 AND b.name = 'TF All Star'
        `, [req.user.playerId]);
        
        const hasAllStarBadge = allStarBadgeResult.rows.length > 0;
        
        // Check if player has CLM badge
        const clmBadgeResult = await pool.query(`
            SELECT 1 FROM player_badges pb
            JOIN badges b ON b.id = pb.badge_id
            WHERE pb.player_id = $1 AND b.name = 'CLM'
        `, [req.user.playerId]);
        
        const hasCLMBadge = clmBadgeResult.rows.length > 0;
        
        // Check if player has Misfits badge
        const misfitsBadgeResult = await pool.query(`
            SELECT 1 FROM player_badges pb
            JOIN badges b ON b.id = pb.badge_id
            WHERE pb.player_id = $1 AND b.name = 'Misfits'
        `, [req.user.playerId]);
        
        const hasMisfitsBadge = misfitsBadgeResult.rows.length > 0;
        
        // Tier-based visibility (exact requirements)
        let hoursAhead = 72; // silver default (72 hours = 3 days)
        if (tier === 'gold') hoursAhead = 28 * 24; // 28 days
        if (tier === 'bronze') hoursAhead = 24; // 24 hours
        if (tier === 'white' || tier === 'black') hoursAhead = 0; // banned - no games visible
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address,
                   g.teams_generated,
                   gs.series_name,
                   g.format as game_format,
                   TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'HH24:MI') as game_time,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'backup') as backup_count,
                   EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1) as is_registered,
                   (SELECT status FROM registrations WHERE game_id = g.id AND player_id = $1) as registration_status,
                   (SELECT backup_type FROM registrations WHERE game_id = g.id AND player_id = $1) as my_backup_type,
                   motm_p.alias as motm_winner_alias, motm_p.full_name as motm_winner_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN game_series gs ON gs.id = g.series_id
            LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
            WHERE (
                (g.game_status = 'available' AND g.game_date >= CURRENT_TIMESTAMP)
                OR (g.game_status = 'confirmed')
                ${isAdmin ? "OR (g.game_status = 'completed')" : ''}
            )
            ${isAdmin ? '' : hoursAhead > 0 ? 'AND g.game_date <= CURRENT_TIMESTAMP + INTERVAL \'' + hoursAhead + ' hours\'' : 'AND 1 = 0'}
            AND g.game_status != 'cancelled'
            ${!isAdmin && !hasAllStarBadge ? "AND (g.exclusivity IS NULL OR g.exclusivity != 'allstars')" : ''}
            ${!isAdmin && !hasCLMBadge ? "AND (g.exclusivity IS NULL OR g.exclusivity != 'clm')" : ''}
            ${!isAdmin && !hasMisfitsBadge ? "AND (g.exclusivity IS NULL OR g.exclusivity != 'misfits')" : ''}
            ORDER BY g.game_date DESC
        `, [req.user.playerId]);
        
        // Map venue names to their photo URLs
        const venuePhotoMap = {
            'Daimler Green': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Power League': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg'
        };
        
        // Add venue photos based on venue name
        const gamesWithPhotos = result.rows.map(game => {
            if (game.venue_name && venuePhotoMap[game.venue_name]) {
                game.venue_photo = venuePhotoMap[game.venue_name];
            }
            return game;
        });
        
        // Log first game to check teams_generated field
        if (gamesWithPhotos.length > 0) {
            console.log('Sample game data:', {
                id: gamesWithPhotos[0].id,
                current_players: gamesWithPhotos[0].current_players,
                max_players: gamesWithPhotos[0].max_players,
                teams_generated: gamesWithPhotos[0].teams_generated
            });
        }
        
        res.json(gamesWithPhotos);
    } catch (error) {
        console.error('Error fetching games:', error);
        res.status(500).json({ error: 'Failed to fetch games' });
    }
});

// Get completed games
app.get('/api/games/completed', authenticateToken, async (req, res) => {
    try {
        // FIX-074: Add pagination and replace correlated subqueries with JOIN aggregation
        const limit = Math.min(parseInt(req.query.limit) || 20, 50);
        const offset = Math.max(parseInt(req.query.offset) || 0, 0);

        const result = await pool.query(`
            SELECT g.*, v.name as venue_name,
                   COALESCE(rc.confirmed_count, 0) + COALESCE(gc.guest_count, 0) AS current_players,
                   p.full_name as motm_winner_name,
                   p.alias as motm_winner_alias
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN players p ON p.id = g.motm_winner_id
            LEFT JOIN (
                SELECT game_id, COUNT(*) AS confirmed_count
                FROM registrations WHERE status = 'confirmed'
                GROUP BY game_id
            ) rc ON rc.game_id = g.id
            LEFT JOIN (
                SELECT game_id, COUNT(*) AS guest_count
                FROM game_guests GROUP BY game_id
            ) gc ON gc.game_id = g.id
            WHERE g.game_status = 'completed'
            ORDER BY g.game_date DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);
        
        // Map venue names to their photo URLs
        const venuePhotoMap = {
            'Daimler Green': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Power League': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg'
        };
        
        // Format the response
        const games = result.rows.map(game => ({
            ...game,
            motm_winner_name: game.motm_winner_alias || game.motm_winner_name,
            venue_photo: game.venue_name && venuePhotoMap[game.venue_name] ? venuePhotoMap[game.venue_name] : null,
            game_time: new Date(game.game_date).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
            game_day: new Date(game.game_date).toLocaleDateString('en-US', { weekday: 'long' })
        }));
        
        res.json(games);
    } catch (error) {
        console.error('Get completed games error:', error);
        res.status(500).json({ error: 'Failed to get completed games' });
    }
});

app.get('/api/games/:id', authenticateToken, async (req, res) => {
    try {
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address,
                   gs.series_name,
                   g.format as game_format,
                   TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'HH24:MI') as game_time,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed' AND UPPER(TRIM(position_preference)) = 'GK') as gk_count,
                   (SELECT status FROM registrations WHERE game_id = g.id AND player_id = $2) as registration_status,
                   (SELECT backup_type FROM registrations WHERE game_id = g.id AND player_id = $2) as my_backup_type
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN game_series gs ON gs.id = g.series_id
            WHERE g.id = $1
        `, [req.params.id, req.user.playerId]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];

        // FIX-067: Enforce exclusivity — non-admins cannot access CLM/allstars games without the badge
        const isAdminUser = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (!isAdminUser && game.exclusivity === 'clm') {
            const hasCLM = await pool.query(
                `SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = $1 AND b.name = 'CLM'`,
                [req.user.playerId]
            );
            if (!hasCLM.rows.length) return res.status(403).json({ error: 'Access denied' });
        }
        if (!isAdminUser && game.exclusivity === 'allstars') {
            const hasAllstars = await pool.query(
                `SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = $1 AND b.name = 'Allstars'`,
                [req.user.playerId]
            );
            if (!hasAllstars.rows.length) return res.status(403).json({ error: 'Access denied' });
        }

        game.max_gk_slots = game.team_selection_type === 'vs_external' ? 1 : game.team_selection_type === 'tournament' ? (game.tournament_team_count || 4) : 2;
        game.gk_count = parseInt(game.gk_count) || 0;
        
        // Get registered players (confirmed)
        const playersResult = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.squad_number, p.reliability_tier, 
                   r.position_preference, r.status
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            ORDER BY r.registered_at
        `, [req.params.id]);
        
        game.registered_players = playersResult.rows;
        
        // Get backup players
        const backupsResult = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.squad_number,
                   r.backup_type, r.position_preference, r.registered_at
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1 AND r.status = 'backup'
            ORDER BY 
                CASE r.backup_type 
                    WHEN 'confirmed_backup' THEN 1 
                    WHEN 'gk_backup' THEN 2 
                    ELSE 3 
                END,
                r.registered_at ASC
        `, [req.params.id]);
        
        game.backup_players = backupsResult.rows;
        
        // Map venue names to their photo URLs
        const venuePhotoMap = {
            'Daimler Green': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Power League': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg'
        };
        
        if (game.venue_name && venuePhotoMap[game.venue_name]) {
            game.venue_photo = venuePhotoMap[game.venue_name];
        }
        
        // Check if current user has guest(s) on this game
        if (req.user && req.user.playerId) {
            try {
                const guestCheck = await pool.query(
                    'SELECT id, guest_name, guest_number, overall_rating FROM game_guests WHERE game_id = $1 AND invited_by = $2 ORDER BY guest_number ASC',
                    [req.params.id, req.user.playerId]
                );
                game.my_guests = guestCheck.rows;
                game.my_guest = guestCheck.rows.length > 0 ? guestCheck.rows[0] : null;
            } catch (guestErr) {
                game.my_guests = [];
                game.my_guest = null;
            }
        }
        
        // For tournament games, add per-team signup counts so UI can show slots remaining
        if (game.team_selection_type === 'tournament' && game.tournament_team_count) {
            try {
                const teamCountsResult = await pool.query(`
                    SELECT tournament_team_preference, COUNT(*) as count
                    FROM registrations
                    WHERE game_id = $1 AND status = 'confirmed' AND tournament_team_preference IS NOT NULL
                    GROUP BY tournament_team_preference
                `, [req.params.id]);
                game.tournament_team_counts = {};
                teamCountsResult.rows.forEach(r => {
                    game.tournament_team_counts[r.tournament_team_preference] = parseInt(r.count);
                });
                game.tournament_team_max = Math.floor(parseInt(game.max_players) / parseInt(game.tournament_team_count));
            } catch (e) {
                game.tournament_team_counts = {};
                game.tournament_team_max = null;
            }
        }
        
        res.json(game);
    } catch (error) {
        console.error('Error fetching game:', error);
        res.status(500).json({ error: 'Failed to fetch game' });
    }
});

app.post('/api/admin/games', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { 
            venueId, gameDate, maxPlayers, costPerPlayer, format, regularity, 
            exclusivity, positionType, teamSelectionType, externalOpponent, tfKitColor, oppKitColor,
            tournamentTeamCount, tournamentName, starRating,
            isVenueClash, venueClashTeam1Name, venueClashTeam2Name
        } = req.body;

        // FIX-023: Validate required game creation inputs
        if (!venueId) return res.status(400).json({ error: 'Venue is required' });
        if (!gameDate || isNaN(Date.parse(gameDate))) return res.status(400).json({ error: 'Valid game date is required' });
        const parsedMax = parseInt(maxPlayers);
        if (!parsedMax || parsedMax < 2 || parsedMax > 999) return res.status(400).json({ error: 'Max players must be between 2 and 999' });
        const parsedCost = parseFloat(costPerPlayer);
        if (isNaN(parsedCost) || parsedCost < 0 || parsedCost > 1000) return res.status(400).json({ error: 'Cost per player must be between £0 and £1000' });
        if (!format || format.trim().length < 2 || format.trim().length > 30) return res.status(400).json({ error: 'Format must be between 2 and 30 characters (e.g. 9v9, 11v11)' });
        // CRIT-35: Reject HTML characters in free-text game fields — these appear in emails and rendered HTML
        if (/[<>"'&]/.test(format)) return res.status(400).json({ error: 'Format contains invalid characters' });
        if (externalOpponent && /[<>"'&]/.test(externalOpponent)) return res.status(400).json({ error: 'Opponent name contains invalid characters' });
        if (externalOpponent && externalOpponent.trim().length > 60) return res.status(400).json({ error: 'Opponent name: max 60 characters' });
        if (!['weekly', 'one-off'].includes(regularity)) return res.status(400).json({ error: 'Regularity must be weekly or one-off' });

        // FIX-084: Validate venue exists before creating games (prevents FK violation 500 error)
        const venueCheck = await pool.query('SELECT id FROM venues WHERE id = $1', [venueId]);
        if (venueCheck.rows.length === 0) return res.status(400).json({ error: 'Invalid venue' });
        
        // CLM admins can only create CLM-exclusive games
        const isCLMAdminOnly = req.user.role !== 'admin' && req.user.role !== 'superadmin';
        const gameExclusivity = isCLMAdminOnly ? 'clm' : (exclusivity || 'everyone');
        
        // Tournament validation
        const selTypeCheck = teamSelectionType || 'normal';
        if (selTypeCheck === 'tournament') {
            if (![4, 6].includes(parseInt(tournamentTeamCount))) {
                return res.status(400).json({ error: 'Tournament must have 4 or 6 teams' });
            }
            if (regularity === 'weekly') {
                return res.status(400).json({ error: 'Tournaments can only be created as one-off events' });
            }
        }

        // Venue Clash validation — MISFITS-exclusive, both team names required
        const vcEnabled = isVenueClash === true || isVenueClash === 'true';
        if (vcEnabled) {
            if (gameExclusivity !== 'misfits') {
                return res.status(400).json({ error: 'Venue Clash games must be set to Misfits Only exclusivity' });
            }
            if (!venueClashTeam1Name || !venueClashTeam1Name.trim()) {
                return res.status(400).json({ error: 'Team 1 name is required for Venue Clash games' });
            }
            if (!venueClashTeam2Name || !venueClashTeam2Name.trim()) {
                return res.status(400).json({ error: 'Team 2 name is required for Venue Clash games' });
            }
        }
        
        const createdGames = [];
        
        if (regularity === 'weekly') {
            // FIX-068: Wrap entire series + 26 game INSERTs in a single transaction to prevent partial series
            const wClient = await pool.connect();
            try {
                await wClient.query('BEGIN');

                // FIX-019: Use sequence for race-condition-free series ID generation
                const seqResult = await wClient.query("SELECT nextval('game_series_name_seq') as n");
                const seriesIdValue = `TF${String(seqResult.rows[0].n).padStart(4, '0')}`;
            
                // Create series record for draft_memory and vs_external games
                let seriesUuid = null;
                const selType = teamSelectionType || 'normal';
                if (selType === 'draft_memory' || selType === 'vs_external') {
                    const seriesResult = await wClient.query(
                        'INSERT INTO game_series (series_name, series_type) VALUES ($1, $2) RETURNING id',
                        [seriesIdValue, selType]
                    );
                    seriesUuid = seriesResult.rows[0].id;
                }
            
                // Create 26 weeks of games (6 months)
                for (let week = 0; week < 26; week++) {
                    // FIX-DST: Use London-timezone-aware date to preserve local clock time
                    // across DST boundaries (clocks change in March/October)
                    const weekDate = addWeeksLondon(gameDate, week);
                    
                    const gameUrl = crypto.randomBytes(8).toString('hex');
                    const gameNumber = String(week + 1).padStart(2, '0');
                    const fullSeriesId = `${seriesIdValue}-${gameNumber}`;
                    
                    const result = await wClient.query(
                        `INSERT INTO games (
                            venue_id, game_date, max_players, cost_per_player, format, regularity, 
                            exclusivity, position_type, game_url, series_id, 
                            team_selection_type, external_opponent, tf_kit_color, opp_kit_color, star_rating,
                            is_venue_clash, venue_clash_team1_name, venue_clash_team2_name
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                        RETURNING id`,
                        [
                            venueId, weekDate.toISOString(), maxPlayers, costPerPlayer, format, 'weekly', 
                            gameExclusivity, positionType || 'outfield_gk', gameUrl, 
                            seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null,
                            starRating || null,
                            vcEnabled || false,
                            vcEnabled ? venueClashTeam1Name.trim() : null,
                            vcEnabled ? venueClashTeam2Name.trim() : null
                        ]
                    );
                    
                    createdGames.push({ id: result.rows[0].id, gameUrl, date: weekDate, seriesId: fullSeriesId });
                }

                await wClient.query('COMMIT');
                res.json({ 
                    message: `Created 26 weekly games (series ${seriesIdValue})`,
                    seriesId: seriesIdValue,
                    games: createdGames 
                });
                setImmediate(() => createdGames.forEach(g => 
                    gameAuditLog(pool, g.id, req.user.playerId, 'game_created',
                        `format:${format} type:normal cost:£${costPerPlayer} max:${maxPlayers} series:${seriesIdValue}`)
                ));
            } catch (e) {
                await wClient.query('ROLLBACK').catch(() => {});
                throw e;
            } finally {
                wClient.release();
            }
        } else {
            // Create single one-off game
            const gameUrl = crypto.randomBytes(8).toString('hex');
            const selType = teamSelectionType || 'normal';
            
            // Create series record for one-off draft_memory or vs_external (for scoreline tracking)
            let seriesUuid = null;
            if (selType === 'draft_memory' || selType === 'vs_external') {
                // FIX-019: Use sequence for atomic series ID generation
                const seqResult = await pool.query("SELECT nextval('game_series_name_seq') as n");
                const seriesIdValue = `TF${String(seqResult.rows[0].n).padStart(4, '0')}`;
                const seriesResult = await pool.query(
                    'INSERT INTO game_series (series_name, series_type) VALUES ($1, $2) RETURNING id',
                    [seriesIdValue, selType]
                );
                seriesUuid = seriesResult.rows[0].id;
            }
            
            const result = await pool.query(
                `INSERT INTO games (
                    venue_id, game_date, max_players, cost_per_player, format, regularity, 
                    exclusivity, position_type, game_url, series_id,
                    team_selection_type, external_opponent, tf_kit_color, opp_kit_color,
                    tournament_team_count, tournament_name, star_rating,
                    is_venue_clash, venue_clash_team1_name, venue_clash_team2_name
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                RETURNING id`,
                [
                    venueId, gameDate, maxPlayers, costPerPlayer, format, 'one-off', 
                    gameExclusivity, positionType || 'outfield_gk', gameUrl,
                    seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null,
                    selType === 'tournament' ? parseInt(tournamentTeamCount) : null,
                    selType === 'tournament' ? (tournamentName || null) : null,
                    starRating || null,
                    vcEnabled || false,
                    vcEnabled ? venueClashTeam1Name.trim() : null,
                    vcEnabled ? venueClashTeam2Name.trim() : null
                ]
            );
            
            res.json({ id: result.rows[0].id, gameUrl });
            setImmediate(() => gameAuditLog(pool, result.rows[0].id, req.user.playerId, 'game_created',
                `format:${format} type:${selType} cost:£${costPerPlayer} max:${maxPlayers}`));
        }
    } catch (error) {
        console.error('Create game error:', error);
        res.status(500).json({ error: 'Failed to create game' });
    }
});

// Get players registered for a specific game
app.get('/api/games/:id/players', authenticateToken, async (req, res) => {
    try {
        // Check if this is a draft_memory game so we can join fixed_team data
        const gameInfo = await pool.query(
            'SELECT team_selection_type, series_id FROM games WHERE id = $1',
            [req.params.id]
        );
        const isDraftMemory = gameInfo.rows.length > 0 &&
            gameInfo.rows[0].team_selection_type === 'draft_memory' &&
            gameInfo.rows[0].series_id;
        const seriesId = isDraftMemory ? gameInfo.rows[0].series_id : null;

        const result = await pool.query(`
            SELECT 
                r.id as registration_id,
                r.registered_by_player_id,
                reg_by.alias as registered_by_alias,
                reg_by.full_name as registered_by_full_name,
                p.id as player_id,
                p.id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.is_organiser,
                r.status,
                r.backup_type,
                r.is_comped,
                r.position_preference as positions,
                r.position_preference as position_preference,
                r.tournament_team_preference,
                t.team_name,
                ${isDraftMemory ? 'pft.fixed_team' : 'NULL::text AS fixed_team'},
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN players reg_by ON reg_by.id = r.registered_by_player_id
            LEFT JOIN team_players tp ON tp.player_id = p.id
                AND tp.team_id IN (SELECT id FROM teams WHERE game_id = $1)
            LEFT JOIN teams t ON t.id = tp.team_id
            ${isDraftMemory ? `LEFT JOIN player_fixed_teams pft ON pft.player_id = p.id AND pft.series_id = $2` : ''}
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status IN ('confirmed', 'backup')
            GROUP BY r.id, r.registered_by_player_id, reg_by.alias, reg_by.full_name,
                     p.id, p.full_name, p.alias, p.squad_number, p.is_organiser,
                     r.status, r.backup_type, r.is_comped,
                     r.position_preference, r.tournament_team_preference, t.team_name
                     ${isDraftMemory ? ', pft.fixed_team' : ''}
            ORDER BY 
                CASE r.status WHEN 'confirmed' THEN 1 WHEN 'backup' THEN 2 ELSE 3 END,
                ${isDraftMemory ? "CASE pft.fixed_team WHEN 'red' THEN 0 WHEN 'blue' THEN 2 ELSE 1 END," : ''}
                p.squad_number NULLS LAST, p.alias
        `, isDraftMemory ? [req.params.id, seriesId] : [req.params.id]);
        
        // FIX-070: Strip pair/avoid preferences for non-admins — sensitive interpersonal data
        const isAdminReq = req.user.role === 'admin' || req.user.role === 'superadmin';
        const players = isAdminReq
            ? result.rows
            : result.rows.map(({ pairs, avoids, ...safe }) => safe);

        // Append guests as pseudo-players so they appear in the confirmed player list
        const guestResult = await pool.query(`
            SELECT 
                NULL::integer as registration_id,
                gg.invited_by as registered_by_player_id,
                host.alias as registered_by_alias,
                host.full_name as registered_by_full_name,
                ('guest_' || gg.id::text) as player_id,
                ('guest_' || gg.id::text) as id,
                gg.guest_name as full_name,
                (gg.guest_name || ' (Guest)') as alias,
                NULL::integer as squad_number,
                'confirmed' as status,
                NULL::text as backup_type,
                'outfield' as positions,
                'outfield' as position_preference,
                NULL::text as tournament_team_preference,
                gg.team_name,
                NULL::text as fixed_team,
                NULL::integer[] as pairs,
                NULL::integer[] as avoids,
                TRUE as is_guest,
                gg.overall_rating
            FROM game_guests gg
            LEFT JOIN players host ON host.id = gg.invited_by
            WHERE gg.game_id = $1
            ORDER BY gg.guest_number
        `, [req.params.id]);

        res.json([...players, ...guestResult.rows]);
    } catch (error) {
        console.error('Get game players error:', error);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

app.post('/api/games/:id/register', authenticateToken, registrationLimiter, async (req, res) => {
    const client = await pool.connect();
    try {
        const { position, positions, pairs, avoids, backupType, tournamentTeamPreference, venueClashTeamPreference } = req.body;
        const gameId = req.params.id;
        const positionValue = positions || position || 'outfield';
        
        await client.query('BEGIN');
        
        // Lock the game row to prevent race conditions
        const gameLock = await client.query(`
            SELECT max_players, cost_per_player, exclusivity, 
                   player_editing_locked, team_selection_type, position_type, tournament_team_count,
                   series_id, game_status, game_date,
                   is_venue_clash, venue_clash_team1_name, venue_clash_team2_name
            FROM games
            WHERE id = $1
            FOR UPDATE
        `, [gameId]);
        
        if (gameLock.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameLock.rows[0];

        // FIX-006: Reject registration for cancelled or completed games
        if (!['available', 'confirmed'].includes(game.game_status)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'This game is no longer accepting registrations' });
        }
        
        // Get current player count separately
        const countResult = await client.query(
            "SELECT (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS current_players",
            [gameId]
        );
        game.current_players = parseInt(countResult.rows[0].current_players);
        
        // Check if game is locked for editing
        if (game.player_editing_locked) {
            await client.query('ROLLBACK');
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        // Check exclusivity restrictions
        if (game.exclusivity === 'allstars') {
            const badgeCheck = await client.query(`
                SELECT 1 FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'TF All Star'
            `, [req.user.playerId]);
            
            if (badgeCheck.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(403).json({ 
                    error: 'This is an All Star game. You need the TF All Star badge to register.',
                    requiresBadge: 'TF All Star'
                });
            }
        }
        
        if (game.exclusivity === 'clm') {
            const badgeCheck = await client.query(`
                SELECT 1 FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'CLM'
            `, [req.user.playerId]);

            if (badgeCheck.rows.length === 0) {
                // N6: Auto-grant CLM badge when player accesses a CLM game via shared URL
                const clmBadge = await client.query("SELECT id FROM badges WHERE name = 'CLM'");
                if (clmBadge.rows.length > 0) {
                    await client.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [req.user.playerId, clmBadge.rows[0].id]
                    );
                    await auditLog(pool, req.user.playerId, 'badge_auto_awarded', req.user.playerId, 'badge: CLM (auto-granted via CLM game registration)');
                }
            }
        }

        if (game.exclusivity === 'misfits') {
            const badgeCheck = await client.query(`
                SELECT 1 FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'Misfits'
            `, [req.user.playerId]);

            if (badgeCheck.rows.length === 0) {
                // N6: Auto-grant Misfits badge when player accesses a Misfits game via shared URL
                const misfitsBadge = await client.query("SELECT id FROM badges WHERE name = 'Misfits'");
                if (misfitsBadge.rows.length > 0) {
                    await client.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [req.user.playerId, misfitsBadge.rows[0].id]
                    );
                    await auditLog(pool, req.user.playerId, 'badge_auto_awarded', req.user.playerId, 'badge: Misfits (auto-granted via Misfits game registration)');
                }
            }
        }
        
        // Check if already registered
        const existingReg = await client.query(
            'SELECT id, status, backup_type FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (existingReg.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Already registered' });
        }
        
        const isFull = parseInt(game.current_players) >= parseInt(game.max_players);
        
        // GK slot check for confirmed registrations
        const isGKOnly = positionValue.trim().toUpperCase() === 'GK';
        if (!isFull && isGKOnly) {
            const maxGKSlots = game.team_selection_type === 'vs_external' ? 1 : game.team_selection_type === 'tournament' ? (game.tournament_team_count || 4) : 2;
            const gkCount = await client.query(`
                SELECT COUNT(*) as gk_count FROM registrations 
                WHERE game_id = $1 AND status = 'confirmed' 
                AND UPPER(TRIM(position_preference)) = 'GK'
            `, [gameId]);
            
            if (parseInt(gkCount.rows[0].gk_count) >= maxGKSlots) {
                await client.query('ROLLBACK');
                return res.status(409).json({ 
                    error: 'gk_full',
                    message: 'Please note, this game already has the maximum number of goalkeepers. To register, please adjust your position or choose another game.',
                    maxGKSlots
                });
            }
        }
        
        // COMP-001: Check if player is an organiser eligible for a free comp slot
        const organiserCheck = await client.query(
            'SELECT is_organiser FROM players WHERE id = $1',
            [req.user.playerId]
        );
        const isOrganiser = organiserCheck.rows[0]?.is_organiser || false;

        let isComped = false;
        if (isOrganiser) {
            const compCount = await client.query(
                "SELECT COUNT(*) as cnt FROM registrations WHERE game_id = $1 AND is_comped = TRUE",
                [gameId]
            );
            if (parseInt(compCount.rows[0].cnt) < 6) {
                isComped = true;
            }
        }

        // Determine registration status
        let status, regBackupType = null;
        
        if (isFull) {
            // Game is full - must be a backup registration
            if (!backupType || !['normal_backup', 'confirmed_backup', 'gk_backup'].includes(backupType)) {
                await client.query('ROLLBACK');
                return res.status(400).json({ 
                    error: 'game_full',
                    message: 'Game is full. Please choose a backup option.',
                    currentPlayers: parseInt(game.current_players),
                    maxPlayers: parseInt(game.max_players)
                });
            }
            
            // Validate GK backup - must have GK as only position
            if (backupType === 'gk_backup' && !isGKOnly) {
                await client.query('ROLLBACK');
                return res.status(400).json({ 
                    error: 'GK Backup is only available if GK is your only selected position.'
                });
            }
            
            status = 'backup';
            regBackupType = backupType;
            
            // For confirmed backup, deduct credits immediately (unless comped organiser)
            if (backupType === 'confirmed_backup') {
                if (!isComped && parseFloat(game.cost_per_player) > 0) {
                    const creditResult = await client.query(
                        'SELECT balance FROM credits WHERE player_id = $1',
                        [req.user.playerId]
                    );
                    
                    if (creditResult.rows.length === 0 || Math.round(parseFloat(creditResult.rows[0].balance) * 100) < Math.round(parseFloat(game.cost_per_player) * 100)) {
                        await client.query('ROLLBACK');
                        return res.status(400).json({ error: 'Insufficient credits for confirmed backup' });
                    }
                    
                    await client.query(
                        'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                        [game.cost_per_player, req.user.playerId]
                    );
                    
                    await client.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [req.user.playerId, -game.cost_per_player, 'game_fee', `Confirmed backup for game ${gameId}`]
                    );
                }
            }
        } else {
            // Game has space - confirm registration
            status = 'confirmed';
            
            // Deduct credits (skip for comped organisers and free games)
            if (!isComped && parseFloat(game.cost_per_player) > 0) {
                const creditResult = await client.query(
                    'SELECT balance FROM credits WHERE player_id = $1',
                    [req.user.playerId]
                );
                
                if (creditResult.rows.length === 0 || Math.round(parseFloat(creditResult.rows[0].balance) * 100) < Math.round(parseFloat(game.cost_per_player) * 100)) {
                    await client.query('ROLLBACK');
                    return res.status(400).json({ error: 'Insufficient credits' });
                }
                
                await client.query(
                    'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                    [game.cost_per_player, req.user.playerId]
                );
                
                await client.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                    [req.user.playerId, -game.cost_per_player, 'game_fee', `Registration for game ${gameId}`]
                );
            }
        }
        
        // Register player
        const regResult = await client.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference, backup_type, tournament_team_preference, venue_clash_team_preference, amount_paid, is_comped)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [gameId, req.user.playerId, status, positionValue, regBackupType,
             game.team_selection_type === 'tournament' ? (tournamentTeamPreference || null) : null,
             game.is_venue_clash ? (venueClashTeamPreference || null) : null,
             isComped ? 0 : (status === 'confirmed' ? game.cost_per_player : 0),
             isComped]
        );
        
        const registrationId = regResult.rows[0].id;
        
        // Insert pair preferences (only for confirmed players)
        if (status === 'confirmed' && pairs && Array.isArray(pairs)) {
            for (const pairPlayerId of pairs) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        
        // Insert avoid preferences (only for confirmed players)
        if (status === 'confirmed' && avoids && Array.isArray(avoids)) {
            for (const avoidPlayerId of avoids) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid')`,
                    [registrationId, avoidPlayerId]
                );
            }
        }
        
        await client.query('COMMIT');
        
        // For draft_memory games — look up if this player has a memorised team in this series
        let fixedTeam = null;
        if (status === 'confirmed' && game.team_selection_type === 'draft_memory' && game.series_id) {
            try {
                const ftResult = await pool.query(
                    'SELECT fixed_team FROM player_fixed_teams WHERE player_id = $1 AND series_id = $2',
                    [req.user.playerId, game.series_id]
                );
                fixedTeam = ftResult.rows[0]?.fixed_team || null;
            } catch (e) {
                // non-critical
            }
        }
        
        // Build response
        let message;
        if (status === 'confirmed') {
            if (isComped) {
                message = "Thank you for signing up, this game is covered by the GAFFA — appreciate everything you guys do to make TF great!";
            } else {
                message = fixedTeam
                    ? `Registered successfully! You've been placed in the ${fixedTeam.charAt(0).toUpperCase() + fixedTeam.slice(1)} team based on previous games.`
                    : 'Registered successfully';
            }
        } else if (regBackupType === 'confirmed_backup') {
            message = `You're on the confirmed backup list. £${parseFloat(game.cost_per_player).toFixed(2)} has been deducted and you'll be first in line if a spot opens. If you don't get on, you'll be refunded after the game.`;
        } else if (regBackupType === 'gk_backup') {
            message = "You're on the GK backup list. You'll be notified if a GK spot becomes available.";
        } else {
            message = "You're on the backup list. You'll be notified if a space becomes available.";
        }
        
        res.json({ message, status, backupType: regBackupType, fixedTeam, isComped });

        // Non-critical: fire notifications + audit after response is sent
        setImmediate(async () => {
            try {
                const evtType = status === 'backup'
                    ? (regBackupType === 'confirmed_backup' ? 'confirmed_backup_joined'
                        : regBackupType === 'gk_backup' ? 'gk_backup_joined' : 'backup_joined')
                    : 'signed_up';
                const evtDetail = `Position: ${positionValue}${regBackupType ? ' | Backup type: ' + regBackupType : ''}${isComped ? ' | Comped' : ''}`;
                await registrationEvent(pool, gameId, req.user.playerId, evtType, evtDetail);
                await gameAuditLog(pool, gameId, null,
                    status === 'backup' ? 'player_backup_joined' : 'player_signed_up',
                    `Player ID ${req.user.playerId} — ${evtDetail}`);
            } catch (e) { /* non-critical */ }
            try {
                const gameData = await getGameDataForNotification(gameId);
                const notifType = status === 'confirmed' ? 'game_registered' : 'backup_added';
                await sendNotification(notifType, req.user.playerId, gameData);
                // Superadmin: notify on game/tournament registration
                const playerRow = await pool.query(
                    'SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                    [req.user.playerId]
                );
                const pName = playerRow.rows[0]?.alias || playerRow.rows[0]?.full_name || req.user.playerId;
                const pEmail = playerRow.rows[0]?.email || '';
                const isTournament = (await pool.query('SELECT team_selection_type FROM games WHERE id = $1', [gameId])).rows[0]?.team_selection_type === 'tournament';
                const regType = status === 'confirmed' ? 'Confirmed' : `Backup (${regBackupType || 'standard'})`;
                await notifyAdmin(
                    `${isTournament ? '🏆 Tournament' : '⚽ Game'} Registration — ${pName}`,
                    [
                        ['Player', pName],
                        ['Email', pEmail],
                        ['Game', `${gameData.day} ${gameData.time}`],
                        ['Venue', gameData.venue],
                        ['Status', regType],
                        ['Position', positionValue],
                    ]
                );
            } catch (e) {
                console.error('Registration notification failed (non-critical):', e.message);
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    } finally {
        client.release();
    }
});


// ==========================================
// GUEST +1 SYSTEM
// ==========================================

// Add a +1 guest to a game
app.post('/api/games/:id/add-guest', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const gameId = req.params.id;
        const { guestName, tournamentTeamPreference } = req.body;
        const playerId = req.user.playerId;

        if (!guestName || guestName.trim().length < 2) {
            client.release();
            return res.status(400).json({ error: "Please provide the guest's name (at least 2 characters)" });
        }

        // FIX-080: Guest name max length
        if (guestName.trim().length > 50) {
            client.release();
            return res.status(400).json({ error: 'Guest name must be 50 characters or fewer' });
        }

        await client.query('BEGIN');

        // Check player is registered and confirmed for this game
        const regCheck = await client.query(
            "SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'",
            [gameId, playerId]
        );
        if (regCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'You must be registered for this game to add a +1' });
        }

        // Count how many guests this player already has on this game
        const existingGuests = await client.query(
            'SELECT COUNT(*) as count FROM game_guests WHERE game_id = $1 AND invited_by = $2',
            [gameId, playerId]
        );
        const guestCount = parseInt(existingGuests.rows[0].count);
        const nextGuestNumber = guestCount + 1;

        // Lock game row and check capacity
        const gameLock = await client.query(
            'SELECT max_players, cost_per_player, player_editing_locked, teams_generated, game_status FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        if (gameLock.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameLock.rows[0];

        // FIX-081: Block guest addition for non-active games
        if (!['available', 'confirmed'].includes(game.game_status)) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'This game is no longer accepting guests' });
        }

        if (game.player_editing_locked) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(423).json({ error: 'Game is currently being edited by an admin. Please try again shortly.' });
        }

        // FIX-018: Block guest addition after teams have been generated
        if (game.teams_generated) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'Cannot add a guest after teams have been generated' });
        }

        // Count current players (confirmed registrations + guests)
        const countResult = await client.query(
            `SELECT 
                (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed') +
                (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS total_players`,
            [gameId]
        );
        const totalPlayers = parseInt(countResult.rows[0].total_players);

        if (totalPlayers >= parseInt(game.max_players)) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'Game is full - no space for another guest' });
        }

        // Check player has enough credits to pay for guest
        const cost = parseFloat(game.cost_per_player);
        const creditResult = await client.query(
            'SELECT balance FROM credits WHERE player_id = $1',
            [playerId]
        );
        if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < cost) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: `Insufficient credits. You need £${cost.toFixed(2)} to add a guest.` });
        }

        // Deduct credits from the inviting player
        await client.query(
            'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
            [cost, playerId]
        );
        await client.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
            [playerId, -cost, 'game_fee', `+1 guest (${guestName.trim()}) for game`]
        );

        // Get player's overall rating (compute from individual stats if overall_rating is NULL)
        const playerRating = await client.query(
            `SELECT overall_rating, defending_rating, strength_rating, fitness_rating,
                    pace_rating, decisions_rating, assisting_rating, shooting_rating
             FROM players WHERE id = $1`,
            [playerId]
        );
        const pr = playerRating.rows[0] || {};
        const computedOverall = (pr.overall_rating != null)
            ? parseInt(pr.overall_rating)
            : (parseInt(pr.defending_rating || 0) + parseInt(pr.strength_rating || 0) +
               parseInt(pr.fitness_rating || 0) + parseInt(pr.pace_rating || 0) +
               parseInt(pr.decisions_rating || 0) + parseInt(pr.assisting_rating || 0) +
               parseInt(pr.shooting_rating || 0));
        const guestRating = Math.max(0, computedOverall - 2);

        // Insert guest record
        await client.query(
            `INSERT INTO game_guests (game_id, invited_by, guest_name, overall_rating, amount_paid, guest_number, tournament_team_preference)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [gameId, playerId, guestName.trim(), guestRating, cost, nextGuestNumber, tournamentTeamPreference || null]
        );

        // Get player's referral code — generate one on the fly if missing (legacy accounts)
        const refResult = await client.query(
            'SELECT referral_code FROM players WHERE id = $1',
            [playerId]
        );
        let referralCode = refResult.rows[0]?.referral_code;
        if (!referralCode) {
            referralCode = 'TF' + crypto.randomBytes(4).toString('hex').toUpperCase();
            await client.query('UPDATE players SET referral_code = $1 WHERE id = $2', [referralCode, playerId]);
            await pool.query(
                'INSERT INTO referrals (referrer_id, referral_code) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [playerId, referralCode]
            );
        }

        await client.query('COMMIT');

        res.json({
            message: `${guestName.trim()} has been added as your guest #${nextGuestNumber}!`,
            guestRating,
            guestNumber: nextGuestNumber,
            totalGuests: nextGuestNumber,
            amountCharged: cost,
            referralLink: referralCode ? `https://totalfooty.co.uk/vibecoding/?ref=${referralCode}` : null,
            referralPrompt: 'Refer a friend for future rewards as they join and play with Total Footy! Here is your personalised link - send it to them now!'
        });
        setImmediate(async () => {
            await gameAuditLog(pool, req.params.id, null, 'guest_added',
                `Guest: ${guestName.trim()} | Host: Player ${req.user.playerId} | OVR: ${guestRating} | Paid: £${cost.toFixed(2)}`);
            try {
                const hostRow = await pool.query(
                    'SELECT p.full_name, p.alias FROM players p WHERE p.id = $1', [req.user.playerId]
                );
                const hostName = hostRow.rows[0]?.alias || hostRow.rows[0]?.full_name || req.user.playerId;
                const gameData = await getGameDataForNotification(req.params.id);
                await notifyAdmin('👤 Guest Added — ' + guestName.trim(), [
                    ['Guest', guestName.trim()],
                    ['Host', hostName],
                    ['Rating', String(guestRating)],
                    ['Cost', '£' + cost.toFixed(2)],
                    ['Game', gameData.day + ' ' + gameData.time],
                    ['Venue', gameData.venue],
                ]);
            } catch (e) { /* non-critical */ }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Add guest error:', error);
        res.status(500).json({ error: 'Failed to add guest' });
    } finally {
        client.release();
    }
});

// Remove +1 guest from a game (with refund)
app.delete('/api/games/:id/remove-guest', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const gameId = req.params.id;
        const playerId = req.user.playerId;
        const { guestId } = req.body;

        await client.query('BEGIN');

        // Check game isn't locked or teams generated
        const gameCheck = await client.query(
            'SELECT player_editing_locked, teams_generated FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        if (gameCheck.rows[0]?.player_editing_locked) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(423).json({ error: 'Game is currently being edited by an admin.' });
        }
        if (gameCheck.rows[0]?.teams_generated) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'Cannot remove guest - teams already generated.' });
        }

        // Lock credits row to prevent concurrent exploits
        await client.query('SELECT id FROM credits WHERE player_id = $1 FOR UPDATE', [playerId]);

        // Find and delete the specific guest (or the most recent one if no guestId given)
        let guestResult;
        if (guestId) {
            guestResult = await client.query(
                'DELETE FROM game_guests WHERE id = $1 AND game_id = $2 AND invited_by = $3 RETURNING guest_name, amount_paid, guest_number',
                [guestId, gameId, playerId]
            );
        } else {
            // Fallback: remove the last-added guest for this player
            guestResult = await client.query(
                'DELETE FROM game_guests WHERE id = (SELECT id FROM game_guests WHERE game_id = $1 AND invited_by = $2 ORDER BY guest_number DESC LIMIT 1) RETURNING guest_name, amount_paid, guest_number',
                [gameId, playerId]
            );
        }

        if (guestResult.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(404).json({ error: 'No guest found for this game' });
        }

        const guest = guestResult.rows[0];
        const refundAmt = parseFloat(guest.amount_paid || 0);

        // Refund the inviting player
        if (refundAmt > 0) {
            await client.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [refundAmt, playerId]
            );
            await client.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [playerId, refundAmt, 'refund', `Guest (${guest.guest_name}) removed - refund`]
            );
        }

        // Re-number remaining guests for this player so numbers stay sequential
        const remaining = await client.query(
            'SELECT id FROM game_guests WHERE game_id = $1 AND invited_by = $2 ORDER BY guest_number ASC',
            [gameId, playerId]
        );
        for (let i = 0; i < remaining.rows.length; i++) {
            await client.query(
                'UPDATE game_guests SET guest_number = $1 WHERE id = $2',
                [i + 1, remaining.rows[i].id]
            );
        }

        await client.query('COMMIT');

        res.json({
            message: `${guest.guest_name} removed. £${refundAmt.toFixed(2)} refunded to your balance.`
        });
        setImmediate(() => gameAuditLog(pool, req.body.gameId || req.params.id, null, 'guest_removed',
            `Guest: ${guest.guest_name} | Host: Player ${req.user.playerId} | Refunded: £${refundAmt.toFixed(2)}`));
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Remove guest error:', error);
        res.status(500).json({ error: 'Failed to remove guest' });
    } finally {
        client.release();
    }
});

// DELETE /api/games/:gameId/remove-my-registration/:registrationId
// Allows the player who signed up a friend to remove them (without game lock).
// Only works if the calling player is the registered_by_player_id on the registration.
app.delete('/api/games/:gameId/remove-my-registration/:registrationId', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId, registrationId } = req.params;
        const playerId = req.user.playerId;

        await client.query('BEGIN');

        // Fetch the registration — must belong to this game and be registered by this player
        const regResult = await client.query(
            `SELECT r.id, r.player_id, r.status, r.amount_paid, r.registered_by_player_id,
                    p.alias, p.full_name,
                    g.game_status, g.teams_generated, g.player_editing_locked
             FROM registrations r
             JOIN players p ON p.id = r.player_id
             JOIN games g ON g.id = $1
             WHERE r.id = $2 AND r.game_id = $1`,
            [gameId, registrationId]
        );

        if (regResult.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(404).json({ error: 'Registration not found' });
        }

        const reg = regResult.rows[0];

        // Ensure the calling player was the one who registered this person
        if (reg.registered_by_player_id !== playerId) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(403).json({ error: 'You can only remove players you personally signed up' });
        }

        // Block if game is past completion
        if (!['available', 'confirmed'].includes(reg.game_status)) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'Cannot remove player from a completed or cancelled game' });
        }

        // Block if teams generated (same rule as admin endpoint for safety)
        if (reg.teams_generated) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'Cannot remove a player after teams have been generated. Ask an admin.' });
        }

        const playerName = reg.alias || reg.full_name;
        const refundAmt = parseFloat(reg.amount_paid || 0);

        // Delete the registration
        await client.query('DELETE FROM registrations WHERE id = $1', [registrationId]);

        // Refund whoever paid (the registering player)
        if (refundAmt > 0) {
            await client.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [refundAmt, playerId]
            );
            await client.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [playerId, refundAmt, 'refund', `Removed ${playerName} from game`]
            );
        }

        await client.query('COMMIT');

        res.json({
            message: `${playerName} has been removed.${refundAmt > 0 ? ` £${refundAmt.toFixed(2)} refunded to your balance.` : ''}`
        });
        setImmediate(() => gameAuditLog(pool, gameId, null, 'player_removed',
            `Player: ${playerName} removed by registering player ${playerId} | Refunded: £${refundAmt.toFixed(2)}`));

    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Remove my registration error:', error);
        res.status(500).json({ error: 'Failed to remove player' });
    } finally {
        client.release();
    }
});

// POST /api/games/:id/register-friend
// A confirmed player signs up another registered player for the same game.
// Credits are deducted from the registering player. Friend's tier window applies.
// If the registering player holds the exclusivity badge, the friend is exempt from that check.
app.post('/api/games/:id/register-friend', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const { friendPlayerId, position, backupType, tournamentTeamPreference } = req.body;
        const gameId = req.params.id;
        const registeringPlayerId = req.user.playerId;
        const positionValue = position || 'outfield';

        if (!friendPlayerId) {
            return res.status(400).json({ error: 'friendPlayerId is required' });
        }
        if (String(friendPlayerId) === String(registeringPlayerId)) {
            return res.status(400).json({ error: 'You cannot sign yourself up via this route' });
        }

        await client.query('BEGIN');

        // Lock game row to prevent race conditions
        const gameLock = await client.query(`
            SELECT max_players, cost_per_player, exclusivity,
                   player_editing_locked, team_selection_type, position_type, tournament_team_count,
                   series_id, game_status, game_date
            FROM games WHERE id = $1 FOR UPDATE
        `, [gameId]);

        if (gameLock.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameLock.rows[0];

        if (!['available', 'confirmed'].includes(game.game_status)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'This game is no longer accepting registrations' });
        }

        if (game.player_editing_locked) {
            await client.query('ROLLBACK');
            return res.status(423).json({ error: 'Game is currently being edited by an admin. Please try again in a few minutes.' });
        }

        // Registering player must be confirmed in this game
        const myReg = await client.query(
            "SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'",
            [gameId, registeringPlayerId]
        );
        if (myReg.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'You must be confirmed in this game to sign up a friend' });
        }

        // Fetch friend details
        const friendResult = await client.query(
            'SELECT id, alias, full_name, reliability_tier FROM players WHERE id = $1',
            [friendPlayerId]
        );
        if (friendResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Player not found' });
        }
        const friend = friendResult.rows[0];
        const friendName = friend.alias || friend.full_name;

        // Banned tiers cannot be registered
        if (friend.reliability_tier === 'white' || friend.reliability_tier === 'black') {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: `${friendName} is not eligible to register for games` });
        }

        // Friend must not already be registered (any status)
        const existingReg = await client.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, friendPlayerId]
        );
        if (existingReg.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: `${friendName} is already registered for this game` });
        }

        // Tier timing window — apply the FRIEND's tier, as if they registered themselves
        const friendTier = friend.reliability_tier || 'silver';
        let hoursAhead = 72;
        if (friendTier === 'gold') hoursAhead = 28 * 24;
        if (friendTier === 'bronze') hoursAhead = 24;

        const windowCheck = await client.query(
            `SELECT 1 FROM games WHERE id = $1 AND game_date <= CURRENT_TIMESTAMP + ($2 || ' hours')::INTERVAL`,
            [gameId, hoursAhead.toString()]
        );
        if (windowCheck.rows.length === 0) {
            const tierLabel = friendTier.charAt(0).toUpperCase() + friendTier.slice(1);
            await client.query('ROLLBACK');
            return res.status(403).json({ error: `This game isn't open for ${friendName}'s tier (${tierLabel}) yet` });
        }

        // Exclusivity badge checks:
        // If the REGISTERING player holds the badge, the friend is exempt — they are vouching for them.
        // If neither holds the badge, registration is blocked.
        if (game.exclusivity === 'allstars') {
            const regBadge = await client.query(`
                SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'TF All Star'
            `, [registeringPlayerId]);
            if (regBadge.rows.length === 0) {
                const friendBadge = await client.query(`
                    SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                    WHERE pb.player_id = $1 AND b.name = 'TF All Star'
                `, [friendPlayerId]);
                if (friendBadge.rows.length === 0) {
                    await client.query('ROLLBACK');
                    return res.status(403).json({ error: `This is an All Star game. Neither you nor ${friendName} has the required badge.` });
                }
            }
        }

        if (game.exclusivity === 'clm') {
            const regBadge = await client.query(`
                SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'CLM'
            `, [registeringPlayerId]);
            if (regBadge.rows.length === 0) {
                const friendBadge = await client.query(`
                    SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                    WHERE pb.player_id = $1 AND b.name = 'CLM'
                `, [friendPlayerId]);
                if (friendBadge.rows.length === 0) {
                    await client.query('ROLLBACK');
                    return res.status(403).json({ error: `This is a CLM exclusive game. Neither you nor ${friendName} has the required badge.` });
                }
            }
        }

        if (game.exclusivity === 'misfits') {
            const regBadge = await client.query(`
                SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'Misfits'
            `, [registeringPlayerId]);
            if (regBadge.rows.length === 0) {
                const friendBadge = await client.query(`
                    SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                    WHERE pb.player_id = $1 AND b.name = 'Misfits'
                `, [friendPlayerId]);
                if (friendBadge.rows.length === 0) {
                    await client.query('ROLLBACK');
                    return res.status(403).json({ error: `This is a Misfits game. Neither you nor ${friendName} has the required badge.` });
                }
            }
        }

        // Current player count
        const countResult = await client.query(
            "SELECT (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS current_players",
            [gameId]
        );
        const currentPlayers = parseInt(countResult.rows[0].current_players);
        const isFull = currentPlayers >= parseInt(game.max_players);

        // GK slot check
        const isGKOnly = positionValue.trim().toUpperCase() === 'GK';
        if (!isFull && isGKOnly) {
            const maxGKSlots = game.team_selection_type === 'vs_external' ? 1 : game.team_selection_type === 'tournament' ? (game.tournament_team_count || 4) : 2;
            const gkCount = await client.query(`
                SELECT COUNT(*) as gk_count FROM registrations
                WHERE game_id = $1 AND status = 'confirmed' AND UPPER(TRIM(position_preference)) = 'GK'
            `, [gameId]);
            if (parseInt(gkCount.rows[0].gk_count) >= maxGKSlots) {
                await client.query('ROLLBACK');
                return res.status(409).json({ error: `GK spots are full. Please choose a different position for ${friendName}.` });
            }
        }

        // Determine status and handle credit deduction from REGISTERING PLAYER
        let status, regBackupType = null;

        if (isFull) {
            if (!backupType || !['normal_backup', 'confirmed_backup', 'gk_backup'].includes(backupType)) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    error: 'game_full',
                    message: 'Game is full. Please choose a backup option for your friend.',
                    currentPlayers,
                    maxPlayers: parseInt(game.max_players)
                });
            }
            if (backupType === 'gk_backup' && !isGKOnly) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'GK Backup requires GK as the only selected position.' });
            }
            status = 'backup';
            regBackupType = backupType;

            if (backupType === 'confirmed_backup') {
                const creditResult = await client.query('SELECT balance FROM credits WHERE player_id = $1', [registeringPlayerId]);
                if (creditResult.rows.length === 0 || Math.round(parseFloat(creditResult.rows[0].balance) * 100) < Math.round(parseFloat(game.cost_per_player) * 100)) {
                    await client.query('ROLLBACK');
                    return res.status(400).json({ error: 'Insufficient credits for confirmed backup' });
                }
                await client.query('UPDATE credits SET balance = balance - $1 WHERE player_id = $2', [game.cost_per_player, registeringPlayerId]);
                await client.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                    [registeringPlayerId, -game.cost_per_player, 'game_fee', `Confirmed backup for ${friendName} in game ${gameId}`]
                );
            }
        } else {
            status = 'confirmed';
            const creditResult = await client.query('SELECT balance FROM credits WHERE player_id = $1', [registeringPlayerId]);
            if (creditResult.rows.length === 0 || Math.round(parseFloat(creditResult.rows[0].balance) * 100) < Math.round(parseFloat(game.cost_per_player) * 100)) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'Insufficient credits' });
            }
            await client.query('UPDATE credits SET balance = balance - $1 WHERE player_id = $2', [game.cost_per_player, registeringPlayerId]);
            await client.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [registeringPlayerId, -game.cost_per_player, 'game_fee', `Registration for ${friendName} in game ${gameId}`]
            );
        }

        // Insert registration under friend's player_id, recording who paid
        await client.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference, backup_type, amount_paid, registered_by_player_id, tournament_team_preference)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
                gameId, friendPlayerId, status, positionValue, regBackupType,
                (status === 'confirmed' || regBackupType === 'confirmed_backup') ? game.cost_per_player : 0,
                registeringPlayerId,
                tournamentTeamPreference || null
            ]
        );

        await client.query('COMMIT');

        let message;
        if (status === 'confirmed') {
            message = `${friendName} has been registered! £${parseFloat(game.cost_per_player).toFixed(2)} deducted from your balance.`;
        } else if (regBackupType === 'confirmed_backup') {
            message = `${friendName} has been added to the confirmed backup list. £${parseFloat(game.cost_per_player).toFixed(2)} deducted from your balance.`;
        } else {
            message = `${friendName} has been added to the backup list.`;
        }

        res.json({ message, status, backupType: regBackupType });

        // Non-critical: notify friend and registering player, and send emails — fires after response
        setImmediate(async () => {
            try {
                // Fetch names and emails for both players
                const regPlayerResult = await pool.query(
                    'SELECT p.alias, p.full_name, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                    [registeringPlayerId]
                );
                const friendEmailResult = await pool.query(
                    'SELECT p.alias, p.full_name, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                    [friendPlayerId]
                );
                const regName = regPlayerResult.rows[0]?.alias || regPlayerResult.rows[0]?.full_name || 'A teammate';
                const regEmail = regPlayerResult.rows[0]?.email;
                const friendFullName = friendEmailResult.rows[0]?.full_name || friendName;
                const friendEmail = friendEmailResult.rows[0]?.email;

                const gameData = await getGameDataForNotification(gameId);
                const gameDate = gameData.game_date || gameData.day || 'upcoming game';
                const venue = gameData.venue || 'the venue';
                const gameUrl = `https://totalfooty.co.uk/vibecoding/game.html?url=${gameData.game_url || ''}`;

                // Push notification to friend
                const notifType = status === 'confirmed' ? 'game_registered' : 'backup_added';
                const friendNotifMsg = status === 'confirmed'
                    ? `${regName} has signed you up for ${gameDate} at ${venue}!`
                    : `${regName} has put you on the backup list for ${gameDate} at ${venue}.`;
                await pool.query(
                    'INSERT INTO notifications (player_id, type, message, game_id) VALUES ($1, $2, $3, $4)',
                    [friendPlayerId, notifType, friendNotifMsg, gameId]
                );
                await sendNotification(notifType, friendPlayerId, gameData);

                // Push notification to registering player
                const regNotifMsg = status === 'confirmed'
                    ? `You signed up ${friendName} for ${gameDate} at ${venue}. £${parseFloat(game.cost_per_player).toFixed(2)} deducted.`
                    : `You added ${friendName} to the backup list for ${gameDate} at ${venue}.`;
                await pool.query(
                    'INSERT INTO notifications (player_id, type, message, game_id) VALUES ($1, $2, $3, $4)',
                    [registeringPlayerId, 'friend_registered', regNotifMsg, gameId]
                );

                // Email to friend
                if (friendEmail) {
                    const friendEmailBody = status === 'confirmed'
                        ? `<p style="color:#888;font-size:14px;margin:0 0 8px;">Hi ${friendFullName},</p>
                           <p style="color:#888;font-size:14px;margin:0 0 20px;"><strong style="color:#fff;">${regName}</strong> has signed you up for a game on TotalFooty!</p>
                           <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;margin-bottom:20px;">
                               <tr><td style="padding:6px 0;color:#888;width:80px;">Date</td><td style="font-weight:900;">${gameDate}</td></tr>
                               <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:900;">${venue}</td></tr>
                               <tr><td style="padding:6px 0;color:#888;">Status</td><td style="font-weight:900;color:#00ff41;">✅ Confirmed</td></tr>
                           </table>
                           <a href="${gameUrl}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;">VIEW GAME</a>`
                        : `<p style="color:#888;font-size:14px;margin:0 0 8px;">Hi ${friendFullName},</p>
                           <p style="color:#888;font-size:14px;margin:0 0 20px;"><strong style="color:#fff;">${regName}</strong> has added you to the backup list for a game on TotalFooty.</p>
                           <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;margin-bottom:20px;">
                               <tr><td style="padding:6px 0;color:#888;width:80px;">Date</td><td style="font-weight:900;">${gameDate}</td></tr>
                               <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:900;">${venue}</td></tr>
                               <tr><td style="padding:6px 0;color:#888;">Status</td><td style="font-weight:900;color:#FFA500;">⏳ Backup</td></tr>
                           </table>
                           <a href="${gameUrl}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;">VIEW GAME</a>`;

                    await emailTransporter.sendMail({
                        from: '"TotalFooty" <totalfooty19@gmail.com>',
                        to: friendEmail,
                        subject: `⚽ ${(regName || '').replace(/[\r\n]/g, '')} signed you up — TotalFooty`,
                        html: `<div style="background:#0d0d0d;padding:40px;font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
                            <img src="https://totalfooty.co.uk/assets/logo.png" width="80" style="margin-bottom:24px"/>
                            <h2 style="color:#fff;font-size:20px;letter-spacing:2px;margin-bottom:20px;">YOU'VE BEEN SIGNED UP</h2>
                            ${friendEmailBody}
                            <p style="color:#333;font-size:11px;margin-top:32px;letter-spacing:1px;">TOTALFOOTY — COVENTRY FOOTBALL COMMUNITY</p>
                        </div>`
                    }).catch(e => console.error('Friend registration email to friend failed (non-critical):', e.message));
                }

                // Email to registering player
                if (regEmail) {
                    await emailTransporter.sendMail({
                        from: '"TotalFooty" <totalfooty19@gmail.com>',
                        to: regEmail,
                        subject: `✅ You signed up ${(friendName || '').replace(/[\r\n]/g, '')} — TotalFooty`,
                        html: `<div style="background:#0d0d0d;padding:40px;font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
                            <img src="https://totalfooty.co.uk/assets/logo.png" width="80" style="margin-bottom:24px"/>
                            <h2 style="color:#fff;font-size:20px;letter-spacing:2px;margin-bottom:20px;">FRIEND REGISTERED</h2>
                            <p style="color:#888;font-size:14px;margin:0 0 20px;">You signed up <strong style="color:#fff;">${friendName}</strong> for a game.</p>
                            <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;margin-bottom:20px;">
                                <tr><td style="padding:6px 0;color:#888;width:80px;">Date</td><td style="font-weight:900;">${gameDate}</td></tr>
                                <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:900;">${venue}</td></tr>
                                <tr><td style="padding:6px 0;color:#888;">Status</td><td style="font-weight:900;color:${status === 'confirmed' ? '#00ff41' : '#FFA500'};">${status === 'confirmed' ? '✅ Confirmed' : '⏳ Backup'}</td></tr>
                                ${status === 'confirmed' || regBackupType === 'confirmed_backup' ? `<tr><td style="padding:6px 0;color:#888;">Deducted</td><td style="font-weight:900;color:#ff3366;">-£${parseFloat(game.cost_per_player).toFixed(2)}</td></tr>` : ''}
                            </table>
                            <a href="${gameUrl}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;">VIEW GAME</a>
                            <p style="color:#333;font-size:11px;margin-top:32px;letter-spacing:1px;">TOTALFOOTY — COVENTRY FOOTBALL COMMUNITY</p>
                        </div>`
                    }).catch(e => console.error('Friend registration email to registering player failed (non-critical):', e.message));
                }

                // Superadmin notify: player added another player
                try {
                    const isTournament = (await pool.query('SELECT team_selection_type FROM games WHERE id = $1', [gameId])).rows[0]?.team_selection_type === 'tournament';
                    await notifyAdmin(
                        `👥 Player Added by ${regName}`,
                        [
                            ['Added by', regName],
                            ['Added player', friendFullName],
                            ['Status', status === 'confirmed' ? 'Confirmed' : 'Backup'],
                            ['Game', (gameData.day || '') + ' ' + (gameData.time || '')],
                            ['Venue', gameData.venue || ''],
                            ['Tournament', isTournament ? 'Yes' : 'No'],
                        ]
                    );
                } catch (e) { /* non-critical */ }
            } catch (e) {
                console.error('Friend registration notification failed (non-critical):', e.message);
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Register friend error:', error);
        res.status(500).json({ error: 'Registration failed' });
    } finally {
        client.release();
    }
});

// Check GK slot availability for a game
app.get('/api/games/:id/gk-slots', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        
        const result = await pool.query(`
            SELECT g.team_selection_type, g.tournament_team_count,
                   COUNT(r.id) FILTER (WHERE r.status = 'confirmed' AND UPPER(TRIM(r.position_preference)) = 'GK') as gk_count
            FROM games g
            LEFT JOIN registrations r ON r.game_id = g.id
            WHERE g.id = $1
            GROUP BY g.id
        `, [gameId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const maxGKSlots = result.rows[0].team_selection_type === 'vs_external' ? 1 : result.rows[0].team_selection_type === 'tournament' ? (result.rows[0].tournament_team_count || 4) : 2;
        const currentGKs = parseInt(result.rows[0].gk_count) || 0;
        
        res.json({ 
            maxGKSlots, 
            currentGKs, 
            slotsAvailable: maxGKSlots - currentGKs 
        });
    } catch (error) {
        console.error('GK slots check error:', error);
        res.status(500).json({ error: 'Failed to check GK slots' });
    }
});

// Get backup queue for a game
app.get('/api/games/:id/backups', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        
        const result = await pool.query(`
            SELECT r.id, r.player_id, r.backup_type, r.position_preference, r.registered_at,
                   p.full_name, p.alias, p.squad_number
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1 AND r.status = 'backup'
            ORDER BY 
                CASE r.backup_type 
                    WHEN 'confirmed_backup' THEN 1 
                    WHEN 'gk_backup' THEN 2 
                    ELSE 3 
                END,
                r.registered_at ASC
        `, [gameId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Get backups error:', error);
        res.status(500).json({ error: 'Failed to get backup queue' });
    }
});

// Drop out of game with refund + backup promotion
app.post('/api/games/:id/drop-out', authenticateToken, registrationLimiter, async (req, res) => {
    const client = await pool.connect();
    try {
        const gameId = req.params.id;
        
        await client.query('BEGIN');
        
        // Lock the game row
        const gameCheck = await client.query(
            'SELECT player_editing_locked, teams_generated, cost_per_player, team_selection_type, tournament_team_count FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        
        if (gameCheck.rows[0]?.player_editing_locked) {
            await client.query('ROLLBACK');
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        const cost = parseFloat(gameCheck.rows[0].cost_per_player);
        const teamsWereGenerated = !!gameCheck.rows[0].teams_generated;
        
        // Get the dropping player's registration — also fetch who paid (registered_by_player_id)
        const regResult = await client.query(
            'SELECT id, status, backup_type, position_preference, registered_by_player_id, is_comped FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (regResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Not registered for this game' });
        }
        
        const droppingReg = regResult.rows[0];
        const wasConfirmed = droppingReg.status === 'confirmed';
        const wasConfirmedBackup = droppingReg.backup_type === 'confirmed_backup';
        const wasGKOnly = droppingReg.position_preference?.trim().toUpperCase() === 'GK';
        const wasComped = !!droppingReg.is_comped;
        // If someone else paid for this registration, refund them — not the dropping player
        const refundTargetId = droppingReg.registered_by_player_id || req.user.playerId;
        
        // Refund if they paid (confirmed players or confirmed backups) — skip if comped (£0 was taken)
        if (!wasComped && (wasConfirmed || wasConfirmedBackup)) {
            await client.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [cost, refundTargetId]
            );
            
            const refundDesc = refundTargetId !== req.user.playerId
                ? `Dropout refund for ${req.user.playerId} (paid by you)`
                : 'Dropped out of game - refund';
            await client.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [refundTargetId, cost, 'refund', refundDesc]
            );
        }
        
        // Remove ALL guests if this player had any, and refund guest fees
        const guestCheck = await client.query(
            'DELETE FROM game_guests WHERE game_id = $1 AND invited_by = $2 RETURNING guest_name, amount_paid',
            [gameId, req.user.playerId]
        );
        let guestRefunded = null;
        if (guestCheck.rows.length > 0) {
            const totalGuestRefund = guestCheck.rows.reduce((sum, g) => sum + parseFloat(g.amount_paid || 0), 0);
            const guestNames = guestCheck.rows.map(g => g.guest_name).join(', ');
            if (totalGuestRefund > 0) {
                await client.query(
                    'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                    [totalGuestRefund, req.user.playerId]
                );
                await client.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                    [req.user.playerId, totalGuestRefund, 'refund', `${guestCheck.rows.length} guest(s) removed - dropout refund`]
                );
            }
            guestRefunded = { names: guestNames, count: guestCheck.rows.length, amount: totalGuestRefund };
        }
        
        // Delete registration (cascade deletes preferences)
        await client.query('DELETE FROM registrations WHERE id = $1', [droppingReg.id]);
        
        // If a confirmed player dropped out, try to promote a backup
        let promotedPlayer = null;
        if (wasConfirmed) {
            // Get GK slot info for validation
            const maxGKSlots = gameCheck.rows[0].team_selection_type === 'vs_external' ? 1 : gameCheck.rows[0].team_selection_type === 'tournament' ? (gameCheck.rows[0].tournament_team_count || 4) : 2;
            const gkCountResult = await client.query(
                `SELECT COUNT(*) as gk_count FROM registrations 
                 WHERE game_id = $1 AND status = 'confirmed' AND UPPER(TRIM(position_preference)) = 'GK'`,
                [gameId]
            );
            const currentGKs = parseInt(gkCountResult.rows[0].gk_count) || 0;
            
            // If a GK dropped out, first check for GK backups
            if (wasGKOnly) {
                const gkBackups = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'gk_backup'
                    ORDER BY r.registered_at ASC
                `, [gameId]);
                
                // Loop through GK backups - check credits for each
                for (const candidate of gkBackups.rows) {
                    const creditCheck = await client.query(
                        'SELECT balance FROM credits WHERE player_id = $1',
                        [candidate.player_id]
                    );
                    const balance = creditCheck.rows.length > 0 ? parseFloat(creditCheck.rows[0].balance) : 0;
                    if (balance >= cost) {
                        promotedPlayer = candidate;
                        break;
                    }
                }
            }
            
            // If no GK backup was promoted, check confirmed backups (already paid - no credit check needed)
            if (!promotedPlayer) {
                const confirmedBackups = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'confirmed_backup'
                    ORDER BY r.registered_at ASC
                `, [gameId]);
                
                // Loop through confirmed backups - check GK slot limits
                for (const candidate of confirmedBackups.rows) {
                    const isGK = candidate.position_preference?.trim().toUpperCase() === 'GK';
                    if (isGK && currentGKs >= maxGKSlots) {
                        continue; // Skip — would exceed GK limit
                    }
                    promotedPlayer = candidate;
                    break;
                }
            }
            
            // Also try normal_backup if no confirmed_backup found — but check credits first (FIX-064)
            if (!promotedPlayer) {
                const normalBackups = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'normal_backup'
                    ORDER BY r.registered_at ASC
                `, [gameId]);

                for (const candidate of normalBackups.rows) {
                    const isGK = candidate.position_preference?.trim().toUpperCase() === 'GK';
                    if (isGK && currentGKs >= maxGKSlots) continue;
                    // FIX-064: Check balance before promoting — skip if insufficient
                    const backupCredit = await client.query('SELECT balance FROM credits WHERE player_id = $1', [candidate.player_id]);
                    const backupBalance = parseFloat(backupCredit.rows[0]?.balance || 0);
                    if (backupBalance < cost) continue; // Skip — insufficient funds
                    promotedPlayer = candidate;
                    break;
                }
            }
            
            // Promote the backup player
            if (promotedPlayer) {
                await client.query(
                    `UPDATE registrations SET status = 'confirmed', backup_type = NULL WHERE id = $1`,
                    [promotedPlayer.id]
                );
                
                // If they weren't a confirmed_backup, charge them now
                if (promotedPlayer.backup_type !== 'confirmed_backup') {
                    await client.query(
                        'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                        [cost, promotedPlayer.player_id]
                    );
                    
                    await client.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [promotedPlayer.player_id, -cost, 'game_fee', `Promoted from backup - game ${gameId}`]
                    );
                }
                
                // Create notification for promoted player
                await client.query(
                    `INSERT INTO notifications (player_id, type, message, game_id)
                     VALUES ($1, 'backup_promoted', $2, $3)`,
                    [promotedPlayer.player_id, 
                     `Great news! A spot opened up and you've been promoted to the game! ${promotedPlayer.backup_type === 'confirmed_backup' ? 'Your payment has already been taken.' : `£${cost.toFixed(2)} has been deducted from your balance.`}`,
                     gameId]
                );
            }
        }
        
        // If teams were already generated, clear them so admin must re-generate
        if (teamsWereGenerated && wasConfirmed) {
            await client.query(
                'UPDATE games SET teams_generated = FALSE, teams_confirmed = FALSE WHERE id = $1',
                [gameId]
            );
            await client.query('DELETE FROM team_players WHERE team_id IN (SELECT id FROM teams WHERE game_id = $1)', [gameId]);
            await client.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        }

        await client.query('COMMIT');
        
        let message;
        if (wasConfirmed || wasConfirmedBackup) {
            if (wasComped) {
                message = 'Successfully dropped out.';
            } else if (refundTargetId !== req.user.playerId) {
                message = `Successfully dropped out. £${cost.toFixed(2)} refunded to the player who signed you up.`;
            } else {
                message = `Successfully dropped out. £${cost.toFixed(2)} refunded to your balance.`;
            }
            if (teamsWereGenerated) {
                message += ' Note: teams have been reset and will need to be regenerated.';
            }
        } else {
            message = 'Successfully removed from backup list.';
        }
            
        if (promotedPlayer) {
            message += ` ${promotedPlayer.alias || promotedPlayer.full_name} has been promoted from the backup list.`;
        }
        
        res.json({ message, promotedPlayer: promotedPlayer ? { name: promotedPlayer.alias || promotedPlayer.full_name } : null });

        // Non-critical: fire notifications after response
        setImmediate(async () => {
            try {
                const gameData = await getGameDataForNotification(gameId);
                if (wasConfirmed || wasConfirmedBackup) {
                    await sendNotification('dropout_confirmed', req.user.playerId, gameData);
                }
                if (promotedPlayer) {
                    await sendNotification('backup_promoted', promotedPlayer.player_id, gameData);
                }
            } catch (e) {
                console.error('Dropout notification failed (non-critical):', e.message);
            }
            try {
                const evtType = wasConfirmed ? 'dropped_out' : 'backup_removed';
                const evtDetail = wasConfirmedBackup ? 'Was confirmed backup' : wasConfirmed ? `Refunded £${cost.toFixed(2)}` : 'No charge';
                // Enrich audit with player full name for easier cross-reference
                const _playerNameRow = await pool.query(
                    'SELECT full_name, alias FROM players WHERE id = $1', [req.user.playerId]
                ).catch(() => ({ rows: [] }));
                const _pName = _playerNameRow.rows[0]?.alias || _playerNameRow.rows[0]?.full_name || req.user.playerId;
                await registrationEvent(pool, gameId, req.user.playerId, evtType, evtDetail);
                await gameAuditLog(pool, gameId, null, evtType,
                    `Player ID ${req.user.playerId}${promotedPlayer ? ` | Promoted: ${promotedPlayer.alias || promotedPlayer.full_name}` : ''}`);
            } catch (e) { /* non-critical */ }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Drop out error:', error);
        res.status(500).json({ error: 'Failed to drop out' });
    } finally {
        client.release();
    }
});

// Update registration preferences
app.put('/api/games/:id/update-preferences', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const gameId = req.params.id;
        const { positions, pairs, avoids } = req.body;

        // FIX-047: Block updates after teams generated
        const state = await client.query('SELECT teams_generated FROM games WHERE id = $1', [gameId]);
        if (state.rows[0]?.teams_generated) {
            return res.status(400).json({ error: 'Cannot update preferences after teams have been generated' });
        }

        // FIX-047: Cap pairs/avoids at 10 each
        if ((pairs?.length || 0) > 10 || (avoids?.length || 0) > 10) {
            return res.status(400).json({ error: 'Max 10 pairs/avoids allowed' });
        }
        
        // Get registration
        const regResult = await client.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (regResult.rows.length === 0) {
            return res.status(404).json({ error: 'Not registered for this game' });
        }
        
        const registrationId = regResult.rows[0].id;

        await client.query('BEGIN');
        
        // Update positions
        await client.query(
            'UPDATE registrations SET position_preference = $1 WHERE id = $2',
            [positions, registrationId]
        );
        
        // Delete old preferences
        await client.query('DELETE FROM registration_preferences WHERE registration_id = $1', [registrationId]);
        
        // Add new pairs
        if (pairs && pairs.length > 0) {
            for (const pairPlayerId of pairs) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        
        // Add new avoids
        if (avoids && avoids.length > 0) {
            for (const avoidPlayerId of avoids) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid')`,
                    [registrationId, avoidPlayerId]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ message: 'Preferences updated successfully' });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Update preferences error:', error);
        res.status(500).json({ error: 'Failed to update preferences' });
    } finally {
        client.release();
    }
});

// Generate teams with algorithm
app.post('/api/admin/games/:gameId/generate-teams', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Block tournament games — must use manual draft
        const tournCheck = await pool.query('SELECT team_selection_type FROM games WHERE id = $1', [gameId]);
        if (tournCheck.rows[0]?.team_selection_type === 'tournament') {
            return res.status(400).json({ error: 'Tournament games must use manual team draft, not auto-generate' });
        }
        
        // Get all confirmed registrations with player stats
        const playersResult = await pool.query(`
            SELECT 
                r.id as reg_id,
                p.id as player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.overall_rating,
                p.goalkeeper_rating,
                p.defending_rating,
                p.strength_rating,
                p.fitness_rating,
                p.pace_rating,
                p.decisions_rating,
                p.assisting_rating,
                p.shooting_rating,
                r.position_preference,
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY r.id, p.id, p.full_name, p.alias, p.squad_number, p.overall_rating, p.goalkeeper_rating, p.defending_rating, p.strength_rating, p.fitness_rating, p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating, r.position_preference
            ORDER BY p.overall_rating DESC
        `, [gameId]);
        
        const players = playersResult.rows.map(p => ({
            ...p,
            // For GK-only players, use goalkeeper_rating as their effective overall throughout
            // the algorithm, display, and fine-tuning. Outfield or dual-position players keep overall_rating.
            overall_rating: p.position_preference?.trim().toLowerCase() === 'gk'
                ? (p.goalkeeper_rating || p.overall_rating || 0)
                : (p.overall_rating || 0)
        }));
        
        // Also fetch +N guests for this game (multi-guest)
        const guestsResult = await pool.query(`
            SELECT g.id as guest_id, g.guest_name, g.overall_rating, g.invited_by, g.guest_number
            FROM game_guests g
            WHERE g.game_id = $1
            ORDER BY g.invited_by, g.guest_number
        `, [gameId]);
        
        // Build guest groups: map of invited_by -> array of guest objects
        const guestGroups = new Map();
        for (const guest of guestsResult.rows) {
            if (!guestGroups.has(guest.invited_by)) {
                guestGroups.set(guest.invited_by, []);
            }
            guestGroups.get(guest.invited_by).push({
                reg_id: null,
                player_id: `guest_${guest.guest_id}`,
                full_name: guest.guest_name,
                alias: `${guest.guest_name} (Guest)`,
                squad_number: null,
                overall_rating: guest.overall_rating || 0,
                goalkeeper_rating: 0,
                defending_rating: 0,
                strength_rating: 0,
                fitness_rating: 0,
                pace_rating: 0,
                decisions_rating: 0,
                assisting_rating: 0,
                shooting_rating: 0,
                position_preference: 'outfield',
                pairs: [guest.invited_by],
                avoids: [],
                is_guest: true
            });
        }
        
        if (players.length + guestsResult.rows.length < 2) {
            return res.status(400).json({ error: 'Need at least 2 players to generate teams' });
        }
        
        // Get beef relationships (rating 3+) - optional, may not exist yet
        let highBeefs = new Map();
        let lowBeefs = new Map();
        
        try {
            const beefsResult = await pool.query(`
                SELECT player_id, target_player_id, rating
                FROM beef
                WHERE rating >= 2
            `);
            
            beefsResult.rows.forEach(beef => {
                if (beef.rating >= 3) {
                    if (!highBeefs.has(beef.player_id)) highBeefs.set(beef.player_id, []);
                    highBeefs.get(beef.player_id).push(beef.target_player_id);
                } else if (beef.rating >= 2) {
                    if (!lowBeefs.has(beef.player_id)) lowBeefs.set(beef.player_id, []);
                    lowBeefs.get(beef.player_id).push(beef.target_player_id);
                }
            });
        } catch (beefError) {
            // Beef table doesn't exist yet - that's fine, continue without it
            console.log('Beef table not found, skipping beef checks');
        }
        
        // ===================================================
        // ALGORITHM — GUEST-FIRST INTERTWINED PICKING
        // ===================================================
        const redTeam = [];
        const blueTeam = [];
        
        // PRIORITY 1: Assign 1 GK to each team
        // Only treat as GK if they selected GK exclusively (not GK + outfield)
        const goalkeepers = players.filter(p => p.position_preference?.trim().toLowerCase() === 'gk');
        const outfield = players.filter(p => p.position_preference?.trim().toLowerCase() !== 'gk');
        
        if (goalkeepers.length >= 1) redTeam.push(goalkeepers[0]);
        if (goalkeepers.length >= 2) blueTeam.push(goalkeepers[1]);
        if (goalkeepers.length >= 3) outfield.push(...goalkeepers.slice(2)); // Extra GKs as outfield
        
        // Separate parents (players who brought guests) from solo players
        const parentPlayers = [];
        const soloPlayers = [];
        
        for (const player of outfield) {
            if (guestGroups.has(player.player_id)) {
                parentPlayers.push({
                    parent: player,
                    guests: guestGroups.get(player.player_id),
                    totalRating: (player.overall_rating || 0) + 
                        guestGroups.get(player.player_id).reduce((sum, g) => sum + (g.overall_rating || 0), 0)
                });
            } else {
                soloPlayers.push(player);
            }
        }
        
        // Check placed GKs for guest groups — their guests must join them
        const gkParentGroups = [];
        for (let i = 0; i < Math.min(goalkeepers.length, 2); i++) {
            const gk = goalkeepers[i];
            if (guestGroups.has(gk.player_id)) {
                gkParentGroups.push({
                    parent: gk,
                    guests: guestGroups.get(gk.player_id),
                    team: i === 0 ? 'red' : 'blue'
                });
            }
        }
        
        // Sort parent groups by total rating descending
        parentPlayers.sort((a, b) => b.totalRating - a.totalRating);
        
        // Sort solo players by overall rating descending
        soloPlayers.sort((a, b) => (b.overall_rating || 0) - (a.overall_rating || 0));
        
        // Helper: find and remove closest-rated solo player to a target rating
        const findClosestSolo = (targetRating, availableSolos) => {
            if (availableSolos.length === 0) return null;
            let bestIdx = 0;
            let bestDiff = Math.abs((availableSolos[0].overall_rating || 0) - targetRating);
            for (let i = 1; i < availableSolos.length; i++) {
                const diff = Math.abs((availableSolos[i].overall_rating || 0) - targetRating);
                if (diff < bestDiff) {
                    bestDiff = diff;
                    bestIdx = i;
                }
            }
            return availableSolos.splice(bestIdx, 1)[0];
        };
        
        // PHASE 0: Place guests for GKs who brought them
        console.log(`\n=== PHASE 0: GK Guest Placement ===`);
        for (const gkGroup of gkParentGroups) {
            const targetTeam = gkGroup.team === 'red' ? redTeam : blueTeam;
            const opposingTeam = gkGroup.team === 'red' ? blueTeam : redTeam;
            const teamLabel = gkGroup.team.toUpperCase();
            const oppLabel = gkGroup.team === 'red' ? 'BLUE' : 'RED';
            
            for (const guest of gkGroup.guests) {
                targetTeam.push(guest);
                console.log(`  GK Guest ${guest.full_name} (OVR ${guest.overall_rating}) → ${teamLabel}`);
                
                const balancePlayer = findClosestSolo(guest.overall_rating || 0, soloPlayers);
                if (balancePlayer) {
                    opposingTeam.push(balancePlayer);
                    console.log(`  Balance ${balancePlayer.full_name} (OVR ${balancePlayer.overall_rating}) → ${oppLabel}`);
                }
            }
        }
        
        // PHASE 1: Place outfield guest groups with intertwined picking
        console.log(`\n=== PHASE 1: Guest Group Placement ===`);
        console.log(`${parentPlayers.length} parent groups, ${soloPlayers.length} solo players available`);
        
        let nextTeamForGroup = 'red';
        
        for (const group of parentPlayers) {
            const targetTeam = nextTeamForGroup === 'red' ? redTeam : blueTeam;
            const opposingTeam = nextTeamForGroup === 'red' ? blueTeam : redTeam;
            const teamLabel = nextTeamForGroup.toUpperCase();
            const oppLabel = nextTeamForGroup === 'red' ? 'BLUE' : 'RED';
            
            targetTeam.push(group.parent);
            console.log(`  Parent ${group.parent.full_name} (OVR ${group.parent.overall_rating}) → ${teamLabel}`);
            
            const matchPlayer = findClosestSolo(group.parent.overall_rating || 0, soloPlayers);
            if (matchPlayer) {
                opposingTeam.push(matchPlayer);
                console.log(`  Match ${matchPlayer.full_name} (OVR ${matchPlayer.overall_rating}) → ${oppLabel}`);
            }
            
            for (const guest of group.guests) {
                targetTeam.push(guest);
                console.log(`  Guest ${guest.full_name} (OVR ${guest.overall_rating}) → ${teamLabel}`);
                
                const balancePlayer = findClosestSolo(guest.overall_rating || 0, soloPlayers);
                if (balancePlayer) {
                    opposingTeam.push(balancePlayer);
                    console.log(`  Balance ${balancePlayer.full_name} (OVR ${balancePlayer.overall_rating}) → ${oppLabel}`);
                }
            }
            
            nextTeamForGroup = nextTeamForGroup === 'red' ? 'blue' : 'red';
        }
        
        // PHASE 2: Remaining solo players via standard priority algorithm
        // Helper functions
        const hasHighBeef = (player, team) => {
            const beefs = highBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        
        const hasLowBeef = (player, team) => {
            const beefs = lowBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        
        const wantsToPairWith = (player, team) => {
            return (player.pairs || []).some(pid => team.find(tp => tp.player_id === pid));
        };
        
        const wantsToAvoid = (player, team) => {
            return (player.avoids || []).some(pid => team.find(tp => tp.player_id === pid));
        };
        
        // Allocate remaining solo players (not consumed by Phase 0/1 matching)
        console.log(`\n=== PHASE 2: Solo Player Placement ===`);
        console.log(`${soloPlayers.length} solo players remaining`);
        console.log(`Red starts with ${redTeam.length}, Blue starts with ${blueTeam.length}`);
        
        for (const player of soloPlayers) {
            let assignToRed = null; // null = undecided
            
            // CRITICAL: Always maintain equal team sizes (ABSOLUTE PRIORITY)
            // If one team is bigger, MUST add to smaller team
            if (redTeam.length > blueTeam.length) {
                console.log(`Red (${redTeam.length}) > Blue (${blueTeam.length}) - Forcing ${player.full_name} to BLUE`);
                assignToRed = false; // Force to blue
            } else if (blueTeam.length > redTeam.length) {
                console.log(`Blue (${blueTeam.length}) > Red (${redTeam.length}) - Forcing ${player.full_name} to RED`);
                assignToRed = true; // Force to red
            } else {
                console.log(`Teams equal (${redTeam.length}/${blueTeam.length}) - Applying rules for ${player.full_name}`);
                // Teams are equal, apply other rules
                
                // PRIORITY 2: Avoid high beefs (3+)
                const redBeef = hasHighBeef(player, redTeam);
                const blueBeef = hasHighBeef(player, blueTeam);
                
                if (redBeef && !blueBeef) {
                    assignToRed = false;
                } else if (blueBeef && !redBeef) {
                    assignToRed = true;
                }
                
                // PRIORITY 3: Balance overall stats (only if teams equal size and no beef)
                if (assignToRed === null) {
                    const redTotal = redTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0);
                    const blueTotal = blueTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0);
                    
                    // Always try to balance overall - assign to team with lower total
                    assignToRed = redTotal <= blueTotal;
                }
                
                // PRIORITY 4: Pair preferences
                if (assignToRed === null) {
                    const redPair = wantsToPairWith(player, redTeam);
                    const bluePair = wantsToPairWith(player, blueTeam);
                    
                    if (redPair && !bluePair && !wantsToAvoid(player, redTeam)) {
                        assignToRed = true;
                    } else if (bluePair && !redPair && !wantsToAvoid(player, blueTeam)) {
                        assignToRed = false;
                    }
                }
                
                // PRIORITY 5: Avoid preferences
                if (assignToRed === null) {
                    const redAvoid = wantsToAvoid(player, redTeam);
                    const blueAvoid = wantsToAvoid(player, blueTeam);
                    
                    if (redAvoid && !blueAvoid) {
                        assignToRed = false;
                    } else if (blueAvoid && !redAvoid) {
                        assignToRed = true;
                    }
                }
                
                // PRIORITY 6: Balance defense & fitness
                if (assignToRed === null) {
                    const redDef = redTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0);
                    const blueDef = blueTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0);
                    const redFit = redTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0);
                    const blueFit = blueTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0);
                    
                    if (redDef < blueDef || redFit < blueFit) {
                        assignToRed = true;
                    } else if (blueDef < redDef || blueFit < redFit) {
                        assignToRed = false;
                    }
                }
                
                // PRIORITY 7: Avoid low beefs (2)
                if (assignToRed === null) {
                    const redLowBeef = hasLowBeef(player, redTeam);
                    const blueLowBeef = hasLowBeef(player, blueTeam);
                    
                    if (redLowBeef && !blueLowBeef) {
                        assignToRed = false;
                    } else if (blueLowBeef && !redLowBeef) {
                        assignToRed = true;
                    }
                }
                
                // DEFAULT: Alternate (snake draft)
                if (assignToRed === null) {
                    assignToRed = redTeam.length <= blueTeam.length;
                }
            }
            
            // Assign player
            if (assignToRed) {
                redTeam.push(player);
                console.log(`✓ Assigned ${player.full_name} to RED (now ${redTeam.length} vs ${blueTeam.length})`);
            } else {
                blueTeam.push(player);
                console.log(`✓ Assigned ${player.full_name} to BLUE (now ${redTeam.length} vs ${blueTeam.length})`);
            }
        }
        
        console.log(`FINAL: Red=${redTeam.length}, Blue=${blueTeam.length}`);
        
        // Delete existing teams if any (for re-generation)
        await pool.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        await pool.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
        
        // Reset confirmation flag (teams need to be re-confirmed after regeneration)
        await pool.query('UPDATE games SET teams_confirmed = FALSE WHERE id = $1', [gameId]);
        
        // Create team records
        const redResult = await pool.query(
            'INSERT INTO teams (game_id, team_name) VALUES ($1, $2) RETURNING id',
            [gameId, 'Red']
        );
        
        const blueResult = await pool.query(
            'INSERT INTO teams (game_id, team_name) VALUES ($1, $2) RETURNING id',
            [gameId, 'Blue']
        );
        
        const redTeamId = redResult.rows[0].id;
        const blueTeamId = blueResult.rows[0].id;
        
        // Add players to teams (skip guests - they go in game_guests.team_name)
        for (const player of redTeam) {
            if (player.is_guest) {
                await pool.query(
                    "UPDATE game_guests SET team_name = 'Red' WHERE id = $1",
                    [player.player_id.replace('guest_', '')]
                );
            } else {
                await pool.query(
                    'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                    [redTeamId, player.player_id]
                );
            }
        }
        
        for (const player of blueTeam) {
            if (player.is_guest) {
                await pool.query(
                    "UPDATE game_guests SET team_name = 'Blue' WHERE id = $1",
                    [player.player_id.replace('guest_', '')]
                );
            } else {
                await pool.query(
                    'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                    [blueTeamId, player.player_id]
                );
            }
        }
        
        // Mark teams as generated
        await pool.query('UPDATE games SET teams_generated = TRUE WHERE id = $1', [gameId]);

        // Non-critical: notify all confirmed players that teams are live
        setImmediate(async () => {
            try {
                const gameData = await getGameDataForNotification(gameId);
                const confirmed = await pool.query(
                    `SELECT player_id FROM registrations WHERE game_id = $1 AND status = 'confirmed'`,
                    [gameId]
                );
                for (const row of confirmed.rows) {
                    await sendNotification('teams_created', row.player_id, gameData).catch(() => {});
                }
            } catch (e) {
                console.error('Teams created notification failed (non-critical):', e.message);
            }
        });
        
        // Calculate stats
        const redStats = {
            overall:   redTeam.reduce((sum, p) => sum + (p.overall_rating    || 0), 0),
            defense:   redTeam.reduce((sum, p) => sum + (p.defending_rating  || 0), 0),
            strength:  redTeam.reduce((sum, p) => sum + (p.strength_rating   || 0), 0),
            fitness:   redTeam.reduce((sum, p) => sum + (p.fitness_rating    || 0), 0),
            pace:      redTeam.reduce((sum, p) => sum + (p.pace_rating       || 0), 0),
            decisions: redTeam.reduce((sum, p) => sum + (p.decisions_rating  || 0), 0),
            assisting: redTeam.reduce((sum, p) => sum + (p.assisting_rating  || 0), 0),
            shooting:  redTeam.reduce((sum, p) => sum + (p.shooting_rating   || 0), 0)
        };
        
        const blueStats = {
            overall:   blueTeam.reduce((sum, p) => sum + (p.overall_rating   || 0), 0),
            defense:   blueTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0),
            strength:  blueTeam.reduce((sum, p) => sum + (p.strength_rating  || 0), 0),
            fitness:   blueTeam.reduce((sum, p) => sum + (p.fitness_rating   || 0), 0),
            pace:      blueTeam.reduce((sum, p) => sum + (p.pace_rating      || 0), 0),
            decisions: blueTeam.reduce((sum, p) => sum + (p.decisions_rating || 0), 0),
            assisting: blueTeam.reduce((sum, p) => sum + (p.assisting_rating || 0), 0),
            shooting:  blueTeam.reduce((sum, p) => sum + (p.shooting_rating  || 0), 0)
        };
        
        const mapPlayer = p => {
            const isGKOnly = p.position_preference?.trim().toLowerCase() === 'gk';
            return {
                id:           p.player_id,
                name:         p.alias || p.full_name,
                full_name:    p.full_name,
                alias:        p.alias,
                squad_number: p.squad_number,
                overall:      isGKOnly ? (p.goalkeeper_rating || 0) : (p.overall_rating || 0),
                defense:      p.defending_rating  || 0,
                strength:     p.strength_rating   || 0,
                fitness:      p.fitness_rating    || 0,
                pace:         p.pace_rating       || 0,
                decisions:    p.decisions_rating  || 0,
                assisting:    p.assisting_rating  || 0,
                shooting:     p.shooting_rating   || 0,
                gk:           p.goalkeeper_rating || 0,
                isGK:         isGKOnly,
                position_preference: p.position_preference || 'outfield',
                is_guest:     p.is_guest || false
            };
        };
        
        res.json({
            message: 'Teams generated successfully',
            redTeam:   redTeam.map(mapPlayer),
            blueTeam:  blueTeam.map(mapPlayer),
            redStats,
            blueStats,
            beefs: Array.from(highBeefs.entries()).map(([playerId, targets]) => ({
                playerId,
                targets,
                rating: 3
            })).concat(
                Array.from(lowBeefs.entries()).map(([playerId, targets]) => ({
                    playerId,
                    targets,
                    rating: 2
                }))
            )
        });
        setImmediate(async () => {
            const redAvg = redTeam.length ? (redStats.overall / redTeam.length).toFixed(1) : '0';
            const blueAvg = blueTeam.length ? (blueStats.overall / blueTeam.length).toFixed(1) : '0';
            await gameAuditLog(pool, gameId, req.user.playerId, 'teams_generated',
                `Teams generated | Red avg OVR: ${redAvg} (${redTeam.length}p) | Blue avg OVR: ${blueAvg} (${blueTeam.length}p)`);
            try {
                const gameData = await getGameDataForNotification(gameId);
                await notifyAdmin('🔀 Teams Generated', [
                    ['Game', (gameData.day || '') + ' ' + (gameData.time || '')],
                    ['Venue', gameData.venue || ''],
                    ['Red team', redTeam.length + ' players | avg OVR ' + redAvg],
                    ['Blue team', blueTeam.length + ' players | avg OVR ' + blueAvg],
                ]);
            } catch (e) { /* non-critical */ }
        });
    } catch (error) {
        console.error('Generate teams error:', error);
        res.status(500).json({ error: 'Failed to generate teams' });
    }
});

// Delete single game with refunds (transaction-protected)
app.delete('/api/admin/games/:gameId', authenticateToken, requireCLMAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        await client.query('BEGIN');
        const registrations = await client.query(
            `SELECT player_id, status, backup_type, amount_paid, registered_by_player_id FROM registrations WHERE game_id = $1 AND (status = 'confirmed' OR (status = 'backup' AND backup_type = 'confirmed_backup'))`,
            [gameId]
        );
        const gameResult = await client.query('SELECT cost_per_player FROM games WHERE id = $1', [gameId]);
        const fallbackCost = parseFloat(gameResult.rows[0]?.cost_per_player || 0);

        // Capture game details for notifications before we delete the game
        const cancelGameInfo = await client.query(`
            SELECT g.game_date, g.game_url, v.name as venue_name
            FROM games g LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [gameId]);
        const cancelGameRow = cancelGameInfo.rows[0] || {};
        const cancelDate = cancelGameRow.game_date ? new Date(cancelGameRow.game_date).toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' }) : '';
        const cancelGameData = {
            day: cancelDate,
            time: cancelGameRow.game_date ? new Date(cancelGameRow.game_date).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : '',
            venue: cancelGameRow.venue_name || 'TBC',
            gameurl: `https://totalfooty.co.uk/vibecoding/game.html?url=${cancelGameRow.game_url}`
        };
        const cancelledPlayerIds = registrations.rows.map(r => r.player_id);
        let totalRefunded = 0;
        for (const reg of registrations.rows) {
            const refundAmt = parseFloat(reg.amount_paid || fallbackCost);
            const refundTarget = reg.registered_by_player_id || reg.player_id;
            if (refundAmt > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [refundAmt, refundTarget]);
                await client.query('INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)', [refundTarget, refundAmt, 'refund', 'Game cancelled - refund']);
                totalRefunded++;
            }
        }
        const guests = await client.query('SELECT invited_by, guest_name, amount_paid FROM game_guests WHERE game_id = $1', [gameId]);
        for (const guest of guests.rows) {
            const guestRefund = parseFloat(guest.amount_paid || 0);
            if (guestRefund > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [guestRefund, guest.invited_by]);
                await client.query('INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)', [guest.invited_by, guestRefund, 'refund', 'Game cancelled - +1 guest refund']);
            }
        }
        await client.query('DELETE FROM motm_votes WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM motm_nominees WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM tournament_results WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM game_messages WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM team_players WHERE team_id IN (SELECT id FROM teams WHERE game_id = $1)', [gameId]);
        await client.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM game_guests WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM registrations WHERE game_id = $1', [gameId]);
        await client.query('UPDATE discipline_records SET game_id = NULL WHERE game_id = $1', [gameId]);
        await client.query('DELETE FROM games WHERE id = $1', [gameId]);
        await client.query('COMMIT');
        res.json({ message: 'Game deleted. Refunded ' + totalRefunded + ' players and ' + guests.rows.length + ' guest fees.' });

        // Non-critical: notify all affected players
        setImmediate(async () => {
            for (const pid of cancelledPlayerIds) {
                try {
                    await sendNotification('game_cancelled', pid, cancelGameData);
                } catch (e) {
                    console.error(`game_cancelled notification failed player ${pid}:`, e.message);
                }
            }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Delete game error:', error);
        res.status(500).json({ error: 'Failed to delete game' });
    } finally {
        client.release();
    }
});

// Delete entire weekly series with refunds (FUTURE games only, transaction-protected)
app.delete('/api/admin/games/:gameId/delete-series', authenticateToken, requireCLMAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        
        const gameResult = await client.query(
            'SELECT series_id, cost_per_player FROM games WHERE id = $1',
            [gameId]
        );
        
        if (gameResult.rows.length === 0) {
            client.release();
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        if (!game.series_id) {
            client.release();
            return res.status(400).json({ error: 'This is not part of a weekly series' });
        }
        
        // Get series name for response
        const seriesNameResult = await client.query(
            'SELECT series_name FROM game_series WHERE id = $1',
            [game.series_id]
        );
        const seriesName = seriesNameResult.rows[0]?.series_name || 'Unknown';
        
        // Find all FUTURE games in this series (same UUID, not LIKE)
        const seriesGames = await client.query(`
            SELECT id FROM games 
            WHERE series_id = $1
            AND game_date > CURRENT_TIMESTAMP
        `, [game.series_id]);
        
        const gameIds = seriesGames.rows.map(g => g.id);
        
        if (gameIds.length === 0) {
            client.release();
            return res.json({ message: 'No future games to delete in this series' });
        }
        
        await client.query('BEGIN');
        
        let totalRefunded = 0;
        let guestRefunds = 0;
        const cost = parseFloat(game.cost_per_player);
        
        for (const gid of gameIds) {
            // Refund all players who paid (confirmed + confirmed_backup)
            const registrations = await client.query(
                `SELECT player_id, amount_paid, registered_by_player_id FROM registrations WHERE game_id = $1 
                 AND (status = 'confirmed' OR (status = 'backup' AND backup_type = 'confirmed_backup'))`,
                [gid]
            );
            for (const reg of registrations.rows) {
                const refundAmt = parseFloat(reg.amount_paid || cost);
                const refundTarget = reg.registered_by_player_id || reg.player_id;
                if (refundAmt > 0) {
                    await client.query(
                        'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                        [refundAmt, refundTarget]
                    );
                    await client.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [refundTarget, refundAmt, 'refund', 'Series ' + seriesName + ' cancelled - refund']
                    );
                    totalRefunded++;
                }
            }
            
            // Refund guest fees to the players who invited them
            const guests = await client.query(
                'SELECT invited_by, amount_paid FROM game_guests WHERE game_id = $1',
                [gid]
            );
            for (const guest of guests.rows) {
                const guestRefund = parseFloat(guest.amount_paid || 0);
                if (guestRefund > 0) {
                    await client.query(
                        'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                        [guestRefund, guest.invited_by]
                    );
                    await client.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [guest.invited_by, guestRefund, 'refund', 'Series ' + seriesName + ' cancelled - +1 guest refund']
                    );
                    guestRefunds++;
                }
            }
        }
        
        // Delete only FUTURE games in series — explicit deletes to avoid FK constraint failures
        for (const gid of gameIds) {
            await client.query('DELETE FROM motm_votes WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM motm_nominees WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM tournament_results WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM game_messages WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM team_players WHERE team_id IN (SELECT id FROM teams WHERE game_id = $1)', [gid]);
            await client.query('DELETE FROM teams WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM game_guests WHERE game_id = $1', [gid]);
            await client.query('DELETE FROM registrations WHERE game_id = $1', [gid]);
            await client.query('UPDATE discipline_records SET game_id = NULL WHERE game_id = $1', [gid]);
        }
        await client.query(
            'DELETE FROM games WHERE id = ANY($1::uuid[])',
            [gameIds]
        );
        
        await client.query('COMMIT');
        
        res.json({ 
            message: 'Deleted ' + gameIds.length + ' future games from series ' + seriesName + '. Refunded ' + totalRefunded + ' registrations and ' + guestRefunds + ' guest fees. Past games preserved.'
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Delete series error:', error);
        res.status(500).json({ error: 'Failed to delete series' });
    } finally {
        client.release();
    }
});

// Update game settings (venue, max players, price, tournament team count)
app.put('/api/admin/games/:gameId/settings', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { game_date, venue_id, max_players, cost_per_player, star_rating, tournament_team_count } = req.body;
        
        // Validate inputs
        if (!venue_id || !max_players || cost_per_player === undefined) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        if (max_players < 1) {
            return res.status(400).json({ error: 'Max players must be at least 1' });
        }
        
        if (cost_per_player < 0) {
            return res.status(400).json({ error: 'Price cannot be negative' });
        }

        // FIX-069: Block updates on completed or cancelled games
        const statusCheck = await pool.query('SELECT game_status, cost_per_player FROM games WHERE id = $1', [gameId]);
        if (statusCheck.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const currentStatus = statusCheck.rows[0].game_status;
        const oldCost = parseFloat(statusCheck.rows[0].cost_per_player);
        if (['completed', 'cancelled'].includes(currentStatus)) {
            return res.status(400).json({ error: 'Cannot modify a completed or cancelled game' });
        }
        
        // Check current registrations
        const currentRegs = await pool.query(
            'SELECT COUNT(*) as count FROM registrations WHERE game_id = $1 AND status = $2',
            [gameId, 'confirmed']
        );
        
        const currentCount = parseInt(currentRegs.rows[0].count);
        
        if (max_players < currentCount) {
            return res.status(400).json({ 
                error: `Cannot reduce max players to ${max_players}. Currently have ${currentCount} confirmed registrations.` 
            });
        }
        
        // Update the game (include game_date if provided, tournament_team_count if provided)
        if (game_date) {
            await pool.query(`
                UPDATE games 
                SET game_date = $1,
                    venue_id = $2, 
                    max_players = $3, 
                    cost_per_player = $4,
                    star_rating = $5,
                    tournament_team_count = COALESCE($6, tournament_team_count)
                WHERE id = $7
            `, [game_date, venue_id, max_players, cost_per_player, star_rating || null, tournament_team_count || null, gameId]);
        } else {
            await pool.query(`
                UPDATE games 
                SET venue_id = $1, 
                    max_players = $2, 
                    cost_per_player = $3,
                    star_rating = $4,
                    tournament_team_count = COALESCE($5, tournament_team_count)
                WHERE id = $6
            `, [venue_id, max_players, cost_per_player, star_rating || null, tournament_team_count || null, gameId]);
        }

        // If tournament_team_count changed, wipe existing team assignments and
        // clear any player team preferences that are now out of range (e.g. player
        // picked "Team 6" but we're now running 4 teams).
        if (tournament_team_count) {
            const existingCount = await pool.query(
                'SELECT tournament_team_count FROM games WHERE id = $1', [gameId]
            );
            const prevCount = existingCount.rows[0]?.tournament_team_count;
            if (prevCount && parseInt(prevCount) !== parseInt(tournament_team_count)) {
                // Delete generated teams (team_players first due to FK)
                await pool.query('DELETE FROM team_players WHERE team_id IN (SELECT id FROM teams WHERE game_id = $1)', [gameId]);
                await pool.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
                // Clear any player preferences that named a team slot that no longer exists
                // Team names are stored as e.g. 'Team 5', 'Team 6' — clear if number > new count
                await pool.query(`
                    UPDATE registrations
                    SET tournament_team_preference = NULL
                    WHERE game_id = $1
                      AND tournament_team_preference IS NOT NULL
                      AND CAST(REGEXP_REPLACE(tournament_team_preference, '[^0-9]', '', 'g') AS INTEGER) > $2
                `, [gameId, parseInt(tournament_team_count)]);
                await pool.query(`
                    UPDATE game_guests
                    SET tournament_team_preference = NULL
                    WHERE game_id = $1
                      AND tournament_team_preference IS NOT NULL
                      AND CAST(REGEXP_REPLACE(tournament_team_preference, '[^0-9]', '', 'g') AS INTEGER) > $2
                `, [gameId, parseInt(tournament_team_count)]);
            }
        }

        // FIX-098: Notify confirmed players if cost changed
        const newCost = parseFloat(cost_per_player);
        if (oldCost !== newCost) {
            const regs = await pool.query(
                "SELECT player_id FROM registrations WHERE game_id = $1 AND status = 'confirmed'",
                [gameId]
            );
            setImmediate(async () => {
                for (const row of regs.rows) {
                    try {
                        await sendNotification('cost_changed', row.player_id, {
                            gameId,
                            oldCost: oldCost.toFixed(2),
                            newCost: newCost.toFixed(2)
                        });
                    } catch (e) { /* non-critical */ }
                }
            });
        }
        
        res.json({ 
            message: 'Game settings updated successfully',
            updated: { game_date, venue_id, max_players, cost_per_player, star_rating, tournament_team_count }
        });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'settings_updated',
            `venue:${venue_id} max:${max_players} cost:£${cost_per_player}${game_date ? ' date:' + game_date : ''}${oldCost !== parseFloat(cost_per_player) ? ` (cost was £${oldCost})` : ''}`));
    } catch (error) {
        console.error('Update game settings error:', error);
        res.status(500).json({ error: 'Failed to update game settings' });
    }
});

// Update ALL future games in a weekly series (venue, players, cost, star rating, time)
app.put('/api/admin/games/:gameId/series-settings', authenticateToken, requireCLMAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { venue_id, max_players, cost_per_player, star_rating, new_time } = req.body;

        if (!venue_id || !max_players || cost_per_player === undefined) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const gameResult = await client.query('SELECT series_id FROM games WHERE id = $1', [gameId]);
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const seriesId = gameResult.rows[0].series_id;
        if (!seriesId) return res.status(400).json({ error: 'This game is not part of a series' });

        // Get all future games in the series
        const futureGames = await client.query(
            'SELECT id, game_date FROM games WHERE series_id = $1 AND game_date > NOW() ORDER BY game_date',
            [seriesId]
        );

        if (futureGames.rows.length === 0) {
            return res.json({ message: 'No future games found in this series', updated: 0 });
        }

        await client.query('BEGIN');

        for (const g of futureGames.rows) {
            if (new_time) {
                // Apply new wall-clock time to each game's date, using London timezone
                const [hours, minutes] = new_time.split(':').map(Number);
                const gameDate = new Date(g.game_date);
                // Build a London-local datetime string and convert to UTC
                const londonDateStr = gameDate.toLocaleDateString('en-GB', { timeZone: 'Europe/London', year: 'numeric', month: '2-digit', day: '2-digit' });
                const [day, month, year] = londonDateStr.split('/');
                const paddedH = String(hours).padStart(2, '0');
                const paddedM = String(minutes).padStart(2, '0');
                const londonLocal = `${year}-${month}-${day}T${paddedH}:${paddedM}:00`;
                const offset = new Date(new Date(londonLocal).toLocaleString('en-US', { timeZone: 'Europe/London' })) - new Date(londonLocal);
                const utcDate = new Date(new Date(londonLocal).getTime() - offset);

                await client.query(
                    'UPDATE games SET venue_id=$1, max_players=$2, cost_per_player=$3, star_rating=$4, game_date=$5 WHERE id=$6',
                    [venue_id, max_players, cost_per_player, star_rating || null, utcDate.toISOString(), g.id]
                );
            } else {
                await client.query(
                    'UPDATE games SET venue_id=$1, max_players=$2, cost_per_player=$3, star_rating=$4 WHERE id=$5',
                    [venue_id, max_players, cost_per_player, star_rating || null, g.id]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ message: `Updated ${futureGames.rows.length} future games in series`, updated: futureGames.rows.length });

    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Series settings update error:', error);
        res.status(500).json({ error: 'Failed to update series settings' });
    } finally {
        client.release();
    }
});

// Get fixed team assignments for a game's series
app.get('/api/admin/games/:gameId/fixed-teams', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Get game's series_id
        const gameResult = await pool.query('SELECT series_id FROM games WHERE id = $1', [gameId]);
        const seriesId = gameResult.rows[0]?.series_id;
        
        if (!seriesId) {
            return res.json([]);
        }
        
        // Get fixed teams for this series
        const result = await pool.query(`
            SELECT player_id, fixed_team
            FROM player_fixed_teams
            WHERE series_id = $1
        `, [seriesId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Get fixed teams error:', error);
        res.status(500).json({ error: 'Failed to get fixed teams' });
    }
});

// Save manual team assignments (for fixed_draft/draft_memory games)
app.post('/api/admin/games/:gameId/save-manual-teams', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { redTeam, blueTeam, teams: tournamentTeams } = req.body;
        
        // Get game info
        const gameResult = await client.query('SELECT series_id, team_selection_type, tournament_team_count FROM games WHERE id = $1', [gameId]);
        const game = gameResult.rows[0];

        // FIX-052: Build set of confirmed player IDs to validate against
        const validPlayersResult = await client.query(
            `SELECT player_id FROM registrations WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );
        const validIds = new Set(validPlayersResult.rows.map(r => r.player_id));

        await client.query('BEGIN');
        
        const isTournament = game.team_selection_type === 'tournament';
        
        if (isTournament && tournamentTeams) {
            // TOURNAMENT MODE: save N teams
            await client.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
            await client.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
            
            for (const [teamName, playerIds] of Object.entries(tournamentTeams)) {
                const teamResult = await client.query(
                    'INSERT INTO teams (game_id, team_name) VALUES ($1, $2) RETURNING id',
                    [gameId, teamName]
                );
                const teamId = teamResult.rows[0].id;
                
                for (const playerId of playerIds) {
                    if (playerId.startsWith && playerId.startsWith('guest_')) {
                        await client.query(
                            "UPDATE game_guests SET team_name = $1 WHERE id = $2",
                            [teamName, playerId.replace('guest_', '')]
                        );
                    } else {
                        if (!validIds.has(playerId)) continue; // FIX-052: skip unregistered players
                        await client.query(
                            'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                            [teamId, playerId]
                        );
                    }
                }
            }
            
            // Mark teams as generated and confirmed
            await client.query(
                'UPDATE games SET teams_generated = true, teams_confirmed = true, game_status = $1 WHERE id = $2',
                ['confirmed', gameId]
            );
            
            await client.query('COMMIT');
            res.json({ message: 'Tournament teams saved successfully' });
            return;
        } else if ((game.team_selection_type === 'fixed_draft' || game.team_selection_type === 'draft_memory' || game.team_selection_type === 'vs_external') && game.series_id) {
            // Save fixed team assignments for the series
            for (const playerId of redTeam) {
                await client.query(`
                    INSERT INTO player_fixed_teams (player_id, series_id, fixed_team)
                    VALUES ($1, $2, 'red')
                    ON CONFLICT (player_id, series_id) DO UPDATE SET fixed_team = 'red'
                `, [playerId, game.series_id]);
            }
            
            for (const playerId of blueTeam) {
                await client.query(`
                    INSERT INTO player_fixed_teams (player_id, series_id, fixed_team)
                    VALUES ($1, $2, 'blue')
                    ON CONFLICT (player_id, series_id) DO UPDATE SET fixed_team = 'blue'
                `, [playerId, game.series_id]);
            }
        }
        
        // Create/update teams for this specific game
        await client.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        await client.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
        
        const redResult = await client.query(
            'INSERT INTO teams (game_id, team_name) VALUES ($1, $2) RETURNING id',
            [gameId, 'Red']
        );
        
        const blueResult = await client.query(
            'INSERT INTO teams (game_id, team_name) VALUES ($1, $2) RETURNING id',
            [gameId, 'Blue']
        );
        
        const redTeamId = redResult.rows[0].id;
        const blueTeamId = blueResult.rows[0].id;
        
        // Add players to teams — skip any not in confirmed registrations
        for (const playerId of redTeam) {
            if (!validIds.has(playerId)) continue;
            await client.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [redTeamId, playerId]
            );
        }
        
        for (const playerId of blueTeam) {
            if (!validIds.has(playerId)) continue;
            await client.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [blueTeamId, playerId]
            );
        }
        
        // Mark teams as generated and confirmed
        await client.query(
            'UPDATE games SET teams_generated = true, teams_confirmed = true, game_status = $1 WHERE id = $2',
            ['confirmed', gameId]
        );
        
        // Get full game details for response
        const fullGameResult = await client.query(`
            SELECT g.*, v.name as venue_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [gameId]);
        
        await client.query('COMMIT');
        
        res.json({ 
            message: 'Teams saved successfully',
            game: fullGameResult.rows[0]
        });
        setImmediate(async () => {
            // Record avg overall rating per team at confirmation time
            try {
                const teamStats = await pool.query(`
                    SELECT t.team_name,
                           COUNT(tp.player_id) as player_count,
                           ROUND(AVG(p.overall_rating)::numeric, 1) as avg_ovr
                    FROM teams t
                    JOIN team_players tp ON tp.team_id = t.id
                    JOIN players p ON p.id = tp.player_id
                    WHERE t.game_id = $1
                    GROUP BY t.team_name ORDER BY t.team_name
                `, [gameId]);
                const teamSummary = teamStats.rows.map(r =>
                    r.team_name + ': ' + r.player_count + 'p avg ' + r.avg_ovr
                ).join(' | ');
                await gameAuditLog(pool, gameId, req.user.playerId, 'teams_confirmed',
                    'Teams confirmed | ' + (teamSummary || 'no team stats'));
            } catch (e) {
                await gameAuditLog(pool, gameId, req.user.playerId, 'teams_confirmed', 'Teams manually confirmed');
            }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Save manual teams error:', error);
        res.status(500).json({ error: 'Failed to save manual teams' });
    } finally {
        client.release();
    }
});

// Confirm game (mark as confirmed without needing team generation)
app.post('/api/admin/games/:gameId/confirm-game', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        await pool.query(
            "UPDATE games SET game_status = 'confirmed', teams_confirmed = true WHERE id = $1",
            [gameId]
        );
        
        res.json({ message: 'Game confirmed' });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'game_confirmed', 'Status set to confirmed'));
    } catch (error) {
        console.error('Confirm game error:', error);
        res.status(500).json({ error: 'Failed to confirm game' });
    }
});

// Confirm teams (saves to database, sets teams_generated = true)
app.post('/api/admin/games/:gameId/confirm-teams', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { redTeam, blueTeam } = req.body;
        
        // Get game details for response
        const gameResult = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);
        const game = gameResult.rows[0];
        
        // Update existing teams (they were created by generate-teams)
        await pool.query(`
            UPDATE teams SET team_name = 'Red'
            WHERE game_id = $1 AND team_name = 'Red'
        `, [gameId]);
        
        await pool.query(`
            UPDATE teams SET team_name = 'Blue'
            WHERE game_id = $1 AND team_name = 'Blue'
        `, [gameId]);
        
        // Clear existing team_players
        await pool.query('DELETE FROM team_players WHERE team_id IN (SELECT id FROM teams WHERE game_id = $1)', [gameId]);
        
        // Get team IDs
        const redTeamResult = await pool.query(
            'SELECT id FROM teams WHERE game_id = $1 AND team_name = $2',
            [gameId, 'Red']
        );
        const blueTeamResult = await pool.query(
            'SELECT id FROM teams WHERE game_id = $1 AND team_name = $2',
            [gameId, 'Blue']
        );
        
        const redTeamId = redTeamResult.rows[0].id;
        const blueTeamId = blueTeamResult.rows[0].id;
        
        // Reset guest team assignments before re-confirming
        await pool.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
        
        // Insert red team players (handle guests separately)
        for (const playerId of redTeam) {
            if (typeof playerId === 'string' && playerId.startsWith('guest_')) {
                const guestDbId = playerId.replace('guest_', '');
                await pool.query(
                    "UPDATE game_guests SET team_name = 'Red' WHERE id = $1",
                    [guestDbId]
                );
            } else {
                await pool.query(
                    'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                    [redTeamId, playerId]
                );
            }
        }
        
        // Insert blue team players (handle guests separately)
        for (const playerId of blueTeam) {
            if (typeof playerId === 'string' && playerId.startsWith('guest_')) {
                const guestDbId = playerId.replace('guest_', '');
                await pool.query(
                    "UPDATE game_guests SET team_name = 'Blue' WHERE id = $1",
                    [guestDbId]
                );
            } else {
                await pool.query(
                    'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                    [blueTeamId, playerId]
                );
            }
        }
        
        // Mark teams as confirmed and set status
        await pool.query(
            'UPDATE games SET teams_generated = true, teams_confirmed = true, game_status = $1 WHERE id = $2',
            ['confirmed', gameId]
        );
        
        // Get full game details with venue for response
        const fullGameResult = await pool.query(`
            SELECT g.*, v.name as venue_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [gameId]);
        
        res.json({ 
            message: 'Teams confirmed',
            game: fullGameResult.rows[0]
        });
    } catch (error) {
        console.error('Confirm teams error:', error);
        res.status(500).json({ error: 'Failed to confirm teams' });
    }
});

// Get teams for a game (for Complete Game modal)
app.get('/api/admin/games/:gameId/teams', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Check if this is a tournament game
        const gameCheck = await pool.query('SELECT team_selection_type, tournament_team_count FROM games WHERE id = $1', [gameId]);
        const isTournament = gameCheck.rows[0]?.team_selection_type === 'tournament';
        
        // Get team IDs
        const teamsResult = await pool.query(
            'SELECT id, team_name FROM teams WHERE game_id = $1 ORDER BY team_name',
            [gameId]
        );
        
        if (teamsResult.rows.length === 0) {
            return res.status(404).json({ error: 'Teams not found' });
        }
        
        // Also fetch guests assigned to teams
        const guestsResult = await pool.query(
            `SELECT id, guest_name, overall_rating, team_name, invited_by
             FROM game_guests WHERE game_id = $1 AND team_name IS NOT NULL`,
            [gameId]
        );
        
        if (isTournament) {
            // Tournament: return all teams keyed by name
            const teams = {};
            for (const team of teamsResult.rows) {
                const playersResult = await pool.query(`
                    SELECT p.id, p.full_name, p.alias, p.squad_number,
                           p.overall_rating, p.defending_rating, p.strength_rating,
                           p.fitness_rating, p.pace_rating, p.decisions_rating,
                           p.assisting_rating, p.shooting_rating, p.goalkeeper_rating,
                           r.position_preference
                    FROM team_players tp
                    JOIN players p ON p.id = tp.player_id
                    JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                    WHERE tp.team_id = $1
                    ORDER BY p.full_name
                `, [team.id, gameId]);
                
                const teamGuests = guestsResult.rows
                    .filter(g => g.team_name === team.team_name)
                    .map(g => ({ id: `guest_${g.id}`, full_name: g.guest_name, alias: `${g.guest_name} (Guest)`, squad_number: null, overall: g.overall_rating || 0, defense: 0, strength: 0, fitness: 0, pace: 0, decisions: 0, assisting: 0, shooting: 0, gk: 0, isGK: false, is_guest: true }));
                
                teams[team.team_name] = [...playersResult.rows.map(p => {
                    const isGKOnly = p.position_preference?.trim().toLowerCase() === 'gk';
                    return {
                        id: p.id, full_name: p.full_name, alias: p.alias, squad_number: p.squad_number,
                        overall: isGKOnly ? (p.goalkeeper_rating || 0) : (p.overall_rating || 0),
                        defense: p.defending_rating || 0,
                        strength: p.strength_rating || 0, fitness: p.fitness_rating || 0,
                        pace: p.pace_rating || 0, decisions: p.decisions_rating || 0,
                        assisting: p.assisting_rating || 0, shooting: p.shooting_rating || 0,
                        gk: p.goalkeeper_rating || 0,
                        isGK: isGKOnly,
                        position_preference: p.position_preference || 'outfield'
                    };
                }), ...teamGuests];
            }
            res.json({ teams, isTournament: true });
        } else {
            // Standard 2-team: return redTeam/blueTeam (backward compatible)
            const redTeamId = teamsResult.rows.find(t => t.team_name === 'Red')?.id;
            const blueTeamId = teamsResult.rows.find(t => t.team_name === 'Blue')?.id;
            
            const [redTeamResult, blueTeamResult] = await Promise.all([
                pool.query(`
                    SELECT p.id, p.full_name, p.alias, p.squad_number,
                           p.overall_rating, p.defending_rating, p.strength_rating,
                           p.fitness_rating, p.pace_rating, p.decisions_rating,
                           p.assisting_rating, p.shooting_rating, p.goalkeeper_rating,
                           r.position_preference
                    FROM team_players tp
                    JOIN players p ON p.id = tp.player_id
                    JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                    WHERE tp.team_id = $1
                    ORDER BY p.full_name
                `, [redTeamId, gameId]),
                pool.query(`
                    SELECT p.id, p.full_name, p.alias, p.squad_number,
                           p.overall_rating, p.defending_rating, p.strength_rating,
                           p.fitness_rating, p.pace_rating, p.decisions_rating,
                           p.assisting_rating, p.shooting_rating, p.goalkeeper_rating,
                           r.position_preference
                    FROM team_players tp
                    JOIN players p ON p.id = tp.player_id
                    JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                    WHERE tp.team_id = $1
                    ORDER BY p.full_name
                `, [blueTeamId, gameId])
            ]);
            
            const mapTeamPlayer = p => {
                const isGKOnly = p.position_preference?.trim().toLowerCase() === 'gk';
                return {
                    id:           p.id,
                    full_name:    p.full_name,
                    alias:        p.alias,
                    squad_number: p.squad_number,
                    overall:      isGKOnly ? (p.goalkeeper_rating || 0) : (p.overall_rating || 0),
                    defense:      p.defending_rating  || 0,
                    strength:     p.strength_rating   || 0,
                    fitness:      p.fitness_rating    || 0,
                    pace:         p.pace_rating       || 0,
                    decisions:    p.decisions_rating  || 0,
                    assisting:    p.assisting_rating  || 0,
                    shooting:     p.shooting_rating   || 0,
                    gk:           p.goalkeeper_rating || 0,
                    isGK:         isGKOnly,
                    position_preference: p.position_preference || 'outfield'
                };
            };

            const redGuests = guestsResult.rows
                .filter(g => g.team_name === 'Red')
                .map(g => ({ id: `guest_${g.id}`, full_name: g.guest_name, alias: `${g.guest_name} (Guest)`, squad_number: null, overall: g.overall_rating || 0, defense: 0, strength: 0, fitness: 0, pace: 0, decisions: 0, assisting: 0, shooting: 0, gk: 0, isGK: false, is_guest: true }));
            const blueGuests = guestsResult.rows
                .filter(g => g.team_name === 'Blue')
                .map(g => ({ id: `guest_${g.id}`, full_name: g.guest_name, alias: `${g.guest_name} (Guest)`, squad_number: null, overall: g.overall_rating || 0, defense: 0, strength: 0, fitness: 0, pace: 0, decisions: 0, assisting: 0, shooting: 0, gk: 0, isGK: false, is_guest: true }));

            const redMapped  = [...redTeamResult.rows.map(mapTeamPlayer),  ...redGuests];
            const blueMapped = [...blueTeamResult.rows.map(mapTeamPlayer), ...blueGuests];

            // Compute team stats for display
            const calcStats = team => ({
                overall:   team.reduce((s, p) => s + (p.overall   || 0), 0),
                defense:   team.reduce((s, p) => s + (p.defense   || 0), 0),
                strength:  team.reduce((s, p) => s + (p.strength  || 0), 0),
                fitness:   team.reduce((s, p) => s + (p.fitness   || 0), 0),
                pace:      team.reduce((s, p) => s + (p.pace      || 0), 0),
                decisions: team.reduce((s, p) => s + (p.decisions || 0), 0),
                assisting: team.reduce((s, p) => s + (p.assisting || 0), 0),
                shooting:  team.reduce((s, p) => s + (p.shooting  || 0), 0)
            });

            res.json({
                redTeam:   redMapped,
                blueTeam:  blueMapped,
                redStats:  calcStats(redMapped),
                blueStats: calcStats(blueMapped)
            });
        }
        
    } catch (error) {
        console.error('Get teams error:', error);
        res.status(500).json({ error: 'Failed to get teams' });
    }
});

// ==========================================
// POST-GAME SYSTEM
// ==========================================

// Start MOTM voting
app.post('/api/admin/games/:gameId/start-motm', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { winningTeam, additionalNominees } = req.body;
        
        // Get winning team players
        const winnersResult = await pool.query(`
            SELECT player_id FROM team_players tp
            JOIN teams t ON t.id = tp.team_id
            WHERE t.game_id = $1 AND t.team_name = $2
        `, [gameId, winningTeam === 'red' ? 'Red' : 'Blue']);
        
        const nominees = winnersResult.rows.map(r => r.player_id);
        
        // Add additional nominees from losing team
        if (additionalNominees && additionalNominees.length > 0) {
            nominees.push(...additionalNominees);
        }
        
        // Insert nominees
        for (const playerId of nominees) {
            await pool.query(
                'INSERT INTO motm_nominees (game_id, player_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [gameId, playerId]
            );
        }
        
        // Set voting end time (24 hours from now)
        const votingEnds = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        await pool.query(
            `UPDATE games SET motm_voting_ends = $1 WHERE id = $2`,
            [votingEnds, gameId]
        );
        
        res.json({ message: 'MOTM voting started', votingEndsAt: votingEnds });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'motm_voting_started', `Voting ends: ${votingEnds}`));

        // Non-critical: notify all nominees that voting is open
        setImmediate(async () => {
            try {
                const gameData = await getGameDataForNotification(gameId);
                for (const pid of nominees) {
                    await sendNotification('motm_voting_open', pid, gameData).catch(() => {});
                }
            } catch (e) {
                console.error('MOTM voting open notification failed (non-critical):', e.message);
            }
        });
    } catch (error) {
        console.error('Start MOTM error:', error);
        res.status(500).json({ error: 'Failed to start MOTM voting' });
    }
});

// Vote for MOTM
app.post('/api/games/:gameId/vote-motm', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { votedForId } = req.body;
        
        // Can't vote for yourself
        if (votedForId === req.user.playerId) {
            return res.status(400).json({ error: 'You cannot vote for yourself' });
        }
        
        // Check if player played in this game
        const playedResult = await pool.query(
            'SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = $3',
            [gameId, req.user.playerId, 'confirmed']
        );
        
        if (playedResult.rows.length === 0) {
            return res.status(403).json({ error: 'Only players who played can vote' });
        }
        
        // Check if voting is open
        const gameResult = await pool.query(
            'SELECT motm_voting_ends FROM games WHERE id = $1',
            [gameId]
        );
        
        // FIX-092: Guard against invalid/non-existent game ID (was crashing with TypeError)
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });

        const game = gameResult.rows[0];
        if (!game.motm_voting_ends || new Date() > new Date(game.motm_voting_ends)) {
            return res.status(400).json({ error: 'Voting is closed' });
        }

        // FIX-017: Validate votedForId is an actual nominee for this game
        const nomineeCheck = await pool.query(
            'SELECT 1 FROM motm_nominees WHERE game_id = $1 AND player_id = $2',
            [gameId, votedForId]
        );
        if (nomineeCheck.rows.length === 0) {
            return res.status(400).json({ error: 'That player is not a nominee for this game' });
        }
        
        // Insert vote (ON CONFLICT will update if already voted)
        await pool.query(
            `INSERT INTO motm_votes (game_id, voter_id, voted_for_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (game_id, voter_id) DO UPDATE SET voted_for_id = $3`,
            [gameId, req.user.playerId, votedForId]
        );
        
        res.json({ message: 'Vote recorded' });

        // Audit: record who voted for whom with full names
        setImmediate(async () => {
            try {
                const [voterRow, nomineeRow] = await Promise.all([
                    pool.query('SELECT full_name, alias FROM players WHERE id = $1', [req.user.playerId]),
                    pool.query('SELECT full_name, alias FROM players WHERE id = $1', [votedForId]),
                ]);
                const voterName = voterRow.rows[0]?.alias || voterRow.rows[0]?.full_name || req.user.playerId;
                const nomineeName = nomineeRow.rows[0]?.alias || nomineeRow.rows[0]?.full_name || votedForId;
                await gameAuditLog(pool, gameId, null, 'motm_vote',
                    `Voter: ${voterName} (${req.user.playerId}) voted for ${nomineeName} (${votedForId})`);
            } catch (e) { /* non-critical */ }
        });
    } catch (error) {
        console.error('Vote MOTM error:', error);
        res.status(500).json({ error: 'Failed to record vote' });
    }
});

// Get MOTM voting results
app.get('/api/games/:gameId/motm-results', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        const result = await pool.query(`
            SELECT 
                p.id,
                p.full_name,
                p.alias,
                COUNT(mv.id) as votes
            FROM motm_nominees mn
            JOIN players p ON p.id = mn.player_id
            LEFT JOIN motm_votes mv ON mv.game_id = mn.game_id AND mv.voted_for_id = mn.player_id
            WHERE mn.game_id = $1
            GROUP BY p.id, p.full_name, p.alias
            ORDER BY votes DESC
        `, [gameId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Get MOTM results error:', error);
        res.status(500).json({ error: 'Failed to get results' });
    }
});

// ==========================================
// COMPLETE GAME ENDPOINT
// ==========================================

// Complete game (post-game process)
// Unconfirm game / Delete teams
app.post('/api/admin/games/:gameId/unconfirm', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { reason, removedPlayers } = req.body;
        
        // Get game details
        const gameResult = await client.query(
            'SELECT cost_per_player, format FROM games WHERE id = $1',
            [gameId]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        const gameCost = parseFloat(game.cost_per_player);
        
        await client.query('BEGIN');
            // Collect late-dropout player IDs for tier recalc AFTER commit (not inside transaction)
            const lateDropoutPlayerIds = [];

            // Handle player removals if reason is player_dropout
            if (reason === 'player_dropout' && removedPlayers && removedPlayers.length > 0) {
                for (const removal of removedPlayers) {
                    const { playerId, registrationId, refundAmount, isLateDropout } = removal;
                    
                    // Remove player registration
                    await client.query(
                        'DELETE FROM registrations WHERE id = $1',
                        [registrationId]
                    );
                    
                    // Process refund if amount > 0
                    if (refundAmount > 0) {
                        await client.query(
                            `UPDATE credits 
                             SET balance = balance + $1 
                             WHERE player_id = $2`,
                            [refundAmount, playerId]
                        );
                        
                        // Log the refund
                        await client.query(
                            `INSERT INTO credit_transactions (player_id, amount, type, description)
                             VALUES ($1, $2, 'refund', $3)`,
                            [playerId, refundAmount, `Removed from game - £${refundAmount.toFixed(2)} refund`]
                        );
                    }
                    
                    // Award discipline points if late dropout
                    if (isLateDropout) {
                        const formatLower = (game.format || '').toLowerCase().replace(/\s+/g, '');
                        const is11aSide = formatLower.includes('11') &&
                            (formatLower.includes('side') || formatLower.includes('v') || formatLower.includes('x'));
                        const disciplinePoints = is11aSide ? 3 : 2;
                        
                        await client.query(
                            `INSERT INTO discipline_records (player_id, game_id, offense_type, points, warning_level)
                             VALUES ($1, $2, 'Late Drop Out', $3, 0)`,
                            [playerId, gameId, disciplinePoints]
                        );
                        // NOTE: Tier recalculation runs AFTER commit (see below) — never inside
                        // the transaction, to prevent a DB function error from aborting everything
                        lateDropoutPlayerIds.push(playerId);
                    }
                }
            }
            
            // Delete teams
            const teamsResult = await client.query(
                'SELECT id FROM teams WHERE game_id = $1',
                [gameId]
            );
            
            for (const team of teamsResult.rows) {
                await client.query('DELETE FROM team_players WHERE team_id = $1', [team.id]);
            }
            
            await client.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
            await client.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
            
            // Revert game status
            await client.query(`
                UPDATE games 
                SET game_status = 'available',
                    teams_confirmed = FALSE,
                    teams_generated = FALSE
                WHERE id = $1
            `, [gameId]);
            
            await client.query('COMMIT');
            
            res.json({ 
                message: 'Game unconfirmed successfully',
                playersRemoved: removedPlayers?.length || 0
            });

            // Audit + superadmin notification
            setImmediate(async () => {
                try {
                    const gameData = await getGameDataForNotification(gameId);
                    await gameAuditLog(pool, gameId, req.user.playerId, 'teams_deleted',
                        `Teams deleted | reason: ${reason || 'other'} | players removed: ${removedPlayers?.length || 0}`);
                    await notifyAdmin('🗑️ Teams Deleted', [
                        ['Game', (gameData.day || '') + ' ' + (gameData.time || '')],
                        ['Venue', gameData.venue || ''],
                        ['Reason', reason || 'other'],
                        ['Players removed', String(removedPlayers?.length || 0)],
                    ]);
                } catch (e) { /* non-critical */ }
            });

            // Recalculate tiers for late dropouts AFTER commit and response,
            // using pool (not client) so any failure is fully isolated.
            // Cast to ::uuid so Postgres resolves the overloaded function correctly.
            if (lateDropoutPlayerIds.length > 0) {
                setImmediate(async () => {
                    for (const pid of lateDropoutPlayerIds) {
                        try {
                            const tierResult = await pool.query(
                                'SELECT calculate_player_tier($1::uuid) as new_tier', [pid]
                            );
                            const newTier = tierResult.rows[0]?.new_tier;
                            if (newTier) {
                                await pool.query(
                                    'UPDATE players SET reliability_tier = $1 WHERE id = $2',
                                    [newTier, pid]
                                );
                            }
                        } catch (tierError) {
                            console.error('Tier recalc failed for player', pid, ':', tierError.message);
                        }
                    }
                });
            }
        
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Unconfirm game error:', error);
        res.status(500).json({ error: 'Failed to unconfirm game' });
    } finally {
        client.release();
    }
});

app.post('/api/admin/games/:gameId/complete', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { winningTeam, disciplineRecords, beefEntries, motmNominees } = req.body;

        // FIX-062: Whitelist winningTeam before any DB work
        const validTeams = ['red', 'blue', 'draw', 'Red', 'Blue', 'Draw'];
        if (!validTeams.includes(winningTeam)) {
            return res.status(400).json({ error: `Invalid winning team. Must be one of: ${validTeams.join(', ')}` });
        }

        // FIX-097: Combine both type queries into one — also grab series_id for FIX-086
        const gameTypeCheck = await pool.query('SELECT team_selection_type, game_status, series_id FROM games WHERE id = $1', [gameId]);
        const gameType = gameTypeCheck.rows[0]?.team_selection_type;
        const gameStatus = gameTypeCheck.rows[0]?.game_status;
        const seriesUuidFromCheck = gameTypeCheck.rows[0]?.series_id;

        // Block tournament games — must use /finalise-tournament instead
        if (gameType === 'tournament') {
            return res.status(400).json({ error: 'Tournament games must be completed via the Finalise Tournament flow' });
        }

        // FIX-061: Prevent double-completion — stats would be doubled
        if (gameStatus === 'completed') {
            return res.status(400).json({ error: 'Game has already been completed' });
        }

        const isExternal = gameType === 'vs_external';
        
        await client.query('BEGIN');

        // FIX-061: Lock the row and re-check inside transaction to prevent races
        const statusCheck = await client.query('SELECT game_status FROM games WHERE id = $1 FOR UPDATE', [gameId]);
        if (statusCheck.rows[0]?.game_status === 'completed') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Game has already been completed' });
        }

        const shouldHaveMotm = !(isExternal && winningTeam === 'blue');
        
        // 1. Update game winning team and status
        await client.query(
            `UPDATE games 
             SET winning_team = $1, 
                 game_status = 'completed',
                 motm_voting_ends = ${shouldHaveMotm ? "NOW() + INTERVAL '24 hours'" : 'NULL'}
             WHERE id = $2`,
            [winningTeam, gameId]
        );
        
        // 2. Get all players in the game
        const playersResult = await client.query(
            `SELECT DISTINCT player_id FROM registrations 
             WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );
        const allPlayerIds = playersResult.rows.map(r => r.player_id);
        const confirmedSet = new Set(allPlayerIds);

        // CRIT-29: Validate motmNominees and beefEntries contain only confirmed participants.
        // Without this, an admin could inflate stats for any player in the DB.
        const invalidNominees = (motmNominees || []).filter(id => !confirmedSet.has(id));
        if (invalidNominees.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'motmNominees contains players not confirmed for this game' });
        }
        const invalidBeef = (beefEntries || []).filter(b => !confirmedSet.has(b.player1) || !confirmedSet.has(b.player2));
        if (invalidBeef.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'beefEntries contains players not confirmed for this game' });
        }
        
        // Get players with no-show discipline
        const noShowPlayerIds = (disciplineRecords || [])
            .filter(d => d.offense === 'no_show')
            .map(d => d.playerId);
        
        // Players who showed up (everyone except no-shows)
        const showedUpPlayerIds = allPlayerIds.filter(id => !noShowPlayerIds.includes(id));
        
        // Update appearances for players who showed up
        if (showedUpPlayerIds.length > 0) {
            await client.query(
                `UPDATE players 
                 SET total_appearances = total_appearances + 1
                 WHERE id = ANY($1)`,
                [showedUpPlayerIds]
            );
        }
        
        // Update wins for winning team players
        if (winningTeam && winningTeam !== 'draw') {
            let winningPlayerIds = [];
            
            if (isExternal && winningTeam === 'red') {
                // TF wins: all confirmed players who showed up get the win
                winningPlayerIds = showedUpPlayerIds;
            } else if (isExternal && winningTeam === 'blue') {
                // Opponent wins: no TF players get wins
                winningPlayerIds = [];
            } else {
                // Standard game: get winners from team_players table
                const winningTeamName = winningTeam === 'red' ? 'Red' : 'Blue';
                const winningPlayersResult = await client.query(`
                    SELECT tp.player_id FROM team_players tp
                    JOIN teams t ON t.id = tp.team_id
                    WHERE t.game_id = $1 AND t.team_name = $2
                `, [gameId, winningTeamName]);
                winningPlayerIds = winningPlayersResult.rows.map(r => r.player_id);
            }
            
            if (winningPlayerIds.length > 0) {
                await client.query(
                    `UPDATE players 
                     SET total_wins = total_wins + 1
                     WHERE id = ANY($1)`,
                    [winningPlayerIds]
                );
                console.log(`Updated wins for ${winningPlayerIds.length} winning players`);
            }
        } else if (winningTeam === 'draw') {
        }
        
        // 3. Save discipline records (only for offenses, not on_time)
        // FIX-022: Only process discipline for players who were actually in the game
        const confirmedPlayerSet = new Set(allPlayerIds);
        for (const record of disciplineRecords || []) {
            if (!confirmedPlayerSet.has(record.playerId)) continue; // skip non-participants
            if (record.points > 0) {
                const offenseTypes = {
                    'on_time': 'On Time',
                    'not_ready': 'Not Ready (0-5 Min)',
                    'late_drop': 'Late Drop Out',
                    '5_10_late': '5-10 Minutes Late',
                    '10_late': '10+ Minutes Late',
                    'no_show': 'No Show'
                };
                
                await client.query(
                    `INSERT INTO discipline_records (player_id, game_id, offense_type, points, warning_level)
                     VALUES ($1, $2, $3, $4, $5)`,
                    [record.playerId, gameId, offenseTypes[record.offense] || 'Unknown', record.points, record.warning]
                );
            }
        }
        
        // 3b. Collect disciplined player IDs for tier recalc AFTER commit
        // (same pattern as unconfirm — never call calculate_player_tier inside a transaction)
        const uniqueDisciplinedIds = [...new Set(
            (disciplineRecords || []).filter(d => d.points > 0).map(d => d.playerId)
        )];
        
        // 4. Save beef entries (bidirectional)
        for (const beef of beefEntries || []) {
            await client.query(
                `INSERT INTO beef (player_id, target_player_id, rating)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (player_id, target_player_id) 
                 DO UPDATE SET rating = $3`,
                [beef.player1, beef.player2, beef.level]
            );
            
            await client.query(
                `INSERT INTO beef (player_id, target_player_id, rating)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (player_id, target_player_id) 
                 DO UPDATE SET rating = $3`,
                [beef.player2, beef.player1, beef.level]
            );
        }
        
        // 5. Create MOTM nominees (skip if external game where opponent won)
        let nomineesInserted = 0;
        if (shouldHaveMotm) {
            for (const playerId of motmNominees || []) {
                await client.query(
                    `INSERT INTO motm_nominees (game_id, player_id)
                     VALUES ($1, $2)
                     ON CONFLICT DO NOTHING`,
                    [gameId, playerId]
                );
                nomineesInserted++;
            }
        } else {
        }
        
        // FIX-086: Series score update moved INSIDE transaction to prevent orphaned scores on crash
        if (seriesUuidFromCheck && (gameType === 'draft_memory' || gameType === 'vs_external')) {
            const seriesCol = winningTeam === 'red' ? 'red_wins' : winningTeam === 'blue' ? 'blue_wins' : 'draws';
            await client.query(`UPDATE game_series SET ${seriesCol} = ${seriesCol} + 1 WHERE id = $1`, [seriesUuidFromCheck]);
        }

        await client.query('COMMIT');
        // FIX-063: Single summary log replacing all step-by-step debug logs
        console.log(`Game ${gameId} completed. Winner: ${winningTeam}. MOTM nominees: ${nomineesInserted}`);
        
        // FIX-085: Auto-allocate badges OUTSIDE transaction in setImmediate (was N+1 inside transaction)
        setImmediate(async () => {
            for (const playerId of allPlayerIds) {
                try {
                    await autoAllocateBadges(playerId);
                } catch (badgeError) {
                    console.error(`Failed to auto-allocate badges for player ${playerId}:`, badgeError.message);
                }
            }
        });

        // Recalculate reliability tiers for disciplined players AFTER commit, using pool
        // (not client) with ::uuid cast so the overloaded DB function resolves correctly
        if (uniqueDisciplinedIds.length > 0) {
            setImmediate(async () => {
                for (const dpId of uniqueDisciplinedIds) {
                    try {
                        const tierResult = await pool.query(
                            'SELECT calculate_player_tier($1::uuid) as new_tier', [dpId]
                        );
                        const newTier = tierResult.rows[0]?.new_tier;
                        if (newTier) {
                            await pool.query(
                                'UPDATE players SET reliability_tier = $1 WHERE id = $2',
                                [newTier, dpId]
                            );
                        }
                    } catch (tierError) {
                        console.error('Tier recalc failed for player', dpId, ':', tierError.message);
                    }
                }
            });
        }
        
        res.json({ 
            message: 'Game completed successfully',
            motmNominees: nomineesInserted,
            motmVotingEnds: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });
        setImmediate(async () => {
            await gameAuditLog(pool, gameId, req.user.playerId, 'game_completed',
                `Winner: ${winningTeam || 'N/A'} | MOTM nominees: ${nomineesInserted}`);
            try {
                const gameData = await getGameDataForNotification(gameId);
                await notifyAdmin('✅ Game Completed', [
                    ['Game', (gameData.day || '') + ' ' + (gameData.time || '')],
                    ['Venue', gameData.venue || ''],
                    ['Winner', winningTeam || 'N/A'],
                    ['MOTM nominees', String(nomineesInserted)],
                ]);
            } catch (e) { /* non-critical */ }
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Complete game error:', error);
        res.status(500).json({ 
            error: 'Failed to complete game'
        });
    } finally {
        client.release();
    }
});

// Get MOTM nominees and votes for a game
app.get('/api/games/:gameId/motm', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Get nominees with vote counts
        const result = await pool.query(`
            SELECT 
                n.player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                COUNT(v.id) as votes
            FROM motm_nominees n
            JOIN players p ON p.id = n.player_id
            LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
            WHERE n.game_id = $1
            GROUP BY n.player_id, p.full_name, p.alias, p.squad_number
            ORDER BY votes DESC, p.full_name ASC
        `, [gameId]);
        
        // Check if voting is still open
        const gameResult = await pool.query(
            'SELECT motm_voting_ends, motm_winner_id FROM games WHERE id = $1',
            [gameId]
        );
        
        const game = gameResult.rows[0];
        const votingOpen = game.motm_voting_ends && new Date(game.motm_voting_ends) > new Date();
        
        // Check if requesting player has already voted
        const voteCheck = await pool.query(
            'SELECT 1 FROM motm_votes WHERE game_id = $1 AND voter_id = $2',
            [gameId, req.user.playerId]
        );
        const hasVoted = voteCheck.rows.length > 0;

        res.json({
            nominees: result.rows,
            votingOpen: votingOpen,
            votingEnds: game.motm_voting_ends,
            winner: game.motm_winner_id,
            hasVoted,
        });
        
    } catch (error) {
        console.error('Get MOTM error:', error);
        res.status(500).json({ error: 'Failed to get MOTM data' });
    }
});

// PUBLIC endpoint - Get team sheet by game URL (no auth required)
app.get('/api/public/game/:gameUrl/teams', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game by URL - allow confirmed games even if not completed
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1 AND g.teams_confirmed = TRUE
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found or teams not confirmed yet' });
        }
        
        const game = gameResult.rows[0];
        
        // Get teams
        const teamsResult = await pool.query(`
            SELECT t.id, t.team_name
            FROM teams t
            WHERE t.game_id = $1
            ORDER BY t.team_name
        `, [game.id]);
        
        if (teamsResult.rows.length === 0) {
            return res.status(404).json({ error: 'Teams not generated yet' });
        }
        
        // TOURNAMENT BRANCH: return all teams + results + league table
        if (game.team_selection_type === 'tournament') {
            const tournamentTeams = {};
            for (const team of teamsResult.rows) {
                const playersResult = await pool.query(`
                    SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position
                    FROM team_players tp
                    JOIN players p ON p.id = tp.player_id
                    JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                    WHERE tp.team_id = $1
                    ORDER BY CASE WHEN r.position_preference = 'goalkeeper' THEN 0 ELSE 1 END, COALESCE(p.alias, p.full_name)
                `, [team.id, game.id]);
                
                // Include guests on this team
                const teamGuests = await pool.query(
                    `SELECT id, guest_name, overall_rating FROM game_guests WHERE game_id = $1 AND team_name = $2`,
                    [game.id, team.team_name]
                );
                
                const players = playersResult.rows.map(p => ({
                    id: p.id, name: p.alias || p.full_name, squadNumber: p.squad_number,
                    photo_url: p.photo_url, isGK: p.position === 'goalkeeper'
                }));
                const guests = teamGuests.rows.map(g => ({
                    id: `guest_${g.id}`, name: `${g.guest_name} (Guest)`, squadNumber: null,
                    photo_url: null, isGK: false, isGuest: true
                }));
                
                tournamentTeams[team.team_name] = [...players, ...guests];
            }
            
            // Get results + league table
            const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [game.id]);
            const teamNames = teamsResult.rows.map(t => t.team_name);
            const leagueTable = calculateLeagueTable(allResults.rows, teamNames);
            
            // MOTM for tournament
            let motmNominees = [];
            let votingOpen = false;
            let votingFinalized = false;
            if (game.game_status === 'completed' && game.motm_voting_ends) {
                const votingEnds = new Date(game.motm_voting_ends);
                votingOpen = votingEnds > new Date();
                votingFinalized = game.motm_winner_id !== null;
                const motmResult = await pool.query(`
                    SELECT n.player_id, p.full_name, p.alias, p.squad_number,
                           COUNT(v.id) as votes, (n.player_id = g.motm_winner_id) as is_winner
                    FROM motm_nominees n
                    JOIN players p ON p.id = n.player_id
                    JOIN games g ON g.id = n.game_id
                    LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
                    WHERE n.game_id = $1
                    GROUP BY n.player_id, p.full_name, p.alias, p.squad_number, g.motm_winner_id
                    ORDER BY votes DESC
                `, [game.id]);
                motmNominees = motmResult.rows;
            }
            
            return res.json({
                isTournament: true,
                game: {
                    id: game.id, game_url: game.game_url, date: game.game_date,
                    venue_name: game.venue_name, venue_address: game.venue_address, format: game.format,
                    tournament_name: game.tournament_name, tournament_team_count: game.tournament_team_count,
                    tournament_results_finalised: game.tournament_results_finalised,
                    winning_team: game.winning_team, game_status: game.game_status,
                    team_selection_type: game.team_selection_type,
                    votingOpen, votingFinalized, votingEnds: game.motm_voting_ends
                },
                teams: tournamentTeams,
                results: allResults.rows,
                leagueTable,
                motmNominees
            });
        }
        
        // STANDARD 2-TEAM MODE
        const redTeamId = teamsResult.rows.find(t => t.team_name === 'Red')?.id;
        const blueTeamId = teamsResult.rows.find(t => t.team_name === 'Blue')?.id;
        
        // Get players for each team
        const [redTeamResult, blueTeamResult] = await Promise.all([
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY 
                    CASE WHEN r.position_preference = 'goalkeeper' THEN 0 ELSE 1 END,
                    COALESCE(p.alias, p.full_name)
            `, [redTeamId, game.id]),
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY 
                    CASE WHEN r.position_preference = 'goalkeeper' THEN 0 ELSE 1 END,
                    COALESCE(p.alias, p.full_name)
            `, [blueTeamId, game.id])
        ]);
        
        // Map to format expected by frontend
        const redTeam = redTeamResult.rows.map(p => ({
            id: p.id,
            name: p.alias || p.full_name,
            squadNumber: p.squad_number,
            photo_url: p.photo_url,
            isGK: p.position === 'goalkeeper'
        }));
        
        const blueTeam = blueTeamResult.rows.map(p => ({
            id: p.id,
            name: p.alias || p.full_name,
            squadNumber: p.squad_number,
            photo_url: p.photo_url,
            isGK: p.position === 'goalkeeper'
        }));
        
        // Also fetch guests assigned to teams
        const guestsTeamResult = await pool.query(
            `SELECT id, guest_name, team_name FROM game_guests WHERE game_id = $1 AND team_name IS NOT NULL`,
            [game.id]
        );
        for (const guest of guestsTeamResult.rows) {
            const guestObj = {
                id: `guest_${guest.id}`,
                name: `${guest.guest_name}`,
                squadNumber: null,
                photo_url: null,
                isGK: false,
                isGuest: true
            };
            if (guest.team_name === 'Red') redTeam.push(guestObj);
            else if (guest.team_name === 'Blue') blueTeam.push(guestObj);
        }
        
        // Get MOTM data if game is completed
        let motmNominees = [];
        let votingOpen = false;
        let votingFinalized = false;
        
        if (game.game_status === 'completed' && game.motm_voting_ends) {
            const votingEnds = new Date(game.motm_voting_ends);
            const now = new Date();
            votingOpen = votingEnds > now;
            votingFinalized = game.motm_winner_id !== null;
            
            // Get MOTM nominees with vote counts
            const motmResult = await pool.query(`
                SELECT 
                    n.player_id,
                    p.full_name,
                    p.alias,
                    p.squad_number,
                    COUNT(v.id) as votes,
                    (n.player_id = g.motm_winner_id) as is_winner
                FROM motm_nominees n
                JOIN players p ON p.id = n.player_id
                JOIN games g ON g.id = n.game_id
                LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
                WHERE n.game_id = $1
                GROUP BY n.player_id, p.full_name, p.alias, p.squad_number, g.motm_winner_id
                ORDER BY votes DESC, p.full_name ASC
            `, [game.id]);
            
            motmNominees = motmResult.rows;
        }
        
        // Get next game in series if exists
        let nextGame = null;
        let seriesScoreline = null;
        if (game.series_id) {
            const nextGameResult = await pool.query(`
                SELECT g.id, g.game_url, g.game_date, g.cost_per_player, g.format,
                       v.name as venue_name,
                       ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                       g.max_players
                FROM games g
                LEFT JOIN venues v ON v.id = g.venue_id
                WHERE g.series_id = $1 
                AND g.game_date > $2
                AND g.game_status IN ('available', 'confirmed')
                ORDER BY g.game_date ASC
                LIMIT 1
            `, [game.series_id, game.game_date]);
            
            if (nextGameResult.rows.length > 0) {
                nextGame = nextGameResult.rows[0];
            }
            
            // Get series scoreline for draft_memory / vs_external
            try {
                const scoreResult = await pool.query(
                    'SELECT series_name, series_type, red_wins, blue_wins, draws FROM game_series WHERE id = $1',
                    [game.series_id]
                );
                if (scoreResult.rows.length > 0) {
                    seriesScoreline = scoreResult.rows[0];
                }
            } catch (e) { /* non-critical */ }
        }
        
        res.json({
            game: {
                id: game.id,
                game_url: game.game_url,
                date: game.game_date,
                venue_name: game.venue_name,
                venue_address: game.venue_address,
                format: game.format,
                winning_team: game.winning_team,
                game_status: game.game_status,
                team_selection_type: game.team_selection_type,
                external_opponent: game.external_opponent,
                tf_kit_color: game.tf_kit_color,
                opp_kit_color: game.opp_kit_color,
                votingOpen,
                votingFinalized,
                votingEnds: game.motm_voting_ends
            },
            redTeam,
            blueTeam,
            motmNominees,
            nextGame,
            seriesScoreline
        });
        
    } catch (error) {
        console.error('Get public team sheet error:', error);
        res.status(500).json({ error: 'Failed to get team sheet' });
    }
});

// ── GAME URL VIEW TRACKING ───────────────────────────────────────────────────
// POST /api/public/game/:gameUrl/view — called by game.html on load.
// Records which player viewed which game URL and when.
// Uses optionalAuth: logged-in players are identified; guests recorded anonymously.
// Table: game_url_views (game_id, player_id nullable, viewed_at, ip_hash)
// Created with: CREATE TABLE IF NOT EXISTS game_url_views (
//   id BIGSERIAL PRIMARY KEY,
//   game_id UUID REFERENCES games(id) ON DELETE CASCADE,
//   player_id UUID REFERENCES players(id) ON DELETE SET NULL,
//   viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//   ip_hash TEXT
// );
app.post('/api/public/game/:gameUrl/view', optionalAuth, async (req, res) => {
    try {
        const { gameUrl } = req.params;

        // Resolve game_id from game_url
        const gameResult = await pool.query(
            'SELECT id FROM games WHERE game_url = $1',
            [gameUrl]
        );
        if (gameResult.rows.length === 0) return res.json({ recorded: false });

        const gameId = gameResult.rows[0].id;
        const playerId = req.user?.playerId || null;

        // Hash IP for privacy (not stored raw)
        const crypto = require('crypto');
        const rawIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '';
        const ipHash = crypto.createHash('sha256').update(rawIp).digest('hex').slice(0, 16);

        await pool.query(
            `INSERT INTO game_url_views (game_id, player_id, viewed_at, ip_hash)
             VALUES ($1, $2, NOW(), $3)`,
            [gameId, playerId, ipHash]
        );

        res.json({ recorded: true });
    } catch (error) {
        // If table doesn't exist yet, silently ignore rather than erroring on game page
        if (error.code === '42P01') {
            console.warn('game_url_views table does not exist yet — run the CREATE TABLE migration');
            return res.json({ recorded: false, hint: 'table_missing' });
        }
        console.error('Game view tracking error:', error);
        res.json({ recorded: false });
    }
});

// GET /api/admin/games/:gameId/views — admin: who has viewed this game URL
app.get('/api/admin/games/:gameId/views', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const result = await pool.query(
            `SELECT
                gv.viewed_at,
                p.full_name,
                p.alias,
                p.squad_number,
                CASE WHEN p.id IS NULL THEN 'Guest (not logged in)' ELSE NULL END as guest_label
             FROM game_url_views gv
             LEFT JOIN players p ON p.id = gv.player_id
             WHERE gv.game_id = $1
             ORDER BY gv.viewed_at DESC
             LIMIT 200`,
            [gameId]
        );
        res.json(result.rows);
    } catch (error) {
        if (error.code === '42P01') return res.json([]);
        console.error('Get game views error:', error);
        res.status(500).json({ error: 'Failed to fetch views' });
    }
});


// PUBLIC endpoint - Get game details for registration/sharing (no auth required)
app.get('/api/public/game/:gameUrl/details', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // FIX-048: Select only safe public columns — no g.* to avoid leaking internal fields
        const gameResult = await pool.query(`
            SELECT g.id, g.game_url, g.game_date, g.venue_id, g.format, g.max_players,
                   g.cost_per_player, g.game_status, g.exclusivity, g.teams_confirmed,
                   g.team_selection_type, g.external_opponent, g.tf_kit_color, g.opp_kit_color,
                   g.winning_team, g.motm_voting_ends, g.motm_winner_id, g.tournament_name,
                   g.tournament_team_count, g.tournament_results_finalised, g.series_id,
                   g.regularity,
                   v.name as venue_name, v.address as venue_address, v.photo_url as venue_photo,
                   v.pitch_location as venue_pitch_location, v.facilities as venue_facilities, v.notes as venue_notes,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        // Map venue names to their photo URLs (override database)
        const venuePhotoMap = {
            'Daimler Green': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/daimler_green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Power League': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/powerleague.jpg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg'
        };
        
        const venue_photo = game.venue_name && venuePhotoMap[game.venue_name] 
            ? venuePhotoMap[game.venue_name] 
            : game.venue_photo;
        
        // Get series scoreline if applicable
        let seriesScoreline = null;
        if (game.series_id) {
            try {
                const scoreResult = await pool.query(
                    'SELECT series_name, series_type, red_wins, blue_wins, draws FROM game_series WHERE id = $1',
                    [game.series_id]
                );
                if (scoreResult.rows.length > 0) {
                    seriesScoreline = scoreResult.rows[0];
                }
            } catch (e) { /* non-critical */ }
        }
        
        res.json({
            id: game.id,
            game_url: game.game_url,
            game_date: game.game_date,
            venue_id: game.venue_id,
            venue_name: game.venue_name,
            venue_address: game.venue_address,
            venue_photo: venue_photo,
            venue_pitch_location: game.venue_pitch_location || null,
            venue_facilities: game.venue_facilities || null,
            venue_notes: game.venue_notes || null,
            format: game.format,
            max_players: game.max_players,
            current_players: game.current_players,
            cost_per_player: game.cost_per_player,
            game_status: game.game_status,
            exclusivity: game.exclusivity,
            teams_confirmed: game.teams_confirmed,
            team_selection_type: game.team_selection_type,
            external_opponent: game.external_opponent,
            tf_kit_color: game.tf_kit_color,
            opp_kit_color: game.opp_kit_color,
            winning_team: game.winning_team,
            motm_voting_ends: game.motm_voting_ends,
            motm_winner_id: game.motm_winner_id,
            tournament_name: game.tournament_name,
            tournament_team_count: game.tournament_team_count,
            tournament_results_finalised: game.tournament_results_finalised,
            series_id: game.series_id || null,
            regularity: game.regularity || null,
            seriesScoreline
        });
        
    } catch (error) {
        console.error('Get public game details error:', error);
        res.status(500).json({ error: 'Failed to get game details' });
    }
});

// ── GET /api/public/game/:gameUrl/series ─────────────────────────────────────
// Returns all games in the same series, ordered by date, with prev/next/position
app.get('/api/public/game/:gameUrl/series', async (req, res) => {
    try {
        const { gameUrl } = req.params;

        // Get the current game's series_id
        const gameResult = await pool.query(
            'SELECT id, series_id, venue_id, regularity, game_date FROM games WHERE game_url = $1',
            [gameUrl]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const { id: gameId, series_id, venue_id, regularity } = gameResult.rows[0];

        // If no series_id but game is weekly recurring, group by venue + regularity as a fallback
        let seriesResult;
        if (series_id) {
            seriesResult = await pool.query(`
                SELECT g.id, g.game_url, g.game_date, g.game_status, g.max_players,
                       ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed')
                        + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players
                FROM games g
                WHERE g.series_id = $1
                ORDER BY g.game_date ASC
            `, [series_id]);
        } else if (regularity === 'weekly' && venue_id) {
            // Legacy weekly games without a series_id — group by venue
            seriesResult = await pool.query(`
                SELECT g.id, g.game_url, g.game_date, g.game_status, g.max_players,
                       ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed')
                        + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players
                FROM games g
                WHERE g.venue_id = $1 AND g.regularity = 'weekly' AND g.series_id IS NULL
                ORDER BY g.game_date ASC
            `, [venue_id]);
        } else {
            return res.json({ series: null });
        }

        const games = seriesResult.rows;
        const currentIndex = games.findIndex(g => g.id === gameId);
        if (currentIndex === -1) return res.json({ series: null });

        const prev = currentIndex > 0 ? games[currentIndex - 1] : null;
        const next = currentIndex < games.length - 1 ? games[currentIndex + 1] : null;

        res.json({
            series: {
                games,
                currentIndex,
                prev: prev ? { game_url: prev.game_url, game_date: prev.game_date, game_status: prev.game_status } : null,
                next: next ? { game_url: next.game_url, game_date: next.game_date, game_status: next.game_status } : null,
                total: games.length
            }
        });
    } catch (error) {
        console.error('Series nav error:', error);
        res.status(500).json({ error: 'Failed to load series' });
    }
});

// ── GET /api/public/game/:gameUrl/next ────────────────────────────────────────
// Returns the next upcoming game in the same series (for CTA "Sign up for next week")
app.get('/api/public/game/:gameUrl/next', async (req, res) => {
    try {
        const { gameUrl } = req.params;

        // Get current game's series_id and date
        const gameResult = await pool.query(
            'SELECT series_id, game_date FROM games WHERE game_url = $1',
            [gameUrl]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const { series_id, game_date } = gameResult.rows[0];

        if (!series_id) return res.json({ next: null });

        // Find the next game in series that is in the future and not cancelled
        const nextResult = await pool.query(`
            SELECT g.game_url, g.game_date, g.max_players,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed')
                    + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players
            FROM games g
            WHERE g.series_id = $1
              AND g.game_date > $2
              AND g.game_status != 'cancelled'
            ORDER BY g.game_date ASC
            LIMIT 1
        `, [series_id, game_date]);

        res.json({ next: nextResult.rows.length > 0 ? nextResult.rows[0] : null });
    } catch (error) {
        console.error('Next game error:', error);
        res.status(500).json({ error: 'Failed to load next game' });
    }
});

// Get MOTM data for public game view (no auth required)
app.get('/api/public/game/:gameUrl/motm', async (req, res) => {
    try {
        const { gameUrl } = req.params;

        console.log('Public MOTM request for game URL:', gameUrl);

        const gameResult = await pool.query(
            'SELECT id, game_status, motm_voting_ends, motm_winner_id FROM games WHERE game_url = $1',
            [gameUrl]
        );

        if (gameResult.rows.length === 0) {
            console.log('MOTM: Game not found for URL:', gameUrl);
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameResult.rows[0];
        console.log('MOTM: Game found:', { id: game.id, status: game.game_status, votingEnds: game.motm_voting_ends, winnerId: game.motm_winner_id });

        if (game.game_status !== 'completed') {
            console.log('MOTM: Game not completed, status:', game.game_status);
            return res.status(400).json({ error: 'Game not completed yet' });
        }

        // Get MOTM nominees with vote counts
        const nomineesResult = await pool.query(`
            SELECT
                p.id as player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.photo_url,
                p.motm_wins,
                p.total_appearances,
                p.total_wins,
                COUNT(v.id) as vote_count
            FROM motm_nominees mn
            JOIN players p ON p.id = mn.player_id
            LEFT JOIN motm_votes v ON v.voted_for_id = mn.player_id AND v.game_id = mn.game_id
            WHERE mn.game_id = $1
            GROUP BY p.id, p.full_name, p.alias, p.squad_number, p.photo_url,
                     p.motm_wins, p.total_appearances, p.total_wins
            ORDER BY vote_count DESC
        `, [game.id]);

        console.log('MOTM: Found', nomineesResult.rows.length, 'nominees for game', game.id);

        const votingEnds  = game.motm_voting_ends ? new Date(game.motm_voting_ends) : new Date(0);
        const votingOpen  = votingEnds > new Date();
        const isFinalized = !!game.motm_winner_id;

        // If finalized, include full winner profile
        let winner = null;
        if (isFinalized) {
            winner = nomineesResult.rows.find(n => n.player_id === game.motm_winner_id)
                  || nomineesResult.rows[0] || null;
        }

        res.json({
            nominees:    nomineesResult.rows,
            votingEnds:  game.motm_voting_ends,
            votingOpen,
            isFinalized,
            winner,
            userHasVoted: false
        });

    } catch (error) {
        console.error('Get public MOTM error:', error);
        res.status(500).json({ error: 'Failed to get MOTM data' });
    }
});

// Get registered players for public game view
app.get('/api/public/game/:gameUrl/players', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game ID, type and series_id
        const gameResult = await pool.query(
            'SELECT id, team_selection_type, series_id FROM games WHERE game_url = $1',
            [gameUrl]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const { id: gameId, team_selection_type, series_id } = gameResult.rows[0];
        const isDraftMemory = team_selection_type === 'draft_memory' && series_id;
        
        // Get registered players — for draft_memory games, also join fixed team memory
        const playersResult = await pool.query(`
            SELECT 
                p.id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.photo_url,
                p.total_appearances,
                p.motm_wins,
                p.total_wins,
                p.reliability_tier,
                r.position_preference,
                r.registered_at,
                ${isDraftMemory ? 'pft.fixed_team' : 'NULL::text AS fixed_team'},
                (SELECT json_agg(json_build_object('name', b.name, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            ${isDraftMemory ? `LEFT JOIN player_fixed_teams pft ON pft.player_id = p.id AND pft.series_id = $2` : ''}
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                     p.total_appearances, p.motm_wins, p.total_wins, p.reliability_tier,
                     r.position_preference, r.registered_at
                     ${isDraftMemory ? ', pft.fixed_team' : ''}
            ORDER BY 
                CASE WHEN ${isDraftMemory ? 'pft.fixed_team' : 'NULL'} = 'red' THEN 0
                     WHEN ${isDraftMemory ? 'pft.fixed_team' : 'NULL'} = 'blue' THEN 2
                     ELSE 1 END,
                r.registered_at ASC
            LIMIT 50
        `, isDraftMemory ? [gameId, series_id] : [gameId]);
        
        // Append guests so they appear on the public game page
        const guestsResult = await pool.query(`
            SELECT
                ('guest_' || gg.id::text) as id,
                gg.guest_name as full_name,
                (gg.guest_name || ' (Guest)') as alias,
                NULL::integer as squad_number,
                NULL::text as photo_url,
                NULL::integer as total_appearances,
                NULL::integer as motm_wins,
                NULL::integer as total_wins,
                NULL::text as reliability_tier,
                'outfield' as position_preference,
                gg.overall_rating,
                NULL::text as fixed_team,
                NULL::json as badges,
                TRUE as is_guest
            FROM game_guests gg
            WHERE gg.game_id = $1
            ORDER BY gg.guest_number
        `, [gameId]);

        res.json([...playersResult.rows, ...guestsResult.rows]);
        
    } catch (error) {
        console.error('Get public game players error:', error);
        res.status(500).json({ error: 'Failed to get players' });
    }
});

// Vote for MOTM
app.post('/api/games/:gameId/motm/vote', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { nomineeId } = req.body;
        const voterId = req.user.playerId;
        
        // Can't vote for yourself
        if (nomineeId === voterId) {
            return res.status(400).json({ error: 'You cannot vote for yourself' });
        }
        
        // Check if player played in this game
        const playedResult = await pool.query(
            'SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = $3',
            [gameId, voterId, 'confirmed']
        );
        
        if (playedResult.rows.length === 0) {
            return res.status(403).json({ error: 'Only players who played can vote' });
        }
        
        // Check if voting is still open
        const gameResult = await pool.query(
            'SELECT motm_voting_ends FROM games WHERE id = $1',
            [gameId]
        );
        
        const votingEnds = new Date(gameResult.rows[0].motm_voting_ends);
        if (votingEnds < new Date()) {
            return res.status(400).json({ error: 'Voting has closed' });
        }
        
        // CRIT-28: Verify nomineeId is an actual nominee for this game
        const nomineeCheck = await pool.query(
            'SELECT 1 FROM motm_nominees WHERE game_id = $1 AND player_id = $2',
            [gameId, nomineeId]
        );
        if (nomineeCheck.rows.length === 0) {
            return res.status(400).json({ error: 'That player is not a nominee for this game' });
        }

        // Cast vote (upsert)
        await pool.query(
            `INSERT INTO motm_votes (game_id, voter_id, voted_for_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (game_id, voter_id)
             DO UPDATE SET voted_for_id = $3, voted_at = NOW()`,
            [gameId, voterId, nomineeId]
        );
        
        res.json({ message: 'Vote recorded' });

        // Audit: record who voted for whom with full names
        setImmediate(async () => {
            try {
                const [voterRow, nomineeRow] = await Promise.all([
                    pool.query('SELECT full_name, alias FROM players WHERE id = $1', [voterId]),
                    pool.query('SELECT full_name, alias FROM players WHERE id = $1', [nomineeId]),
                ]);
                const voterName = voterRow.rows[0]?.alias || voterRow.rows[0]?.full_name || voterId;
                const nomineeName = nomineeRow.rows[0]?.alias || nomineeRow.rows[0]?.full_name || nomineeId;
                await gameAuditLog(pool, gameId, null, 'motm_vote',
                    `Voter: ${voterName} (${voterId}) voted for ${nomineeName} (${nomineeId})`);
            } catch (e) { /* non-critical */ }
        });
        
    } catch (error) {
        console.error('MOTM vote error:', error);
        res.status(500).json({ error: 'Failed to record vote' });
    }
});

// Get player profile (public)
app.get('/api/public/player/:playerId', publicPlayerLimiter, async (req, res) => {
    try {
        const { playerId } = req.params;
        
        // Get player by ID or squad number
        let playerResult;
        if (isNaN(playerId)) {
            // UUID
            playerResult = await pool.query(
                `SELECT id, full_name, alias, squad_number, photo_url, reliability_tier,
                        total_appearances, total_wins, motm_wins
                 FROM players WHERE id = $1`,
                [playerId]
            );
        } else {
            // Squad number
            playerResult = await pool.query(
                `SELECT id, full_name, alias, squad_number, photo_url, reliability_tier,
                        total_appearances, total_wins, motm_wins
                 FROM players WHERE squad_number = $1`,
                [parseInt(playerId)]
            );
        }
        
        if (playerResult.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        const player = playerResult.rows[0];
        
        // Get badges
        const badgesResult = await pool.query(`
            SELECT b.name, b.icon, b.color, b.description
            FROM player_badges pb
            JOIN badges b ON b.id = pb.badge_id
            WHERE pb.player_id = $1
            ORDER BY b.name
        `, [player.id]);
        
        // Calculate win ratio
        const appearances = player.total_appearances || 0;
        const wins = player.total_wins || 0;
        const winRatio = appearances > 0 ? ((wins / appearances) * 100).toFixed(1) : '0.0';
        
        // Calculate MOTM ratio
        const motmWins = parseFloat(player.motm_wins || 0);
        const motmRatio = appearances > 0 ? ((motmWins / appearances) * 100).toFixed(1) : '0.0';
        
        res.json({
            player: {
                id: player.id,
                alias: player.alias || player.full_name,
                squad_number: player.squad_number,
                photo_url: player.photo_url,
                reliability_tier: player.reliability_tier,
                total_appearances: appearances,
                total_wins: wins,
                motm_wins: motmWins,
                win_ratio: winRatio,
                motm_ratio: motmRatio
            },
            badges: badgesResult.rows
        });
        
    } catch (error) {
        console.error('Player profile error:', error);
        res.status(500).json({ error: 'Failed to load player profile' });
    }
});

// ==========================================
// GAME PLAYER EDITING (ADMIN)
// ==========================================

// Lock game for player editing
app.post('/api/admin/games/:gameId/lock', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // FIX-041: Atomic acquire — single UPDATE avoids check-then-act race condition
        const result = await pool.query(`
            UPDATE games
            SET player_editing_locked = TRUE,
                locked_by = $1,
                locked_at = NOW()
            WHERE id = $2 AND (player_editing_locked = FALSE OR locked_by = $1)
            RETURNING id`,
            [req.user.playerId, gameId]
        );
        
        if (result.rowCount === 0) {
            return res.status(409).json({ error: 'Game is locked by another admin' });
        }
        
        res.json({ message: 'Game locked for editing' });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'game_locked', 'Player editing locked'));
    } catch (error) {
        console.error('Lock game error:', error);
        res.status(500).json({ error: 'Failed to lock game' });
    }
});

// Unlock game
app.post('/api/admin/games/:gameId/unlock', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;

        // FIX-040: Only the lock owner (or full admin/superadmin) can unlock
        const lockOwner = await pool.query('SELECT locked_by FROM games WHERE id = $1', [gameId]);
        const isFullAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (!isFullAdmin && lockOwner.rows[0]?.locked_by !== req.user.playerId) {
            return res.status(403).json({ error: 'You cannot unlock a game locked by another admin' });
        }
        
        await pool.query(
            `UPDATE games 
             SET player_editing_locked = FALSE,
                 locked_by = NULL,
                 locked_at = NULL
             WHERE id = $1`,
            [gameId]
        );
        
        res.json({ message: 'Game unlocked' });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'game_unlocked', 'Player editing unlocked'));
    } catch (error) {
        console.error('Unlock game error:', error);
        res.status(500).json({ error: 'Failed to unlock game' });
    }
});

// Get registered players for a game
app.get('/api/admin/games/:gameId/players', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        const result = await pool.query(`
            SELECT 
                r.id as registration_id,
                p.id as player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.overall_rating,
                r.status,
                r.position_preference,
                r.tournament_team_preference
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1
            ORDER BY p.squad_number ASC NULLS LAST
        `, [gameId]);
        
        // Also fetch guests for this game
        const guestsResult = await pool.query(
            `SELECT id, guest_name, overall_rating, invited_by FROM game_guests WHERE game_id = $1 ORDER BY guest_number ASC`,
            [gameId]
        );
        
        // Return combined: players array + guests array
        // Guests are appended as pseudo-players for draft compatibility
        const guests = guestsResult.rows.map(g => ({
            registration_id: null,
            player_id: `guest_${g.id}`,
            full_name: g.guest_name,
            alias: `${g.guest_name} (+1)`,
            squad_number: null,
            overall_rating: g.overall_rating || 0,
            status: 'confirmed',
            position_preference: 'outfield',
            tournament_team_preference: null,
            is_guest: true,
            invited_by: g.invited_by
        }));
        
        res.json([...result.rows, ...guests]);
        
    } catch (error) {
        console.error('Get game players error:', error);
        res.status(500).json({ error: 'Failed to get players' });
    }
});

// Add player to game (admin)
app.post('/api/admin/games/:gameId/add-player', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { playerId, position } = req.body;
        
        // Check if game is locked by this admin
        const lockCheck = await pool.query(
            'SELECT locked_by FROM games WHERE id = $1 AND player_editing_locked = TRUE',
            [gameId]
        );
        
        if (lockCheck.rows.length === 0 || lockCheck.rows[0].locked_by !== req.user.playerId) {
            return res.status(403).json({ error: 'Game must be locked by you to edit players' });
        }
        
        // Check if player already registered
        const existingReg = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, playerId]
        );
        
        if (existingReg.rows.length > 0) {
            return res.status(400).json({ error: 'Player already registered' });
        }
        
        // Get game details for capacity + GK checks
        const gameResult = await pool.query(
            'SELECT cost_per_player, max_players, team_selection_type, tournament_team_count FROM games WHERE id = $1',
            [gameId]
        );
        const game = gameResult.rows[0];
        const cost = parseFloat(game.cost_per_player);
        
        // Check capacity (confirmed registrations + guests)
        const countResult = await pool.query(
            `SELECT (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed') +
                    (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS total`,
            [gameId]
        );
        if (parseInt(countResult.rows[0].total) >= parseInt(game.max_players)) {
            return res.status(400).json({
                error: `Game is full (${game.max_players}/${game.max_players}). Remove a player first.`
            });
        }
        
        // Check GK slot limits if adding as GK
        const posValue = position || 'outfield';
        const isGK = posValue.trim().toUpperCase() === 'GK';
        if (isGK) {
            const maxGKSlots = game.team_selection_type === 'vs_external' ? 1 : game.team_selection_type === 'tournament' ? (game.tournament_team_count || 4) : 2;
            const gkCount = await pool.query(
                `SELECT COUNT(*) as gk_count FROM registrations
                 WHERE game_id = $1 AND status = 'confirmed'
                 AND UPPER(TRIM(position_preference)) = 'GK'`,
                [gameId]
            );
            if (parseInt(gkCount.rows[0].gk_count) >= maxGKSlots) {
                return res.status(400).json({
                    error: `GK slots full (${maxGKSlots} max). Change position or remove an existing GK.`
                });
            }
        }
        
        // Check/deduct credits — wrapped in transaction to prevent partial failure
        const creditResult = await pool.query(
            'SELECT balance FROM credits WHERE player_id = $1',
            [playerId]
        );
        
        if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < cost) {
            return res.status(400).json({ error: 'Player has insufficient credits' });
        }

        // FIX-007: Use a dedicated client for atomic credit deduction + registration
        const txClient = await pool.connect();
        try {
            await txClient.query('BEGIN');
        
            await txClient.query(
                'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                [cost, playerId]
            );
        
            await txClient.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [playerId, -cost, 'game_fee', `Admin added to game ${gameId}`]
            );
        
            // Add player
            await txClient.query(
                `INSERT INTO registrations (game_id, player_id, status, position_preference, amount_paid)
                 VALUES ($1, $2, 'confirmed', $3, $4)`,
                [gameId, playerId, position || 'outfield', cost]
            );

            await txClient.query('COMMIT');
        } catch (txErr) {
            await txClient.query('ROLLBACK').catch(() => {});
            throw txErr;
        } finally {
            txClient.release();
        }
        
        res.json({ message: 'Player added successfully' });
        setImmediate(() => {
            registrationEvent(pool, gameId, playerId, 'admin_added', `Added by admin ${req.user.playerId}`);
            gameAuditLog(pool, gameId, req.user.playerId, 'admin_player_added', `Player ID: ${playerId} | Position: ${position}`);
        });
    } catch (error) {
        console.error('Add player error:', error);
        res.status(500).json({ error: 'Failed to add player' });
    }
});

// Add player with custom discount (admin)
app.post('/api/admin/games/:gameId/add-player-discount', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { playerId, customAmount, position } = req.body;
        
        // Check if game is locked by this admin
        const lockCheck = await pool.query(
            'SELECT locked_by FROM games WHERE id = $1 AND player_editing_locked = TRUE',
            [gameId]
        );
        
        if (lockCheck.rows.length === 0 || lockCheck.rows[0].locked_by !== req.user.playerId) {
            return res.status(403).json({ error: 'Game must be locked by you to edit players' });
        }
        
        // Check if player already registered
        const existingReg = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, playerId]
        );
        
        if (existingReg.rows.length > 0) {
            return res.status(400).json({ error: 'Player already registered' });
        }
        
        // Get game details for capacity + GK checks
        const gameCheck = await pool.query(
            'SELECT max_players, team_selection_type, tournament_team_count FROM games WHERE id = $1',
            [gameId]
        );
        
        // Check capacity (confirmed registrations + guests)
        const countResult = await pool.query(
            `SELECT (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed') +
                    (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS total`,
            [gameId]
        );
        if (parseInt(countResult.rows[0].total) >= parseInt(gameCheck.rows[0].max_players)) {
            return res.status(400).json({
                error: `Game is full (${gameCheck.rows[0].max_players}/${gameCheck.rows[0].max_players}). Remove a player first.`
            });
        }
        
        // Check GK slot limits if adding as GK
        const posValue = position || 'outfield';
        const isGK = posValue.trim().toUpperCase() === 'GK';
        if (isGK) {
            const maxGKSlots = gameCheck.rows[0].team_selection_type === 'vs_external' ? 1 : gameCheck.rows[0].team_selection_type === 'tournament' ? (gameCheck.rows[0].tournament_team_count || 4) : 2;
            const gkCount = await pool.query(
                `SELECT COUNT(*) as gk_count FROM registrations
                 WHERE game_id = $1 AND status = 'confirmed'
                 AND UPPER(TRIM(position_preference)) = 'GK'`,
                [gameId]
            );
            if (parseInt(gkCount.rows[0].gk_count) >= maxGKSlots) {
                return res.status(400).json({
                    error: `GK slots full (${maxGKSlots} max). Change position or remove an existing GK.`
                });
            }
        }
        
        // Get player credits
        const creditResult = await pool.query(
            'SELECT balance FROM credits WHERE player_id = $1',
            [playerId]
        );
        
        if (creditResult.rows.length === 0) {
            return res.status(400).json({ error: 'Player has no credits account' });
        }
        
        const currentBalance = parseFloat(creditResult.rows[0].balance);
        const customCharge = parseFloat(customAmount);
        
        if (currentBalance < customCharge) {
            return res.status(400).json({ error: `Player only has £${currentBalance.toFixed(2)} but custom charge is £${customCharge.toFixed(2)}` });
        }
        
        // Deduct custom amount from player credits
        await pool.query(
            'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
            [customCharge, playerId]
        );
        
        // Record transaction
        await pool.query(
            `INSERT INTO credit_transactions (player_id, amount, type, description)
             VALUES ($1, $2, $3, $4)`,
            [playerId, -customCharge, 'game_fee', `Game registration (custom charge: £${customCharge.toFixed(2)})`]
        );
        
        // Add player
        await pool.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference, amount_paid)
             VALUES ($1, $2, 'confirmed', $3, $4)`,
            [gameId, playerId, position || 'outfield', customCharge]
        );
        
        res.json({ message: 'Player added with custom charge' });
        
    } catch (error) {
        console.error('Add player with discount error:', error);
        res.status(500).json({ error: 'Failed to add player with discount' });
    }
});

// Remove player from game (admin)
app.delete('/api/admin/games/:gameId/remove-player/:registrationId', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId, registrationId } = req.params;
        
        // Get registration details (include position + status + who paid for backup promotion and correct refund)
        const regResult = await pool.query(
            'SELECT player_id, status, backup_type, position_preference, registered_by_player_id FROM registrations WHERE id = $1 AND game_id = $2',
            [registrationId, gameId]
        );
        
        if (regResult.rows.length === 0) {
            return res.status(404).json({ error: 'Registration not found' });
        }
        
        const removedReg = regResult.rows[0];
        const playerId = removedReg.player_id;
        const wasConfirmed = removedReg.status === 'confirmed';
        const wasConfirmedBackup = removedReg.backup_type === 'confirmed_backup';
        const wasGKOnly = removedReg.position_preference?.trim().toUpperCase() === 'GK';
        // If a friend was registered by someone else, refund that person — not the friend
        const refundTargetId = removedReg.registered_by_player_id || playerId;
        
        // Get game cost and type
        const gameResult = await pool.query(
            'SELECT cost_per_player, team_selection_type, tournament_team_count FROM games WHERE id = $1',
            [gameId]
        );
        const cost = parseFloat(gameResult.rows[0].cost_per_player);
        
        // Only refund if they actually paid (confirmed or confirmed_backup)
        if (wasConfirmed || wasConfirmedBackup) {
            await pool.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [cost, refundTargetId]
            );
            
            const refundDesc = refundTargetId !== playerId
                ? `Admin removed ${playerId} from game — refund to original payer`
                : `Admin removed from game ${gameId}`;
            await pool.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [refundTargetId, cost, 'refund', refundDesc]
            );
        }
        
        // Delete registration
        await pool.query(
            'DELETE FROM registrations WHERE id = $1',
            [registrationId]
        );
        
        // Try to promote a backup if a confirmed player was removed
        let promotedPlayer = null;
        if (wasConfirmed) {
            const maxGKSlots = gameResult.rows[0].team_selection_type === 'vs_external' ? 1 : gameResult.rows[0].team_selection_type === 'tournament' ? (gameResult.rows[0].tournament_team_count || 4) : 2;
            const gkCountResult = await pool.query(
                `SELECT COUNT(*) as gk_count FROM registrations 
                 WHERE game_id = $1 AND status = 'confirmed' AND UPPER(TRIM(position_preference)) = 'GK'`,
                [gameId]
            );
            const currentGKs = parseInt(gkCountResult.rows[0].gk_count) || 0;
            
            // If a GK was removed, try GK backups first
            if (wasGKOnly) {
                const gkBackups = await pool.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'gk_backup'
                    ORDER BY r.registered_at ASC
                `, [gameId]);
                
                for (const candidate of gkBackups.rows) {
                    const creditCheck = await pool.query(
                        'SELECT balance FROM credits WHERE player_id = $1', [candidate.player_id]
                    );
                    if (parseFloat(creditCheck.rows[0]?.balance || 0) >= cost) {
                        promotedPlayer = candidate;
                        break;
                    }
                }
            }
            
            // Then try confirmed backups (with GK slot check)
            if (!promotedPlayer) {
                const confirmedBackups = await pool.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'confirmed_backup'
                    ORDER BY r.registered_at ASC
                `, [gameId]);
                
                for (const candidate of confirmedBackups.rows) {
                    const isGK = candidate.position_preference?.trim().toUpperCase() === 'GK';
                    if (isGK && currentGKs >= maxGKSlots) continue;
                    promotedPlayer = candidate;
                    break;
                }
            }
            
            if (promotedPlayer) {
                await pool.query(
                    `UPDATE registrations SET status = 'confirmed', backup_type = NULL WHERE id = $1`,
                    [promotedPlayer.id]
                );
                
                if (promotedPlayer.backup_type !== 'confirmed_backup') {
                    await pool.query(
                        'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                        [cost, promotedPlayer.player_id]
                    );
                    await pool.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [promotedPlayer.player_id, -cost, 'game_fee', `Promoted from backup - game ${gameId}`]
                    );
                }
                
                try {
                    await pool.query(
                        `INSERT INTO notifications (player_id, type, message, game_id) VALUES ($1, 'backup_promoted', $2, $3)`,
                        [promotedPlayer.player_id,
                         `Great news! A spot opened up and you've been promoted to the game! ${promotedPlayer.backup_type === 'confirmed_backup' ? 'Your payment has already been taken.' : `£${cost.toFixed(2)} has been deducted from your balance.`}`,
                         gameId]
                    );
                    // Send push + WhatsApp notification to promoted player
                    const promoGameData = await getGameDataForNotification(gameId);
                    sendNotification('backup_promoted', promotedPlayer.player_id, promoGameData).catch(e =>
                        console.error('backup_promoted notification (admin remove) failed:', e.message)
                    );
                } catch (notifErr) {
                    console.error('Notification insert failed (non-critical):', notifErr.message);
                }
            }
        }
        
        const msg = promotedPlayer 
            ? `Player removed. ${promotedPlayer.alias || promotedPlayer.full_name} promoted from backup.`
            : 'Player removed successfully';
        
        res.json({ message: msg, promotedPlayer: promotedPlayer ? { name: promotedPlayer.alias || promotedPlayer.full_name } : null });
        setImmediate(() => {
            registrationEvent(pool, gameId, playerId, 'admin_removed', `Removed by admin ${req.user.playerId}${promotedPlayer ? ' | ' + (promotedPlayer.alias || promotedPlayer.full_name) + ' promoted' : ''}`);
            gameAuditLog(pool, gameId, req.user.playerId, 'admin_player_removed', `Player ID: ${playerId}${promotedPlayer ? ' | Promoted: ' + (promotedPlayer.alias || promotedPlayer.full_name) : ''}`);
        });
    } catch (error) {
        console.error('Remove player error:', error);
        res.status(500).json({ error: 'Failed to remove player' });
    }
});

// Finalize MOTM voting - called manually or by cron job
// ── Shared MOTM finalize logic (called by endpoint + auto-scheduler) ──────────
async function runMotmFinalize(gameId) {
    // Already finalized?
    const gameResult = await pool.query(
        `SELECT g.motm_voting_ends, g.motm_winner_id, g.game_date, g.game_url,
                v.name as venue_name
         FROM games g LEFT JOIN venues v ON v.id = g.venue_id
         WHERE g.id = $1`,
        [gameId]
    );
    if (gameResult.rows.length === 0) throw new Error('Game not found');
    const game = gameResult.rows[0];
    if (game.motm_winner_id) return { alreadyFinalized: true };

    // Get vote counts
    const votesResult = await pool.query(`
        SELECT
            n.player_id,
            p.full_name,
            p.alias,
            COUNT(v.id) as votes
        FROM motm_nominees n
        JOIN players p ON p.id = n.player_id
        LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
        WHERE n.game_id = $1
        GROUP BY n.player_id, p.full_name, p.alias
        ORDER BY votes DESC
    `, [gameId]);

    if (votesResult.rows.length === 0) throw new Error('No MOTM nominees found');

    const maxVotes = parseInt(votesResult.rows[0].votes);
    const winners  = votesResult.rows.filter(r => parseInt(r.votes) === maxVotes);
    const motmIncrement = 1.0 / winners.length;

    console.log(`MOTM finalize game ${gameId}: ${winners.length} winner(s), ${maxVotes} votes, +${motmIncrement} each`);

    // Award MOTM wins
    for (const winner of winners) {
        await pool.query(
            'UPDATE players SET motm_wins = motm_wins + $1 WHERE id = $2',
            [motmIncrement, winner.player_id]
        );
    }

    // Set official winner on game
    await pool.query(
        'UPDATE games SET motm_winner_id = $1 WHERE id = $2',
        [winners[0].player_id, gameId]
    );

    // Auto-allocate badges for all winners (non-critical)
    for (const winner of winners) {
        try { await autoAllocateBadges(winner.player_id); } catch (e) {
            console.error(`Badge alloc failed for ${winner.player_id}:`, e.message);
        }
    }

    // Send MOTM winner notification (non-critical)
    const gameDate  = new Date(game.game_date).toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' });
    const gameUrlFull = `https://totalfooty.co.uk/vibecoding/game.html?url=${game.game_url}`;
    for (const winner of winners) {
        try {
            await sendNotification('motm_winner', winner.player_id, {
                game_date:    gameDate,
                venue:        game.venue_name || 'the match',
                game_url:     gameUrlFull,
            });
        } catch (e) {
            console.error(`MOTM notification failed for ${winner.player_id}:`, e.message);
        }
    }

    return {
        alreadyFinalized: false,
        winners: winners.map(w => ({
            playerId: w.player_id,
            name:     w.alias || w.full_name,
            votes:    maxVotes,
            motmIncrement
        }))
    };
}

// Admin endpoint — manual finalize (still available as fallback)
app.post('/api/admin/games/:gameId/finalize-motm', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        const result = await runMotmFinalize(gameId);
        if (result.alreadyFinalized) {
            return res.status(400).json({ error: 'MOTM already finalized' });
        }
        res.json({ message: 'MOTM voting finalized', winners: result.winners });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'motm_finalized',
            `Winner(s): ${result.winners?.map(w => w.alias || w.full_name).join(', ') || 'none'}`));
    } catch (error) {
        console.error('Finalize MOTM error:', error);
        res.status(500).json({ error: error.message || 'Failed to finalize MOTM voting' });
    }
});

// ==========================================
// ==========================================
// REFERRAL ENDPOINTS
// ==========================================

// Get my referral info (code, link, who I referred)
app.get('/api/players/me/referral', authenticateToken, async (req, res) => {
    try {
        const playerId = req.user.playerId;
        
        // Get my referral code and who referred me
        const myInfo = await pool.query(
            `SELECT p.referral_code, p.referred_by,
             (SELECT alias FROM players WHERE id = p.referred_by) as referred_by_alias
             FROM players p WHERE p.id = $1`,
            [playerId]
        );
        
        if (myInfo.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const me = myInfo.rows[0];
        
        // Get list of players I referred
        const referred = await pool.query(
            `SELECT p.id, p.alias, p.full_name, p.created_at,
             p.total_appearances, p.reliability_tier
             FROM players p WHERE p.referred_by = $1
             ORDER BY p.created_at DESC`,
            [playerId]
        );
        
        res.json({
            referralCode: me.referral_code,
            referralLink: me.referral_code
                ? 'https://totalfooty.co.uk/vibecoding/?ref=' + me.referral_code
                : null,
            referredBy: me.referred_by ? { id: me.referred_by, alias: me.referred_by_alias } : null,
            referrals: referred.rows.map(r => ({
                id: r.id,
                alias: r.alias || r.full_name,
                joinedAt: r.created_at,
                appearances: r.total_appearances || 0,
                tier: r.reliability_tier
            })),
            totalReferred: referred.rows.length
        });
    } catch (error) {
        console.error('Get referral info error:', error);
        res.status(500).json({ error: 'Failed to get referral info' });
    }
});

// #15: Player top-up request — emails admin and logs the request
app.post('/api/players/me/topup-request', authenticateToken, topupLimiter, async (req, res) => {
    try {
        const { amount } = req.body;
        const playerId = req.user.playerId;
        const playerResult = await pool.query(
            'SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
            [playerId]
        );
        if (playerResult.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const player = playerResult.rows[0];
        const displayName = player.alias || player.full_name;
        const amountStr = amount ? `£${parseFloat(amount).toFixed(2)}` : 'Amount not specified';

        setImmediate(async () => {
            try {
                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to: SUPERADMIN_EMAIL || 'totalfooty19@gmail.com',
                    subject: `💰 Top-Up Request — ${(displayName || '').replace(/[\r\n]/g, '')}`,
                    html: wrapEmailHtml(`
                        <p style="color:#888;font-size:14px;margin:0 0 16px">Player has requested a credit top-up</p>
                        <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;">
                            <tr><td style="padding:6px 0;color:#888;width:120px;">Player</td><td style="font-weight:900;">${htmlEncode(displayName)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Email</td><td>${htmlEncode(player.email)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Player ID</td><td style="font-family:monospace;">${htmlEncode(playerId)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Requested</td><td style="font-weight:900;color:#00cc66;">${htmlEncode(amountStr)}</td></tr>
                        </table>
                        <p style="color:#888;font-size:13px;margin-top:16px;">Once you receive their bank transfer, use the admin panel to add the credits.</p>
                    `)
                });
            } catch (e) {
                console.error('Top-up request email failed (non-critical):', e.message);
            }
        });

        res.json({ message: 'Top-up request submitted. Admin will be in touch.' });
    } catch (error) {
        console.error('Top-up request error:', error);
        res.status(500).json({ error: 'Failed to submit top-up request' });
    }
});
// FIX-095: Rate limit to prevent code enumeration (20 req / 10 min per IP)
const referralCodeLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, standardHeaders: true, message: { error: 'Too many requests, please try again later' } });
app.get('/api/public/referral/:code', referralCodeLimiter, async (req, res) => {
    try {
        const { code } = req.params;
        
        // Look up in players table first, then referrals
        let referrer = null;
        const pRef = await pool.query(
            `SELECT p.id, p.alias, p.full_name,
             EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'CLM') as has_clm,
             EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'Misfits') as has_misfits
             FROM players p WHERE p.referral_code = $1`,
            [code.toUpperCase()]
        );
        
        if (pRef.rows.length > 0) {
            referrer = pRef.rows[0];
        } else {
            const rRef = await pool.query(
                `SELECT p.id, p.alias, p.full_name,
                 EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'CLM') as has_clm,
                 EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'Misfits') as has_misfits
                 FROM referrals r JOIN players p ON r.referrer_id = p.id WHERE r.referral_code = $1`,
                [code.toUpperCase()]
            );
            if (rRef.rows.length > 0) referrer = rRef.rows[0];
        }
        
        if (!referrer) {
            return res.status(404).json({ valid: false, error: 'Referral code not found' });
        }
        
        res.json({
            valid: true,
            referrerName: referrer.alias || referrer.full_name,
            hasCLM: referrer.has_clm,
            hasMisfits: referrer.has_misfits,
            message: (() => {
                const badges = [];
                if (referrer.has_clm) badges.push('CLM');
                if (referrer.has_misfits) badges.push('Misfits');
                const name = referrer.alias || referrer.full_name;
                if (badges.length > 0) {
                    return `You have been referred by ${name}! You will receive ${badges.join(' + ')} access upon registration.`;
                }
                return `You have been referred by ${name}! Welcome to Total Footy.`;
            })()
        });
    } catch (error) {
        console.error('Validate referral error:', error);
        res.status(500).json({ error: 'Failed to validate referral code' });
    }
});

// Public: Get any player's referral link (for profile/directory pages)
// FIX-094: Player name removed from response — unauthenticated callers should not scrape player names
app.get('/api/public/player/:playerId/referral', async (req, res) => {
    try {
        const { playerId } = req.params;
        const result = await pool.query(
            'SELECT referral_code FROM players WHERE id = $1',
            [playerId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const p = result.rows[0];
        res.json({
            referralCode: p.referral_code,
            referralLink: p.referral_code
                ? 'https://totalfooty.co.uk/vibecoding/?ref=' + p.referral_code
                : null
            // FIX-094: playerName intentionally omitted
        });
    } catch (error) {
        console.error('Get player referral error:', error);
        res.status(500).json({ error: 'Failed to get referral link' });
    }
});

// Admin: Referral leaderboard
app.get('/api/admin/referrals', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.alias, p.full_name, p.referral_code,
                   (SELECT COUNT(*) FROM players WHERE referred_by = p.id) as total_referred,
                   (SELECT COUNT(*) FROM players WHERE referred_by = p.id AND total_appearances > 0) as active_referred
            FROM players p
            WHERE EXISTS (SELECT 1 FROM players WHERE referred_by = p.id)
            ORDER BY total_referred DESC
            LIMIT 50
        `);
        res.json({ referrers: result.rows });
    } catch (error) {
        console.error('Admin referrals error:', error);
        res.status(500).json({ error: 'Failed to get referral data' });
    }
});

// ==========================================
// MANAGE GAMES (scoped for CLM admin / Organiser)
// ==========================================

app.get('/api/manage/games', authenticateToken, async (req, res) => {
    try {
        const playerId = req.user.playerId;
        const isFullAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        const playerResult = await pool.query(
            'SELECT is_clm_admin, is_organiser FROM players WHERE id = $1', [playerId]
        );
        const player = playerResult.rows[0];
        if (!player) return res.status(403).json({ error: 'Player not found' });
        if (!isFullAdmin && !player.is_clm_admin && !player.is_organiser) {
            return res.status(403).json({ error: 'No management access' });
        }
        
        let query, params;
        if (isFullAdmin) {
            query = `SELECT g.*, v.name as venue_name,
                ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') +
                 (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                motm_p.alias as motm_winner_alias,
                COALESCE((SELECT SUM(r.amount_paid) FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) as confirmed_revenue,
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg WHERE gg.game_id = g.id), 0) as guest_revenue,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.is_comped = TRUE AND r.status = 'confirmed'), 0) as comped_count
                FROM games g LEFT JOIN venues v ON v.id = g.venue_id LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
                ORDER BY g.game_date DESC`;
            params = [];
        } else {
            // Build OR conditions for each role the player has
            const conditions = [];
            if (player.is_clm_admin) {
                conditions.push(`g.exclusivity = 'clm'`);
            }
            if (player.is_organiser) {
                conditions.push(`EXISTS (
                    SELECT 1 FROM registrations r 
                    WHERE r.game_id = g.id AND r.player_id = $1 AND r.status = 'confirmed'
                )`);
            }
            query = `SELECT g.*, v.name as venue_name,
                ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') +
                 (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                motm_p.alias as motm_winner_alias,
                COALESCE((SELECT SUM(r.amount_paid) FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) as confirmed_revenue,
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg WHERE gg.game_id = g.id), 0) as guest_revenue,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.is_comped = TRUE AND r.status = 'confirmed'), 0) as comped_count
                FROM games g LEFT JOIN venues v ON v.id = g.venue_id LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
                WHERE (${conditions.join(' OR ')})
                ORDER BY g.game_date DESC LIMIT 50`;
            params = player.is_organiser ? [playerId] : [];
        }
        
        const result = await pool.query(query, params);
        res.json({
            games: result.rows,
            managerRole: isFullAdmin ? 'admin' : (player.is_clm_admin && player.is_organiser) ? 'clm_organiser' : player.is_clm_admin ? 'clm_admin' : 'organiser',
            permissions: {
                canCreate: isFullAdmin || player.is_clm_admin,
                canDelete: isFullAdmin || player.is_clm_admin,
                canChangeSettings: isFullAdmin || player.is_clm_admin,
                canAddRemovePlayers: isFullAdmin || player.is_clm_admin,
                canGenerateTeams: true,
                canComplete: true,
                canAccessCredits: isFullAdmin,
                canSendWhatsApp: isFullAdmin
            }
        });
    } catch (error) {
        console.error('Get manage games error:', error);
        res.status(500).json({ error: 'Failed to get manageable games' });
    }
});

// Superadmin: Toggle CLM admin or Organiser flag on a player
app.put('/api/admin/players/:playerId/role-flags', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        const { is_clm_admin, is_organiser, role } = req.body;
        
        // Safety: never allow promoting to superadmin via API
        if (role === 'superadmin') {
            return res.status(403).json({ error: 'Cannot assign superadmin role via UI' });
        }
        // Safety: only allow valid role values
        if (role !== undefined && role !== 'admin' && role !== 'player') {
            return res.status(400).json({ error: 'Invalid role. Must be admin or player' });
        }
        // Safety: cannot demote yourself
        if (role !== undefined) {
            const selfCheck = await pool.query('SELECT user_id FROM players WHERE id = $1', [playerId]);
            if (selfCheck.rows[0]?.user_id === req.user.userId) {
                return res.status(403).json({ error: 'Cannot change your own role' });
            }
        }
        
        const updates = [];
        const values = [];
        let idx = 1;
        
        if (is_clm_admin !== undefined) {
            updates.push('is_clm_admin = $' + idx);
            values.push(!!is_clm_admin);
            idx++;
        }
        if (is_organiser !== undefined) {
            updates.push('is_organiser = $' + idx);
            values.push(!!is_organiser);
            idx++;
        }
        
        // Update players table flags
        if (updates.length > 0) {
            values.push(playerId);
            await pool.query(
                'UPDATE players SET ' + updates.join(', ') + ' WHERE id = $' + idx,
                values
            );
        }
        
        // Update users.role if provided
        if (role !== undefined) {
            const userResult = await pool.query('SELECT user_id FROM players WHERE id = $1', [playerId]);
            if (userResult.rows.length > 0) {
                await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, userResult.rows[0].user_id]);
            }
        }
        
        if (updates.length === 0 && role === undefined) {
            return res.status(400).json({ error: 'No flags to update' });
        }
        
        // Auto-grant CLM badge if setting CLM admin
        if (is_clm_admin) {
            const cb = await pool.query("SELECT id FROM badges WHERE name = 'CLM'");
            if (cb.rows.length > 0) {
                await pool.query(
                    'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [playerId, cb.rows[0].id]
                );
                await auditLog(pool, req.user.playerId, 'badge_auto_awarded', playerId, 'badge: CLM (granted with CLM admin role)');
            }
        }
        
        // Auto-grant Organiser badge if setting organiser
        if (is_organiser) {
            const ob = await pool.query("SELECT id FROM badges WHERE name = 'Organiser'");
            if (ob.rows.length > 0) {
                await pool.query(
                    'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [playerId, ob.rows[0].id]
                );
                await auditLog(pool, req.user.playerId, 'badge_auto_awarded', playerId, 'badge: Organiser (granted with organiser role)');
            }
        }
        
        const updated = await pool.query(
            `SELECT p.id, p.alias, p.full_name, p.is_clm_admin, p.is_organiser, u.role as user_role 
             FROM players p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
            [playerId]
        );
        res.json({ message: 'Role flags updated', player: updated.rows[0] });
    } catch (error) {
        console.error('Update role flags error:', error);
        res.status(500).json({ error: 'Failed to update role flags' });
    }
});

// ==========================================
// START SERVER
// ==========================================

// ==========================================
// WHATSAPP ADMIN ENDPOINTS
// ==========================================



// ==========================================
// TOURNAMENT SYSTEM
// ==========================================

function calculateLeagueTable(results, teamNames) {
    const table = {};
    for (const name of teamNames) {
        table[name] = { team: name, played: 0, won: 0, drawn: 0, lost: 0, gf: 0, ga: 0, gd: 0, points: 0 };
    }
    
    for (const r of results) {
        const a = r.team_a_name;
        const b = r.team_b_name;
        if (!table[a] || !table[b]) continue;
        
        table[a].played++;
        table[b].played++;
        table[a].gf += r.team_a_score;
        table[a].ga += r.team_b_score;
        table[b].gf += r.team_b_score;
        table[b].ga += r.team_a_score;
        
        if (r.team_a_score > r.team_b_score) {
            table[a].won++;
            table[a].points += 3;
            table[b].lost++;
        } else if (r.team_b_score > r.team_a_score) {
            table[b].won++;
            table[b].points += 3;
            table[a].lost++;
        } else {
            table[a].drawn++;
            table[b].drawn++;
            table[a].points += 1;
            table[b].points += 1;
        }
    }
    
    // Calculate GD and sort
    const sorted = Object.values(table).map(t => ({ ...t, gd: t.gf - t.ga }));
    sorted.sort((a, b) => b.points - a.points || b.gd - a.gd || b.gf - a.gf || a.team.localeCompare(b.team));
    return sorted;
}

// Enter a tournament match result
app.post('/api/admin/games/:gameId/tournament-result', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { teamA, teamB, teamAScore, teamBScore } = req.body;
        
        // Validate game is a tournament and not finalised
        const gameCheck = await pool.query(
            'SELECT team_selection_type, tournament_results_finalised, tournament_team_count FROM games WHERE id = $1',
            [gameId]
        );
        if (gameCheck.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        if (gameCheck.rows[0].team_selection_type !== 'tournament') return res.status(400).json({ error: 'Not a tournament game' });
        if (gameCheck.rows[0].tournament_results_finalised) return res.status(400).json({ error: 'Tournament already finalised' });
        
        // Validate teams exist for this game
        const teamsCheck = await pool.query('SELECT team_name FROM teams WHERE game_id = $1', [gameId]);
        const validTeams = teamsCheck.rows.map(t => t.team_name);
        if (!validTeams.includes(teamA) || !validTeams.includes(teamB)) {
            return res.status(400).json({ error: 'Invalid team name(s)' });
        }
        if (teamA === teamB) return res.status(400).json({ error: 'A team cannot play itself' });
        
        // Validate scores
        const scoreA = parseInt(teamAScore);
        const scoreB = parseInt(teamBScore);
        if (isNaN(scoreA) || isNaN(scoreB) || scoreA < 0 || scoreB < 0) {
            return res.status(400).json({ error: 'Scores must be non-negative integers' });
        }
        // FIX-059: Sensible upper bound for 5-a-side scores
        const MAX_SCORE = 30;
        if (scoreA > MAX_SCORE || scoreB > MAX_SCORE) {
            return res.status(400).json({ error: `Score cannot exceed ${MAX_SCORE}` });
        }
        
        // Check for duplicate matchup
        const dupCheck = await pool.query(
            `SELECT id FROM tournament_results 
             WHERE game_id = $1 AND (
                 (team_a_name = $2 AND team_b_name = $3) OR 
                 (team_a_name = $3 AND team_b_name = $2)
             )`,
            [gameId, teamA, teamB]
        );
        if (dupCheck.rows.length > 0) {
            return res.status(400).json({ error: `Result already entered for ${teamA} vs ${teamB}. Delete or edit the existing result first.` });
        }
        
        // Insert result
        const result = await pool.query(
            `INSERT INTO tournament_results (game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [gameId, teamA, teamB, scoreA, scoreB, req.user.playerId]
        );
        
        // Return updated results + league table
        const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        res.json({
            message: 'Result entered',
            result: result.rows[0],
            results: allResults.rows,
            leagueTable
        });
    } catch (error) {
        console.error('Enter tournament result error:', error);
        res.status(500).json({ error: 'Failed to enter result' });
    }
});

// Edit a tournament match result (update scores)
app.put('/api/admin/games/:gameId/tournament-result/:resultId', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId, resultId } = req.params;
        const { teamAScore, teamBScore } = req.body;
        
        // Validate game is tournament and not finalised
        const gameCheck = await pool.query(
            'SELECT team_selection_type, tournament_results_finalised FROM games WHERE id = $1',
            [gameId]
        );
        if (gameCheck.rows[0]?.team_selection_type !== 'tournament') return res.status(400).json({ error: 'Not a tournament game' });
        if (gameCheck.rows[0]?.tournament_results_finalised) return res.status(400).json({ error: 'Tournament already finalised' });
        
        const scoreA = parseInt(teamAScore);
        const scoreB = parseInt(teamBScore);
        if (isNaN(scoreA) || isNaN(scoreB) || scoreA < 0 || scoreB < 0) {
            return res.status(400).json({ error: 'Scores must be non-negative integers' });
        }
        
        await pool.query(
            'UPDATE tournament_results SET team_a_score = $1, team_b_score = $2 WHERE id = $3 AND game_id = $4',
            [scoreA, scoreB, resultId, gameId]
        );
        
        // Return updated results + league table
        const teamsCheck = await pool.query('SELECT team_name FROM teams WHERE game_id = $1', [gameId]);
        const validTeams = teamsCheck.rows.map(t => t.team_name);
        const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        res.json({ message: 'Result updated', results: allResults.rows, leagueTable });
    } catch (error) {
        console.error('Edit tournament result error:', error);
        res.status(500).json({ error: 'Failed to edit result' });
    }
});

// Delete a tournament match result
app.delete('/api/admin/games/:gameId/tournament-result/:resultId', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId, resultId } = req.params;
        
        const gameCheck = await pool.query(
            'SELECT team_selection_type, tournament_results_finalised FROM games WHERE id = $1',
            [gameId]
        );
        if (gameCheck.rows[0]?.tournament_results_finalised) return res.status(400).json({ error: 'Tournament already finalised' });
        
        await pool.query('DELETE FROM tournament_results WHERE id = $1 AND game_id = $2', [resultId, gameId]);
        
        // Return updated results + league table
        const teamsCheck = await pool.query('SELECT team_name FROM teams WHERE game_id = $1', [gameId]);
        const validTeams = teamsCheck.rows.map(t => t.team_name);
        const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        res.json({ message: 'Result deleted', results: allResults.rows, leagueTable });
    } catch (error) {
        console.error('Delete tournament result error:', error);
        res.status(500).json({ error: 'Failed to delete result' });
    }
});

// Get tournament results + league table (admin, authenticated)
app.get('/api/admin/games/:gameId/tournament-results', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        const teamsCheck = await pool.query('SELECT team_name FROM teams WHERE game_id = $1', [gameId]);
        const validTeams = teamsCheck.rows.map(t => t.team_name);
        const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        res.json({ results: allResults.rows, leagueTable });
    } catch (error) {
        console.error('Get tournament results error:', error);
        res.status(500).json({ error: 'Failed to get results' });
    }
});

// Public: Get tournament data (teams, results, league table) — no auth
app.get('/api/public/game/:gameUrl/tournament', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1 AND g.team_selection_type = 'tournament'
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Tournament not found' });
        }
        
        const game = gameResult.rows[0];
        
        // Get all teams with players
        const teamsResult = await pool.query('SELECT id, team_name FROM teams WHERE game_id = $1 ORDER BY team_name', [game.id]);
        const teams = {};
        for (const team of teamsResult.rows) {
            const playersResult = await pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY 
                    CASE WHEN r.position_preference = 'goalkeeper' THEN 0 ELSE 1 END,
                    COALESCE(p.alias, p.full_name)
            `, [team.id, game.id]);
            
            // Include guests
            const teamGuests = await pool.query(
                `SELECT id, guest_name, overall_rating FROM game_guests WHERE game_id = $1 AND team_name = $2`,
                [game.id, team.team_name]
            );
            
            const players = playersResult.rows.map(p => ({
                id: p.id, name: p.alias || p.full_name, squadNumber: p.squad_number,
                photo_url: p.photo_url, isGK: p.position === 'goalkeeper'
            }));
            const guests = teamGuests.rows.map(g => ({
                id: `guest_${g.id}`, name: `${g.guest_name} (Guest)`, squadNumber: null,
                photo_url: null, isGK: false, isGuest: true
            }));
            
            teams[team.team_name] = [...players, ...guests];
        }
        
        // Get results and league table
        const allResults = await pool.query('SELECT * FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [game.id]);
        const teamNames = teamsResult.rows.map(t => t.team_name);
        const leagueTable = calculateLeagueTable(allResults.rows, teamNames);
        
        // Get MOTM data if completed
        let motmNominees = [];
        let votingOpen = false;
        let votingFinalized = false;
        
        if (game.game_status === 'completed' && game.motm_voting_ends) {
            const votingEnds = new Date(game.motm_voting_ends);
            votingOpen = votingEnds > new Date();
            votingFinalized = game.motm_winner_id !== null;
            
            const motmResult = await pool.query(`
                SELECT n.player_id, p.full_name, p.alias, p.squad_number,
                       COUNT(v.id) as votes, (n.player_id = g.motm_winner_id) as is_winner
                FROM motm_nominees n
                JOIN players p ON p.id = n.player_id
                JOIN games g ON g.id = n.game_id
                LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
                WHERE n.game_id = $1
                GROUP BY n.player_id, p.full_name, p.alias, p.squad_number, g.motm_winner_id
                ORDER BY votes DESC
            `, [game.id]);
            motmNominees = motmResult.rows;
        }
        
        res.json({
            game: {
                id: game.id, game_url: game.game_url, date: game.game_date,
                venue_name: game.venue_name, venue_address: game.venue_address, format: game.format,
                tournament_name: game.tournament_name, tournament_team_count: game.tournament_team_count,
                tournament_results_finalised: game.tournament_results_finalised,
                winning_team: game.winning_team, game_status: game.game_status,
                teams_confirmed: game.teams_confirmed,
                votingOpen, votingFinalized, votingEnds: game.motm_voting_ends
            },
            teams,
            results: allResults.rows,
            leagueTable,
            motmNominees
        });
    } catch (error) {
        console.error('Get public tournament error:', error);
        res.status(500).json({ error: 'Failed to get tournament data' });
    }
});

// Finalise tournament — complete it based on league table
app.post('/api/admin/games/:gameId/finalise-tournament', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { disciplineRecords, motmNominees } = req.body;
        
        await client.query('BEGIN');
        
        // Validate game is a tournament and not already finalised
        const gameCheck = await client.query(
            'SELECT team_selection_type, tournament_results_finalised, tournament_team_count FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        if (gameCheck.rows[0]?.team_selection_type !== 'tournament') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Not a tournament game' });
        }
        if (gameCheck.rows[0]?.tournament_results_finalised) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Tournament already finalised' });
        }
        
        // Get results and calculate league table
        const teamsCheck = await client.query('SELECT team_name FROM teams WHERE game_id = $1', [gameId]);
        const teamNames = teamsCheck.rows.map(t => t.team_name);
        const allResults = await client.query('SELECT * FROM tournament_results WHERE game_id = $1', [gameId]);
        
        if (allResults.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'No results entered. Enter at least one result before finalising.' });
        }

        // SEC-025: Require at least (teamCount - 1) results before finalising — prevents declaring a winner with almost no data
        const minResults = parseInt(gameCheck.rows[0].tournament_team_count || 4) - 1;
        if (allResults.rows.length < minResults) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: `At least ${minResults} result(s) required before finalising (currently ${allResults.rows.length}).`
            });
        }
        
        const leagueTable = calculateLeagueTable(allResults.rows, teamNames);
        
        // Determine winner — top of league table
        // If top 2 are tied on points AND GD AND GF, it's a draw
        let winningTeam;
        if (leagueTable.length >= 2 && 
            leagueTable[0].points === leagueTable[1].points && 
            leagueTable[0].gd === leagueTable[1].gd && 
            leagueTable[0].gf === leagueTable[1].gf) {
            winningTeam = 'draw';
        } else {
            winningTeam = leagueTable[0].team;
        }
        
        // 1. Update game status
        await client.query(
            `UPDATE games 
             SET winning_team = $1, 
                 game_status = 'completed',
                 tournament_results_finalised = TRUE,
                 motm_voting_ends = NOW() + INTERVAL '24 hours'
             WHERE id = $2`,
            [winningTeam, gameId]
        );
        
        // 2. Get all confirmed players
        const playersResult = await client.query(
            `SELECT DISTINCT player_id FROM registrations 
             WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );
        const allPlayerIds = playersResult.rows.map(r => r.player_id);
        
        // Get no-show players from discipline
        const noShowPlayerIds = (disciplineRecords || [])
            .filter(d => d.offense === 'no_show')
            .map(d => d.playerId);
        
        const showedUpPlayerIds = allPlayerIds.filter(id => !noShowPlayerIds.includes(id));
        
        // Update appearances
        if (showedUpPlayerIds.length > 0) {
            await client.query(
                'UPDATE players SET total_appearances = total_appearances + 1 WHERE id = ANY($1)',
                [showedUpPlayerIds]
            );
        }
        
        // Update wins for winning team players (if not a draw)
        if (winningTeam !== 'draw') {
            const winningTeamPlayers = await client.query(
                `SELECT tp.player_id FROM team_players tp
                 JOIN teams t ON t.id = tp.team_id
                 WHERE t.game_id = $1 AND t.team_name = $2`,
                [gameId, winningTeam]
            );
            const winnerIds = winningTeamPlayers.rows.map(r => r.player_id);
            if (winnerIds.length > 0) {
                await client.query(
                    'UPDATE players SET total_wins = total_wins + 1 WHERE id = ANY($1)',
                    [winnerIds]
                );
            }
        }
        
        // 3. Save discipline records
        const offenseTypes = {
            'on_time': 'On Time',
            'not_ready': 'Not Ready (0-5 Min)',
            'late_drop': 'Late Drop Out',
            '5_10_late': '5-10 Minutes Late',
            '10_late': '10+ Minutes Late',
            'no_show': 'No Show'
        };
        const tournamentDisciplinedIds = [];
        for (const record of disciplineRecords || []) {
            if (record.points > 0) {
                await client.query(
                    `INSERT INTO discipline_records (player_id, game_id, offense_type, points, warning_level)
                     VALUES ($1, $2, $3, $4, $5)`,
                    [record.playerId, gameId, offenseTypes[record.offense] || 'Unknown', record.points, record.warning]
                );
                tournamentDisciplinedIds.push(record.playerId);
            }
        }
        
        // 4. Create MOTM nominees (from winning team only)
        let nomineesInserted = 0;
        for (const playerId of motmNominees || []) {
            await client.query(
                `INSERT INTO motm_nominees (game_id, player_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
                [gameId, playerId]
            );
            nomineesInserted++;
        }
        
        await client.query('COMMIT');
        
        // Auto-allocate badges (non-critical, outside transaction)
        for (const playerId of allPlayerIds) {
            try {
                await autoAllocateBadges(playerId);
            } catch (badgeError) {
                console.error(`Badge allocation failed for ${playerId}:`, badgeError.message);
            }
        }

        // Tier recalculation for disciplined players — after commit, pool not client, ::uuid cast
        const uniqueTournamentDisciplinedIds = [...new Set(tournamentDisciplinedIds)];
        if (uniqueTournamentDisciplinedIds.length > 0) {
            setImmediate(async () => {
                for (const dpId of uniqueTournamentDisciplinedIds) {
                    try {
                        const tierResult = await pool.query(
                            'SELECT calculate_player_tier($1::uuid) as new_tier', [dpId]
                        );
                        const newTier = tierResult.rows[0]?.new_tier;
                        if (newTier) {
                            await pool.query(
                                'UPDATE players SET reliability_tier = $1 WHERE id = $2',
                                [newTier, dpId]
                            );
                        }
                    } catch (tierError) {
                        console.error('Tier recalc failed for player', dpId, ':', tierError.message);
                    }
                }
            });
        }
        
        res.json({
            message: 'Tournament finalised successfully',
            winningTeam,
            leagueTable,
            motmNominees: nomineesInserted,
            motmVotingEnds: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });
        
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Finalise tournament error:', error);
        res.status(500).json({ error: 'Failed to finalise tournament' });
    } finally {
        client.release();
    }
});

// ==========================================
// AUDIT ENDPOINTS
// ==========================================

// ==========================================
// GAME TYPE CONVERSION
// ==========================================

// PUT /api/admin/games/:gameId/convert-type — convert a game between types
app.put('/api/admin/games/:gameId/convert-type', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { newType } = req.body;

        const validTypes = ['normal', 'vs_external', 'tournament', 'draft_memory'];
        if (!validTypes.includes(newType)) {
            return res.status(400).json({ error: `Invalid game type. Must be one of: ${validTypes.join(', ')}` });
        }

        const gameResult = await pool.query(
            'SELECT game_status, team_selection_type, teams_confirmed FROM games WHERE id = $1',
            [gameId]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });

        const game = gameResult.rows[0];
        const oldType = game.team_selection_type;

        if (['completed', 'cancelled'].includes(game.game_status)) {
            return res.status(400).json({ error: 'Cannot change the type of a completed or cancelled game' });
        }

        if (game.game_status === 'confirmed' || game.teams_confirmed) {
            return res.status(400).json({
                error: 'Game is confirmed. Unconfirm it first before changing the type.',
                requiresUnconfirm: true
            });
        }

        if (oldType === newType) {
            return res.status(400).json({ error: 'Game is already that type' });
        }

        // Clear fields that no longer apply when switching types
        const clearFields = {};
        if (newType === 'normal' || newType === 'draft_memory') {
            clearFields.external_opponent = null;
            clearFields.tf_kit_color = null;
            clearFields.opp_kit_color = null;
            clearFields.tournament_team_count = null;
            clearFields.tournament_name = null;
        }
        if (newType === 'vs_external') {
            clearFields.tournament_team_count = null;
            clearFields.tournament_name = null;
        }
        if (newType === 'tournament') {
            clearFields.external_opponent = null;
            clearFields.tf_kit_color = null;
            clearFields.opp_kit_color = null;
        }

        // Build targeted UPDATE — only nulls out fields that don't apply to new type
        const setClauses = ['team_selection_type = $1'];
        const params = [newType];
        let idx = 2;
        for (const col of Object.keys(clearFields)) {
            setClauses.push(`${col} = $${idx}`);
            params.push(null);
            idx++;
        }
        params.push(gameId);
        await pool.query(
            `UPDATE games SET ${setClauses.join(', ')} WHERE id = $${idx}`,
            params
        );

        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'type_converted',
            `Changed from ${oldType} to ${newType}`));

        res.json({ message: `Game type changed from ${oldType} to ${newType}. Existing registrations preserved.` });
    } catch (error) {
        console.error('Convert game type error:', error);
        res.status(500).json({ error: 'Failed to convert game type' });
    }
});

// ==========================================
// PLAYER WIN RATE ANALYSIS
// ==========================================

// GET /api/admin/players/stats-list — player list for dropdown (id, alias, full_name only)
app.get('/api/admin/players/stats-list', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.alias, p.full_name, p.squad_number
            FROM players p
            ORDER BY COALESCE(p.alias, p.full_name)
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load players' });
    }
});

// GET /api/admin/players/:id/stats-graph
// Returns per-overall-rating data points: for each distinct overall rating the player
// held, calculate Win% and MOTM% across all completed games played at that rating.
app.get('/api/admin/players/:id/stats-graph', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Build rating timeline: each period = (overall_rating, from_date, to_date)
        //    player_stat_history records each time rating changed
        const historyResult = await pool.query(`
            SELECT overall_rating, created_at
            FROM player_stat_history
            WHERE player_id = $1 AND overall_rating IS NOT NULL
            ORDER BY created_at ASC
        `, [id]);

        // Also get the player's current overall rating as the latest period
        const currentResult = await pool.query(
            'SELECT overall_rating, created_at FROM players WHERE id = $1',
            [id]
        );
        const current = currentResult.rows[0];

        // Build periods array
        const historyRows = historyResult.rows;
        const periods = [];

        // Add a synthetic "before first history entry" period using current rating if no history
        if (historyRows.length === 0) {
            if (current && current.overall_rating) {
                periods.push({
                    rating: parseFloat(current.overall_rating),
                    from: new Date('2020-01-01'),
                    to: new Date('2099-01-01')
                });
            }
        } else {
            // First period: from beginning of time to first history entry
            // (player had this rating before the first recorded change)
            periods.push({
                rating: parseFloat(historyRows[0].overall_rating),
                from: new Date('2020-01-01'),
                to: new Date(historyRows[0].created_at)
            });
            // Middle periods
            for (let i = 1; i < historyRows.length; i++) {
                periods.push({
                    rating: parseFloat(historyRows[i].overall_rating),
                    from: new Date(historyRows[i - 1].created_at),
                    to: new Date(historyRows[i].created_at)
                });
            }
            // Final period: last change to now
            periods.push({
                rating: parseFloat(current?.overall_rating || historyRows[historyRows.length - 1].overall_rating),
                from: new Date(historyRows[historyRows.length - 1].created_at),
                to: new Date('2099-01-01')
            });
        }

        // 2. For each period, get completed games the player appeared in and calculate stats
        const grouped = {}; // keyed by rating

        for (const period of periods) {
            const gamesResult = await pool.query(`
                SELECT
                    g.id,
                    g.game_date,
                    g.motm_winner_id,
                    g.winning_team,
                    t.team_name
                FROM registrations r
                JOIN games g ON g.id = r.game_id
                LEFT JOIN team_players tp ON tp.player_id = r.player_id
                LEFT JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                WHERE r.player_id = $1
                  AND r.status = 'confirmed'
                  AND g.game_status = 'completed'
                  AND g.game_date >= $2
                  AND g.game_date < $3
            `, [id, period.from.toISOString(), period.to.toISOString()]);

            const rKey = period.rating;
            if (!grouped[rKey]) grouped[rKey] = { appearances: 0, wins: 0, motms: 0 };

            for (const g of gamesResult.rows) {
                grouped[rKey].appearances++;
                if (g.winning_team && g.team_name &&
                    g.winning_team.toLowerCase() === g.team_name.toLowerCase()) {
                    grouped[rKey].wins++;
                }
                if (parseInt(g.motm_winner_id) === parseInt(id)) {
                    grouped[rKey].motms++;
                }
            }
        }

        // 3. Build output — only include rating bands with at least 1 appearance
        const dataPoints = Object.entries(grouped)
            .filter(([, v]) => v.appearances > 0)
            .map(([rating, v]) => ({
                rating: parseFloat(rating),
                appearances: v.appearances,
                wins: v.wins,
                motms: v.motms,
                win_pct: v.appearances > 0 ? Math.round((v.wins / v.appearances) * 1000) / 10 : 0,
                motm_pct: v.appearances > 0 ? Math.round((v.motms / v.appearances) * 1000) / 10 : 0
            }))
            .sort((a, b) => a.rating - b.rating);

        res.json(dataPoints);
    } catch (error) {
        console.error('Stats graph error:', error);
        res.status(500).json({ error: 'Failed to load stats graph' });
    }
});

// GET /api/admin/audit/player/:id — full audit history for a player
app.get('/api/admin/audit/player/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Balance history
        const balance = await pool.query(`
            SELECT ct.created_at, ct.amount, ct.type, ct.description,
                   p.alias as admin_alias, p.full_name as admin_name
            FROM credit_transactions ct
            LEFT JOIN users u ON u.id = ct.admin_id
            LEFT JOIN players p ON p.user_id = u.id
            WHERE ct.player_id = $1
            ORDER BY ct.created_at DESC
        `, [id]);

        // 2. Stat history
        const stats = await pool.query(`
            SELECT psh.created_at, psh.overall_rating, psh.defending_rating, psh.strength_rating,
                   psh.fitness_rating, psh.pace_rating, psh.decisions_rating,
                   psh.assisting_rating, psh.shooting_rating, psh.goalkeeper_rating,
                   psh.reliability_tier, p.alias as changed_by_alias, p.full_name as changed_by_name
            FROM player_stat_history psh
            LEFT JOIN players p ON p.id = psh.changed_by
            WHERE psh.player_id = $1
            ORDER BY psh.created_at DESC
        `, [id]);

        // 3. Registration events (sign up / drop out)
        const regEvents = await pool.query(`
            SELECT re.created_at, re.event_type, re.detail,
                   g.game_date, g.format, g.game_url, v.name as venue_name
            FROM registration_events re
            JOIN games g ON g.id = re.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE re.player_id = $1
            ORDER BY re.created_at DESC
        `, [id]);

        // 4. MOTM received
        const motmReceived = await pool.query(`
            SELECT g.game_date, g.format, g.game_url, v.name as venue_name,
                   g.motm_winner_id
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.motm_winner_id = $1 AND g.game_status = 'completed'
            ORDER BY g.game_date DESC
        `, [id]);

        // 5. MOTM votes cast
        const motmVotes = await pool.query(`
            SELECT mv.created_at, g.game_date, g.format, g.game_url, v.name as venue_name,
                   p.alias as voted_for_alias, p.full_name as voted_for_name
            FROM motm_votes mv
            JOIN games g ON g.id = mv.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            JOIN players p ON p.id = mv.voted_for_id
            WHERE mv.voter_id = $1
            ORDER BY mv.created_at DESC
        `, [id]);

        // 6. Admin actions (audit_logs targeting this player)
        const adminActions = await pool.query(`
            SELECT al.created_at, al.action, al.detail,
                   p.alias as admin_alias, p.full_name as admin_name
            FROM audit_logs al
            LEFT JOIN players p ON p.id = al.admin_id
            WHERE al.target_id = $1
            ORDER BY al.created_at DESC
        `, [id]);

        res.json({
            balance: balance.rows,
            stats: stats.rows,
            registrations: regEvents.rows,
            motmReceived: motmReceived.rows,
            motmVotesCast: motmVotes.rows,
            adminActions: adminActions.rows
        });
    } catch (error) {
        console.error('Player audit error:', error);
        res.status(500).json({ error: 'Failed to load player audit' });
    }
});

// GET /api/admin/audit/game/:id — full audit history for a game
app.get('/api/admin/audit/game/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Game audit log (admin actions)
        const gameLogs = await pool.query(`
            SELECT gal.created_at, gal.action, gal.detail,
                   p.alias as admin_alias, p.full_name as admin_name
            FROM game_audit_log gal
            LEFT JOIN players p ON p.id = gal.admin_id
            WHERE gal.game_id = $1
            ORDER BY gal.created_at DESC
        `, [id]);

        // 2. Registration events for this game
        const regEvents = await pool.query(`
            SELECT re.created_at, re.event_type, re.detail,
                   p.alias as player_alias, p.full_name as player_name, p.squad_number
            FROM registration_events re
            JOIN players p ON p.id = re.player_id
            WHERE re.game_id = $1
            ORDER BY re.created_at DESC
        `, [id]);

        // 3. Registrations (signed up currently)
        const currentRegs = await pool.query(`
            SELECT r.registered_at, r.status, r.backup_type, r.position_preference,
                   p.alias, p.full_name, p.squad_number
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1
            ORDER BY r.registered_at ASC
        `, [id]);

        res.json({
            gameLogs: gameLogs.rows,
            registrationEvents: regEvents.rows,
            currentRegistrations: currentRegs.rows
        });
    } catch (error) {
        console.error('Game audit error:', error);
        res.status(500).json({ error: 'Failed to load game audit' });
    }
});

// ==========================================
// PUSH NOTIFICATION TOKEN MANAGEMENT
// ==========================================

// Register a player's FCM device token (called on app launch / permission grant)
app.post('/api/push/register', authenticateToken, async (req, res) => {
    try {
        const { fcmToken, deviceName } = req.body;
        if (!fcmToken) return res.status(400).json({ error: 'fcmToken is required' });

        // SEC-043: Purge tokens unused for 90+ days before adding new one — prevents stale token accumulation
        await pool.query(
            `DELETE FROM fcm_tokens WHERE player_id = $1 AND last_used_at < NOW() - INTERVAL '90 days'`,
            [req.user.playerId]
        );

        // FIX-042: Enforce per-player token cap of 5 — remove oldest if at limit
        const tokenCount = await pool.query('SELECT COUNT(*) FROM fcm_tokens WHERE player_id = $1', [req.user.playerId]);
        if (parseInt(tokenCount.rows[0].count) >= 5) {
            await pool.query(
                `DELETE FROM fcm_tokens WHERE player_id = $1 AND fcm_token NOT IN
                 (SELECT fcm_token FROM fcm_tokens WHERE player_id = $1 ORDER BY last_used_at DESC LIMIT 4)`,
                [req.user.playerId]
            );
        }

        await pool.query(`
            INSERT INTO fcm_tokens (player_id, fcm_token, device_name, last_used_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (player_id, fcm_token)
            DO UPDATE SET last_used_at = NOW(), device_name = EXCLUDED.device_name
        `, [req.user.playerId, fcmToken, deviceName || null]);

        res.json({ message: 'Push token registered' });
    } catch (error) {
        console.error('Push register error:', error);
        res.status(500).json({ error: 'Failed to register push token' });
    }
});

// Unregister a player's FCM token (called on logout or permission revoke)
app.delete('/api/push/unregister', authenticateToken, async (req, res) => {
    try {
        const { fcmToken } = req.body;
        if (fcmToken) {
            // Remove specific token
            await pool.query(
                'DELETE FROM fcm_tokens WHERE player_id = $1 AND fcm_token = $2',
                [req.user.playerId, fcmToken]
            );
        } else {
            // Remove all tokens for this player (full logout)
            await pool.query(
                'DELETE FROM fcm_tokens WHERE player_id = $1',
                [req.user.playerId]
            );
        }
        res.json({ message: 'Push token unregistered' });
    } catch (error) {
        console.error('Push unregister error:', error);
        res.status(500).json({ error: 'Failed to unregister push token' });
    }
});

// ── IN-APP NOTIFICATIONS ─────────────────────────────────────────────────────

// GET /api/players/me/notifications — return last 50 notifications for the logged-in player
app.get('/api/players/me/notifications', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, type, message, game_id, read_at, created_at
            FROM notifications
            WHERE player_id = $1
            ORDER BY created_at DESC
            LIMIT 50
        `, [req.user.playerId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// POST /api/players/me/notifications/mark-read — mark a list of notification IDs as read
// Body: { ids: [1, 2, 3] }
app.post('/api/players/me/notifications/mark-read', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.json({ updated: 0 });
        }
        // Only mark notifications that belong to the authenticated player (security check)
        const result = await pool.query(`
            UPDATE notifications
            SET read_at = NOW()
            WHERE id = ANY($1::int[])
              AND player_id = $2
              AND read_at IS NULL
        `, [ids, req.user.playerId]);
        res.json({ updated: result.rowCount });
    } catch (error) {
        console.error('Mark notifications read error:', error);
        res.status(500).json({ error: 'Failed to mark notifications as read' });
    }
});

// ── ADMIN: UNBAN PLAYER ───────────────────────────────────────────────────────

// POST /api/admin/players/:id/discipline — manually add discipline points (admin only)
// Points number only — no reason required. Recalculates tier immediately.
app.post('/api/admin/players/:id/discipline', authenticateToken, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { points } = req.body;

    const pts = parseInt(points);
    if (!pts || pts < 1 || pts > 20) {
        return res.status(400).json({ error: 'Points must be between 1 and 20' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Insert manual record (game_id NULL = manual admin entry)
        await client.query(`
            INSERT INTO discipline_records (player_id, game_id, points, offense_type, recorded_by)
            VALUES ($1, NULL, $2, 'Manual (admin)', $3)
        `, [id, pts, req.user.playerId]);

        // Immediately recalculate tier
        const tierResult = await client.query(
            'SELECT calculate_player_tier($1::uuid) AS new_tier', [id]
        );
        const newTier = tierResult.rows[0]?.new_tier || 'silver';
        await client.query('UPDATE players SET reliability_tier = $1 WHERE id = $2', [newTier, id]);

        await client.query('COMMIT');
        res.json({ success: true, newTier, pointsAdded: pts });
        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'discipline_added', id,
                `${pts} point(s) added manually | new tier: ${newTier}`);
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Add discipline points error:', error);
    } finally {
        client.release();
    }
});

// POST /api/admin/players/:id/unban — superadmin only, clears discipline and adds 1 warning point
// CRIT-14: requireSuperAdmin — admins must not be able to unban players the superadmin deliberately banned
app.post('/api/admin/players/:id/unban', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Clear all existing discipline records for this player
        await client.query('DELETE FROM discipline_records WHERE player_id = $1', [id]);

        // Add a single warning-level discipline point (clean slate but flagged)
        // SEC-038: game_id explicitly NULL — unban is not tied to a specific game
        await client.query(`
            INSERT INTO discipline_records (player_id, game_id, points, reason, recorded_by)
            VALUES ($1, NULL, 1, 'Reinstated after ban', $2)
        `, [id, req.user.playerId]);

        // Recalculate tier (1 point with sufficient appearances = silver)
        const tierResult = await client.query(`
            SELECT calculate_player_tier($1::uuid) AS new_tier
        `, [id]);
        const newTier = tierResult.rows[0]?.new_tier || 'silver';

        await client.query(
            'UPDATE players SET reliability_tier = $1 WHERE id = $2',
            [newTier, id]
        );

        // Insert reinstatement notification for the player
        await client.query(`
            INSERT INTO notifications (player_id, type, message)
            VALUES ($1, 'account_reinstated', '✅ Your account has been reinstated. Welcome back.')
        `, [id]);

        await client.query('COMMIT');

        // Fire push notification (non-blocking)
        sendPushNotification(id, 'account_reinstated', '✅ Your account has been reinstated. Welcome back.').catch(() => {});

        res.json({ message: 'Player unbanned successfully', newTier });
        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'player_unbanned', id,
                `Discipline cleared | new tier: ${newTier}`);
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Unban error:', error);
    } finally {
        client.release();
    }
});

// ── DIRECT MESSAGES ──────────────────────────────────────────────────────────

// GET /api/dm/conversations — list all DM conversations for the logged-in player
// Returns latest message per conversation, unread count, other player info
app.get('/api/dm/conversations', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                other_player_id,
                other_name,
                other_alias,
                other_tier,
                last_message,
                last_message_at,
                last_sender_id,
                COUNT(*) FILTER (
                    WHERE sender_id != $1 AND read_at IS NULL
                ) AS unread_count
            FROM (
                SELECT
                    CASE WHEN dm.sender_id = $1 THEN dm.recipient_id ELSE dm.sender_id END AS other_player_id,
                    p.full_name    AS other_name,
                    p.alias        AS other_alias,
                    p.reliability_tier AS other_tier,
                    dm.message     AS last_message,
                    dm.created_at  AS last_message_at,
                    dm.sender_id   AS last_sender_id,
                    dm.sender_id,
                    dm.read_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY LEAST(dm.sender_id, dm.recipient_id), GREATEST(dm.sender_id, dm.recipient_id)
                        ORDER BY dm.created_at DESC
                    ) AS rn
                FROM direct_messages dm
                JOIN players p ON p.id = CASE WHEN dm.sender_id = $1 THEN dm.recipient_id ELSE dm.sender_id END
                WHERE (dm.sender_id = $1 OR dm.recipient_id = $1)
                  AND dm.deleted_at IS NULL
            ) sub
            WHERE rn = 1
            GROUP BY other_player_id, other_name, other_alias, other_tier,
                     last_message, last_message_at, last_sender_id
            ORDER BY last_message_at DESC
        `, [req.user.playerId]);

        res.json(result.rows);
    } catch (error) {
        console.error('Get conversations error:', error);
        res.status(500).json({ error: 'Failed to fetch conversations' });
    }
});

// GET /api/dm/:playerId — get the DM thread between logged-in player and another player
// ?since=<ISO> for incremental polling, ?limit=&offset= for pagination
app.get('/api/dm/:playerId', authenticateToken, async (req, res) => {
    const { playerId } = req.params;
    const { since }    = req.query;
    // SEC-022b: Validate `since` + Fix 33: pagination
    if (since && isNaN(Date.parse(since))) {
        return res.status(400).json({ error: 'Invalid `since` parameter — must be a valid ISO date' });
    }
    const limit  = Math.min(parseInt(req.query.limit)  || 50, 100);
    const offset = Math.max(parseInt(req.query.offset) || 0,  0);

    try {
        // Verify other player exists
        const check = await pool.query('SELECT id FROM players WHERE id = $1', [playerId]);
        if (check.rows.length === 0) return res.status(404).json({ error: 'Player not found' });

        const sinceClause = since ? 'AND dm.created_at > $3' : '';
        // Fix 33: paginate DM threads — prevents unbounded query on high-volume conversations
        const paginateSuffix = since
            ? `LIMIT ${limit} OFFSET ${offset}`
            : `LIMIT ${limit} OFFSET ${offset}`;
        const params = since
            ? [req.user.playerId, playerId, since]
            : [req.user.playerId, playerId];

        const result = await pool.query(`
            SELECT
                dm.id,
                dm.sender_id,
                dm.recipient_id,
                dm.message,
                dm.read_at,
                dm.created_at,
                COALESCE(p.alias, p.full_name) AS sender_name
            FROM direct_messages dm
            JOIN players p ON p.id = dm.sender_id
            WHERE (
                (dm.sender_id = $1 AND dm.recipient_id = $2)
                OR
                (dm.sender_id = $2 AND dm.recipient_id = $1)
            )
            AND dm.deleted_at IS NULL
            ${sinceClause}
            ORDER BY dm.created_at ASC
            ${paginateSuffix}
        `, params);

        res.json(result.rows);
    } catch (error) {
        console.error('Get DM thread error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// POST /api/dm/:playerId — send a DM to a player (SEC-009: rate limited)
app.post('/api/dm/:playerId', authenticateToken, dmSendLimiter, async (req, res) => {
    const { playerId }    = req.params;
    const { message }     = req.body;
    const senderId        = req.user.playerId;

    if (String(playerId) === String(senderId)) {
        return res.status(400).json({ error: 'You cannot message yourself' });
    }
    if (!message || typeof message !== 'string' || !message.trim()) {
        return res.status(400).json({ error: 'Message is required' });
    }
    if (message.trim().length > 500) {
        return res.status(400).json({ error: 'Message must be 500 characters or fewer' });
    }

    try {
        // Verify recipient exists
        const recipientCheck = await pool.query(
            'SELECT id, alias, full_name FROM players WHERE id = $1', [playerId]
        );
        if (recipientCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        const recipient = recipientCheck.rows[0];

        const result = await pool.query(`
            INSERT INTO direct_messages (sender_id, recipient_id, message)
            VALUES ($1, $2, $3)
            RETURNING id, sender_id, recipient_id, message, read_at, created_at,
                (SELECT COALESCE(alias, full_name) FROM players WHERE id = $1) AS sender_name
        `, [senderId, playerId, message.trim()]);

        const newMsg = result.rows[0];

        // In-app notification + push to recipient (fire and forget)
        const senderResult = await pool.query(
            'SELECT COALESCE(alias, full_name) AS name FROM players WHERE id = $1',
            [senderId]
        );
        const senderName = senderResult.rows[0]?.name || 'Someone';
        const preview    = message.trim().length > 40
            ? message.trim().substring(0, 40) + '…'
            : message.trim();

        pool.query(`
            INSERT INTO notifications (player_id, type, message)
            VALUES ($1, 'new_dm', $2)
        `, [playerId, `${senderName}: ${preview}`]).catch(() => {});

        sendPushNotification(playerId, 'new_dm', `${senderName}: ${preview}`, {
            senderId:   String(senderId),
            senderName,
        }).catch(() => {});

        res.status(201).json(newMsg);
    } catch (error) {
        console.error('Send DM error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// POST /api/dm/:playerId/mark-read — mark all messages from playerId as read
app.post('/api/dm/:playerId/mark-read', authenticateToken, async (req, res) => {
    const { playerId } = req.params;
    try {
        await pool.query(`
            UPDATE direct_messages
            SET read_at = NOW()
            WHERE sender_id = $1
              AND recipient_id = $2
              AND read_at IS NULL
        `, [playerId, req.user.playerId]);
        res.json({ ok: true });
    } catch (error) {
        console.error('Mark DM read error:', error);
        res.status(500).json({ error: 'Failed to mark messages as read' });
    }
});

// ── TEAM FAIRNESS VOTING ─────────────────────────────────────────────────────

// GET /api/games/:gameId/fairness — get vote counts + logged-in player's vote
app.get('/api/games/:gameId/fairness', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    try {
        const counts = await pool.query(`
            SELECT
                COUNT(*) FILTER (WHERE vote = 'up')   AS up,
                COUNT(*) FILTER (WHERE vote = 'down') AS down
            FROM team_fairness_votes
            WHERE game_id = $1
        `, [gameId]);

        const myVoteResult = await pool.query(
            'SELECT vote FROM team_fairness_votes WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );

        const revealResult = await pool.query(
            'SELECT 1 FROM team_reveals WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );

        res.json({
            up:          parseInt(counts.rows[0].up)   || 0,
            down:        parseInt(counts.rows[0].down) || 0,
            myVote:      myVoteResult.rows[0]?.vote || null,
            hasRevealed: revealResult.rows.length > 0,
        });
    } catch (error) {
        console.error('Get fairness error:', error);
        res.status(500).json({ error: 'Failed to fetch fairness votes' });
    }
});


// POST /api/games/:gameId/reveal-teams — record that this player has revealed teams
// Idempotent — safe to call multiple times, only stores once
app.post('/api/games/:gameId/reveal-teams', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    try {
        await pool.query(`
            INSERT INTO team_reveals (game_id, player_id)
            VALUES ($1, $2)
            ON CONFLICT (game_id, player_id) DO NOTHING
        `, [gameId, req.user.playerId]);
        res.json({ revealed: true });
    } catch (error) {
        console.error('Reveal teams error:', error);
        res.status(500).json({ error: 'Failed to record reveal' });
    }
});

// POST /api/games/:gameId/fairness-vote — cast or update a fairness vote (SEC-010: rate limited)
app.post('/api/games/:gameId/fairness-vote', authenticateToken, fairnessLimiter, async (req, res) => {
    const { gameId }  = req.params;
    const { vote }    = req.body;

    if (!['up', 'down'].includes(vote)) {
        return res.status(400).json({ error: 'vote must be "up" or "down"' });
    }

    try {
        // Verify player is registered for this game (confirmed or backup)
        const regCheck = await pool.query(
            `SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status IN ('confirmed','backup')`,
            [gameId, req.user.playerId]
        );
        if (regCheck.rows.length === 0) {
            return res.status(403).json({ error: 'You must be registered to vote on team fairness' });
        }

        // Verify teams have been generated
        const gameCheck = await pool.query('SELECT teams_generated FROM games WHERE id = $1', [gameId]);
        if (!gameCheck.rows[0]?.teams_generated) {
            return res.status(403).json({ error: 'Teams have not been generated yet' });
        }

        // Upsert — players can change their vote
        await pool.query(`
            INSERT INTO team_fairness_votes (game_id, player_id, vote)
            VALUES ($1, $2, $3)
            ON CONFLICT (game_id, player_id)
            DO UPDATE SET vote = EXCLUDED.vote, created_at = NOW()
        `, [gameId, req.user.playerId, vote]);

        // Return updated totals
        const counts = await pool.query(`
            SELECT
                COUNT(*) FILTER (WHERE vote = 'up')   AS up,
                COUNT(*) FILTER (WHERE vote = 'down') AS down
            FROM team_fairness_votes
            WHERE game_id = $1
        `, [gameId]);

        res.json({
            up:     parseInt(counts.rows[0].up)   || 0,
            down:   parseInt(counts.rows[0].down) || 0,
            myVote: vote,
        });
    } catch (error) {
        console.error('Fairness vote error:', error);
        res.status(500).json({ error: 'Failed to record vote' });
    }
});

// GET /api/public/game/:gameUrl/fairness — public counts only (no voter info)
app.get('/api/public/game/:gameUrl/fairness', async (req, res) => {
    const { gameUrl } = req.params;
    try {
        const gameRes = await pool.query('SELECT id FROM games WHERE game_url = $1', [gameUrl]);
        if (gameRes.rows.length === 0) return res.status(404).json({ error: 'Game not found' });

        const counts = await pool.query(`
            SELECT
                COUNT(*) FILTER (WHERE vote = 'up')   AS up,
                COUNT(*) FILTER (WHERE vote = 'down') AS down
            FROM team_fairness_votes
            WHERE game_id = $1
        `, [gameRes.rows[0].id]);

        res.json({
            up:   parseInt(counts.rows[0].up)   || 0,
            down: parseInt(counts.rows[0].down) || 0,
        });
    } catch (error) {
        console.error('Public fairness error:', error);
        res.status(500).json({ error: 'Failed to fetch fairness votes' });
    }
});

// ── GAME CHAT ─────────────────────────────────────────────────────────────────

// GET /api/games/:gameId/messages — fetch chat messages for a game
// SEC-026: General chat is public (guests included). Team chat requires auth + team assignment.
// ?since=<ISO timestamp> — if provided, only returns messages after that time (for polling)
app.get('/api/games/:gameId/messages', optionalAuth, async (req, res) => {
    const { gameId } = req.params;
    const { since } = req.query;

    // SEC-022: Validate `since` is a valid ISO date before interpolating into SQL
    if (since && isNaN(Date.parse(since))) {
        return res.status(400).json({ error: 'Invalid `since` parameter — must be a valid ISO date' });
    }

    try {
        // Verify game exists
        const gameCheck = await pool.query('SELECT id, game_status FROM games WHERE id = $1', [gameId]);
        if (gameCheck.rows.length === 0) return res.status(404).json({ error: 'Game not found' });

        // N7: Anyone can read general (scope='chat') messages — no auth required.
        // Team messages are filtered server-side to the requesting player's team only.
        let myTeamId = null;
        if (req.user?.playerId) {
            const teamRes = await pool.query(`
                SELECT tp.team_id
                FROM team_players tp
                JOIN teams t ON t.id = tp.team_id
                WHERE tp.player_id = $1 AND t.game_id = $2
                LIMIT 1
            `, [req.user.playerId, gameId]);
            myTeamId = teamRes.rows[0]?.team_id || null;
        }

        // Guests and unauthenticated users see only general (scope='chat') messages.
        // Authenticated players also see their own team channel if assigned.
        const sinceClause = since ? 'AND gm.created_at > $3::timestamptz' : '';
        const params = since ? [gameId, myTeamId, since] : [gameId, myTeamId];

        const result = await pool.query(`
            SELECT
                gm.id,
                gm.game_id,
                gm.player_id,
                gm.scope,
                gm.message,
                gm.created_at,
                COALESCE(p.alias, p.full_name, 'Unknown') AS player_alias,
                p.full_name AS player_name
            FROM game_messages gm
            JOIN players p ON p.id = gm.player_id
            WHERE gm.game_id = $1
              AND gm.deleted_at IS NULL
              AND (
                  gm.scope = 'chat'
                  OR (gm.scope = 'team' AND $2 IS NOT NULL AND gm.team_id = $2)
              )
              ${sinceClause}
            ORDER BY gm.created_at ASC
        `, params);

        res.json(result.rows);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// POST /api/games/:gameId/messages — post a new chat message
// Body: { message: string, scope: 'chat' | 'team' }
app.post('/api/games/:gameId/messages', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    const { message, scope = 'chat' } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
        return res.status(400).json({ error: 'Message is required' });
    }
    if (message.trim().length > 500) {
        return res.status(400).json({ error: 'Message must be 500 characters or fewer' });
    }
    if (!['chat', 'team'].includes(scope)) {
        return res.status(400).json({ error: 'scope must be "chat" or "team"' });
    }

    try {
        // Verify game exists and is not cancelled
        const gameCheck = await pool.query('SELECT id, game_status FROM games WHERE id = $1', [gameId]);
        if (gameCheck.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        if (gameCheck.rows[0].game_status === 'cancelled') {
            return res.status(403).json({ error: 'Chat is disabled for cancelled games' });
        }

        // CRIT-7/N7: Must be registered in the game (any status) to post to general chat.
        // Team chat is further restricted to team members only (handled below via team_id resolution).
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (!isAdmin) {
            const regCheck = await pool.query(
                `SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2`,
                [gameId, req.user.playerId]
            );
            if (regCheck.rows.length === 0) {
                return res.status(403).json({ error: 'You must be registered for this game to post in chat' });
            }
        }

        // Resolve team_id server-side — never trust client to send their own team_id
        let teamId = null;
        if (scope === 'team') {
            const teamRes = await pool.query(`
                SELECT tp.team_id
                FROM team_players tp
                JOIN teams t ON t.id = tp.team_id
                WHERE tp.player_id = $1 AND t.game_id = $2
                LIMIT 1
            `, [req.user.playerId, gameId]);

            if (teamRes.rows.length === 0) {
                return res.status(403).json({ error: 'You are not assigned to a team in this game' });
            }
            teamId = teamRes.rows[0].team_id;
        }

        const result = await pool.query(`
            INSERT INTO game_messages (game_id, player_id, team_id, scope, message)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, game_id, player_id, scope, message, created_at,
                (SELECT COALESCE(alias, full_name, 'Unknown') FROM players WHERE id = $2) AS player_alias,
                (SELECT full_name FROM players WHERE id = $2) AS player_name
        `, [gameId, req.user.playerId, teamId, scope, message.trim()]);

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Post message error:', error);
        res.status(500).json({ error: 'Failed to post message' });
    }
});

// GET /api/public/game/:gameUrl/messages — read-only, public chat feed for the web dashboard
// Only returns 'chat' scope messages (team messages never shown on web)
app.get('/api/public/game/:gameUrl/messages', async (req, res) => {
    const { gameUrl } = req.params;
    const { since } = req.query;

    try {
        // Resolve game by URL slug
        const gameRes = await pool.query('SELECT id FROM games WHERE game_url = $1', [gameUrl]);
        if (gameRes.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const gameId = gameRes.rows[0].id;

        // CRIT-12: Validate since is a valid ISO date before using in query
        if (since && isNaN(Date.parse(since))) {
            return res.status(400).json({ error: 'Invalid since parameter' });
        }

        const sinceClause = since ? 'AND gm.created_at > $2' : '';
        const params = since ? [gameId, since] : [gameId];

        const result = await pool.query(`
            SELECT
                gm.id,
                gm.scope,
                gm.message,
                gm.created_at,
                COALESCE(p.alias, p.full_name, 'Unknown') AS player_name
            FROM game_messages gm
            JOIN players p ON p.id = gm.player_id
            WHERE gm.game_id = $1
              AND gm.scope = 'chat'
              AND gm.deleted_at IS NULL
              ${sinceClause}
            ORDER BY gm.created_at ASC
        `, params);

        res.json(result.rows);
    } catch (error) {
        console.error('Public get messages error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// DELETE /api/admin/messages/:messageId — soft-delete a message (admin only)
app.delete('/api/admin/messages/:messageId', authenticateToken, requireAdmin, async (req, res) => {
    const { messageId } = req.params;
    try {
        const result = await pool.query(
            'UPDATE game_messages SET deleted_at = NOW() WHERE id = $1 RETURNING id',
            [messageId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Message not found' });
        res.json({ message: 'Message deleted', id: messageId });
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// ── PASSWORD RESET ──────────────────────────────────────────────────────────

// POST /api/auth/forgot-password — request a reset token
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    try {
        // Always return success to prevent email enumeration
        const result = await pool.query(
            `SELECT p.id, p.full_name, u.email FROM players p
             JOIN users u ON u.id = p.user_id
             WHERE LOWER(u.email) = LOWER($1)`,
            [email.trim()]
        );

        if (result.rows.length > 0) {
            const player = result.rows[0];
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

            // Upsert token — try ON CONFLICT first, fall back to DELETE+INSERT if constraint missing
            try {
                await pool.query(
                    `INSERT INTO password_reset_tokens (player_id, token, expires_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (player_id) DO UPDATE SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at, used_at = NULL`,
                    [player.id, token, expiresAt]
                );
            } catch (upsertErr) {
                // Unique constraint may not exist — fall back to delete + insert
                console.warn('Reset token upsert failed, falling back to delete+insert:', upsertErr.message);
                await pool.query('DELETE FROM password_reset_tokens WHERE player_id = $1', [player.id]);
                await pool.query(
                    'INSERT INTO password_reset_tokens (player_id, token, expires_at) VALUES ($1, $2, $3)',
                    [player.id, token, expiresAt]
                );
            }

            // Send email — decoupled from main try/catch so email failure doesn't 500 the request
            const resetLink = `https://totalfooty.co.uk/vibecoding/reset-password.html?token=${token}`;
            emailTransporter.sendMail({
                from: '"TotalFooty" <totalfooty19@gmail.com>',
                to: email.trim(),
                subject: 'TotalFooty — Reset Your Password',
                html: `
                    <div style="background:#0d0d0d;padding:40px;font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
                        <img src="https://totalfooty.co.uk/assets/logo.png" width="80" style="margin-bottom:24px"/>
                        <h2 style="color:#fff;font-size:20px;letter-spacing:2px;margin-bottom:8px">PASSWORD RESET</h2>
                        <p style="color:#888;font-size:14px">Hi ${player.full_name},</p>
                        <p style="color:#888;font-size:14px">You requested a password reset for your TotalFooty account. Click the button below to set a new password.</p>
                        <a href="${resetLink}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;margin:24px 0">RESET PASSWORD</a>
                        <p style="color:#555;font-size:12px">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
                        <p style="color:#333;font-size:11px;margin-top:32px;letter-spacing:1px">TOTALFOOTY — COVENTRY FOOTBALL COMMUNITY</p>
                    </div>
                `,
            }).then(() => {
                console.log(`Password reset email sent to ${email.trim()}`);
            }).catch(emailErr => {
                // Log the real reason — check Render logs if email not arriving
                console.error('Password reset email FAILED:', emailErr.message);
                console.error('Check: GMAIL_APP_PASSWORD env var set correctly on Render?');
            });
        }

        // Always return success — don't reveal whether email exists or if email send failed
        res.json({ message: 'If an account exists with that email, a reset link has been sent.' });
    } catch (error) {
        console.error('Forgot password DB error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// FIX-076: PUT /api/auth/change-password — authenticated password change (no email flow needed)
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both current and new password are required' });
        if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

        const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });

        const valid = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
        if (!valid) return res.status(403).json({ error: 'Current password is incorrect' });

        const hash = await bcrypt.hash(newPassword, 12); // SEC-035: consistent cost 12 across all password hashing
        // HIGH-2: Bump token_version — all previously issued JWTs are now invalid
        await pool.query(
            'UPDATE users SET password_hash = $1, token_version = token_version + 1 WHERE id = $2',
            [hash, req.user.userId]
        );

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// POST /api/auth/reset-password — submit new password with token
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
    // SEC-015: Enforce same minimum length as registration (was 6, raised to 8)
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    try {
        const result = await pool.query(
            `SELECT prt.id, prt.token AS stored_token, prt.player_id, prt.expires_at, prt.used_at
             FROM password_reset_tokens prt
             WHERE prt.token = $1`,
            [token]
        );

        if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset link' });

        const resetToken = result.rows[0];

        // MED-1: Timing-safe comparison to prevent brute-force enumeration via timing side-channel
        let tokenMatch = false;
        try {
            tokenMatch = crypto.timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(resetToken.stored_token, 'hex'));
        } catch (_) { tokenMatch = false; }
        if (!tokenMatch) return res.status(400).json({ error: 'Invalid or expired reset link' });

        if (resetToken.used_at) return res.status(400).json({ error: 'This reset link has already been used' });
        if (new Date() > new Date(resetToken.expires_at)) return res.status(400).json({ error: 'This reset link has expired' });

        // Update password on users table
        const passwordHash = await bcrypt.hash(newPassword, 12); // SEC-035: bcrypt cost 12 consistent with registration

        await pool.query(
            `UPDATE users SET password_hash = $1 WHERE id = (SELECT user_id FROM players WHERE id = $2)`,
            [passwordHash, resetToken.player_id]
        );

        // SEC-036: Invalidate all existing sessions by bumping token_version — prevents token reuse post-reset
        await pool.query(
            `UPDATE users SET token_version = COALESCE(token_version, 0) + 1
             WHERE id = (SELECT user_id FROM players WHERE id = $1)`,
            [resetToken.player_id]
        );

        // Mark token as used
        await pool.query('UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1', [resetToken.id]);

        res.json({ message: 'Password updated successfully. Please log in again.' });
    } catch (error) {
        console.error('Reset password error'); // SEC-037: No error details in log — no token/email leak
        res.status(500).json({ error: 'Failed to reset password' });
    }
});


// ── CONTACT FORM ──────────────────────────────────────────────────────────────
// POST /api/public/contact — anyone can submit (covered by publicEndpointLimiter)
app.post('/api/public/contact', async (req, res) => {
    try {
        const { name, mobile, message } = req.body || {};

        // Validate
        if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 80) {
            return res.status(400).json({ error: 'Please provide your name (2–80 characters).' });
        }
        if (!mobile || typeof mobile !== 'string' || mobile.trim().length < 7 || mobile.trim().length > 20) {
            return res.status(400).json({ error: 'Please provide a valid mobile number.' });
        }
        const dangerousChars = /[<>"'`]/;
        if (dangerousChars.test(name) || dangerousChars.test(mobile)) {
            return res.status(400).json({ error: 'Invalid characters in submission.' });
        }
        if (message && (typeof message !== 'string' || message.length > 500)) {
            return res.status(400).json({ error: 'Message must be 500 characters or less.' });
        }
        if (message && dangerousChars.test(message)) {
            return res.status(400).json({ error: 'Invalid characters in message.' });
        }

        res.json({ message: "Thanks! We'll be in touch soon." });

        // Send email to admin (non-critical, after response)
        setImmediate(async () => {
            try {
                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to:   SUPERADMIN_EMAIL || 'totalfooty19@gmail.com',
                    subject: '📬 Contact Form Submission — TotalFooty',
                    html: wrapEmailHtml(
                        '<p style="color:#888;font-size:14px;margin:0 0 16px">New contact form submission</p>' +
                        '<table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;">' +
                        `<tr><td style="padding:6px 0;color:#888;width:100px;">Name</td><td style="font-weight:900;">${htmlEncode(name.trim())}</td></tr>` +
                        `<tr><td style="padding:6px 0;color:#888;">Mobile</td><td>${htmlEncode(mobile.trim())}</td></tr>` +
                        `<tr><td style="padding:6px 0;color:#888;">Message</td><td>${htmlEncode(message ? message.trim() : '(none)')}</td></tr>` +
                        '</table>'
                    ),
                });
            } catch (e) {
                console.error('Contact form email failed (non-critical):', e.message);
            }
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ error: 'Failed to submit contact form.' });
    }
});

// FIX-043: Catch-all 404 handler (must be after all routes)
app.use((req, res) => { res.status(404).json({ error: 'Not found' }); });

// FIX-037: Global handlers — SEC-012: uncaughtException now exits to prevent undefined server state
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled Promise Rejection:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception — exiting:', err.message);
    process.exit(1);
});

app.listen(PORT, () => {
    console.log(`🚀 Total Footy API running on port ${PORT}`);
    
    // Keep database AND backend warm (ping every 5 minutes)
    setInterval(async () => {
        try {
            await pool.query('SELECT 1');
            console.log('✓ Keep-alive ping:', new Date().toLocaleTimeString());
        } catch (error) {
            console.error('✗ Keep-alive error:', error.message);
        }
    }, 5 * 60 * 1000); // 5 minutes (more aggressive)

    // Game reminder — fires 4 hours before each game, checks every 5 minutes
    // SEC-040: DB-level reminder_sent flag prevents double-send on process restart
    let reminderRunning = false;
    setInterval(async () => {
        if (reminderRunning) return; // Skip if previous tick still running
        reminderRunning = true;
        try {
            // Find games starting in the next 4h that haven't had a reminder sent yet
            // FIX-025: Use reminder_sent column instead of fragile LIKE match on log content
            // NOTE: Requires: ALTER TABLE games ADD COLUMN IF NOT EXISTS reminder_sent BOOLEAN DEFAULT FALSE;
            const upcoming = await pool.query(`
                SELECT g.id
                FROM games g
                WHERE g.game_date BETWEEN NOW() + INTERVAL '3 hours 55 minutes'
                  AND NOW() + INTERVAL '4 hours 5 minutes'
                  AND g.game_status NOT IN ('cancelled', 'completed')
                  AND g.reminder_sent = FALSE
            `);
            for (const row of upcoming.rows) {
                // Atomic claim — prevents double-send if two processes run simultaneously
                const claimed = await pool.query(
                    `UPDATE games SET reminder_sent = TRUE WHERE id = $1 AND reminder_sent = FALSE RETURNING id`,
                    [row.id]
                );
                if (claimed.rowCount === 0) continue; // Another instance already claimed it
                const gameData = await getGameDataForNotification(row.id);
                const confirmed = await pool.query(
                    `SELECT player_id FROM registrations WHERE game_id = $1 AND status = 'confirmed'`,
                    [row.id]
                );
                for (const reg of confirmed.rows) {
                    await sendNotification('game_reminder', reg.player_id, gameData).catch(() => {});
                }
                console.log(`⏰ Reminders sent for game ${row.id} (${confirmed.rows.length} players)`);
            }
        } catch (error) {
            console.error('✗ Game reminder scheduler error:', error.message);
        } finally {
            reminderRunning = false;
        }
    }, 5 * 60 * 1000); // Check every 5 minutes

    // Daily sweep: remove expired 'New' (baby) badge from players > 30 days old
    // This catches players who registered but never played (autoAllocateBadges never ran for them)
    setInterval(async () => {
        try {
            // Get affected players before deleting so we can audit each one
            const affected = await pool.query(`
                SELECT pb.player_id
                FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                JOIN players p ON p.id = pb.player_id
                WHERE b.name = 'New'
                  AND p.created_at < NOW() - INTERVAL '30 days'
            `);
            if (affected.rows.length === 0) return;

            const result = await pool.query(`
                DELETE FROM player_badges pb
                USING badges b, players p
                WHERE pb.badge_id = b.id
                  AND pb.player_id = p.id
                  AND b.name = 'New'
                  AND p.created_at < NOW() - INTERVAL '30 days'
            `);

            if (result.rowCount > 0) {
                console.log(`⏰ Baby badge sweep: removed New badge from ${result.rowCount} player(s)`);
                for (const row of affected.rows) {
                    await auditLog(pool, null, 'badge_auto_removed', row.player_id, 'badge: New (30-day sweep)');
                }
            }
        } catch (error) {
            console.error('✗ Baby badge sweep error:', error.message);
        }
    }, 24 * 60 * 60 * 1000); // Once every 24 hours

    // Auto-finalize expired MOTM voting every 10 minutes
    setInterval(async () => {
        try {
            const expired = await pool.query(`
                SELECT g.id
                FROM games g
                WHERE g.motm_voting_ends < NOW()
                  AND g.motm_winner_id IS NULL
                  AND g.game_status = 'completed'
                  AND EXISTS (SELECT 1 FROM motm_nominees mn WHERE mn.game_id = g.id)
            `);

            if (expired.rows.length === 0) return;

            console.log(`⏰ Auto-finalizing MOTM for ${expired.rows.length} game(s)...`);
            for (const row of expired.rows) {
                try {
                    const result = await runMotmFinalize(row.id);
                    if (!result.alreadyFinalized) {
                        const names = result.winners.map(w => w.name).join(' & ');
                        console.log(`✅ MOTM auto-finalized game ${row.id}: ${names}`);
                    }
                } catch (e) {
                    console.error(`✗ MOTM auto-finalize failed for game ${row.id}:`, e.message);
                }
            }
        } catch (error) {
            console.error('✗ MOTM scheduler error:', error.message);
        }
    }, 10 * 60 * 1000); // 10 minutes
});
