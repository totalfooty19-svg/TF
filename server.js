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
const CORS_ORIGINS = ['https://totalfooty.co.uk', 'https://www.totalfooty.co.uk', 'https://api.totalfooty.co.uk'];
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
    max: 20,
    message: { error: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // FIX: only count failed attempts — successful logins do not burn quota
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

// FIX-036: Global 500kb body limit — large-payload routes listed explicitly below
const LARGE_PAYLOAD_PATHS = [
    '/api/players/me/photo',
    '/api/players/me/coach-document',
    '/api/players/me/ref-document',
    '/api/coaching/apply',
    '/api/ref/apply',
];
// Also match admin doc-upload paths: /api/admin/players/:id/coach-document etc.
app.use((req, res, next) => {
    const isLarge = LARGE_PAYLOAD_PATHS.includes(req.path)
        || /^\/api\/admin\/players\/[0-9a-f-]{36}\/(coach|ref)-document$/.test(req.path);
    if (isLarge) return next();
    express.json({ limit: '500kb' })(req, res, next);
});
// 5mb body parser for large-payload routes — applied via LARGE_PAYLOAD_PATHS middleware above.
// BUG-04: stub app.post() registrations removed — they shadowed the real handlers below and
// caused photo upload, doc upload, coach/ref apply to hang with no response.
const largeJson = express.json({ limit: '5mb' }); // kept for inline use in coach/ref-document handlers
// Admin doc-upload routes get largeJson via their own inline middleware (already applied)

// FIX-055: No-cache headers on all API responses
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// SEC-007: CSRF — reject state-changing requests from unexpected origins
// CRIT-33: Use URL().origin for exact match — startsWith() was spoofable via https://totalfooty.co.uk.evil.com
const ALLOWED_ORIGINS = ['https://totalfooty.co.uk', 'https://www.totalfooty.co.uk', 'https://api.totalfooty.co.uk'];
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
// Exempt external webhooks from CSRF — they POST from third-party servers, not our origin
app.use('/api', (req, res, next) => {
    if (req.path.startsWith('/webhooks/')) return next();
    return csrfProtect(req, res, next);
});

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

    // Check what London hour this UTC instant corresponds to (may differ across DST boundary).
    // FIX-DST2: clamp hourDiff to ±1 to guard against the midnight edge case where a 23h→0h
    // or 0h→23h wrap produces a spurious diff of ±23 instead of the real ±1 DST shift.
    const checkParts = fmt.formatToParts(target);
    const checkHour = parseInt(checkParts.find(p => p.type === 'hour')?.value || '0');
    let hourDiff = checkHour - hour;
    if (hourDiff > 12)  hourDiff -= 24;   // e.g. 23 - 0 = 23  → clamp to -1 (clocks went back)
    if (hourDiff < -12) hourDiff += 24;   // e.g. 0  - 23 = -23 → clamp to +1 (clocks went forward)
    if (hourDiff !== 0) {
        return new Date(target.getTime() - hourDiff * 3600 * 1000);
    }
    return target;
}
async function auditLog(pool, adminId, action, targetId, detail = '') {
    try {
        if (adminId) {
            await pool.query(
                `INSERT INTO audit_logs (admin_id, action, target_id, detail, created_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 ON CONFLICT DO NOTHING`,
                [adminId, action, targetId, detail]
            );
        } else {
            // System-generated action — omit admin_id to avoid FK violation
            await pool.query(
                `INSERT INTO audit_logs (action, target_id, detail, created_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT DO NOTHING`,
                [action, targetId, detail]
            );
        }
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



// ── CREDIT TRANSACTION HELPER ────────────────────────────────────────────────
// Records a credit_transactions row with balance_before / balance_after.
// Call AFTER the UPDATE credits statement so the SELECT sees the new balance.
//   db          — pool or client (transaction-aware)
//   playerId    — player whose balance changed
//   amount      — signed amount (negative = spend, positive = credit)
//   type        — 'game_fee' | 'refund' | 'admin_adjustment' | …
//   description — human-readable string
//   adminId     — users.id of acting admin (null for player-initiated)
async function recordCreditTransaction(db, playerId, amount, type, description, adminId = null) {
    try {
        const balRes = await db.query(
            'SELECT balance FROM credits WHERE player_id = $1', [playerId]
        );
        const balAfter  = balRes.rows.length > 0 ? parseFloat(balRes.rows[0].balance) : 0;
        const balBefore = parseFloat((balAfter - parseFloat(amount)).toFixed(2));
        await db.query(
            `INSERT INTO credit_transactions
             (player_id, amount, type, description, admin_id, balance_before, balance_after)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [playerId, amount, type, description, adminId || null, balBefore, balAfter]
        );
    } catch (e) {
        console.error('recordCreditTransaction failed (non-critical):', e.message);
    }
}

// ── FREE-CREDIT-FIRST GAME FEE HELPER ───────────────────────────────────────
// Deducts a game fee, consuming any remaining free credits before real balance.
// Free credits were added to credits.balance at grant time so the total balance
// already includes them — we just need to classify the transaction correctly.
// Returns { realCharged } — the portion paid from real balance (for amount_paid).
async function applyGameFee(db, playerId, cost, description) {
    if (!cost || cost <= 0) return { realCharged: 0 };

    // Remaining free credits = net sum of all free_credit transactions
    const fcResult = await db.query(
        `SELECT COALESCE(SUM(amount), 0) as remaining_free
         FROM credit_transactions WHERE player_id = $1 AND type = 'free_credit'`,
        [playerId]
    );
    const remainingFree = Math.max(0, parseFloat(fcResult.rows[0].remaining_free));

    // How much of this charge is covered by free credits (pence-accurate)
    const costCents = Math.round(cost * 100);
    const freeCents = Math.min(Math.round(remainingFree * 100), costCents);
    const realCents = costCents - freeCents;
    const freeUsed    = freeCents / 100;
    const realCharged = realCents / 100;

    // Deduct full cost from balance (free credits already live in balance)
    await db.query(
        'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
        [cost, playerId]
    );

    // Record free credit consumption as a negative free_credit transaction
    if (freeUsed > 0) {
        await recordCreditTransaction(db, playerId, -freeUsed, 'free_credit',
            `${description} (free credit used)`);
    }
    // Record real balance charge
    if (realCharged > 0) {
        await recordCreditTransaction(db, playerId, -realCharged, 'game_fee', description);
    }

    return { realCharged };
}

// ── RAF (REFER A FRIEND) HELPERS ─────────────────────────────────────────────

async function getRafEnabled() {
    try {
        const r = await pool.query("SELECT value FROM system_settings WHERE key = 'raf_enabled'");
        return r.rows[0]?.value === 'true';
    } catch (e) { return false; }
}

// Trigger £1 activation bonus — called when admin tops up a referred player for the first time
async function triggerRafActivation(referredPlayerId) {
    try {
        const enabled = await getRafEnabled();
        if (!enabled) return;
        const ref = await pool.query('SELECT referred_by FROM players WHERE id = $1', [referredPlayerId]);
        if (!ref.rows[0]?.referred_by) return;
        const referrerId = ref.rows[0].referred_by;
        await pool.query(
            'INSERT INTO raf_rewards (referrer_id, referred_id) VALUES ($1,$2) ON CONFLICT (referrer_id, referred_id) DO NOTHING',
            [referrerId, referredPlayerId]
        );
        // BUG-02: Atomic activation — UPDATE only fires if activation_paid IS FALSE, preventing double-pay race condition
        const activationClaim = await pool.query(
            `UPDATE raf_rewards SET activation_paid=TRUE, activation_paid_at=NOW(), total_paid=total_paid+1.00
             WHERE referrer_id=$1 AND referred_id=$2 AND activation_paid=FALSE
             RETURNING referrer_id`,
            [referrerId, referredPlayerId]
        );
        if (activationClaim.rows.length === 0) return; // already paid — nothing to do
        await pool.query(
            'UPDATE credits SET balance = balance + 1.00, last_updated = CURRENT_TIMESTAMP WHERE player_id = $1',
            [referrerId]
        );
        await recordCreditTransaction(pool, referrerId, 1.00, 'raf_reward', `RAF activation bonus — referred player ${referredPlayerId} topped up`);
        const [refRow, rfdRow] = await Promise.all([
            pool.query('SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id=p.user_id WHERE p.id=$1', [referrerId]),
            pool.query('SELECT full_name, alias FROM players WHERE id=$1', [referredPlayerId])
        ]);
        const referrerName  = refRow.rows[0]?.alias  || refRow.rows[0]?.full_name  || 'Referrer';
        const referrerEmail = refRow.rows[0]?.email;
        const referredName  = rfdRow.rows[0]?.alias  || rfdRow.rows[0]?.full_name  || 'Your referral';
        if (referrerEmail) {
            await emailTransporter.sendMail({
                from: '"TotalFooty" <totalfooty19@gmail.com>',
                to: referrerEmail,
                subject: '💰 Refer a Friend — £1 Activation Bonus Earned!',
                html: wrapEmailHtml(`
                    <h2 style="color:#c0c0c0;font-size:22px;font-weight:900;margin:0 0 16px;">YOU'VE EARNED £1! 💰</h2>
                    <p style="color:#ccc;font-size:15px;margin:0 0 12px;"><strong style="color:#fff;">${htmlEncode(referredName)}</strong> — your referral — has just topped up their TF account.</p>
                    <p style="color:#ccc;font-size:14px;margin:0 0 24px;">Your <strong style="color:#00cc66;">£1 activation bonus</strong> has been added to your balance. You'll also earn <strong style="color:#fff;">50p for every game they sign up to</strong>, capped at £13 in game credits (26 games) — so up to <strong style="color:#00cc66;">£14 total</strong> per referral!</p>
                    <div style="background:#111;border:2px solid #333;border-radius:10px;padding:16px 20px;margin:0 0 24px;text-align:center;">
                        <div style="font-size:11px;color:#666;font-weight:700;letter-spacing:1px;margin-bottom:6px;">MAXIMUM PER REFERRAL</div>
                        <div style="font-size:30px;font-weight:900;color:#00cc66;">£14.00</div>
                        <div style="font-size:12px;color:#666;">£1 activation + 26 × 50p game credits</div>
                    </div>
                    <a href="https://totalfooty.co.uk/" style="display:block;text-align:center;padding:14px;background:#c0c0c0;color:#000;font-weight:900;border-radius:8px;text-decoration:none;font-size:15px;">VIEW MY PROFILE →</a>
                `)
            }).catch(() => {});
        }
        await notifyAdmin(`💰 RAF Activation — ${referredName} topped up`, [
            ['Referrer', referrerName], ['Referred Player', referredName],
            ['Amount Credited', '£1.00'], ['Type', 'Activation Bonus']
        ]);
    } catch (e) { console.error('triggerRafActivation error (non-critical):', e.message); }
}

// Trigger 50p game credit — called on every confirmed self-registration by a referred player
async function triggerRafGameCredit(referredPlayerId) {
    try {
        const enabled = await getRafEnabled();
        if (!enabled) return;
        const ref = await pool.query('SELECT referred_by, created_at FROM players WHERE id=$1', [referredPlayerId]);
        if (!ref.rows[0]?.referred_by) return;
        const referrerId = ref.rows[0].referred_by;
        const joinedAt   = ref.rows[0].created_at;
        const windowEnd  = new Date(joinedAt);
        windowEnd.setFullYear(windowEnd.getFullYear() + 1);
        if (new Date() > windowEnd) return; // 1-year window expired
        await pool.query(
            'INSERT INTO raf_rewards (referrer_id, referred_id) VALUES ($1,$2) ON CONFLICT (referrer_id, referred_id) DO NOTHING',
            [referrerId, referredPlayerId]
        );
        // BUG-02b: Atomic cap claim — increments counter only if not already capped, prevents race condition double-pay
        const creditClaim = await pool.query(`
            UPDATE raf_rewards
            SET game_credits_paid = game_credits_paid + 1,
                game_credits_total = game_credits_total + 0.50,
                total_paid         = total_paid + 0.50,
                cap_reached        = (game_credits_paid + 1 >= 26),
                cap_reached_at     = CASE WHEN (game_credits_paid + 1 >= 26) AND cap_reached_at IS NULL THEN NOW() ELSE cap_reached_at END
            WHERE referrer_id=$1 AND referred_id=$2
              AND cap_reached = FALSE AND game_credits_paid < 26
            RETURNING game_credits_paid AS new_count, (game_credits_paid >= 26) AS cap_reached
        `, [referrerId, referredPlayerId]);
        if (creditClaim.rows.length === 0) return; // cap already reached or row missing — nothing to do
        const newCount   = parseInt(creditClaim.rows[0].new_count);
        const capReached = creditClaim.rows[0].cap_reached;
        await pool.query(
            'UPDATE credits SET balance = balance + 0.50, last_updated = CURRENT_TIMESTAMP WHERE player_id = $1',
            [referrerId]
        );
        await recordCreditTransaction(pool, referrerId, 0.50, 'raf_reward', `RAF game credit (${newCount}/26) — referred player ${referredPlayerId}`);
        const [refRow, rfdRow] = await Promise.all([
            pool.query('SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id=p.user_id WHERE p.id=$1', [referrerId]),
            pool.query('SELECT full_name, alias FROM players WHERE id=$1', [referredPlayerId])
        ]);
        const referrerName  = refRow.rows[0]?.alias  || refRow.rows[0]?.full_name  || 'Referrer';
        const referrerEmail = refRow.rows[0]?.email;
        const referredName  = rfdRow.rows[0]?.alias  || rfdRow.rows[0]?.full_name  || 'Your referral';
        await notifyAdmin(`💰 RAF Game Credit — ${referredName} signed up (${newCount}/26)`, [
            ['Referrer', referrerName], ['Referred Player', referredName],
            ['Amount Credited', '£0.50'], ['Sign-ups Counted', `${newCount} / 26`],
            ['Cap Reached', capReached ? 'YES — £13 game credits fully earned (26 sign-ups)' : 'No']
        ]);
        if (referrerEmail && (newCount === 13 || capReached)) {
            const gameCreditsSoFar = (newCount * 0.50).toFixed(2); // 50p per sign-up
            // Fetch actual total_paid (activation may not have been paid)
            const rrActual = await pool.query(
                'SELECT total_paid, activation_paid FROM raf_rewards WHERE referrer_id=$1 AND referred_id=$2',
                [referrerId, referredPlayerId]
            );
            const actualTotal = parseFloat(rrActual.rows[0]?.total_paid || 0).toFixed(2);
            const activationWasPaid = rrActual.rows[0]?.activation_paid || false;
            await emailTransporter.sendMail({
                from: '"TotalFooty" <totalfooty19@gmail.com>',
                to: referrerEmail,
                subject: capReached
                    ? `🏆 Refer a Friend — Maximum Earned from ${referredName}!`
                    : `🎉 Refer a Friend — ${referredName} has played 13 games!`,
                html: wrapEmailHtml(capReached ? `
                    <h2 style="color:#FFD700;font-size:22px;font-weight:900;margin:0 0 16px;">MAXIMUM EARNED! 🏆</h2>
                    <p style="color:#ccc;font-size:15px;margin:0 0 12px;"><strong style="color:#fff;">${htmlEncode(referredName)}</strong> has played <strong style="color:#FFD700;">26 games</strong> — you've earned the full reward from this referral.</p>
                    <div style="background:#111;border:2px solid #FFD700;border-radius:10px;padding:20px;margin:0 0 24px;text-align:center;">
                        <div style="font-size:11px;color:#888;font-weight:700;letter-spacing:1px;margin-bottom:6px;">TOTAL EARNED FROM ${htmlEncode(referredName.toUpperCase())}</div>
                        <div style="font-size:36px;font-weight:900;color:#FFD700;">£${actualTotal}</div>
                        <div style="font-size:12px;color:#888;">${activationWasPaid ? '£1 activation + ' : ''}£13 game credits (26 × 50p)</div>
                    </div>
                    <p style="color:#ccc;font-size:14px;margin:0 0 24px;">Know anyone else? Keep referring — every friend earns you up to £14!</p>
                    <a href="https://totalfooty.co.uk/" style="display:block;text-align:center;padding:14px;background:#c0c0c0;color:#000;font-weight:900;border-radius:8px;text-decoration:none;font-size:15px;">VIEW MY REFERRALS →</a>
                ` : `
                    <h2 style="color:#c0c0c0;font-size:22px;font-weight:900;margin:0 0 16px;">🎉 HALFWAY THERE!</h2>
                    <p style="color:#ccc;font-size:15px;margin:0 0 12px;"><strong style="color:#fff;">${htmlEncode(referredName)}</strong> has now played <strong style="color:#fff;">13 games</strong>. You've earned <strong style="color:#00cc66;">£${gameCreditsSoFar}</strong> in game credits from their sign-ups so far.</p>
                    <div style="background:#111;border:2px solid #333;border-radius:10px;padding:16px 20px;margin:0 0 24px;text-align:center;">
                        <div style="font-size:11px;color:#666;font-weight:700;letter-spacing:1px;margin-bottom:6px;">STILL TO EARN</div>
                        <div style="font-size:28px;font-weight:900;color:#00cc66;">£${(13 - parseFloat(gameCreditsSoFar)).toFixed(2)}</div>
                        <div style="font-size:12px;color:#666;">${26 - newCount} more sign-ups to go</div>
                    </div>
                    <a href="https://totalfooty.co.uk/" style="display:block;text-align:center;padding:14px;background:#c0c0c0;color:#000;font-weight:900;border-radius:8px;text-decoration:none;font-size:15px;">VIEW MY PROFILE →</a>
                `)
            }).catch(() => {});
        }
    } catch (e) { console.error('triggerRafGameCredit error (non-critical):', e.message); }
}


// ── MIN RATING HELPER ────────────────────────────────────────────────────────
// Single source of truth for the effective minimum OVR at any moment.
// Visibility-only rating filter — determines which games appear on a player's list.
// A player passes if overall_rating >= minOvr OR goalkeeper_rating >= minGk.
// Registration is never blocked by this filter — shared URLs always allow sign-up.
const MIN_OVR_BY_STARS = { 1: 0, 2: 75, 3: 82, 4: 84, 5: 85 };
const MIN_GK_BY_STARS  = { 1: 0, 2:  0, 3: 82, 4: 84, 5: 86 };
function effectiveMinRating(game) {
    const stars = parseInt(game.star_rating);
    if (!stars || stars < 1) return { minOvr: 0, minGk: 0 };
    const baseOvr = MIN_OVR_BY_STARS[stars] ?? 0;
    const baseGk  = MIN_GK_BY_STARS[stars]  ?? 0;
    if (!game.min_rating_enabled) return { minOvr: baseOvr, minGk: baseGk };
    const hoursToKickoff = (new Date(game.game_date) - Date.now()) / 36e5;
    const drop = hoursToKickoff <= 24 ? 2 : hoursToKickoff <= 48 ? 1 : 0;
    const effectiveStar = Math.max(1, stars - drop);
    return {
        minOvr: MIN_OVR_BY_STARS[effectiveStar] ?? 0,
        minGk:  MIN_GK_BY_STARS[effectiveStar]  ?? 0,
    };
}
// Backwards-compatible alias used by scheduler logging — returns overall threshold only
function effectiveMinOvr(game) { return effectiveMinRating(game).minOvr; }

// ── STAR CLASS ───────────────────────────────────────────────────────────────
// starClassFromRating: maps a game's star_rating to an A–E class letter.
//   A = 5★ (top-tier)  B = 4★  C = 3★  D = 2★  E = 1★
//   Null / unknown defaults to D (assigned to all historic awards at migration).
function starClassFromRating(starRating) {
    const r = parseInt(starRating);
    if (r === 5) return 'A';
    if (r === 4) return 'B';
    if (r === 3) return 'C';
    if (r === 2) return 'D';
    if (r === 1) return 'E';
    return 'D';
}

// ── DYNAMIC STAR RATINGS ─────────────────────────────────────────────────────
// reviewDynamicStarRating: recalculate star_rating for a game based on avg OVR.
// Rules:
//   - Only runs if star_rating_locked = FALSE (games originally created at 4★ or 5★ are locked)
//   - Only runs once ≥ 8 confirmed players are signed up
//   - avg OVR < 85  → 1★ | 85–<86 → 2★ | 86–<87 → 3★ | ≥87 → 4★
//   - Called non-critically (never throws to caller)
async function reviewDynamicStarRating(pool, gameId) {
    try {
        const gameRow = await pool.query(
            `SELECT star_rating, star_rating_locked FROM games WHERE id = $1`,
            [gameId]
        );
        if (!gameRow.rows.length) return;

        const { star_rating_locked } = gameRow.rows[0];
        if (star_rating_locked) return; // 4★ / 5★ at creation — never touch

        // Count confirmed players + guests
        const countRow = await pool.query(
            `SELECT (SELECT COUNT(*) FROM registrations WHERE game_id = $1 AND status = 'confirmed')
                  + (SELECT COUNT(*) FROM game_guests WHERE game_id = $1) AS total`,
            [gameId]
        );
        const total = parseInt(countRow.rows[0].total) || 0;
        if (total < 8) return; // Minimum 8 players before dynamic rating kicks in

        // Avg OVR of confirmed registered players (guests have no OVR, so we exclude them)
        const ovrRow = await pool.query(
            `SELECT ROUND(AVG(p.overall_rating)::numeric, 2) AS avg_ovr
             FROM registrations r
             JOIN players p ON p.id = r.player_id
             WHERE r.game_id = $1 AND r.status = 'confirmed' AND p.overall_rating IS NOT NULL`,
            [gameId]
        );
        const avgOvr = parseFloat(ovrRow.rows[0]?.avg_ovr);
        if (isNaN(avgOvr)) return; // No OVR data — leave rating unchanged

        // Map avg OVR → star rating
        let newStars;
        if (avgOvr < 85)      newStars = 1;
        else if (avgOvr < 86) newStars = 2;
        else if (avgOvr < 87) newStars = 3;
        else                   newStars = 4;

        // Only write if changed
        const currentStars = parseInt(gameRow.rows[0].star_rating) || 0;
        if (newStars !== currentStars) {
            await pool.query(
                `UPDATE games SET star_rating = $1 WHERE id = $2`,
                [newStars, gameId]
            );
            await gameAuditLog(pool, gameId, null, 'star_rating_auto_updated',
                `Dynamic review: avg OVR ${avgOvr.toFixed(2)} → ${newStars}★ (was ${currentStars}★, players: ${total})`);
        }
    } catch (e) {
        console.warn(`reviewDynamicStarRating failed for game ${gameId} (non-critical):`, e.message);
    }
}

// ── PUSH NOTIFICATIONS ───────────────────────────────────────────────────────

// sendTeamsConfirmedEmails: notify all confirmed players of their team assignment
async function sendTeamsConfirmedEmails(gameId) {
    try {
        // Fetch game info
        const gRow = await pool.query(`
            SELECT g.game_date, g.game_url, g.format,
                   v.name AS venue_name
            FROM games g LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1`, [gameId]);
        if (!gRow.rows.length) return;
        const g = gRow.rows[0];
        const d = new Date(g.game_date);
        const day    = d.toLocaleDateString('en-GB',  { weekday:'long', day:'numeric', month:'long', timeZone:'Europe/London' });
        const time   = d.toLocaleTimeString('en-GB',  { hour:'2-digit', minute:'2-digit', timeZone:'Europe/London' });
        const venue  = g.venue_name || 'TBC';
        const gameLink = `https://totalfooty.co.uk/game.html?url=${g.game_url}`;

        // Fetch each player with their team colour + email
        const players = await pool.query(`
            SELECT p.alias, p.full_name, u.email, t.team_name
            FROM team_players tp
            JOIN teams t ON t.id = tp.team_id
            JOIN players p ON p.id = tp.player_id
            JOIN users u ON u.id = p.user_id
            WHERE t.game_id = $1
            ORDER BY t.team_name`, [gameId]);

        for (const player of players.rows) {
            const name      = player.alias || player.full_name;
            const teamName  = player.team_name || 'TBC';
            const isRed     = teamName.toLowerCase() === 'red';
            const teamColor = isRed ? '#ff3366' : '#4488ff';
            const teamLabel = isRed ? '🔴 RED TEAM' : '🔵 BLUE TEAM';

            await emailTransporter.sendMail({
                from: '"TotalFooty" <totalfooty19@gmail.com>',
                to:   player.email,
                subject: `🏟️ Teams are live — you're ${isRed ? 'Red' : 'Blue'} | TotalFooty`,
                html: wrapEmailHtml(`
                    <h2 style="color:#fff;font-size:22px;font-weight:900;margin:0 0 6px;">TEAMS ARE LIVE!</h2>
                    <p style="color:#888;font-size:14px;margin:0 0 20px;">The squads are set for your upcoming game. Here's where you stand:</p>
                    <div style="background:#111;border:2px solid ${teamColor};border-radius:10px;padding:16px 20px;margin:0 0 20px;text-align:center;">
                        <div style="font-size:11px;color:#666;font-weight:700;letter-spacing:1px;margin-bottom:6px;">YOUR TEAM</div>
                        <div style="font-size:26px;font-weight:900;color:${teamColor};">${teamLabel}</div>
                    </div>
                    <table style="width:100%;border-collapse:collapse;font-size:14px;margin:0 0 24px;">
                        <tr><td style="padding:6px 0;color:#888;width:100px;">Date</td><td style="font-weight:700;color:#fff;">${htmlEncode(day)}</td></tr>
                        <tr><td style="padding:6px 0;color:#888;">Time</td><td style="font-weight:700;color:#fff;">${htmlEncode(time)}</td></tr>
                        <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:700;color:#fff;">${htmlEncode(venue)}</td></tr>
                    </table>
                    <a href="${gameLink}" style="display:block;text-align:center;padding:14px;background:${teamColor};color:#fff;font-weight:900;border-radius:8px;text-decoration:none;font-size:15px;letter-spacing:1px;">VIEW GAME PAGE →</a>
                `)
            }).catch(e => console.error(`Teams email failed for ${player.email}:`, e.message));
        }
        console.log(`📧 Teams confirmed emails sent for game ${gameId} (${players.rows.length} players)`);
    } catch (e) {
        console.error('sendTeamsConfirmedEmails error (non-critical):', e.message);
    }
}

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
    // Referee system
    referee_confirmed: d => ({ title: "You're confirmed to ref! 👮", body: `You're officiating on ${d.day} at ${d.venue}.` }),
    ref_review_open:   d => ({ title: 'Rate the referee 🌟',       body: `How was the ref on ${d.day}? Leave your rating.` }),
    account_reinstated: _d => ({ title: 'Account Reinstated ✅',   body: 'Your account has been reinstated. Welcome back.' }),
    new_dm:            d => ({ title: 'New message 💬',            body: d.preview || 'You have a new message.' }),
    // TF Game Awards
    award_motm:           d => ({ title: '⭐ Man of the Match!',          body: `You won MOTM for ${d.day} at ${d.venue}!` }),
    award_engine:         d => ({ title: '🔋 Best Engine!',               body: `Voted Best Engine for ${d.day} at ${d.venue}.` }),
    award_wall:           d => ({ title: '🧱 Brick Wall!',                body: `Voted Brick Wall for ${d.day} at ${d.venue}.` }),
    award_reckless:       d => ({ title: '🦵 Reckless Tackler',           body: `You won Reckless Tackler for ${d.day}. You know what you did.` }),
    award_hollywood:      d => ({ title: '🎬 Mr Hollywood',               body: `You won Mr Hollywood for ${d.day}. No end product, as always.` }),
    award_moaner:         d => ({ title: '😩 The Moaner',                 body: `You won The Moaner for ${d.day}. The team appreciated your encouragement.` }),
    award_howler:         d => ({ title: '🤦 Howler Award',               body: `You won The Howler for ${d.day}. Moment of the match, for the wrong reasons.` }),
    award_donkey:         d => ({ title: '🐴 Donkey Award',               body: `You won the Donkey Award for ${d.day}. Below par — even for yourself.` }),
    award_mr_day:         d => ({ title: `📅 Mr ${d.day}!`,              body: `7 consecutive ${d.day} appearances in a row. Legendary consistency.` }),
    award_on_fire:        d => ({ title: "🔥 You're On Fire!",           body: `4 wins in a row. Your team can't stop winning right now.` }),
    award_back_from_dead: d => ({ title: "🧟 Back from the Dead!",        body: `Welcome back! You've been away for a while. Good to have you back.` }),
    award_engine_badge:   _d => ({ title: '🔋 Engine Badge Earned!',      body: '5 Best Engine awards — the Engine Badge is now on your profile.' }),
    award_wall_badge:     _d => ({ title: '🧱 Brick Wall Badge Earned!',  body: '5 Brick Wall awards — the Brick Wall Badge is now on your profile.' }),
    award_donkey_badge:   _d => ({ title: '🐴 Donkey Badge Earned!',      body: '5 Donkey Awards — the Donkey Badge is now on your profile. A bad smell that won\'t go away.' }),
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

// Rate limit DM reports — max 5 per hour per player
const dmReportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many reports submitted. Please wait before reporting again.' },
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

// Rate limit Wonderful payment initiation — max 5 per player per 10 minutes
const wonderfulInitiateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    message: { error: 'Too many payment requests. Please wait a few minutes.' },
    keyGenerator: (req) => req.user?.playerId || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limit game chat — prevents flood/spam (20 messages per minute per player)
const gameChatLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'You are posting too fast. Please slow down.' },
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
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const WONDERFUL_API_KEY = process.env.WONDERFUL_API_KEY; // Wonderful open-banking payments
if (!SUPERADMIN_EMAIL)    console.warn('WARNING: SUPERADMIN_EMAIL not set — auto-assign disabled');
if (!WONDERFUL_API_KEY)   console.warn('WARNING: WONDERFUL_API_KEY not set — Wonderful payments disabled');

// ==========================================
// MIDDLEWARE
// ==========================================

const authenticateToken = async (req, res, next) => {
    // CRIT-2: Read JWT from httpOnly cookie — not Authorization header
    const token = req.cookies?.tf_token;
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) return res.status(401).json({ error: 'Session expired. Please log in again.' });
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
        const { fullName, alias, email, password, phone, ref, skillLevel, roleParam, ageRange, region, interests } = req.body;

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

        // SEC: skill_level must be one of four exact values or absent entirely
        const VALID_SKILL_LEVELS = ['beginner', 'casual', 'average', 'decent'];
        const validatedSkillLevel = (skillLevel && VALID_SKILL_LEVELS.includes(skillLevel))
            ? skillLevel
            : null;

        const SKILL_STAT_MAP = {
            beginner: { gk: 84, def: 12, str: 12, fit: 12, pac: 12, dec: 11, ast: 10, sht: 10, overall: 79 },
            casual:   { gk: 86, def: 12, str: 12, fit: 12, pac: 12, dec: 12, ast: 12, sht: 12, overall: 84 },
            average:  { gk: 87, def: 13, str: 12, fit: 13, pac: 12, dec: 12, ast: 12, sht: 12, overall: 86 },
            decent:   { gk: 88, def: 12, str: 12, fit: 13, pac: 12, dec: 13, ast: 13, sht: 13, overall: 88 },
        };
        // Skipped = casual. Same overall (84), same GK (86). skill_level stored as null.
        const stats = SKILL_STAT_MAP[validatedSkillLevel] || SKILL_STAT_MAP.casual;

        // Validate age range — required for insurance purposes
        // Validate region
        const VALID_REGIONS = ['Coventry', 'Birmingham', 'Leamington', 'Nuneaton', 'Manchester'];
        const validatedRegion = (region && VALID_REGIONS.includes(region)) ? region : null;

        // Validate interests
        const VALID_INTERESTS = ['playing', 'reffing', 'coaching'];
        const validatedInterests = Array.isArray(interests)
            ? interests.filter(i => VALID_INTERESTS.includes(i))
            : [];

        const VALID_AGE_RANGES = ['16_18', '18_plus'];
        if (!ageRange || ageRange === 'under_16') {
            return res.status(400).json({ error: 'You must be at least 16 years old to register with TotalFooty.' });
        }
        if (!VALID_AGE_RANGES.includes(ageRange)) {
            return res.status(400).json({ error: 'Invalid age range.' });
        }

        // Check if email already exists
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

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

        // Create player with skill-level-seeded stats. New players start on gold tier.
        const playerResult = await pool.query(
            `INSERT INTO players (user_id, full_name, first_name, last_name, alias, phone, position, reliability_tier,
                goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
                pace_rating, decisions_rating, assisting_rating, shooting_rating, overall_rating,
                skill_level, age_range, region_code, coachable)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'gold',
                     $8,  $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) RETURNING id`,
            [
                userId,               // $1
                fullName.trim(),      // $2
                firstName,            // $3
                lastName,             // $4
                playerAlias,          // $5
                phone.trim(),         // $6
                'outfield',           // $7
                stats.gk,             // $8  goalkeeper_rating
                stats.def,            // $9  defending_rating
                stats.str,            // $10 strength_rating
                stats.fit,            // $11 fitness_rating
                stats.pac,            // $12 pace_rating
                stats.dec,            // $13 decisions_rating
                stats.ast,            // $14 assisting_rating
                stats.sht,            // $15 shooting_rating
                stats.overall,        // $16 overall_rating
                validatedSkillLevel,  // $17 skill_level (null if skipped)
                ageRange,             // $18 age_range
                validatedRegion,      // $19 region_code (null if not selected)
                validatedInterests.includes('coaching')  // $20 coachable
            ]
        );
        const playerId = playerResult.rows[0].id;

        // Create credits record
        await pool.query('INSERT INTO credits (player_id, balance) VALUES ($1, 0.00)', [playerId]);

        // Auto-assign Youth badge for 16-18 players (non-public, for insurance tracking)
        if (ageRange === '16_18') {
            try {
                const youthBadge = await pool.query("SELECT id FROM badges WHERE name = 'Youth'");
                if (youthBadge.rows.length > 0) {
                    await pool.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [playerId, youthBadge.rows[0].id]
                    );
                    setImmediate(() => auditLog(pool, null, 'badge_auto_awarded', playerId,
                        'badge: Youth (age 16-18 at registration)'));
                }
            } catch (youthErr) {
                console.error('Youth badge assign (non-critical):', youthErr.message);
            }
        }

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
        
        // Auto-assign player_number — region-prefixed for Birmingham (B) and Manchester (M)
        try {
            const regionPrefix = validatedRegion === 'Birmingham' ? 'B'
                               : validatedRegion === 'Manchester' ? 'M'
                               : null;
            if (regionPrefix) {
                // Region-prefixed IDs: stored as text e.g. 'B1000'
                const maxRes = await pool.query(
                    `SELECT COALESCE(MAX(CAST(SUBSTRING(player_number_text, 2) AS INTEGER)), 999) as max_num
                     FROM players WHERE player_number_text LIKE $1`,
                    [regionPrefix + '%']
                );
                const newNum = parseInt(maxRes.rows[0].max_num) + 1;
                await pool.query(
                    'UPDATE players SET player_number_text = $1 WHERE id = $2',
                    [regionPrefix + newNum, playerId]
                );
            } else {
                // Standard numeric player_number
                const maxNumResult = await pool.query(
                    'SELECT COALESCE(MAX(player_number), 999) as max_num FROM players WHERE player_number >= 1000'
                );
                const newPlayerNumber = parseInt(maxNumResult.rows[0].max_num) + 1;
                await pool.query('UPDATE players SET player_number = $1 WHERE id = $2', [newPlayerNumber, playerId]);
            }
        } catch (pnErr) {
            console.error('Player number assign (non-critical):', pnErr.message);
        }

        // Grant Referee badge if user expressed interest in reffing during signup
        if (validatedInterests.includes('reffing')) {
            try {
                const refBadge = await pool.query("SELECT id FROM badges WHERE name = 'Referee'");
                if (refBadge.rows.length > 0) {
                    await pool.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [playerId, refBadge.rows[0].id]
                    );
                    await auditLog(pool, null, 'badge_auto_awarded', playerId,
                        'badge: Referee (expressed interest at signup)');
                }
            } catch (refInterestErr) {
                console.error('Referee badge (interest, non-critical):', refInterestErr.message);
            }
        }

        // Handle ?referee_invite=CODE — one-time invite that grants Referee badge
        const referee_invite = req.body.referee_invite;
        if (referee_invite) {
            try {
                const inviteResult = await pool.query(
                    `SELECT id FROM referee_invites
                     WHERE code = $1 AND used_at IS NULL AND expires_at > NOW()`,
                    [referee_invite.toUpperCase()]
                );
                if (inviteResult.rows.length > 0) {
                    const refBadge = await pool.query("SELECT id FROM badges WHERE name = 'Referee'");
                    if (refBadge.rows.length > 0) {
                        await pool.query(
                            'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                            [playerId, refBadge.rows[0].id]
                        );
                        await auditLog(pool, null, 'badge_auto_awarded', playerId,
                            `badge: Referee (via invite ${referee_invite})`);
                    }
                    await pool.query(
                        `UPDATE referee_invites SET used_by = $1, used_at = NOW() WHERE id = $2`,
                        [playerId, inviteResult.rows[0].id]
                    );
                    // Notify superadmin
                    setImmediate(async () => {
                        try {
                            const adminEmail = SUPERADMIN_EMAIL || 'totalfooty19@gmail.com';
                            const pName = alias || fullName;
                            await emailTransporter.sendMail({
                                from: '"TotalFooty" <totalfooty19@gmail.com>',
                                to: adminEmail,
                                subject: `👮 Referee Joined via Invite — ${pName.replace(/[\r\n]/g, '')}`,
                                html: wrapEmailHtml(`
                                    <p style="font-weight:700;font-size:16px;">New Referee Registration</p>
                                    <table style="width:100%;border-collapse:collapse;">
                                        <tr><td style="padding:6px 0;color:#888;width:120px;">Name</td>
                                            <td style="font-weight:700;color:#fff;">${htmlEncode(pName)}</td></tr>
                                        <tr><td style="padding:6px 0;color:#888;">Email</td>
                                            <td style="font-weight:700;color:#fff;">${htmlEncode(email)}</td></tr>
                                        <tr><td style="padding:6px 0;color:#888;">Invite code</td>
                                            <td style="font-weight:700;color:#fff;">${htmlEncode(referee_invite)}</td></tr>
                                    </table>`)
                            });
                        } catch (e) {
                            console.error('Referee invite email failed:', e.message);
                        }
                    });
                }
                // Invalid/expired: silently proceed — never block registration
            } catch (inviteErr) {
                console.error('Referee invite processing (non-critical):', inviteErr.message);
            }
        }

        // Handle ?role=referee — grants Referee badge to new user, no referral chain
        if (roleParam === 'referee') {
            try {
                const refBadge = await pool.query("SELECT id FROM badges WHERE name = 'Referee'");
                if (refBadge.rows.length > 0) {
                    await pool.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [playerId, refBadge.rows[0].id]
                    );
                    setImmediate(() => auditLog(pool, null, 'badge_auto_awarded', playerId,
                        'badge: Referee (via referee referral link)'));
                }
            } catch (roleErr) {
                console.error('Referee badge assign error (non-critical):', roleErr.message);
            }
        }

        // Handle referral: look up referrer by code
        // N6: ref=clm and ref=misfits badge auto-assignment REMOVED — exclusive badges must be admin-granted only.
        // Any user who reads the source could self-assign restricted badges via ?ref=clm on the register URL.
        if (ref) {
            try {
                if (ref.toLowerCase() === 'clm' || ref.toLowerCase() === 'misfits') {
                    // Silently ignore — no longer auto-assigns badges from URL param
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
                        } else {
                            // FIX-065: Block circular chain (referrer was referred by this new player)
                            const circularCheck = await pool.query('SELECT referred_by FROM players WHERE id = $1', [referrerId]);
                            if (circularCheck.rows[0]?.referred_by === playerId) {
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
            // Change E: seed stat history baseline for new player
            try {
                await statHistory(pool, playerId, null, {
                    overall:    stats.overall,
                    defending:  stats.def,
                    strength:   stats.str,
                    fitness:    stats.fit,
                    pace:       stats.pac,
                    decisions:  stats.dec,
                    assisting:  stats.ast,
                    shooting:   stats.sht,
                    goalkeeper: stats.gk
                }, 'gold');
            } catch (e) { /* statHistory is non-critical, has internal try/catch */ }
            try {
                await auditLog(pool, playerId, 'player_created', playerId, `email:${email} name:${fullName} skill:${validatedSkillLevel || 'not_set'} ovr:${stats.overall}`);
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
                            ${validatedSkillLevel ? `<tr><td style="padding:6px 0;color:#888;">Skill Level</td><td style="font-weight:900;">${htmlEncode(validatedSkillLevel)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Starting OVR</td><td>${stats.overall}</td></tr>` : ''}
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

        const userResult = await pool.query(
            'SELECT id, email, password_hash, role, token_version, force_password_change FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
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

        // LOGIN-SLIM: Only fetch fields needed to boot the session and build navigation.
        // Full player data (stats, credits, ratings, photo etc.) is fetched by loadDashboard
        // via /api/players/me immediately after — no need to duplicate it here.
        // This keeps the login response tiny (~300 bytes) so it passes through Cloudflare instantly.
        const playerResult = await pool.query(
            `SELECT p.id, p.full_name, p.alias, p.is_clm_admin, p.is_organiser, u.token_version,
             (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
              FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges
             FROM players p
             LEFT JOIN users u ON u.id = p.user_id
             WHERE p.user_id = $1`,
            [user.id]
        );

        const player = playerResult.rows[0];

        if (!player) {
            console.error(`Login error: no player record found for user ${user.id} (${email})`);
            return res.status(401).json({ error: 'Account setup incomplete. Please contact support.' });
        }

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
            sameSite: 'lax',   // 'none' blocked by Samsung/DuckDuckGo/Firefox strict.
                               // 'lax' works because api.totalfooty.co.uk is same-site as totalfooty.co.uk
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
        });

        // LOGIN-SLIM: Minimal response — just enough to boot the session.
        // loadDashboard fetches full player data via /api/players/me immediately after.
        res.json({
            mustChangePassword: user.force_password_change === true,
            user: {
                id: player.id,
                userId: user.id,
                email: user.email,
                fullName: player.full_name,
                alias: player.alias,
                role: user.role,
                isCLMAdmin: player.is_clm_admin || false,
                isOrganiser: player.is_organiser || false,
                badges: player.badges || []
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
app.post('/api/auth/logout', optionalAuth, async (req, res) => {
    const playerId = req.user?.playerId || null;
    res.clearCookie('tf_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
    });
    if (playerId) {
        setImmediate(() => auditLog(pool, playerId, 'logout', playerId, 'Player logged out'));
    }
    res.json({ message: 'Logged out' });
});

// Get current user info (for game.html auth check)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const playerResult = await pool.query(
            `SELECT p.id, p.full_name, p.alias, p.squad_number, p.referral_code, u.role,
             COALESCE(p.is_clm_admin, false) as is_clm_admin,
             COALESCE(p.is_organiser, false) as is_organiser,
             u.force_password_change
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
            isOrganiser: player.is_organiser || false,
            mustChangePassword: player.force_password_change === true
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
                    (SELECT COUNT(*) FROM registrations
                     WHERE player_id = p.id AND status = 'confirmed')::int AS confirmed_registration_count,
                    p.is_clm_admin,
                    p.is_organiser,
                    p.referred_by,
                    c.balance as credits,
                    COALESCE((SELECT SUM(amount) FROM credit_transactions WHERE player_id = p.id AND type = 'free_credit'), 0) as free_credits,
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
                     WHERE r3.player_id = p.id AND r3.status = 'confirmed'
                       AND g3.game_status = 'completed'
                       AND g3.team_selection_type = 'vs_external'
                       AND g3.winning_team = 'red')::int AS external_game_wins
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
                    0 AS external_game_wins
                FROM registrations r
                JOIN games g ON g.id = r.game_id
                JOIN team_players tp ON tp.player_id = r.player_id
                JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                WHERE r.status = 'confirmed' AND g.game_status = 'completed'
                  AND LOWER(g.winning_team) = LOWER(t.team_name)
                  AND g.team_selection_type != 'vs_external'
                GROUP BY r.player_id
            )
            SELECT 
                p.id, p.full_name, p.alias, p.squad_number, p.player_number, p.photo_url, 
                p.reliability_tier, p.total_appearances, p.motm_wins, p.total_wins,
                p.phone, u.email,
                p.is_clm_admin, p.is_organiser,
                c.balance as credits,
                p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                p.goalkeeper_rating,
                COALESCE(p.is_featured, false) AS is_featured,
                COALESCE(p.is_external_ref, false) AS is_external_ref,
                p.social_tiktok, p.social_instagram, p.social_youtube, p.social_facebook,
                COALESCE(p.position, 'outfield') AS position,
                p.referral_code,
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
                p.id, p.full_name, p.alias, p.squad_number, p.player_number, p.photo_url, 
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

                -- FREE CREDITS: all time
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'free_credit'), 0) as free_credits,

                -- FREE CREDITS: last 3 months
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'free_credit'
                 AND ct.created_at >= NOW() - INTERVAL '3 months'), 0) as free_credits_3m,

                -- FREE CREDITS: calendar year
                COALESCE((SELECT SUM(ct.amount) FROM credit_transactions ct
                 WHERE ct.player_id = p.id AND ct.type = 'free_credit'
                 AND ct.created_at >= DATE_TRUNC('year', NOW())), 0) as free_credits_year,

                -- FEATURED PROFILE & SOCIALS
                COALESCE(p.is_featured, false) as is_featured,
                p.social_tiktok,
                p.social_instagram,
                p.social_youtube,
                p.social_facebook,
                COALESCE(p.position, 'outfield') as position,

                -- DISCIPLINE: all-time total points
                COALESCE((
                    SELECT SUM(dr.points) FROM discipline_records dr WHERE dr.player_id = p.id
                ), 0) as disc_points_total,

                -- DISCIPLINE: revolving — last 10 completed games + all manual (admin) entries
                COALESCE((
                    SELECT SUM(dr.points)
                    FROM discipline_records dr
                    WHERE dr.player_id = p.id
                    AND (dr.game_id IS NULL OR dr.game_id IN (
                        SELECT r.game_id FROM registrations r
                        JOIN games g2 ON g2.id = r.game_id
                        WHERE r.player_id = p.id AND r.status = 'confirmed'
                        AND g2.game_status = 'completed'
                        ORDER BY g2.game_date DESC LIMIT 10
                    ))
                ), 0) as disc_points_revolving,

                -- DISCIPLINE: most recent offense type
                (SELECT dr.offense_type FROM discipline_records dr
                 WHERE dr.player_id = p.id AND dr.game_id IS NOT NULL
                 ORDER BY dr.id DESC LIMIT 1) as last_offense

            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.squad_number NULLS LAST, p.full_name
            LIMIT 1500
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

// GET /api/players/:playerId/ref-stats — referee profile stats (authenticated)
// BUG-05: was unauthenticated — any caller could enumerate referee PII by player ID
app.get('/api/players/:playerId/ref-stats', authenticateToken, async (req, res) => {
    const { playerId } = req.params;
    try {
        // Total confirmed ref appearances
        const apps = await pool.query(
            `SELECT COUNT(*) AS appearances
             FROM game_referees WHERE player_id = $1 AND status = 'confirmed'`,
            [playerId]
        );

        // All-time average across all games
        const allTime = await pool.query(
            `SELECT ROUND(AVG(rating), 1) AS avg_rating, COUNT(*) AS total_reviews
             FROM referee_reviews WHERE referee_player_id = $1`,
            [playerId]
        );

        // Last 5 game averages (one avg per game, then average those)
        const last5 = await pool.query(
            `SELECT ROUND(AVG(avg_per_game), 1) AS last5_avg
             FROM (
                 SELECT game_id, AVG(rating) AS avg_per_game
                 FROM referee_reviews
                 WHERE referee_player_id = $1
                 GROUP BY game_id
                 ORDER BY MAX(created_at) DESC
                 LIMIT 5
             ) sub`,
            [playerId]
        );

        res.json({
            appearances:   parseInt(apps.rows[0].appearances),
            avg_rating:    allTime.rows[0].avg_rating,
            total_reviews: parseInt(allTime.rows[0].total_reviews),
            last5_avg:     last5.rows[0].last5_avg
        });
    } catch (error) {
        console.error('Ref stats error:', error);
        res.status(500).json({ error: 'Failed to fetch referee stats' });
    }
});


// Must be defined before /api/players/:id to avoid route collision
app.get('/api/players/superadmin-id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.id FROM players p JOIN users u ON u.id = p.user_id WHERE u.role = 'superadmin' LIMIT 1`
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        res.json({ id: result.rows[0].id });
    } catch (err) {
        console.error('superadmin-id error:', err);
        res.status(500).json({ error: 'Server error' });
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
                AND (dr.game_id IS NULL OR dr.game_id IN (
                    SELECT r.game_id FROM registrations r
                    JOIN games g2 ON g2.id = r.game_id
                    WHERE r.player_id = p.id AND r.status = 'confirmed'
                    AND g2.game_status = 'completed'
                    ORDER BY g2.game_date DESC LIMIT 10
                ))
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
            WHERE r.player_id = $1 AND r.status = 'confirmed'
              AND g.game_status = 'completed' AND g.team_selection_type = 'vs_external'
              AND g.winning_team = 'red'
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
                ai_bio:           player.ai_bio || null,
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

            // N5 removed — password not required to change email; session auth is sufficient
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
        
        setImmediate(() => auditLog(pool, req.user.playerId, 'photo_uploaded', req.user.playerId, 'Player updated profile photo'));
        res.json({ message: 'Photo uploaded successfully' });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});


// ══════════════════════════════════════════════════════════════
// POST /api/players/me/coach-document
// Upload coaching license/certificate (base64) — stores in players.coach_license_doc
// ══════════════════════════════════════════════════════════════
app.post('/api/players/me/coach-document',
    authenticateToken,
    express.json({ limit: '5mb' }),
async (req, res) => {
    const { docData } = req.body;
    if (!docData) return res.status(400).json({ error: 'No document data provided' });
    if (docData.length > 3_000_000) return res.status(400).json({ error: 'Document too large. Max ~2MB.' });

    const DOC_PREFIXES = {
        'data:application/pdf;base64,':  { magic: [0x25, 0x50, 0x44, 0x46], label: 'PDF'  },
        'data:image/jpeg;base64,':       { magic: [0xFF, 0xD8, 0xFF],        label: 'JPEG' },
        'data:image/png;base64,':        { magic: [0x89, 0x50, 0x4E, 0x47],  label: 'PNG'  },
    };
    const matchedPrefix = Object.keys(DOC_PREFIXES).find(p => docData.startsWith(p));
    if (!matchedPrefix) return res.status(400).json({ error: 'Invalid format. PDF, JPEG or PNG only.' });

    const b64Data   = docData.slice(matchedPrefix.length);
    const rawBytes  = Buffer.from(b64Data, 'base64');
    const expected  = DOC_PREFIXES[matchedPrefix].magic;
    const actual    = [...rawBytes.slice(0, expected.length)];
    if (!expected.every((byte, i) => actual[i] === byte))
        return res.status(400).json({ error: 'File contents do not match declared type.' });

    try {
        await pool.query('UPDATE players SET coach_license_doc = $1 WHERE id = $2',
            [docData, req.user.playerId]);
        res.json({ success: true });
    } catch (e) {
        console.error('Coach document upload error:', e.message);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Superadmin: upload coach document for a specific player
app.post('/api/admin/players/:id/coach-document',
    authenticateToken, requireSuperAdmin,
    express.json({ limit: '5mb' }),
async (req, res) => {
    const { id } = req.params;
    const { docData } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid player ID' });
    if (!docData) return res.status(400).json({ error: 'No document data provided' });
    if (docData.length > 3_000_000) return res.status(400).json({ error: 'Document too large. Max ~2MB.' });

    const DOC_PREFIXES = {
        'data:application/pdf;base64,':  { magic: [0x25, 0x50, 0x44, 0x46] },
        'data:image/jpeg;base64,':       { magic: [0xFF, 0xD8, 0xFF]        },
        'data:image/png;base64,':        { magic: [0x89, 0x50, 0x4E, 0x47] },
    };
    const matchedPrefix = Object.keys(DOC_PREFIXES).find(p => docData.startsWith(p));
    if (!matchedPrefix) return res.status(400).json({ error: 'Invalid format. PDF, JPEG or PNG only.' });

    const b64     = docData.slice(matchedPrefix.length);
    const raw     = Buffer.from(b64, 'base64');
    const exp     = DOC_PREFIXES[matchedPrefix].magic;
    if (!exp.every((byte, i) => raw[i] === byte))
        return res.status(400).json({ error: 'File contents do not match declared type.' });

    try {
        await pool.query('UPDATE players SET coach_license_doc = $1 WHERE id = $2', [docData, id]);
        res.json({ success: true });
    } catch (e) {
        console.error('Admin coach document upload error:', e.message);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// ══════════════════════════════════════════════════════════════
// POST /api/players/me/ref-document
// Upload referee certification (base64) — stores in players.ref_license_doc
// ══════════════════════════════════════════════════════════════
app.post('/api/players/me/ref-document',
    authenticateToken,
    express.json({ limit: '5mb' }),
async (req, res) => {
    const { docData } = req.body;
    if (!docData) return res.status(400).json({ error: 'No document data provided' });
    if (docData.length > 3_000_000) return res.status(400).json({ error: 'Document too large. Max ~2MB.' });

    const DOC_PREFIXES = {
        'data:application/pdf;base64,':  { magic: [0x25, 0x50, 0x44, 0x46] },
        'data:image/jpeg;base64,':       { magic: [0xFF, 0xD8, 0xFF]        },
        'data:image/png;base64,':        { magic: [0x89, 0x50, 0x4E, 0x47] },
    };
    const matchedPrefix = Object.keys(DOC_PREFIXES).find(p => docData.startsWith(p));
    if (!matchedPrefix) return res.status(400).json({ error: 'Invalid format. PDF, JPEG or PNG only.' });

    const b64     = docData.slice(matchedPrefix.length);
    const raw     = Buffer.from(b64, 'base64');
    const exp     = DOC_PREFIXES[matchedPrefix].magic;
    if (!exp.every((byte, i) => raw[i] === byte))
        return res.status(400).json({ error: 'File contents do not match declared type.' });

    try {
        await pool.query('UPDATE players SET ref_license_doc = $1 WHERE id = $2',
            [docData, req.user.playerId]);
        res.json({ success: true });
    } catch (e) {
        console.error('Ref document upload error:', e.message);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Superadmin: upload ref document for a specific player
app.post('/api/admin/players/:id/ref-document',
    authenticateToken, requireSuperAdmin,
    express.json({ limit: '5mb' }),
async (req, res) => {
    const { id } = req.params;
    const { docData } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid player ID' });
    if (!docData) return res.status(400).json({ error: 'No document data provided' });
    if (docData.length > 3_000_000) return res.status(400).json({ error: 'Document too large. Max ~2MB.' });

    const DOC_PREFIXES = {
        'data:application/pdf;base64,':  { magic: [0x25, 0x50, 0x44, 0x46] },
        'data:image/jpeg;base64,':       { magic: [0xFF, 0xD8, 0xFF]        },
        'data:image/png;base64,':        { magic: [0x89, 0x50, 0x4E, 0x47] },
    };
    const matchedPrefix = Object.keys(DOC_PREFIXES).find(p => docData.startsWith(p));
    if (!matchedPrefix) return res.status(400).json({ error: 'Invalid format. PDF, JPEG or PNG only.' });

    const b64     = docData.slice(matchedPrefix.length);
    const raw     = Buffer.from(b64, 'base64');
    const exp     = DOC_PREFIXES[matchedPrefix].magic;
    if (!exp.every((byte, i) => raw[i] === byte))
        return res.status(400).json({ error: 'File contents do not match declared type.' });

    try {
        await pool.query('UPDATE players SET ref_license_doc = $1 WHERE id = $2', [docData, id]);
        res.json({ success: true });
    } catch (e) {
        console.error('Admin ref document upload error:', e.message);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.put('/api/admin/players/:id/stats', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { overall, defending, strength, fitness, pace, decisions, assisting, shooting, goalkeeper } = req.body;

        // Capture before state for audit diff
        const beforeRow = await pool.query(
            `SELECT overall_rating, defending_rating, strength_rating, fitness_rating,
                    pace_rating, decisions_rating, assisting_rating, shooting_rating, goalkeeper_rating
             FROM players WHERE id = $1`, [req.params.id]
        );
        const b = beforeRow.rows[0] || {};

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
            // Include before→after in detail so player audit can render the diff
            const detail = [
                `OVR:${b.overall_rating ?? '?'}→${overall}`,
                `DEF:${b.defending_rating ?? '?'}→${defending}`,
                `STR:${b.strength_rating ?? '?'}→${strength}`,
                `FIT:${b.fitness_rating ?? '?'}→${fitness}`,
                `PAC:${b.pace_rating ?? '?'}→${pace}`,
                `DEC:${b.decisions_rating ?? '?'}→${decisions}`,
                `AST:${b.assisting_rating ?? '?'}→${assisting}`,
                `SHT:${b.shooting_rating ?? '?'}→${shooting}`,
                `GK:${b.goalkeeper_rating ?? '?'}→${goalkeeper}`,
            ].join(' ');
            await auditLog(pool, req.user.playerId, 'stats_updated', req.params.id, detail);
        });
    } catch (error) {
        console.error('Update stats error:', error);
        res.status(500).json({ error: 'Update failed' });
    }
});


// ── sendBalanceEmail: notify player when their balance is topped up or adjusted
async function sendBalanceEmail(playerId, oldBalance, newBalance, description) {
    try {
        const pr = await pool.query(
            'SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
            [playerId]
        );
        if (!pr.rows.length) return;
        const p     = pr.rows[0];
        const name  = p.alias || p.full_name;
        const diff  = parseFloat((newBalance - oldBalance).toFixed(2));
        const sign  = diff >= 0 ? '+' : '';
        const col   = diff >= 0 ? '#00cc66' : '#ff4444';
        await emailTransporter.sendMail({
            from: '"TotalFooty" <totalfooty19@gmail.com>',
            to:   p.email,
            subject: `Your TotalFooty balance has been updated 💳`,
            html: wrapEmailHtml(`
                <p style="color:#888;font-size:14px;margin:0 0 20px;">Hi ${htmlEncode(name)}, your TotalFooty credit balance has been updated.</p>
                <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;">
                    <tr>
                        <td style="padding:8px 0;color:#888;width:150px;">Previous balance</td>
                        <td style="font-weight:700;">£${parseFloat(oldBalance).toFixed(2)}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;color:#888;">Change</td>
                        <td style="font-weight:900;color:${col};">${sign}£${Math.abs(diff).toFixed(2)}</td>
                    </tr>
                    <tr style="border-top:1px solid #222;">
                        <td style="padding:10px 0 8px;color:#888;">New balance</td>
                        <td style="font-weight:900;font-size:18px;color:#fff;padding-top:10px;">£${parseFloat(newBalance).toFixed(2)}</td>
                    </tr>
                    ${description ? `<tr><td style="padding:8px 0;color:#888;vertical-align:top;">Note</td><td style="color:#aaa;font-size:13px;">${htmlEncode(description)}</td></tr>` : ''}
                </table>
                <p style="color:#444;font-size:12px;margin-top:24px;">Questions about your balance? Reply to this email.</p>
            `),
        });
        console.log('Balance email sent to player', playerId);
    } catch (e) {
        console.warn('sendBalanceEmail failed (non-critical):', e.message);
    }
}

app.post('/api/admin/players/:id/credits', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { amount, description } = req.body;

        // FIX-024: Validate amount and description
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount)) return res.status(400).json({ error: 'Amount must be a number' });
        if (!description?.trim()) return res.status(400).json({ error: 'Description is required' });
        if (Math.abs(parsedAmount) > 500) return res.status(400).json({ error: 'Amount too large — max ±£500' });

        // Capture old balance before update so we can show it in the email
        const prevBalResult = await pool.query('SELECT balance FROM credits WHERE player_id = $1', [req.params.id]);
        const oldBalance = prevBalResult.rows.length > 0 ? parseFloat(prevBalResult.rows[0].balance) : 0;

        await pool.query(
            'UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2',
            [parsedAmount, req.params.id]
        );

        await recordCreditTransaction(pool, req.params.id, amount, 'admin_adjustment', description, req.user.userId);
        await auditLog(pool, req.user.userId, 'credit_adjustment', req.params.id, `${parsedAmount >= 0 ? '+' : ''}£${parsedAmount.toFixed(2)} — ${description.trim()}`);

        res.json({ message: 'Credits adjusted' });

        // Non-critical: email player with old/new balance + RAF activation check
        setImmediate(async () => {
            await sendBalanceEmail(req.params.id, oldBalance, oldBalance + parsedAmount, description?.trim() || 'Balance adjustment');
            // FIX-101-RAF: trigger £2 RAF activation if this is a positive top-up for a referred player
            if (parsedAmount > 0) await triggerRafActivation(req.params.id);
        });
    } catch (error) {
        console.error('Credit adjustment error:', error);
        res.status(500).json({ error: 'Adjustment failed' });
    }
});

// POST /api/admin/players/:id/free-credits — record free credit grant (superadmin only)
// Does NOT change the player's real balance — informational record only
app.post('/api/admin/players/:id/free-credits', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { amount, description } = req.body;
        console.log('[free-credits] body:', req.body, 'playerId:', req.params.id);
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount === 0) return res.status(400).json({ error: 'Amount must be non-zero' });
        if (Math.abs(parsedAmount) > 500) return res.status(400).json({ error: 'Amount too large — max ±£500' });

        const desc = description?.trim() || (parsedAmount < 0 ? 'Free credit removal' : 'Free credit grant');

        // Record transaction and update balance so free credits can actually be spent
        await pool.query(
            `INSERT INTO credits (player_id, balance) VALUES ($1, $2)
             ON CONFLICT (player_id) DO UPDATE SET balance = credits.balance + $2`,
            [req.params.id, parsedAmount]
        );

        await recordCreditTransaction(pool, req.params.id, parsedAmount, 'free_credit',
            desc, req.user.userId);
        await auditLog(pool, req.user.userId, 'free_credit_grant', req.params.id, `${parsedAmount >= 0 ? '+' : ''}£${parsedAmount.toFixed(2)} free credits — ${desc}`);

        res.json({ message: 'Free credits recorded' });
    } catch (error) {
        console.error('Free credit record error:', error);
        res.status(500).json({ error: 'Failed to record free credits' });
    }
});

// Update player (admin)
app.put('/api/admin/players/:playerId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        const {
            goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            total_wins, squad_number, phone, balance, alias, position,
            is_featured, social_tiktok, social_instagram, social_youtube, social_facebook,
            email
        } = req.body;

        // Email update — superadmin only, check uniqueness
        if (email !== undefined && email !== null && email !== '') {
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            const userRow = await pool.query('SELECT u.id FROM users u JOIN players p ON p.user_id = u.id WHERE p.id = $1', [playerId]);
            if (userRow.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
            const userId = userRow.rows[0].id;
            const emailCheck = await pool.query(
                'SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2',
                [email, userId]
            );
            if (emailCheck.rows.length > 0) {
                return res.status(400).json({ error: 'Email already in use by another account' });
            }
            const oldEmailRow = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
            await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email.toLowerCase().trim(), userId]);
            await auditLog(pool, req.user.userId, 'admin_email_changed', playerId,
                `Email changed from ${oldEmailRow.rows[0]?.email} to ${email.toLowerCase().trim()}`);
        }
        
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
                social_facebook = $18,
                position = $19
            WHERE id = $20
        `, [goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            overall_rating, total_wins, squad_number, phone, alias || null,
            is_featured !== undefined ? is_featured : null,
            validateSocialUrl(social_tiktok), validateSocialUrl(social_instagram),
            validateSocialUrl(social_youtube), validateSocialUrl(social_facebook),
            ['goalkeeper','outfield'].includes(position) ? position : 'outfield',
            playerId]);
        
        // Sync player_number with squad_number when a squad number is assigned/changed
        if (squad_number !== undefined && squad_number !== null) {
            await pool.query(
                'UPDATE players SET player_number = $1 WHERE id = $2',
                [squad_number, playerId]
            );
        }

        // FIX-053: Update balance with audit trail if changed
        if (balance !== undefined) {
            const prevResult = await pool.query('SELECT balance FROM credits WHERE player_id = $1', [playerId]);
            const prevBalance = prevResult.rows.length > 0 ? parseFloat(prevResult.rows[0].balance) : 0;
            const newBalance = parseFloat(balance);
            const diff = parseFloat((newBalance - prevBalance).toFixed(2));
            await pool.query('UPDATE credits SET balance = $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2', [newBalance, playerId]);
            if (diff !== 0) {
                await recordCreditTransaction(pool, playerId, diff, 'admin_adjustment', `Direct balance set to £${newBalance.toFixed(2)} by admin`, req.user.userId);
                // SEC-028: Audit log every balance change — tamper-evident record for disputes
                await auditLog(pool, req.user.playerId, 'balance_adjustment',
                    playerId, `prev=£${prevBalance.toFixed(2)} new=£${newBalance.toFixed(2)} diff=£${diff}`);
                // Notify player with old/new balance
                setImmediate(async () => {
                    await sendBalanceEmail(playerId, prevBalance, newBalance, `Direct balance set to £${newBalance.toFixed(2)} by admin`);
                });
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
            'SELECT id, name, icon, description FROM badges ORDER BY name'
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

        // SEC: Referee badge can only be assigned by superadmin
        if (req.user.role !== 'superadmin' && badgeIds && badgeIds.length > 0) {
            const refBadgeRow = await client.query("SELECT id FROM badges WHERE name = 'Referee'");
            const refBadgeId = refBadgeRow.rows[0]?.id;
            if (refBadgeId && badgeIds.includes(refBadgeId)) {
                await client.query('ROLLBACK');
                return res.status(403).json({ error: 'Only superadmin can assign the Referee badge' });
            }
        }

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
        
        setImmediate(() => auditLog(pool, req.user.playerId, 'referral_set', playerId,
            `Referred by set: ${referrer.alias || referrer.full_name} (${referredBy}) -> ${player.alias || player.full_name} (${playerId})`));
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
            'SELECT reliability_tier, overall_rating, goalkeeper_rating FROM players WHERE id = $1',
            [req.user.playerId]
        );
        
        const tier      = playerResult.rows[0]?.reliability_tier || 'silver';
        const playerOvr = parseInt(playerResult.rows[0]?.overall_rating    ?? 0);
        const playerGk  = parseInt(playerResult.rows[0]?.goalkeeper_rating ?? 0);
        
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
        let hoursAhead = 168; // silver default (168 hours = 7 days)
        if (tier === 'gold') hoursAhead = 28 * 24; // 28 days
        if (tier === 'bronze') hoursAhead = 24; // 24 hours
        if (tier === 'white' || tier === 'black') hoursAhead = 0; // banned - no games visible
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address, v.region as venue_region,
                   g.teams_generated,
                   gs.series_name,
                   g.format as game_format,
                   TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'HH24:MI') as game_time,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   COALESCE((SELECT COUNT(*) FROM registrations r JOIN players p ON p.id = r.player_id WHERE r.game_id = g.id AND r.status = 'confirmed' AND p.is_organiser = true)::int, 0) as confirmed_organiser_count,
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
                OR (g.game_status = 'completed' AND (
                    ${isAdmin ? 'TRUE' : 'EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1)'}
                ))
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
            'Daimler Green - Astro': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green - Grass': 'https://totalfooty.co.uk/assets/Daimler_Green_Grass.webp',
            'Daimler Green': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/Corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Power League': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
                'Nuneaton Academy':        'https://totalfooty.co.uk/assets/nuneaton_academy.webp',
                'Tudor Grange Academy':     'https://totalfooty.co.uk/assets/Tudor-Grange-pitch.webp',
        };
        
        // Add venue photos based on venue name
        const gamesWithPhotos = result.rows.map(game => {
            if (game.venue_name && venuePhotoMap[game.venue_name]) {
                game.venue_photo = venuePhotoMap[game.venue_name];
            }
            return game;
        });
        

        // Visibility-only filter — admins see all games regardless.
        // Completed games always shown (history must never disappear).
        // Player passes if: overall_rating >= minOvr OR goalkeeper_rating >= minGk.
        // Registration is never blocked — only visibility is affected.
        const visibleGames = isAdmin
            ? gamesWithPhotos
            : gamesWithPhotos.filter(game => {
                if (game.game_status === 'completed') return true;
                const { minOvr, minGk } = effectiveMinRating(game);
                return playerOvr >= minOvr || (minGk > 0 && playerGk >= minGk);
            });

        res.json(visibleGames);
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
            'Daimler Green - Astro': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green - Grass': 'https://totalfooty.co.uk/assets/Daimler_Green_Grass.webp',
            'Daimler Green': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/Corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Power League': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
                'Nuneaton Academy':        'https://totalfooty.co.uk/assets/nuneaton_academy.webp',
                'Tudor Grange Academy':     'https://totalfooty.co.uk/assets/Tudor-Grange-pitch.webp',
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

// GET /api/games/needing-refs — games with refs_required > 0 and unfilled slots
// Used by referee badge holders in "Ref mode"
app.get('/api/games/needing-refs', authenticateToken, async (req, res) => {
    try {
        // Verify player has Referee badge
        const badgeCheck = await pool.query(
            `SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
             WHERE pb.player_id = $1 AND b.name = 'Referee'`,
            [req.user.playerId]
        );
        if (!badgeCheck.rows.length) {
            return res.status(403).json({ error: 'Referee badge required' });
        }

        const result = await pool.query(`
            SELECT g.id, g.game_url, g.game_date, g.format, g.refs_required,
                   g.ref_pay, g.game_status,
                   v.name AS venue_name,
                   (SELECT COUNT(*) FROM game_referees gr
                    WHERE gr.game_id = g.id AND gr.status = 'confirmed') AS confirmed_refs,
                   (SELECT COUNT(*) FROM game_referees gr
                    WHERE gr.game_id = g.id AND gr.player_id = $1) AS my_application,
                   (SELECT status FROM game_referees gr
                    WHERE gr.game_id = g.id AND gr.player_id = $1 LIMIT 1) AS my_status,
                   EXISTS(SELECT 1 FROM registrations r
                          WHERE r.game_id = g.id AND r.player_id = $1
                          AND r.status = 'confirmed') AS also_playing
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.refs_required > 0
              AND g.game_status IN ('available','confirmed')
              AND g.game_date >= NOW()
            ORDER BY g.game_date ASC
        `, [req.user.playerId]);

        res.json(result.rows);
    } catch (error) {
        console.error('Needing refs error:', error);
        res.status(500).json({ error: 'Failed to fetch games needing referees' });
    }
});

app.get('/api/games/:id', authenticateToken, async (req, res) => {
    try {
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address, v.region as venue_region,
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

        // ORGANISER-003: Add confirmed organiser count for client-side capacity calculation
        if (game.requires_organiser) {
            const orgCount = await pool.query(`
                SELECT COUNT(*) AS cnt FROM registrations r
                JOIN players p ON p.id = r.player_id
                WHERE r.game_id = $1 AND r.status = 'confirmed' AND p.is_organiser = true
            `, [req.params.id]);
            game.confirmed_organiser_count = parseInt(orgCount.rows[0].cnt) || 0;
        } else {
            game.confirmed_organiser_count = 0;
        }
        
        // Map venue names to their photo URLs
        const venuePhotoMap = {
            'Daimler Green - Astro': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green - Grass': 'https://totalfooty.co.uk/assets/Daimler_Green_Grass.webp',
            'Daimler Green': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/Corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Power League': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
                'Nuneaton Academy':        'https://totalfooty.co.uk/assets/nuneaton_academy.webp',
                'Tudor Grange Academy':     'https://totalfooty.co.uk/assets/Tudor-Grange-pitch.webp',
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
        
        // FIX-03: server-side boolean so frontend never needs to re-derive from team_selection_type string
        game.show_pair_avoid = !['draft_memory', 'vs_external'].includes((game.team_selection_type || '').trim().toLowerCase()) && !game.is_venue_clash && !game.venue_clash_team1_name;

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
            isVenueClash, venueClashTeam1Name, venueClashTeam2Name,
            maxReferees, refereeFee, requiresOrganiser
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
            
                // Create series record for ALL weekly games (not just draft_memory/vs_external)
                // This UUID is what delete-series uses to find and delete all games in the series
                const selType = teamSelectionType || 'normal';
                const seriesResult = await wClient.query(
                    'INSERT INTO game_series (series_name, series_type) VALUES ($1, $2) RETURNING id',
                    [seriesIdValue, selType]
                );
                let seriesUuid = seriesResult.rows[0].id;
            
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
                            team_selection_type, external_opponent, tf_kit_color, opp_kit_color,
                            tournament_team_count, tournament_name, star_rating, star_rating_locked,
                            is_venue_clash, venue_clash_team1_name, venue_clash_team2_name,
                            refs_required, ref_pay, requires_organiser
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
                        RETURNING id`,
                        [
                            venueId, weekDate.toISOString(), maxPlayers, costPerPlayer, format, 'weekly', 
                            gameExclusivity, positionType || 'outfield_gk', gameUrl, 
                            seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null,
                            selType === 'tournament' ? parseInt(tournamentTeamCount) : null,
                            selType === 'tournament' ? (tournamentName || null) : null,
                            starRating || null,
                            parseInt(starRating) >= 4, // DYNSTAR: lock if originally 4★ or 5★
                            vcEnabled || false,
                            vcEnabled ? venueClashTeam1Name.trim() : null,
                            vcEnabled ? venueClashTeam2Name.trim() : null,
                            parseInt(maxReferees) || 0,
                            parseFloat(refereeFee) || 0.00,
                            requiresOrganiser === true || requiresOrganiser === 'true' || false
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
                        `format:${format} type:${selType} cost:£${costPerPlayer} max:${maxPlayers} series:${seriesIdValue}`)
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
                    tournament_team_count, tournament_name, star_rating, star_rating_locked,
                    is_venue_clash, venue_clash_team1_name, venue_clash_team2_name,
                    refs_required, ref_pay, requires_organiser
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
                RETURNING id`,
                [
                    venueId, gameDate, maxPlayers, costPerPlayer, format, 'one-off', 
                    gameExclusivity, positionType || 'outfield_gk', gameUrl,
                    seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null,
                    selType === 'tournament' ? parseInt(tournamentTeamCount) : null,
                    selType === 'tournament' ? (tournamentName || null) : null,
                    starRating || null,
                    parseInt(starRating) >= 4, // DYNSTAR: lock if originally 4★ or 5★
                    vcEnabled || false,
                    vcEnabled ? venueClashTeam1Name.trim() : null,
                    vcEnabled ? venueClashTeam2Name.trim() : null,
                    parseInt(maxReferees) || 0,
                    parseFloat(refereeFee) || 0.00,
                    requiresOrganiser === true || requiresOrganiser === 'true' || false
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
// GET /api/games/:id/calendar.ics — download ICS file for a registered game
app.get('/api/games/:id/calendar.ics', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(`
            SELECT g.game_date, g.format, g.cost_per_player, g.game_url,
                   v.name as venue_name, v.address as venue_address, v.postcode as venue_postcode
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [id]);

        if (!result.rows[0]) return res.status(404).json({ error: 'Game not found' });

        // Verify player is registered
        const regCheck = await pool.query(
            `SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [id, req.user.playerId]
        );
        if (!regCheck.rows.length) return res.status(403).json({ error: 'Not registered for this game' });

        const game = result.rows[0];
        const start = new Date(game.game_date);
        const end = new Date(start.getTime() + 60 * 60 * 1000); // 1 hour default

        const pad = n => String(n).padStart(2, '0');
        const icsDate = (d) => `${d.getUTCFullYear()}${pad(d.getUTCMonth()+1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}00Z`;
        // RFC 5545: escape backslash, semicolon, comma, newline in TEXT values
        const icsEscape = s => (s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\n/g, '\\n');
        const locationRaw = [game.venue_name, game.venue_address, game.venue_postcode].filter(Boolean).join(', ');
        const uid = `tf-game-${id}@totalfooty.co.uk`;
        const summary = icsEscape(`⚽ TotalFooty — ${game.format || 'Football'}`);
        const description = icsEscape(`TotalFooty game at ${game.venue_name || 'TBA'}. View details: https://totalfooty.co.uk/game.html?url=${game.game_url || ''}`);
        const location = icsEscape(locationRaw);

        const ics = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//TotalFooty//Game Calendar//EN',
            'CALSCALE:GREGORIAN',
            'METHOD:PUBLISH',
            'BEGIN:VEVENT',
            `UID:${uid}`,
            `DTSTAMP:${icsDate(new Date())}`,
            `DTSTART:${icsDate(start)}`,
            `DTEND:${icsDate(end)}`,
            `SUMMARY:${summary}`,
            `DESCRIPTION:${description}`,
            `LOCATION:${location}`,
            'STATUS:CONFIRMED',
            'END:VEVENT',
            'END:VCALENDAR'
        ].join('\r\n');

        res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="totalfooty-game.ics"`);
        res.send(ics);
    } catch (e) {
        console.error('ICS generation error:', e.message);
        res.status(500).json({ error: 'Failed to generate calendar file' });
    }
});

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
                p.goalkeeper_rating,
                p.defending_rating,
                p.strength_rating,
                p.fitness_rating,
                p.pace_rating,
                p.decisions_rating,
                p.assisting_rating,
                p.shooting_rating,
                p.overall_rating,
                r.status,
                r.backup_type,
                r.is_comped,
                r.position_preference as positions,
                r.position_preference as position_preference,
                r.tournament_team_preference,
                r.venue_clash_team_preference,
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
                     p.goalkeeper_rating, p.defending_rating, p.strength_rating,
                     p.fitness_rating, p.pace_rating, p.decisions_rating,
                     p.assisting_rating, p.shooting_rating, p.overall_rating,
                     r.status, r.backup_type, r.is_comped,
                     r.position_preference, r.tournament_team_preference, r.venue_clash_team_preference, t.team_name
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
                   series_id, game_status, game_date, star_rating, min_rating_enabled,
                   is_venue_clash, venue_clash_team1_name, venue_clash_team2_name,
                   requires_organiser
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

        // Min-rating is visibility-only — registration is never blocked by rating.
        // Players can always sign up if they have the game URL or find it via games list.

        // ORGANISER-001: If game requires an organiser and this player is NOT an organiser,
        // the effective capacity is max_players - 1 while no organiser is confirmed.
        // This reserves the last slot for an organiser.
        let effectiveMax = parseInt(game.max_players);
        if (game.requires_organiser) {
            // We already fetched is_organiser below — but we need it here. Fetch now.
            const _orgCheck = await client.query(
                'SELECT is_organiser FROM players WHERE id = $1', [req.user.playerId]
            );
            const _playerIsOrganiser = _orgCheck.rows[0]?.is_organiser || false;
            if (!_playerIsOrganiser) {
                // Count confirmed organisers currently in this game
                const _orgCount = await client.query(`
                    SELECT COUNT(*) AS cnt FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'confirmed' AND p.is_organiser = true
                `, [gameId]);
                if (parseInt(_orgCount.rows[0].cnt) === 0) {
                    effectiveMax = parseInt(game.max_players) - 1;
                }
            }
        }
        const isFull = parseInt(game.current_players) >= effectiveMax;
        
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
        let status, regBackupType = null, regAmountPaid = null;
        
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
                    
                    // Capture realCharged so amount_paid correctly records the real-balance portion
                    const { realCharged: backupCharged } = await applyGameFee(client, req.user.playerId, game.cost_per_player, `Confirmed backup for game ${gameId}`);
                    regAmountPaid = backupCharged;
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
                
                const { realCharged: selfRegCharged } = await applyGameFee(client, req.user.playerId, game.cost_per_player, `Registration for game ${gameId}`);
                regAmountPaid = selfRegCharged;
            }
        }
        
        // SEC: Block registration if player is already a confirmed referee for this game
        const refConflict = await client.query(
            `SELECT 1 FROM game_referees WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [gameId, req.user.playerId]
        );
        if (refConflict.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'You are already confirmed as a referee for this game' });
        }

        // Register player
        const regResult = await client.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference, backup_type, tournament_team_preference, venue_clash_team_preference, amount_paid, is_comped)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [gameId, req.user.playerId, status, positionValue, regBackupType,
             game.team_selection_type === 'tournament' ? (tournamentTeamPreference || null) : null,
             game.is_venue_clash ? (venueClashTeamPreference || null) : null,
             isComped ? 0 : ((status === 'confirmed' || regBackupType === 'confirmed_backup') ? (regAmountPaid ?? game.cost_per_player) : 0),
             isComped]
        );
        
        const registrationId = regResult.rows[0].id;
        
        // Insert pair/avoid preferences — only for confirmed players on modes where teams are auto-drafted
        const regNoDraftMode = game.team_selection_type === 'draft_memory'
            || game.team_selection_type === 'vs_external'
            || game.is_venue_clash;
        if (status === 'confirmed' && !regNoDraftMode && pairs && Array.isArray(pairs)) {
            for (const pairPlayerId of pairs) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        if (status === 'confirmed' && !regNoDraftMode && avoids && Array.isArray(avoids)) {
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
                const regType = status === 'backup'
                    ? (regBackupType === 'confirmed_backup' ? 'confirmed backup' : regBackupType === 'gk_backup' ? 'GK backup' : 'backup')
                    : 'standard';
                // Fetch player name for readable audit trail
                const _snRow = await pool.query('SELECT full_name, alias FROM players WHERE id = $1', [req.user.playerId]).catch(() => ({ rows: [] }));
                const _snName = _snRow.rows[0]?.alias || _snRow.rows[0]?.full_name || req.user.playerId;
                // Resolve pair/avoid player names for audit (confirmed registrations only)
                let _pairStr = '', _avoidStr = '';
                if (status === 'confirmed' && registrationId) {
                    const _prefRows = await pool.query(`
                        SELECT rp.preference_type, COALESCE(p.alias, p.full_name) AS name
                        FROM registration_preferences rp
                        JOIN players p ON p.id = rp.target_player_id
                        WHERE rp.registration_id = $1
                        ORDER BY rp.preference_type, p.alias, p.full_name
                    `, [registrationId]).catch(() => ({ rows: [] }));
                    const _pairNames  = _prefRows.rows.filter(r => r.preference_type === 'pair').map(r => r.name);
                    const _avoidNames = _prefRows.rows.filter(r => r.preference_type === 'avoid').map(r => r.name);
                    if (_pairNames.length)  _pairStr  = ` | Pair: ${_pairNames.join(', ')}`;
                    if (_avoidNames.length) _avoidStr = ` | Avoid: ${_avoidNames.join(', ')}`;
                }
                const evtDetail = `Position: ${positionValue}${regBackupType ? ' | Backup type: ' + regBackupType : ''}${isComped ? ' | Comped' : ''}${_pairStr}${_avoidStr}`;
                await registrationEvent(pool, gameId, req.user.playerId, evtType, evtDetail);
                await gameAuditLog(pool, gameId, null,
                    status === 'backup' ? 'player_backup_joined' : 'player_signed_up',
                    `${_snName} (${req.user.playerId}) | ${regType} | Position: ${positionValue}${isComped ? ' | Comped' : ''}${_pairStr}${_avoidStr}`);
            } catch (e) { /* non-critical */ }
            try {
                const gameData = await getGameDataForNotification(gameId);
                const notifType = status === 'confirmed' ? 'game_registered' : 'backup_added';
                await sendNotification(notifType, req.user.playerId, gameData);
                // Superadmin: notify on game/tournament registration
                const playerRow = await pool.query(
                    'SELECT p.full_name, p.alias, p.player_number, p.squad_number, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
                    [req.user.playerId]
                );
                const pName = playerRow.rows[0]?.alias || playerRow.rows[0]?.full_name || req.user.playerId;
                const pEmail = playerRow.rows[0]?.email || '';
                const isTournament = (await pool.query('SELECT team_selection_type FROM games WHERE id = $1', [gameId])).rows[0]?.team_selection_type === 'tournament';
                const adminRegType = status === 'confirmed' ? 'Confirmed' : `Backup (${regBackupType || 'standard'})`;
                await notifyAdmin(
                    `${isTournament ? '🏆 Tournament' : '⚽ Game'} Registration — ${pName}`,
                    [
                        ['Player', pName],
                        ['Email', pEmail],
                        ['Game', `${gameData.day} ${gameData.time}`],
                        ['Venue', gameData.venue],
                        ['Status', adminRegType],
                        ['Position', positionValue],
                    ]
                );
            } catch (e) {
                console.error('Registration notification failed (non-critical):', e.message);
            }
            // DYNSTAR: review star rating on every confirmed sign-up
            if (status === 'confirmed') await reviewDynamicStarRating(pool, gameId);
            // FIX-101-RAF: trigger 50p game credit for referrer if this is a confirmed self-registration
            if (status === 'confirmed') await triggerRafGameCredit(req.user.playerId);
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
            return res.status(400).json({ error: "Please provide the guest's name (at least 2 characters)" });
        }

        // FIX-080: Guest name max length
        if (guestName.trim().length > 50) {
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

        // Admins bypass the lock — they shouldn't be blocked by their own edit session
        const isAdminAddingGuest = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (game.player_editing_locked && !isAdminAddingGuest) {
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

        // Deduct credits from the inviting player (free credits first)
        await applyGameFee(client, playerId, cost, `+1 guest (${guestName.trim()}) for game`);

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
            referralLink: referralCode ? `https://totalfooty.co.uk/?ref=${referralCode}` : null,
            referralPrompt: 'Refer a friend for future rewards as they join and play with Total Footy! Here is your personalised link - send it to them now!'
        });
        setImmediate(async () => {
            const _hostRow = await pool.query('SELECT full_name, alias FROM players WHERE id = $1', [req.user.playerId]).catch(() => ({ rows: [] }));
            const _hostName = _hostRow.rows[0]?.alias || _hostRow.rows[0]?.full_name || req.user.playerId;
            await gameAuditLog(pool, req.params.id, null, 'guest_added',
                `Guest: ${guestName.trim()} | Host: ${_hostName} (${req.user.playerId}) | OVR: ${guestRating} | Paid: £${cost.toFixed(2)}`);
            await reviewDynamicStarRating(pool, req.params.id); // DYNSTAR: guest add triggers rating review
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
        // Admins bypass the lock — they shouldn't be blocked by their own edit session
        const isAdminRemovingGuest = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (gameCheck.rows[0]?.player_editing_locked && !isAdminRemovingGuest) {
            await client.query('ROLLBACK');
            return res.status(423).json({ error: 'Game is currently being edited by an admin.' });
        }
        if (gameCheck.rows[0]?.teams_generated) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Cannot remove guest - teams already generated.' });
        }

        // Find and delete the specific guest.
        // Admins can remove any guest regardless of who invited them — no invited_by filter.
        // Non-admins can only remove their own guests.
        let guestResult;
        if (guestId) {
            if (isAdminRemovingGuest) {
                guestResult = await client.query(
                    'DELETE FROM game_guests WHERE id = $1 AND game_id = $2 RETURNING guest_name, amount_paid, guest_number, invited_by',
                    [guestId, gameId]
                );
            } else {
                guestResult = await client.query(
                    'DELETE FROM game_guests WHERE id = $1 AND game_id = $2 AND invited_by = $3 RETURNING guest_name, amount_paid, guest_number, invited_by',
                    [guestId, gameId, playerId]
                );
            }
        } else {
            // Fallback: remove the last-added guest for this player (non-admin only path)
            guestResult = await client.query(
                'DELETE FROM game_guests WHERE id = (SELECT id FROM game_guests WHERE game_id = $1 AND invited_by = $2 ORDER BY guest_number DESC LIMIT 1) RETURNING guest_name, amount_paid, guest_number, invited_by',
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
        // Always refund the original inviter, not the admin doing the removal
        const refundTargetId = guest.invited_by || playerId;

        // Lock the refund target's credits row before updating
        await client.query('SELECT id FROM credits WHERE player_id = $1 FOR UPDATE', [refundTargetId]);

        // Refund the inviting player
        if (refundAmt > 0) {
            await client.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [refundAmt, refundTargetId]
            );
            await recordCreditTransaction(client, refundTargetId, refundAmt, 'refund', `Guest (${guest.guest_name}) removed - refund`);
        }

        // Re-number remaining guests for the original inviter so numbers stay sequential
        const remaining = await client.query(
            'SELECT id FROM game_guests WHERE game_id = $1 AND invited_by = $2 ORDER BY guest_number ASC',
            [gameId, refundTargetId]
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
            await recordCreditTransaction(client, playerId, refundAmt, 'refund', `Removed ${playerName} from game`);
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

        // Block if friend is already a confirmed referee for this game
        const friendRefConflict = await client.query(
            `SELECT 1 FROM game_referees WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [req.params.id, friendPlayerId]
        );
        if (friendRefConflict.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'This player is already confirmed as a referee for this game' });
        }

        // Lock game row to prevent race conditions
        const gameLock = await client.query(`
            SELECT max_players, cost_per_player, exclusivity,
                   player_editing_locked, team_selection_type, position_type, tournament_team_count,
                   series_id, game_status, game_date, star_rating, min_rating_enabled
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
            'SELECT id, alias, full_name, reliability_tier, overall_rating FROM players WHERE id = $1',
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
        let hoursAhead = 168; // silver (7 days)
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

        // Min-rating is visibility-only — friend registration is never blocked by rating.

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
        let status, regBackupType = null, friendAmountPaid = null;

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
                await applyGameFee(client, registeringPlayerId, game.cost_per_player, `Confirmed backup for ${friendName} in game ${gameId}`);
            }
        } else {
            status = 'confirmed';
            const creditResult = await client.query('SELECT balance FROM credits WHERE player_id = $1', [registeringPlayerId]);
            if (creditResult.rows.length === 0 || Math.round(parseFloat(creditResult.rows[0].balance) * 100) < Math.round(parseFloat(game.cost_per_player) * 100)) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'Insufficient credits' });
            }
            await applyGameFee(client, registeringPlayerId, game.cost_per_player, `Registration for ${friendName} in game ${gameId}`);
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
                const gameUrl = `https://totalfooty.co.uk/game.html?url=${gameData.game_url || ''}`;

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

                // Email 3 (receipt to registering player) removed — unnecessary

                // Audit: add-friend registration
                try {
                    const friendRegType = status === 'backup'
                        ? (regBackupType === 'confirmed_backup' ? 'confirmed backup' : regBackupType === 'gk_backup' ? 'GK backup' : 'backup')
                        : 'standard';
                    await registrationEvent(pool, gameId, friendPlayerId,
                        status === 'backup' ? 'backup_joined' : 'signed_up',
                        `Signed up by ${regName} | ${friendRegType}`);
                    await gameAuditLog(pool, gameId, null,
                        status === 'backup' ? 'player_backup_joined' : 'player_signed_up',
                        `${friendFullName} (${friendPlayerId}) | ${friendRegType} | Added by ${regName} (${registeringPlayerId})`);
                } catch (e) { /* non-critical */ }

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
            // DYNSTAR: review star rating on every confirmed friend sign-up
            if (status === 'confirmed') await reviewDynamicStarRating(pool, gameId);
            // RAF: trigger 50p game credit for referrer if the friend being registered was referred
            if (status === 'confirmed') await triggerRafGameCredit(friendPlayerId);
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



// ── PUBLIC lineup — no auth, read-only
app.get('/api/public/game/:gameId/lineup', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT team_name, positions, subs FROM game_lineups WHERE game_id = $1 ORDER BY team_name',
            [req.params.gameId]
        );
        const lineups = {};
        for (const row of result.rows) {
            lineups[row.team_name] = { positions: row.positions || [], subs: row.subs || [] };
        }
        res.json({ lineups });
    } catch (err) {
        console.error('Public GET lineup error:', err);
        res.status(500).json({ error: 'Failed to fetch lineup' });
    }
});

// ── LINEUP BUILDER ──────────────────────────────────────────────────────────
app.get('/api/games/:id/lineup', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        let canEdit = false;
        if (req.user.role === 'admin' || req.user.role === 'superadmin') {
            canEdit = true;
        } else {
            const regCheck = await pool.query(
                `SELECT r.id, p.is_organiser FROM registrations r
                 JOIN players p ON p.id = r.player_id
                 WHERE r.game_id = $1 AND r.player_id = $2 AND r.status = 'confirmed'`,
                [gameId, req.user.playerId]
            );
            if (regCheck.rows.length === 0) {
                return res.status(403).json({ error: 'Access denied — confirmed players only' });
            }
            if (regCheck.rows[0].is_organiser) canEdit = true;
        }
        // Also check game_captains for edit rights
        if (!canEdit) {
            const captainCheck = await pool.query(
                'SELECT 1 FROM game_captains WHERE game_id = $1 AND player_id = $2',
                [gameId, req.user.playerId]
            );
            if (captainCheck.rows.length > 0) canEdit = true;
        }

        const [lineupResult, captainsResult] = await Promise.all([
            pool.query('SELECT team_name, positions, subs, updated_at FROM game_lineups WHERE game_id = $1 ORDER BY team_name', [gameId]),
            pool.query(
                `SELECT gc.player_id, COALESCE(p.alias, p.full_name) as name
                 FROM game_captains gc JOIN players p ON p.id = gc.player_id
                 WHERE gc.game_id = $1`,
                [gameId]
            )
        ]);
        const lineups = {};
        for (const row of lineupResult.rows) {
            lineups[row.team_name] = {
                positions: row.positions || [],
                subs:      row.subs      || [],
                updated_at: row.updated_at,
            };
        }
        const isCaptain = captainsResult.rows.some(c => c.player_id === req.user.playerId);
        res.json({
            lineups,
            can_edit: canEdit,
            is_captain: isCaptain,
            captains: captainsResult.rows
        });
    } catch (err) {
        console.error('GET lineup error:', err);
        res.status(500).json({ error: 'Failed to fetch lineup' });
    }
});

app.put('/api/admin/games/:id/lineup/:teamName', authenticateToken, async (req, res) => {
    try {
        const gameId   = req.params.id;
        const teamName = decodeURIComponent(req.params.teamName);
        const { positions, subs } = req.body;
        if (!Array.isArray(positions) || !Array.isArray(subs)) {
            return res.status(400).json({ error: 'positions and subs must be arrays' });
        }
        // Allow: admin/superadmin, confirmed organiser, or designated captain
        if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
            const [orgCheck, capCheck] = await Promise.all([
                pool.query(
                    `SELECT 1 FROM registrations r JOIN players p ON p.id = r.player_id
                     WHERE r.game_id = $1 AND r.player_id = $2 AND r.status = 'confirmed' AND p.is_organiser = true`,
                    [gameId, req.user.playerId]
                ),
                pool.query('SELECT 1 FROM game_captains WHERE game_id = $1 AND player_id = $2', [gameId, req.user.playerId])
            ]);
            if (orgCheck.rows.length === 0 && capCheck.rows.length === 0) {
                return res.status(403).json({ error: 'Not authorised to edit lineup' });
            }
        }
        await pool.query(
            `INSERT INTO game_lineups (game_id, team_name, positions, subs, updated_by, updated_at)
             VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, NOW())
             ON CONFLICT (game_id, team_name) DO UPDATE
             SET positions  = $3::jsonb,
                 subs       = $4::jsonb,
                 updated_by = $5,
                 updated_at = NOW()`,
            [gameId, teamName, JSON.stringify(positions), JSON.stringify(subs), req.user.playerId]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PUT lineup error:', err);
        res.status(500).json({ error: 'Failed to save lineup' });
    }
});


// ── LINEUP BUILDER SETTINGS ───────────────────────────────────────────────────

// GET /api/admin/games/:id/lineup-settings — get lineup_enabled + current captains
app.get('/api/admin/games/:id/lineup-settings', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const gameId = req.params.id;
        const [gameRes, captainsRes, playersRes] = await Promise.all([
            pool.query('SELECT lineup_enabled, team_selection_type, external_opponent FROM games WHERE id = $1', [gameId]),
            pool.query(
                `SELECT gc.player_id, COALESCE(p.alias, p.full_name) as name, p.squad_number
                 FROM game_captains gc JOIN players p ON p.id = gc.player_id
                 WHERE gc.game_id = $1 ORDER BY gc.assigned_at`,
                [gameId]
            ),
            pool.query(
                `SELECT p.id, COALESCE(p.alias, p.full_name) as name, p.squad_number,
                        r.status, p.is_organiser
                 FROM registrations r JOIN players p ON p.id = r.player_id
                 WHERE r.game_id = $1 AND r.status = 'confirmed'
                 ORDER BY p.alias, p.full_name`,
                [gameId]
            )
        ]);
        if (gameRes.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const game = gameRes.rows[0];
        // For VS External, only TF-side players (all confirmed players are TF side)
        res.json({
            lineupEnabled: game.lineup_enabled || false,
            teamSelectionType: game.team_selection_type,
            captains: captainsRes.rows,
            eligiblePlayers: playersRes.rows  // confirmed players who can be captain
        });
    } catch (e) {
        console.error('GET lineup-settings error:', e.message);
        res.status(500).json({ error: 'Failed to get lineup settings' });
    }
});

// PUT /api/admin/games/:id/lineup-settings — update lineup_enabled + captains
app.put('/api/admin/games/:id/lineup-settings', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const gameId = req.params.id;
        const { lineupEnabled, captainIds } = req.body;
        if (typeof lineupEnabled !== 'boolean') return res.status(400).json({ error: 'lineupEnabled must be boolean' });
        if (!Array.isArray(captainIds)) return res.status(400).json({ error: 'captainIds must be an array' });

        await pool.query('UPDATE games SET lineup_enabled = $1 WHERE id = $2', [lineupEnabled, gameId]);

        // Replace captain list atomically
        // BUG1-FIX: Validate captainIds — only confirmed players on this game
        const validCaptains = captainIds.length > 0
            ? await pool.query(
                `SELECT player_id FROM registrations
                 WHERE game_id = $1 AND player_id = ANY($2::uuid[]) AND status = 'confirmed'`,
                [gameId, captainIds]
              )
            : { rows: [] };
        const validIds = validCaptains.rows.map(r => r.player_id);

        await pool.query('DELETE FROM game_captains WHERE game_id = $1', [gameId]);
        for (const playerId of validIds) {
            await pool.query(
                'INSERT INTO game_captains (game_id, player_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
                [gameId, playerId, req.user.playerId]
            );
        }
        await gameAuditLog(pool, gameId, req.user.playerId, 'lineup_settings_updated',
            `Lineup builder ${lineupEnabled ? 'ENABLED' : 'DISABLED'}, captains: ${captainIds.length}`);
        res.json({ success: true, lineupEnabled, captainCount: validIds.length });
    } catch (e) {
        console.error('PUT lineup-settings error:', e.message);
        res.status(500).json({ error: 'Failed to update lineup settings' });
    }
});

// POST /api/games/:id/captain/handoff — captain passes captaincy to another player
app.post('/api/games/:id/captain/handoff', authenticateToken, async (req, res) => {
    try {
        const gameId  = req.params.id;
        const { toPlayerId } = req.body;
        if (!toPlayerId) return res.status(400).json({ error: 'toPlayerId is required' });

        // Only current captains and admins can hand off
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (!isAdmin) {
            const capCheck = await pool.query(
                'SELECT 1 FROM game_captains WHERE game_id = $1 AND player_id = $2',
                [gameId, req.user.playerId]
            );
            if (capCheck.rows.length === 0) return res.status(403).json({ error: 'Only captains can hand off captaincy' });
        }

        // Target must be a confirmed player on this game
        const targetCheck = await pool.query(
            `SELECT p.id, COALESCE(p.alias, p.full_name) as name
             FROM registrations r JOIN players p ON p.id = r.player_id
             WHERE r.game_id = $1 AND r.player_id = $2 AND r.status = 'confirmed'`,
            [gameId, toPlayerId]
        );
        if (targetCheck.rows.length === 0) return res.status(400).json({ error: 'Target player must be a confirmed player on this game' });

        // Remove current player from captains (if admin handing off, skip removal)
        if (!isAdmin) {
            await pool.query('DELETE FROM game_captains WHERE game_id = $1 AND player_id = $2', [gameId, req.user.playerId]);
        }
        // Add new captain
        await pool.query(
            'INSERT INTO game_captains (game_id, player_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
            [gameId, toPlayerId, req.user.playerId]
        );
        await gameAuditLog(pool, gameId, req.user.playerId, 'captain_handoff',
            `Captaincy handed to player ${toPlayerId} (${targetCheck.rows[0].name})`);
        res.json({ success: true, newCaptain: targetCheck.rows[0].name });
    } catch (e) {
        console.error('Captain handoff error:', e.message);
        res.status(500).json({ error: 'Failed to hand off captaincy' });
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
            'SELECT player_editing_locked, teams_generated, cost_per_player, team_selection_type, tournament_team_count, requires_organiser FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        
        // Admins bypass the lock — they shouldn't be blocked from dropping out by their own edit session
        const isAdminDroppingOut = req.user.role === 'admin' || req.user.role === 'superadmin';
        if (gameCheck.rows[0]?.player_editing_locked && !isAdminDroppingOut) {
            await client.query('ROLLBACK');
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        const cost = parseFloat(gameCheck.rows[0].cost_per_player);
        const teamsWereGenerated = !!gameCheck.rows[0].teams_generated;
        
        // Get the dropping player's registration — also fetch who paid (registered_by_player_id)
        const regResult = await client.query(
            'SELECT id, status, backup_type, position_preference, registered_by_player_id, is_comped, amount_paid FROM registrations WHERE game_id = $1 AND player_id = $2',
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
            const paidAmt = parseFloat(droppingReg.amount_paid ?? cost);
            const freeAmt = Math.max(0, cost - paidAmt);
            const refundDesc = refundTargetId !== req.user.playerId
                ? `Dropout refund for ${req.user.playerId} (paid by you)`
                : 'Dropped out of game - refund';
            if (paidAmt > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [paidAmt, refundTargetId]);
                await recordCreditTransaction(client, refundTargetId, paidAmt, 'refund', refundDesc);
            }
            if (freeAmt > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [freeAmt, refundTargetId]);
                await recordCreditTransaction(client, refundTargetId, freeAmt, 'free_credit', `Free credit restored — dropped out of game ${droppingReg.id}`);
            }
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
                await recordCreditTransaction(client, req.user.playerId, totalGuestRefund, 'refund', `${guestCheck.rows.length} guest(s) removed - dropout refund`);
            }
            guestRefunded = { names: guestNames, count: guestCheck.rows.length, amount: totalGuestRefund };
        }
        
        // Delete registration (cascade deletes preferences)
        await client.query('DELETE FROM registrations WHERE id = $1', [droppingReg.id]);
        // BUG3-FIX: Clear captaincy when player drops out
        await client.query('DELETE FROM game_captains WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]).catch(() => {});
        
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
                    await applyGameFee(client, promotedPlayer.player_id, cost, `Promoted from backup - game ${gameId}`);
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
        
        // ORGANISER-002: If game requires organiser and the dropping player was the last confirmed organiser,
        // try to auto-promote an organiser backup. Otherwise the slot stays reserved.
        let promotedOrganiser = null;
        if (wasConfirmed && gameCheck.rows[0].requires_organiser) {
            const remainingOrg = await client.query(`
                SELECT COUNT(*) AS cnt FROM registrations r
                JOIN players p ON p.id = r.player_id
                WHERE r.game_id = $1 AND r.status = 'confirmed' AND p.is_organiser = true
            `, [gameId]);
            if (parseInt(remainingOrg.rows[0].cnt) === 0) {
                // No confirmed organiser left — look for an organiser in the backup list
                const orgBackup = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, r.position_preference,
                           r.amount_paid, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND p.is_organiser = true
                    ORDER BY
                        CASE r.backup_type
                            WHEN 'confirmed_backup' THEN 1
                            WHEN 'gk_backup'        THEN 2
                            ELSE                         3
                        END,
                        r.registered_at ASC
                    LIMIT 1
                `, [gameId]);

                if (orgBackup.rows.length > 0) {
                    const ob = orgBackup.rows[0];
                    // Refund if confirmed_backup (they pre-paid) — organisers always play free
                    if (ob.backup_type === 'confirmed_backup') {
                        const obCost    = parseFloat(gameCheck.rows[0].cost_per_player);
                        const obPaid    = parseFloat(ob.amount_paid ?? obCost);
                        const obFree    = Math.max(0, obCost - obPaid);
                        if (obPaid > 0) {
                            await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [obPaid, ob.player_id]);
                            await recordCreditTransaction(client, ob.player_id, obPaid, 'refund', `Organiser comp — promoted from backup for game ${gameId}`);
                        }
                        if (obFree > 0) {
                            await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [obFree, ob.player_id]);
                            await recordCreditTransaction(client, ob.player_id, obFree, 'free_credit', `Free credit restored — organiser comp for game ${gameId}`);
                        }
                    }
                    // Promote: mark confirmed, comped, clear backup_type
                    await client.query(
                        `UPDATE registrations SET status = 'confirmed', backup_type = NULL, is_comped = true WHERE id = $1`,
                        [ob.id]
                    );
                    await client.query(
                        `INSERT INTO notifications (player_id, type, message, game_id)
                         VALUES ($1, 'backup_promoted', $2, $3)`,
                        [ob.player_id,
                         `You've been promoted into the game as organiser! Your spot is now confirmed.`,
                         gameId]
                    );
                    promotedOrganiser = ob;
                }
                // If no organiser backup found: slot stays reserved (effectiveMax shrinks by 1)
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
        if (promotedOrganiser) {
            message += ` ${promotedOrganiser.alias || promotedOrganiser.full_name} has been promoted as organiser.`;
        }
        }
        
        res.json({ message, promotedPlayer: promotedPlayer ? { name: promotedPlayer.alias || promotedPlayer.full_name } : null, promotedOrganiser: promotedOrganiser ? { name: promotedOrganiser.alias || promotedOrganiser.full_name } : null });

        // Non-critical: fire notifications after response
        setImmediate(async () => {
            // FIX: declare gameData outside try blocks so it's accessible to both
            let gameData = {};
            try {
                gameData = await getGameDataForNotification(gameId);
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
                    'SELECT p.full_name, p.alias, u.email FROM players p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = $1', [req.user.playerId]
                ).catch(() => ({ rows: [] }));
                const _pName = _playerNameRow.rows[0]?.alias || _playerNameRow.rows[0]?.full_name || req.user.playerId;
                const _pEmail = _playerNameRow.rows[0]?.email || '';
                await registrationEvent(pool, gameId, req.user.playerId, evtType, evtDetail);
                await gameAuditLog(pool, gameId, null, evtType,
                    `${_pName} (${req.user.playerId}) | ${evtDetail}${promotedPlayer ? ` | Promoted: ${promotedPlayer.alias || promotedPlayer.full_name}` : ''}`);
                // Notify superadmin
                const _dropType = wasConfirmed ? 'Confirmed player' : wasConfirmedBackup ? 'Confirmed backup' : 'Backup';
                const _notifRows = [
                    ['Player',   _pName],
                    ['Email',    _pEmail],
                    ['Type',     _dropType],
                    ['Game',     `${gameData.day} ${gameData.time}`],
                    ['Venue',    gameData.venue],
                ];
                if (!wasComped && (wasConfirmed || wasConfirmedBackup) && cost > 0) {
                    _notifRows.push(['Refunded', `£${cost.toFixed(2)}${refundTargetId !== req.user.playerId ? ' (to original payer)' : ''}`]);
                }
                if (promotedPlayer) {
                    _notifRows.push(['Promoted', promotedPlayer.alias || promotedPlayer.full_name]);
                }
                if (guestRefunded && guestRefunded.count > 0) {
                    _notifRows.push(['Guests removed', `${guestRefunded.count} (${guestRefunded.names})`]);
                }
                await notifyAdmin(`🚪 Drop Out — ${_pName}`, _notifRows);
                // Email 4 (drop out confirmation to player) removed — player knows they dropped out
            } catch (e) { /* non-critical */ }
            // DYNSTAR: review star rating on every confirmed dropout
            if (wasConfirmed) await reviewDynamicStarRating(pool, gameId);
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Drop out error:', error);
        res.status(500).json({ error: 'Failed to drop out' });
    } finally {
        client.release();
    }
});

// PUT /api/admin/games/:gameId/player/:playerId/preferences — admin edits any player's prefs
app.put('/api/admin/games/:gameId/player/:playerId/preferences', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId, playerId } = req.params;
        const { positions, pairs, avoids, fixed_team } = req.body;

        // Find the registration — accept confirmed and backup players
        const regResult = await client.query(
            `SELECT r.id, g.team_selection_type, g.series_id, g.teams_generated
             FROM registrations r
             JOIN games g ON g.id = r.game_id
             WHERE r.game_id = $1 AND r.player_id = $2 AND r.status IN ('confirmed', 'backup')`,
            [gameId, playerId]
        );
        if (!regResult.rows.length) return res.status(404).json({ error: 'Registration not found' });
        const reg = regResult.rows[0];
        const registrationId = reg.id;

        await client.query('BEGIN');

        // Update position preference
        if (positions !== undefined) {
            await client.query(
                'UPDATE registrations SET position_preference = $1 WHERE id = $2',
                [positions || null, registrationId]
            );
        }

        // Update pair/avoid preferences
        if (pairs !== undefined || avoids !== undefined) {
            await client.query('DELETE FROM registration_preferences WHERE registration_id = $1', [registrationId]);
            const safePairs  = Array.isArray(pairs)  ? pairs.filter(id => id !== playerId)  : [];
            const safeAvoids = Array.isArray(avoids) ? avoids.filter(id => id !== playerId) : [];
            for (const id of safePairs) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair') ON CONFLICT DO NOTHING`,
                    [registrationId, id]
                );
            }
            for (const id of safeAvoids) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid') ON CONFLICT DO NOTHING`,
                    [registrationId, id]
                );
            }
        }

        // Update fixed_team (draft_memory only)
        if (fixed_team !== undefined && reg.team_selection_type === 'draft_memory' && reg.series_id) {
            if (fixed_team === 'red' || fixed_team === 'blue') {
                await client.query(
                    `INSERT INTO player_fixed_teams (player_id, series_id, fixed_team)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (player_id, series_id) DO UPDATE SET fixed_team = $3`,
                    [playerId, reg.series_id, fixed_team]
                );
            } else {
                await client.query(
                    'DELETE FROM player_fixed_teams WHERE player_id = $1 AND series_id = $2',
                    [playerId, reg.series_id]
                );
            }
        }

        await client.query('COMMIT');

        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'preferences_updated',
            `Admin updated prefs for player ${playerId}: pos=${positions ?? 'unchanged'} pairs=${(pairs||[]).length} avoids=${(avoids||[]).length}${fixed_team !== undefined ? ' team=' + fixed_team : ''}`
        ).catch(() => {}));

        res.json({ ok: true });
    } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Admin update player prefs error:', e.message);
        res.status(500).json({ error: 'Failed to update preferences' });
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
        const state = await client.query('SELECT teams_generated, team_selection_type, is_venue_clash FROM games WHERE id = $1', [gameId]);
        if (state.rows[0]?.teams_generated) {
            return res.status(400).json({ error: 'Cannot update preferences after teams have been generated' });
        }

        // Strip pairs/avoids for game modes where teams are never auto-drafted
        const noDraftMode = state.rows[0]?.team_selection_type === 'draft_memory'
            || state.rows[0]?.team_selection_type === 'vs_external'
            || state.rows[0]?.is_venue_clash;
        const safePairs  = noDraftMode ? [] : (pairs  || []);
        const safeAvoids = noDraftMode ? [] : (avoids || []);

        // FIX-047: Cap pairs/avoids at 10 each
        if (safePairs.length > 10 || safeAvoids.length > 10) {
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
        if (safePairs.length > 0) {
            for (const pairPlayerId of safePairs) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        
        // Add new avoids
        if (safeAvoids.length > 0) {
            for (const avoidPlayerId of safeAvoids) {
                await client.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid')`,
                    [registrationId, avoidPlayerId]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ message: 'Preferences updated successfully' });

        // Non-critical: audit preferences change with resolved names
        setImmediate(async () => {
            try {
                const _pRow = await pool.query('SELECT full_name, alias FROM players WHERE id = $1', [req.user.playerId]).catch(() => ({ rows: [] }));
                const _pName = _pRow.rows[0]?.alias || _pRow.rows[0]?.full_name || req.user.playerId;
                let _pairStr = '', _avoidStr = '';
                if (safePairs.length > 0) {
                    const _pairRows = await pool.query(
                        `SELECT COALESCE(alias, full_name) AS name FROM players WHERE id = ANY($1) ORDER BY alias, full_name`,
                        [safePairs]
                    ).catch(() => ({ rows: [] }));
                    if (_pairRows.rows.length) _pairStr = ` | Pair: ${_pairRows.rows.map(r => r.name).join(', ')}`;
                }
                if (safeAvoids.length > 0) {
                    const _avoidRows = await pool.query(
                        `SELECT COALESCE(alias, full_name) AS name FROM players WHERE id = ANY($1) ORDER BY alias, full_name`,
                        [safeAvoids]
                    ).catch(() => ({ rows: [] }));
                    if (_avoidRows.rows.length) _avoidStr = ` | Avoid: ${_avoidRows.rows.map(r => r.name).join(', ')}`;
                }
                const _noPrefs = !_pairStr && !_avoidStr;
                await gameAuditLog(pool, gameId, null, 'preferences_updated',
                    `${_pName} (${req.user.playerId})${_noPrefs ? ' | cleared all preferences' : `${_pairStr}${_avoidStr}`}`);
            } catch (e) { /* non-critical */ }
        });
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
                p.is_organiser,
                r.position_preference,
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY r.id, p.id, p.full_name, p.alias, p.squad_number, p.overall_rating, p.goalkeeper_rating, p.defending_rating, p.strength_rating, p.fitness_rating, p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating, p.is_organiser, r.position_preference
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
        for (const gkGroup of gkParentGroups) {
            const targetTeam = gkGroup.team === 'red' ? redTeam : blueTeam;
            const opposingTeam = gkGroup.team === 'red' ? blueTeam : redTeam;
            const teamLabel = gkGroup.team.toUpperCase();
            const oppLabel = gkGroup.team === 'red' ? 'BLUE' : 'RED';
            
            for (const guest of gkGroup.guests) {
                targetTeam.push(guest);
                
                const balancePlayer = findClosestSolo(guest.overall_rating || 0, soloPlayers);
                if (balancePlayer) {
                    opposingTeam.push(balancePlayer);
                }
            }
        }
        
        // PHASE 1: Place outfield guest groups with intertwined picking
        
        let nextTeamForGroup = 'red';
        
        for (const group of parentPlayers) {
            const targetTeam = nextTeamForGroup === 'red' ? redTeam : blueTeam;
            const opposingTeam = nextTeamForGroup === 'red' ? blueTeam : redTeam;
            const teamLabel = nextTeamForGroup.toUpperCase();
            const oppLabel = nextTeamForGroup === 'red' ? 'BLUE' : 'RED';
            
            targetTeam.push(group.parent);
            
            const matchPlayer = findClosestSolo(group.parent.overall_rating || 0, soloPlayers);
            if (matchPlayer) {
                opposingTeam.push(matchPlayer);
            }
            
            for (const guest of group.guests) {
                targetTeam.push(guest);
                
                const balancePlayer = findClosestSolo(guest.overall_rating || 0, soloPlayers);
                if (balancePlayer) {
                    opposingTeam.push(balancePlayer);
                }
            }
            
            nextTeamForGroup = nextTeamForGroup === 'red' ? 'blue' : 'red';
        }
        
        // ===================================================
        // PHASE 2: OVR Snake Draft (REPLACES old priority waterfall)
        // ===================================================
        // Why OVR-only sort: tested 10,000 games — composite sorting
        // (OVR + DEF*0.3 + FIT*0.3) degrades OVR balance in 26% of cases.
        // The snake's equalising property only holds when sorted by the
        // thing you're balancing. DEF+FIT is handled by Phase 3B instead.
        soloPlayers.sort((a, b) => (b.overall_rating || 0) - (a.overall_rating || 0));

        // Helper functions (used in Phase 2 and both swap passes below)
        const hasHighBeef = (player, team) => {
            const beefs = highBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        const hasLowBeef = (player, team) => {
            const beefs = lowBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        const wantsToPairWith = (player, team) =>
            (player.pairs || []).some(pid => team.find(tp => tp.player_id === pid));
        const wantsToAvoid = (player, team) =>
            (player.avoids || []).some(pid => team.find(tp => tp.player_id === pid));
        // Organiser split helper — counts organisers already placed on a team
        const orgCount = team => team.filter(p => p.is_organiser).length;

        // snakeIdx starts from total players already placed (Phases 0+1)
        // so the snake direction continues correctly rather than resetting.
        // Without this, two consecutive picks go to the same team.
        let snakeIdx = redTeam.length + blueTeam.length;
        for (const player of soloPlayers) {
            let assignToRed;
            if (redTeam.length > blueTeam.length) {
                assignToRed = false; // size
            } else if (blueTeam.length > redTeam.length) {
                assignToRed = true;  // size
            } else {
                // Snake direction
                const round = Math.floor(snakeIdx / 2);
                const posInRound = snakeIdx % 2;
                assignToRed = (round % 2 === 0) ? posInRound === 0 : posInRound === 1;
                // High beef override
                if (assignToRed && hasHighBeef(player, redTeam))  assignToRed = false;
                else if (!assignToRed && hasHighBeef(player, blueTeam)) assignToRed = true;
                // Organiser split — just below high beef; keeps organisers distributed across teams
                if (player.is_organiser) {
                    const redOrgs  = orgCount(redTeam);
                    const blueOrgs = orgCount(blueTeam);
                    if (redOrgs > blueOrgs)  assignToRed = false; // red already has more, push to blue
                    else if (blueOrgs > redOrgs) assignToRed = true;  // blue already has more, push to red
                    // If equal, snake direction already determined above — leave unchanged
                }
                // Pair preference (soft — only if beef/organiser split didn't already decide)
                const snakeResult = (round % 2 === 0) ? posInRound === 0 : posInRound === 1;
                if (assignToRed === snakeResult) {
                    if (wantsToPairWith(player, redTeam)  && !wantsToAvoid(player, redTeam))  assignToRed = true;
                    if (wantsToPairWith(player, blueTeam) && !wantsToAvoid(player, blueTeam)) assignToRed = false;
                }
                // Low beef — last tiebreaker
                if (assignToRed  && hasLowBeef(player, redTeam)  && !hasLowBeef(player, blueTeam)) assignToRed = false;
                if (!assignToRed && hasLowBeef(player, blueTeam) && !hasLowBeef(player, redTeam))  assignToRed = true;
            }
            if (assignToRed) { redTeam.push(player); }
            else             { blueTeam.push(player); }
            snakeIdx++;
        }

        // ===================================================
        // PHASE 3A: OVR Equalisation (NEW — does not exist today)
        // ===================================================
        const ovrSum = arr => arr.reduce((s, p) => s + (p.overall_rating || 0), 0);
        const defSum = arr => arr.reduce((s, p) => s + (p.defending_rating || 0), 0);
        const fitSum = arr => arr.reduce((s, p) => s + (p.fitness_rating || 0), 0);
        const swapAllowed = (rp, bp) => {
            const newRed  = redTeam.map(p  => p.player_id === rp.player_id ? bp : p);
            const newBlue = blueTeam.map(p => p.player_id === bp.player_id ? rp : p);
            if (hasHighBeef(rp, newBlue)) return false;
            if (hasHighBeef(bp, newRed))  return false;
            // Don't move rp if its pair partner is in red with it
            if ((rp.pairs || []).some(pid => redTeam.find(t => t.player_id === pid && t.player_id !== rp.player_id))) return false;
            // Don't move bp if its pair partner is in blue with it
            if ((bp.pairs || []).some(pid => blueTeam.find(t => t.player_id === pid && t.player_id !== bp.player_id))) return false;
            // Don't worsen organiser balance — a swap that puts both organisers on same team is blocked
            const orgImbalanceBefore = Math.abs(orgCount(redTeam) - orgCount(blueTeam));
            const orgImbalanceAfter  = Math.abs(orgCount(newRed)  - orgCount(newBlue));
            if (orgImbalanceAfter > orgImbalanceBefore) return false;
            return true;
        };
        for (let pass = 0; pass < 5; pass++) {
            const currentDiff = Math.abs(ovrSum(redTeam) - ovrSum(blueTeam));
            if (currentDiff <= 1) { break; }
            let best = null, bestDiff = currentDiff;
            for (let i = 0; i < redTeam.length; i++) {
                for (let j = 0; j < blueTeam.length; j++) {
                    if (!swapAllowed(redTeam[i], blueTeam[j])) continue;
                    const nr = redTeam.map(p  => p.player_id === redTeam[i].player_id  ? blueTeam[j] : p);
                    const nb = blueTeam.map(p => p.player_id === blueTeam[j].player_id ? redTeam[i]  : p);
                    const d  = Math.abs(ovrSum(nr) - ovrSum(nb));
                    if (d < bestDiff) { bestDiff = d; best = { i, j }; }
                }
            }
            if (best) {
                [redTeam[best.i], blueTeam[best.j]] = [blueTeam[best.j], redTeam[best.i]];
            } else {
                break;
            }
        }
        const lockedOvr = Math.abs(ovrSum(redTeam) - ovrSum(blueTeam));

        // ===================================================
        // PHASE 3B: DEF+FIT Optimisation (NEW — does not exist today)
        // ===================================================
        let currentLockedOvr = lockedOvr;
        for (let pass = 0; pass < 3; pass++) {
            const currSec = Math.abs(defSum(redTeam) - defSum(blueTeam)) + Math.abs(fitSum(redTeam) - fitSum(blueTeam));
            let best = null, bestSec = currSec, bestOvr = currentLockedOvr;
            for (let i = 0; i < redTeam.length; i++) {
                for (let j = 0; j < blueTeam.length; j++) {
                    if (!swapAllowed(redTeam[i], blueTeam[j])) continue;
                    const nr = redTeam.map(p  => p.player_id === redTeam[i].player_id  ? blueTeam[j] : p);
                    const nb = blueTeam.map(p => p.player_id === blueTeam[j].player_id ? redTeam[i]  : p);
                    const newOvr = Math.abs(ovrSum(nr) - ovrSum(nb));
                    const newSec = Math.abs(defSum(nr) - defSum(nb)) + Math.abs(fitSum(nr) - fitSum(nb));
                    // Only accept if OVR doesn't worsen AND secondary improves
                    if (newOvr <= currentLockedOvr && newSec < bestSec) {
                        bestSec = newSec; bestOvr = newOvr; best = { i, j };
                    }
                }
            }
            if (best) {
                [redTeam[best.i], blueTeam[best.j]] = [blueTeam[best.j], redTeam[best.i]];
                currentLockedOvr = bestOvr;
            } else {
                break;
            }
        }
        
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
        
        // Mark teams as generated and confirmed — auto-generate confirms immediately
        await pool.query(`UPDATE games SET teams_generated = TRUE, teams_confirmed = TRUE,
            game_status = CASE WHEN game_status = 'completed' THEN game_status ELSE 'confirmed' END
            WHERE id = $1`, [gameId]);

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
            // Email all players their team assignment (generate path also confirms teams)
            await sendTeamsConfirmedEmails(gameId);
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
        
        // Build a name lookup for pairs/avoids resolution
        const allGamePlayers = [...players, ...Array.from(guestGroups.values()).flat()];
        const playerNameLookup = new Map();
        for (const pl of allGamePlayers) {
            playerNameLookup.set(String(pl.player_id), pl.alias || pl.full_name || String(pl.player_id));
        }
        const mapPlayer = p => {
            const isGKOnly  = p.position_preference?.trim().toLowerCase() === 'gk';
            const pairIds   = (p.pairs  || []).filter(Boolean).map(String);
            const avoidIds  = (p.avoids || []).filter(Boolean).map(String);
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
                is_guest:     p.is_guest || false,
                pair_names:   pairIds.map(id => playerNameLookup.get(id)).filter(Boolean),
                avoid_names:  avoidIds.map(id => playerNameLookup.get(id)).filter(Boolean)
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
            gameurl: `https://totalfooty.co.uk/game.html?url=${cancelGameRow.game_url}`
        };
        const cancelledPlayerIds = registrations.rows.map(r => r.player_id);

        // Capture confirmed referee IDs before CASCADE deletes them
        // Filter out external refs (player_id IS NULL) — they have no push tokens
        const confirmedRefRows = await client.query(
            `SELECT player_id FROM game_referees WHERE game_id = $1 AND status = 'confirmed' AND player_id IS NOT NULL`,
            [gameId]
        );
        const cancelledRefIds = confirmedRefRows.rows.map(r => r.player_id);

        let totalRefunded = 0;
        for (const reg of registrations.rows) {
            const refundAmt = parseFloat(reg.amount_paid || fallbackCost);
            const refundTarget = reg.registered_by_player_id || reg.player_id;
            if (refundAmt > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [refundAmt, refundTarget]);
                await recordCreditTransaction(client, refundTarget, refundAmt, 'refund', 'Game cancelled - refund');
                totalRefunded++;
            }
        }
        const guests = await client.query('SELECT invited_by, guest_name, amount_paid FROM game_guests WHERE game_id = $1', [gameId]);
        for (const guest of guests.rows) {
            const guestRefund = parseFloat(guest.amount_paid || 0);
            if (guestRefund > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [guestRefund, guest.invited_by]);
                await recordCreditTransaction(client, guest.invited_by, guestRefund, 'refund', 'Game cancelled - +1 guest refund');
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
        setImmediate(() => auditLog(pool, req.user.playerId, 'game_deleted', null,
            `Game ${gameId} deleted by admin. Refunded ${totalRefunded} players. Date: ${cancelDate} | Venue: ${cancelGameData.venue}`));
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
            // Notify confirmed referees of cancellation
            for (const pid of cancelledRefIds) {
                await sendNotification('game_cancelled', pid, cancelGameData).catch(() => {});
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
        
        let seriesName = 'Unknown';
        let seriesGames;

        if (game.series_id) {
            // Modern path: series_id UUID exists — use it directly
            const seriesNameResult = await client.query(
                'SELECT series_name FROM game_series WHERE id = $1',
                [game.series_id]
            );
            seriesName = seriesNameResult.rows[0]?.series_name || 'Unknown';

            seriesGames = await client.query(`
                SELECT id FROM games
                WHERE series_id = $1
                AND game_date > CURRENT_TIMESTAMP
            `, [game.series_id]);
        } else {
            // Legacy path: game was created before series_id was added.
            // Match future games with same venue + format + day-of-week + weekly regularity.
            const anchorResult = await client.query(
                'SELECT venue_id, format, game_date FROM games WHERE id = $1',
                [gameId]
            );
            if (anchorResult.rows.length === 0) {
                client.release();
                return res.status(404).json({ error: 'Game not found' });
            }
            const anchor = anchorResult.rows[0];
            seriesName = anchor.format || 'Legacy series';

            seriesGames = await client.query(`
                SELECT id FROM games
                WHERE venue_id     = $1
                AND   format       = $2
                AND   regularity   = 'weekly'
                AND   series_id    IS NULL
                AND   EXTRACT(DOW FROM game_date AT TIME ZONE 'Europe/London')
                      = EXTRACT(DOW FROM $3::timestamptz AT TIME ZONE 'Europe/London')
                AND   game_date    > CURRENT_TIMESTAMP
            `, [anchor.venue_id, anchor.format, anchor.game_date]);
        }
        
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
                    await recordCreditTransaction(client, refundTarget, refundAmt, 'refund', 'Series ' + seriesName + ' cancelled - refund');
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
                    await recordCreditTransaction(client, guest.invited_by, guestRefund, 'refund', 'Series ' + seriesName + ' cancelled - +1 guest refund');
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
        const { game_date, venue_id, max_players, cost_per_player, star_rating, tournament_team_count, min_rating_enabled, refs_required, ref_pay, requires_organiser, external_opponent, tf_kit_color, opp_kit_color, position_type, format, exclusivity, tournament_name } = req.body;
        
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
            // Evaluate the 48hr check in JS to avoid PostgreSQL type ambiguity on $1
            const resetMinRatingFlag = new Date(game_date) > new Date(Date.now() + 48 * 60 * 60 * 1000);
            await pool.query(`
                UPDATE games 
                SET game_date = $1,
                    venue_id = $2, 
                    max_players = $3, 
                    cost_per_player = $4,
                    star_rating = $5,
                    star_rating_locked = CASE WHEN $5::smallint >= 4 THEN TRUE ELSE star_rating_locked END,
                    tournament_team_count = COALESCE($6, tournament_team_count),
                    min_rating_enabled = COALESCE($7, min_rating_enabled),
                    refs_required = COALESCE($9, refs_required),
                    ref_pay = COALESCE($10, ref_pay),
                    min_rating_drop_sent = CASE WHEN $12 THEN 0 ELSE min_rating_drop_sent END,
                    requires_organiser = COALESCE($11, requires_organiser),
                    external_opponent = $13,
                    tf_kit_color  = COALESCE($14, tf_kit_color),
                    opp_kit_color = COALESCE($15, opp_kit_color),
                    position_type = COALESCE($16, position_type),
                    format = COALESCE($17, format),
                    exclusivity = COALESCE($18, exclusivity),
                    tournament_name = COALESCE($19, tournament_name)
                WHERE id = $8
            `, [game_date, venue_id, max_players, cost_per_player, star_rating || null, tournament_team_count || null, min_rating_enabled !== undefined ? min_rating_enabled : null, gameId, refs_required !== undefined ? parseInt(refs_required) : null, ref_pay !== undefined ? parseFloat(ref_pay) : null, requires_organiser !== undefined ? !!requires_organiser : null, resetMinRatingFlag, external_opponent !== undefined ? (external_opponent || null) : null, tf_kit_color || null, opp_kit_color || null, position_type || null, format || null, exclusivity || null, tournament_name || null]);
        } else {
            await pool.query(`
                UPDATE games 
                SET venue_id = $1, 
                    max_players = $2, 
                    cost_per_player = $3,
                    star_rating = $4,
                    star_rating_locked = CASE WHEN $4::smallint >= 4 THEN TRUE ELSE star_rating_locked END,
                    tournament_team_count = COALESCE($5, tournament_team_count),
                    min_rating_enabled = COALESCE($6, min_rating_enabled),
                    refs_required = COALESCE($8, refs_required),
                    ref_pay = COALESCE($9, ref_pay),
                    requires_organiser = COALESCE($10, requires_organiser),
                    external_opponent = $11,
                    tf_kit_color  = COALESCE($12, tf_kit_color),
                    opp_kit_color = COALESCE($13, opp_kit_color),
                    position_type = COALESCE($14, position_type),
                    format = COALESCE($15, format),
                    exclusivity = COALESCE($16, exclusivity),
                    tournament_name = COALESCE($17, tournament_name)
                WHERE id = $7
            `, [venue_id, max_players, cost_per_player, star_rating || null, tournament_team_count || null, min_rating_enabled !== undefined ? min_rating_enabled : null, gameId, refs_required !== undefined ? parseInt(refs_required) : null, ref_pay !== undefined ? parseFloat(ref_pay) : null, requires_organiser !== undefined ? !!requires_organiser : null, external_opponent !== undefined ? (external_opponent || null) : null, tf_kit_color || null, opp_kit_color || null, position_type || null, format || null, exclusivity || null, tournament_name || null]);
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
            updated: { game_date, venue_id, max_players, cost_per_player, star_rating, tournament_team_count, min_rating_enabled }
        });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'settings_updated',
            `venue:${venue_id} max:${max_players} cost:£${cost_per_player}${game_date ? ' date:' + game_date : ''}${oldCost !== parseFloat(cost_per_player) ? ` (cost was £${oldCost})` : ''}${min_rating_enabled !== undefined ? ' minRating:' + min_rating_enabled : ''}`));
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
        const { venue_id, max_players, cost_per_player, star_rating, new_time, min_rating_enabled, requires_organiser, format, position_type, refs_required, ref_pay } = req.body;

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
                    'UPDATE games SET venue_id=$1, max_players=$2, cost_per_player=$3, star_rating=$4, star_rating_locked = CASE WHEN $4::smallint >= 4 THEN TRUE ELSE star_rating_locked END, game_date=$5, min_rating_enabled=COALESCE($6, min_rating_enabled), requires_organiser=COALESCE($8, requires_organiser), format=COALESCE($9, format), position_type=COALESCE($10, position_type), refs_required=COALESCE($11, refs_required), ref_pay=COALESCE($12, ref_pay) WHERE id=$7',
                    [venue_id, max_players, cost_per_player, star_rating || null, utcDate.toISOString(), min_rating_enabled !== undefined ? min_rating_enabled : null, g.id, requires_organiser !== undefined ? !!requires_organiser : null, format || null, position_type || null, refs_required !== undefined ? parseInt(refs_required) : null, ref_pay !== undefined ? parseFloat(ref_pay) : null]
                );
            } else {
                await client.query(
                    'UPDATE games SET venue_id=$1, max_players=$2, cost_per_player=$3, star_rating=$4, star_rating_locked = CASE WHEN $4::smallint >= 4 THEN TRUE ELSE star_rating_locked END, min_rating_enabled=COALESCE($5, min_rating_enabled), requires_organiser=COALESCE($7, requires_organiser), format=COALESCE($8, format), position_type=COALESCE($9, position_type), refs_required=COALESCE($10, refs_required), ref_pay=COALESCE($11, ref_pay) WHERE id=$6',
                    [venue_id, max_players, cost_per_player, star_rating || null, min_rating_enabled !== undefined ? min_rating_enabled : null, g.id, requires_organiser !== undefined ? !!requires_organiser : null, format || null, position_type || null, refs_required !== undefined ? parseInt(refs_required) : null, ref_pay !== undefined ? parseFloat(ref_pay) : null]
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
            // Email all confirmed players their team assignment
            await sendTeamsConfirmedEmails(gameId);
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

        // Audit: capture full team composition as one entry
        setImmediate(async () => {
            try {
                const nonGuestRed  = redTeam.filter(id => !String(id).startsWith('guest_'));
                const nonGuestBlue = blueTeam.filter(id => !String(id).startsWith('guest_'));
                const allNonGuests = [...nonGuestRed, ...nonGuestBlue];
                const nameMap = {};
                if (allNonGuests.length > 0) {
                    const nameRes = await pool.query(
                        `SELECT p.id, COALESCE(p.alias, p.full_name) AS name
                         FROM players p WHERE p.id = ANY($1)`,
                        [allNonGuests]
                    );
                    nameRes.rows.forEach(r => { nameMap[r.id] = r.name; });
                }
                const redNames   = nonGuestRed.map(id => nameMap[id] || id);
                const blueNames  = nonGuestBlue.map(id => nameMap[id] || id);
                const redGuests  = redTeam.filter(id => String(id).startsWith('guest_')).map(id => `Guest(${id.replace('guest_','')})`);
                const blueGuests = blueTeam.filter(id => String(id).startsWith('guest_')).map(id => `Guest(${id.replace('guest_','')})`);
                const detail = `RED: ${[...redNames,...redGuests].join(', ')} | BLUE: ${[...blueNames,...blueGuests].join(', ')}`;
                await gameAuditLog(pool, gameId, null, 'teams_confirmed', detail);
            } catch (e) {
                console.warn('Audit team composition failed (non-critical):', e.message);
            }
            sendTeamsConfirmedEmails(gameId);
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
            
            // Fix 06: fetch pairs/avoids so fine-tune modal can show pref icons
            // FIX-100: was reading dead r.pairs/r.avoids columns on registrations (always null).
            // Must JOIN registration_preferences — same pattern as generate-teams endpoint.
            const prefsResult = await pool.query(
                `SELECT r.player_id,
                        array_agg(DISTINCT rp_pair.target_player_id)
                            FILTER (WHERE rp_pair.preference_type  = 'pair')  AS pairs,
                        array_agg(DISTINCT rp_avoid.target_player_id)
                            FILTER (WHERE rp_avoid.preference_type = 'avoid') AS avoids
                 FROM registrations r
                 LEFT JOIN registration_preferences rp_pair
                        ON rp_pair.registration_id  = r.id
                       AND rp_pair.preference_type = 'pair'
                 LEFT JOIN registration_preferences rp_avoid
                        ON rp_avoid.registration_id = r.id
                       AND rp_avoid.preference_type = 'avoid'
                 WHERE r.game_id = $1 AND r.status = 'confirmed'
                 GROUP BY r.player_id`,
                [gameId]
            );
            const prefsMap = new Map();
            for (const row of prefsResult.rows) {
                prefsMap.set(String(row.player_id), {
                    pairs:  Array.isArray(row.pairs)  ? row.pairs.map(String)  : [],
                    avoids: Array.isArray(row.avoids) ? row.avoids.map(String) : []
                });
            }

            // Build name lookup from both team results for pair_names/avoid_names resolution
            const allTeamRows = [...redTeamResult.rows, ...blueTeamResult.rows];
            const nameMap = new Map();
            for (const row of allTeamRows) {
                nameMap.set(String(row.id), row.alias || row.full_name || String(row.id));
            }

            const mapTeamPlayer = p => {
                const isGKOnly = p.position_preference?.trim().toLowerCase() === 'gk';
                const prefs    = prefsMap.get(String(p.id)) || { pairs: [], avoids: [] };
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
                    position_preference: p.position_preference || 'outfield',
                    pair_names:   prefs.pairs.map(id => nameMap.get(id)).filter(Boolean),
                    avoid_names:  prefs.avoids.map(id => nameMap.get(id)).filter(Boolean)
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

// Vote for MOTM

// Get MOTM voting results

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
                        await recordCreditTransaction(client, playerId, refundAmount, 'refund', `Removed from game - £${refundAmount.toFixed(2)} refund`);
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
                    // Notify confirmed platform refs that the game has been unconfirmed
                    // External refs (player_id IS NULL) are skipped — no push tokens
                    const confirmedRefs = await pool.query(
                        `SELECT player_id FROM game_referees WHERE game_id = $1 AND status = 'confirmed' AND player_id IS NOT NULL`,
                        [gameId]
                    );
                    for (const r of confirmedRefs.rows) {
                        await sendNotification('game_cancelled', r.player_id, gameData).catch(() => {});
                    }
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

// PUT /api/admin/games/:gameId/player-stats — bulk update player stats from post-game wizard
// SEC: only confirmed players for this game can be updated; no guest rows; validated ranges
app.put('/api/admin/games/:gameId/player-stats', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId } = req.params;
    const { playerStats } = req.body; // array of { playerId, gk, def, str, fit, pac, dec, ass, sho }

    if (!Array.isArray(playerStats) || playerStats.length === 0) {
        return res.status(400).json({ error: 'playerStats must be a non-empty array' });
    }

    // Fetch confirmed players for this game
    const confirmedRes = await pool.query(
        `SELECT DISTINCT player_id FROM registrations WHERE game_id = $1 AND status = 'confirmed'`,
        [gameId]
    );
    const confirmedSet = new Set(confirmedRes.rows.map(r => r.player_id));

    const clamp = (v, min, max) => Math.max(min, Math.min(max, Math.round(v)));
    const errors = [];

    // STAT-AUDIT: Capture current stats BEFORE updating so we can store the diff
    const validIds = playerStats
        .filter(r => r.playerId && !String(r.playerId).startsWith('guest_') && confirmedSet.has(r.playerId))
        .map(r => r.playerId);
    const beforeMap = {};
    if (validIds.length > 0) {
        const beforeRes = await pool.query(
            `SELECT id, overall_rating, goalkeeper_rating, defending_rating, strength_rating,
                    fitness_rating, pace_rating, decisions_rating, assisting_rating, shooting_rating
             FROM players WHERE id = ANY($1)`,
            [validIds]
        );
        for (const r of beforeRes.rows) beforeMap[r.id] = r;
    }

    const statChanges = [];

    for (const row of playerStats) {
        // Skip guests (player_id starts with 'guest_')
        if (!row.playerId || String(row.playerId).startsWith('guest_')) continue;
        // IDOR: only confirmed participants
        if (!confirmedSet.has(row.playerId)) {
            errors.push(row.playerId);
            continue;
        }
        const gk  = clamp(parseInt(row.gk)  || 0, 0, 100);
        const def = clamp(parseInt(row.def) || 0, 0, 20);
        const str = clamp(parseInt(row.str) || 0, 0, 20);
        const fit = clamp(parseInt(row.fit) || 0, 0, 20);
        const pac = clamp(parseInt(row.pac) || 0, 0, 20);
        const dec = clamp(parseInt(row.dec) || 0, 0, 20);
        const ass = clamp(parseInt(row.ass) || 0, 0, 20);
        const sho = clamp(parseInt(row.sho) || 0, 0, 20);
        const ovr = def + str + fit + pac + dec + ass + sho;

        await pool.query(
            `UPDATE players
             SET goalkeeper_rating = $1,
                 defending_rating  = $2,
                 strength_rating   = $3,
                 fitness_rating    = $4,
                 pace_rating       = $5,
                 decisions_rating  = $6,
                 assisting_rating  = $7,
                 shooting_rating   = $8,
                 overall_rating    = $9
             WHERE id = $10`,
            [gk, def, str, fit, pac, dec, ass, sho, ovr, row.playerId]
        );

        const b = beforeMap[row.playerId] || {};
        statChanges.push({
            playerId: row.playerId,
            oldOverall: b.overall_rating    ?? null, newOverall: ovr,
            oldGk:      b.goalkeeper_rating ?? null, newGk:      gk,
            oldDef:     b.defending_rating  ?? null, newDef:     def,
            oldStr:     b.strength_rating   ?? null, newStr:     str,
            oldFit:     b.fitness_rating    ?? null, newFit:     fit,
            oldPac:     b.pace_rating       ?? null, newPac:     pac,
            oldDec:     b.decisions_rating  ?? null, newDec:     dec,
            oldAss:     b.assisting_rating  ?? null, newAss:     ass,
            oldSho:     b.shooting_rating   ?? null, newSho:     sho,
        });
    }

    // STAT-AUDIT: Upsert into game_stat_changes.
    // ON CONFLICT preserves old_* from first run (original baseline); updates new_* to latest values.
    if (statChanges.length > 0) {
        for (const c of statChanges) {
            await pool.query(
                `INSERT INTO game_stat_changes
                    (game_id, player_id, changed_by,
                     old_overall, new_overall, old_gk, new_gk,
                     old_def, new_def, old_str, new_str, old_fit, new_fit,
                     old_pac, new_pac, old_dec, new_dec, old_ass, new_ass, old_sho, new_sho)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
                 ON CONFLICT (game_id, player_id) DO UPDATE SET
                     changed_by  = EXCLUDED.changed_by,
                     new_overall = EXCLUDED.new_overall, new_gk  = EXCLUDED.new_gk,
                     new_def     = EXCLUDED.new_def,     new_str = EXCLUDED.new_str,
                     new_fit     = EXCLUDED.new_fit,     new_pac = EXCLUDED.new_pac,
                     new_dec     = EXCLUDED.new_dec,     new_ass = EXCLUDED.new_ass,
                     new_sho     = EXCLUDED.new_sho,     created_at = NOW()`,
                [gameId, c.playerId, req.user.playerId,
                 c.oldOverall, c.newOverall, c.oldGk, c.newGk,
                 c.oldDef, c.newDef, c.oldStr, c.newStr, c.oldFit, c.newFit,
                 c.oldPac, c.newPac, c.oldDec, c.newDec, c.oldAss, c.newAss,
                 c.oldSho, c.newSho]
            ).catch(e => console.warn('game_stat_changes upsert failed (non-critical):', e.message));
        }
    }

    if (errors.length > 0) {
        console.warn(`player-stats: skipped non-participants: ${errors.join(', ')}`);
    }

    setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'player_stats_updated',
        `Bulk stat update: ${playerStats.length} players`));

    res.json({ message: 'Player stats updated', updated: playerStats.length - errors.length });
});

app.post('/api/admin/games/:gameId/complete', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { winningTeam, disciplineRecords, beefEntries, motmNominees, teamBalanceScore, swappedPlayerIds } = req.body;

        // Validate teamBalanceScore
        let validatedBalanceScore = null;
        if (teamBalanceScore !== null && teamBalanceScore !== undefined) {
            const bs = parseInt(teamBalanceScore);
            if (isNaN(bs) || bs < -3 || bs > 3) {
                return res.status(400).json({ error: 'teamBalanceScore must be an integer between -3 and 3' });
            }
            validatedBalanceScore = bs;
        }

        // FIX-062: Whitelist winningTeam before any DB work
        const validTeams = ['red', 'blue', 'draw', 'Red', 'Blue', 'Draw'];
        if (!validTeams.includes(winningTeam)) {
            return res.status(400).json({ error: `Invalid winning team. Must be one of: ${validTeams.join(', ')}` });
        }

        // FIX-097: Combine both type queries into one — also grab series_id for FIX-086
        const gameTypeCheck = await pool.query('SELECT team_selection_type, game_status, series_id, star_rating FROM games WHERE id = $1', [gameId]);
        const gameType = gameTypeCheck.rows[0]?.team_selection_type;
        const gameStatus = gameTypeCheck.rows[0]?.game_status;
        const seriesUuidFromCheck = gameTypeCheck.rows[0]?.series_id;
        // S-class: vs_external and tournament games always award S regardless of star rating
        const starClass = gameTypeCheck.rows[0]?.team_selection_type === 'vs_external'
            ? 'S' : starClassFromRating(gameTypeCheck.rows[0]?.star_rating);

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
        // awards_open = true opens TF Game Awards voting automatically (replaces old MOTM nominee selection)
        await client.query(
            `UPDATE games 
             SET winning_team = $1, 
                 game_status = 'completed',
                 team_balance_score = $3,
                 motm_voting_ends = ${shouldHaveMotm ? "NOW() + INTERVAL '24 hours'" : 'NULL'},
                 awards_open = ${shouldHaveMotm ? 'true' : 'false'},
                 awards_close_at = ${shouldHaveMotm ? "NOW() + INTERVAL '24 hours'" : 'NULL'},
                 ref_review_ends = NOW() + INTERVAL '24 hours'
             WHERE id = $2`,
            [winningTeam, gameId, validatedBalanceScore]
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
            
            // Add swapped players who should receive a win (deduped, non-guest only)
            if (!isExternal && Array.isArray(swappedPlayerIds) && swappedPlayerIds.length > 0) {
                const winSet = new Set(winningPlayerIds);
                for (const sid of swappedPlayerIds) {
                    if (sid && !String(sid).startsWith('guest_') && !winSet.has(sid)) {
                        winningPlayerIds.push(sid);
                        winSet.add(sid);
                    }
                }
            }

            if (winningPlayerIds.length > 0) {
                const winsClassCol = `total_wins_${starClass.toLowerCase()}`;
                await client.query(
                    `UPDATE players 
                     SET total_wins = total_wins + 1, ${winsClassCol} = ${winsClassCol} + 1
                     WHERE id = ANY($1)`,
                    [winningPlayerIds]
                );
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
            // Use explicit column per winning team — never interpolate user-supplied values into SQL
            const seriesColMap = { red: 'red_wins', blue: 'blue_wins', draw: 'draws' };
            const seriesColSql = winningTeam === 'red'
                ? 'UPDATE game_series SET red_wins = red_wins + 1 WHERE id = $1'
                : winningTeam === 'blue'
                    ? 'UPDATE game_series SET blue_wins = blue_wins + 1 WHERE id = $1'
                    : 'UPDATE game_series SET draws = draws + 1 WHERE id = $1';
            await client.query(seriesColSql, [seriesUuidFromCheck]);
        }

        await client.query('COMMIT');
        // FIX-063: Single summary log replacing all step-by-step debug logs
        console.log(`Game ${gameId} completed. Winner: ${winningTeam}. MOTM nominees: ${nomineesInserted}`);

        // FIX-099: Refund confirmed backups who were never promoted when game completes
        // Runs after COMMIT in setImmediate — uses its own client per player to avoid blocking the response
        // NOTE: cost_per_player is NOT in scope here (game completion does not fetch it),
        // so we JOIN g.cost_per_player directly in the query
        setImmediate(async () => {
            try {
                const unpromotedBackups = await pool.query(
                    `SELECT r.id, r.player_id, r.is_comped, r.registered_by_player_id,
                            r.amount_paid, g.cost_per_player
                     FROM registrations r
                     JOIN games g ON g.id = r.game_id
                     WHERE r.game_id = $1
                       AND r.status = 'backup'
                       AND r.backup_type = 'confirmed_backup'`,
                    [gameId]
                );

                if (unpromotedBackups.rows.length === 0) return;

                console.log(`⏰ FIX-099: Refunding ${unpromotedBackups.rows.length} unused confirmed backup(s) for game ${gameId}`);

                for (const backup of unpromotedBackups.rows) {
                    const refundTarget = backup.registered_by_player_id || backup.player_id;
                    const wasComped    = !!backup.is_comped;
                    // Mirror exactly how the game was paid — same logic as the dropout refund:
                    //   amount_paid = real balance charged at signup  → restore as 'refund'
                    //   freeAmt     = free credits consumed at signup → restore as 'free_credit'
                    // amount_paid is now correctly stored at registration time.
                    // Null fallback: assume full real-balance payment if amount_paid missing.
                    const paidAmt = parseFloat(backup.amount_paid ?? backup.cost_per_player ?? 0);
                    const freeAmt = Math.max(0, parseFloat(backup.cost_per_player || 0) - paidAmt);

                    const refundClient = await pool.connect();
                    try {
                        await refundClient.query('BEGIN');

                        if (!wasComped) {
                            // Restore real-balance portion
                            if (paidAmt > 0) {
                                await refundClient.query(
                                    'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                                    [paidAmt, refundTarget]
                                );
                                await recordCreditTransaction(
                                    refundClient, refundTarget, paidAmt, 'refund',
                                    `Confirmed backup unused — real balance refund, game ${gameId}`
                                );
                            }
                            // Restore free-credit portion back to FC pool
                            if (freeAmt > 0) {
                                await refundClient.query(
                                    'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                                    [freeAmt, refundTarget]
                                );
                                await recordCreditTransaction(
                                    refundClient, refundTarget, freeAmt, 'free_credit',
                                    `Confirmed backup unused — free credit restored, game ${gameId}`
                                );
                            }
                        }

                        const totalRestored = wasComped ? 0 : paidAmt + freeAmt;
                        const notifMsg = wasComped
                            ? `The game has now ended. You were on the confirmed backup list but weren't needed — no charge was made.`
                            : totalRestored > 0
                                ? `The game has now ended. You were on the confirmed backup list but weren't needed — £${totalRestored.toFixed(2)} refunded to your balance.`
                                : `The game has now ended. You were on the confirmed backup list but weren't needed — no charge was made.`;

                        await refundClient.query(
                            `INSERT INTO notifications (player_id, type, message, game_id)
                             VALUES ($1, 'backup_refund', $2, $3)`,
                            [backup.player_id, notifMsg, gameId]
                        );

                        await refundClient.query('COMMIT');

                        await auditLog(pool, null, 'confirmed_backup_refund', backup.player_id,
                            `Game ${gameId} completed — ${wasComped ? 'comped, no charge' : `refunded £${totalRestored.toFixed(2)}`}`
                        ).catch(() => {});

                        console.log(`✅ FIX-099: Confirmed backup refund — player ${backup.player_id} ${wasComped ? '(comped, no charge)' : `refunded £${totalRestored.toFixed(2)}`} for game ${gameId}`);

                    } catch (e) {
                        await refundClient.query('ROLLBACK').catch(() => {});
                        console.error(`✗ FIX-099: Confirmed backup refund failed for player ${backup.player_id} game ${gameId}:`, e.message);
                    } finally {
                        refundClient.release();
                    }
                }
            } catch (e) {
                console.error(`✗ FIX-099: Confirmed backup refund sweep failed for game ${gameId}:`, e.message);
            }
        });

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

        // TF Game Awards — automated award checks (non-critical, run after commit)
        if (shouldHaveMotm) {
            setImmediate(async () => {
                try {
                    // Get day name and series info for Mr Day check
                    const gameInfoResult = await pool.query(
                        `SELECT series_id, TO_CHAR(game_date AT TIME ZONE 'Europe/London', 'Day') as day_name
                         FROM games WHERE id = $1`,
                        [gameId]
                    );
                    const gameInfo = gameInfoResult.rows[0];
                    const dayName = (gameInfo?.day_name || '').trim();
                    const seriesId = gameInfo?.series_id;

                    // Get winning player IDs for On Fire check
                    let winningPlayerIds = [];
                    if (winningTeam && winningTeam !== 'draw') {
                        if (isExternal && winningTeam === 'red') {
                            winningPlayerIds = showedUpPlayerIds;
                        } else if (!isExternal) {
                            const winningTeamName = winningTeam === 'red' ? 'Red' : 'Blue';
                            const wpResult = await pool.query(
                                `SELECT tp.player_id FROM team_players tp
                                 JOIN teams t ON t.id = tp.team_id
                                 WHERE t.game_id = $1 AND t.team_name = $2`,
                                [gameId, winningTeamName]
                            );
                            winningPlayerIds = wpResult.rows.map(r => r.player_id);
                        }
                    }

                    // Run all three automated checks
                    await checkMrDay(gameId, showedUpPlayerIds, seriesId, dayName, starClass);
                    await checkOnFire(gameId, showedUpPlayerIds, winningPlayerIds, starClass);
                    await checkBackFromDead(gameId, showedUpPlayerIds, starClass);
                } catch (e) {
                    console.error('Automated award checks failed (non-critical):', e.message);
                }
            });
        }

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
            motmVotingEnds: shouldHaveMotm ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() : null,
            awardsOpen: shouldHaveMotm,
            awardsCloseAt: shouldHaveMotm ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() : null,
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

// PUBLIC endpoint - Get team sheet by game URL (no auth required)
app.get('/api/public/game/:gameUrl/teams', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game by URL - allow confirmed games even if not completed
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1 AND (g.teams_confirmed = TRUE OR g.game_status = 'completed' OR g.is_venue_clash = TRUE OR g.venue_clash_team1_name IS NOT NULL)
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found or teams not confirmed yet' });
        }
        
        const game = gameResult.rows[0];

        // Fetch discipline records for this game — used by player list judge emoji
        const discResult = await pool.query(
            `SELECT dr.player_id, dr.offense_type, dr.points,
                    p.reliability_tier AS current_tier, p.alias, p.full_name
             FROM discipline_records dr
             JOIN players p ON p.id = dr.player_id
             WHERE dr.game_id = $1 AND dr.points > 0`,
            [game.id]
        );
        const disciplineMap = {};
        const tierFromPoints = pts => {
            if (pts >= 15) return 'black';
            if (pts >= 10) return 'white';
            if (pts >= 4)  return 'bronze';
            if (pts >= 1)  return 'silver';
            return 'gold';
        };
        if (discResult.rows.length > 0) {
            // Get prior discipline points per player (excluding this game) to detect tier changes
            const playerIds = discResult.rows.map(r => r.player_id);
            const priorResult = await pool.query(
                `SELECT dr2.player_id, COALESCE(SUM(dr2.points), 0) AS prior_pts
                 FROM discipline_records dr2
                 WHERE dr2.player_id = ANY($1::uuid[]) AND dr2.game_id != $2
                 GROUP BY dr2.player_id`,
                [playerIds, game.id]
            );
            const priorMap = {};
            for (const r of priorResult.rows) priorMap[r.player_id] = parseInt(r.prior_pts) || 0;
            for (const d of discResult.rows) {
                const tierBefore = tierFromPoints(priorMap[d.player_id] || 0);
                const tierAfter  = d.current_tier;
                disciplineMap[d.player_id] = {
                    offenseType: d.offense_type,
                    points:      d.points,
                    tierAfter,
                    tierBefore:  tierBefore !== tierAfter ? tierBefore : null,
                    name:        d.alias || d.full_name,
                };
            }
        }

        // ── VENUE CLASH BRANCH ───────────────────────────────────────────────
        if ((game.is_venue_clash || game.venue_clash_team1_name) && !game.teams_confirmed) {
            const t1 = game.venue_clash_team1_name;
            const t2 = game.venue_clash_team2_name;

            const playersResult = await pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url,
                       r.venue_clash_team_preference, r.position_preference
                FROM registrations r
                JOIN players p ON p.id = r.player_id
                WHERE r.game_id = $1 AND r.status = 'confirmed'
                ORDER BY COALESCE(p.alias, p.full_name)
            `, [game.id]);

            const team1 = [], team2 = [], flexible = [], undecided = [];
            for (const p of playersResult.rows) {
                const obj = {
                    id: p.id, name: p.alias || p.full_name,
                    squadNumber: p.squad_number, photo_url: p.photo_url,
                    isGK: p.position_preference === 'goalkeeper'
                };
                const pref = p.venue_clash_team_preference;
                if (pref === t1 || pref === 'team1') team1.push(obj);
                else if (pref === t2 || pref === 'team2') team2.push(obj);
                else if (pref === 'both') flexible.push(obj);
                else undecided.push(obj);
            }

            return res.json({
                isVenueClash: true,
                team1Name: t1, team2Name: t2,
                redTeam: team1, blueTeam: team2,
                flexible, undecided,
                disciplineMap,
                game: {
                    id: game.id, game_url: game.game_url,
                    team_selection_type: game.team_selection_type,
                    is_venue_clash: game.is_venue_clash,
                    venue_clash_team1_name: t1,
                    venue_clash_team2_name: t2,
                    teams_confirmed: false
                }
            });
        }

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
                    ORDER BY CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                    p.squad_number ASC NULLS LAST, p.motm_wins DESC NULLS LAST, p.total_appearances DESC NULLS LAST
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
            const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [game.id]);
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
                           p.motm_wins, p.total_appearances,
                           COUNT(v.id) as votes, (n.player_id = g.motm_winner_id) as is_winner
                    FROM motm_nominees n
                    JOIN players p ON p.id = n.player_id
                    JOIN games g ON g.id = n.game_id
                    LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
                    WHERE n.game_id = $1
                    GROUP BY n.player_id, p.full_name, p.alias, p.squad_number,
                             p.motm_wins, p.total_appearances, g.motm_winner_id
                    ORDER BY
                        CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                        p.squad_number ASC NULLS LAST,
                        p.motm_wins DESC NULLS LAST,
                        p.total_appearances DESC NULLS LAST
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
                motmNominees,
                disciplineMap
            });
        }
        
        // STANDARD 2-TEAM MODE
        const redTeamId = teamsResult.rows.find(t => t.team_name === 'Red')?.id;
        const blueTeamId = teamsResult.rows.find(t => t.team_name === 'Blue')?.id;
        
        // Get players for each team
        const [redTeamResult, blueTeamResult] = await Promise.all([
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position,
                       p.motm_wins, p.total_appearances
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY
                    CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                    p.squad_number ASC NULLS LAST,
                    p.motm_wins DESC NULLS LAST,
                    p.total_appearances DESC NULLS LAST
            `, [redTeamId, game.id]),
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position,
                       p.motm_wins, p.total_appearances
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY
                    CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                    p.squad_number ASC NULLS LAST,
                    p.motm_wins DESC NULLS LAST,
                    p.total_appearances DESC NULLS LAST
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
                    p.motm_wins,
                    p.total_appearances,
                    COUNT(v.id) as votes,
                    (n.player_id = g.motm_winner_id) as is_winner
                FROM motm_nominees n
                JOIN players p ON p.id = n.player_id
                JOIN games g ON g.id = n.game_id
                LEFT JOIN motm_votes v ON v.voted_for_id = n.player_id AND v.game_id = $1
                WHERE n.game_id = $1
                GROUP BY n.player_id, p.full_name, p.alias, p.squad_number,
                         p.motm_wins, p.total_appearances, g.motm_winner_id
                ORDER BY
                    CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                    p.squad_number ASC NULLS LAST,
                    p.motm_wins DESC NULLS LAST,
                    p.total_appearances DESC NULLS LAST
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
            seriesScoreline,
            disciplineMap
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
// GET /g/:gameUrl — Open Graph preview page for WhatsApp / social sharing
// Returns minimal HTML with OG tags (date + venue), then redirects to game.html.
// WhatsApp crawler sees the OG tags; real users are bounced in <1s.
app.get('/g/:gameUrl', async (req, res) => {
    // Legacy share-link route — kept so old /g/XXXX links still work after domain migration.
    // OG tag injection is now handled by the Cloudflare CSP Worker on game.html?url=...
    // This route simply redirects to the canonical game page URL.
    const { gameUrl } = req.params;
    const refParam = (req.query.ref && /^[a-zA-Z0-9_-]{1,40}$/.test(req.query.ref))
        ? `&ref=${encodeURIComponent(req.query.ref)}` : '';
    const dest = `https://totalfooty.co.uk/game.html?url=${encodeURIComponent(gameUrl)}${refParam}`;
    res.redirect(301, dest);
});

// PUT /api/games/:id/my-team-preference — let a confirmed player set their venue clash team side
// Used when a player was added by admin without a venue_clash_team_preference set
app.put('/api/games/:id/my-team-preference', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        const { venueClashTeam } = req.body;
        if (!venueClashTeam || typeof venueClashTeam !== 'string' || venueClashTeam.length > 50) {
            return res.status(400).json({ error: 'venueClashTeam is required' });
        }
        // Verify game is venue clash
        const gameCheck = await pool.query(
            'SELECT is_venue_clash, venue_clash_team1_name, venue_clash_team2_name FROM games WHERE id = $1',
            [gameId]
        );
        if (!gameCheck.rows.length || !gameCheck.rows[0].is_venue_clash) {
            return res.status(400).json({ error: 'This game is not a Venue Clash game' });
        }
        const g = gameCheck.rows[0];
        const validTeams = [g.venue_clash_team1_name, g.venue_clash_team2_name].filter(Boolean);
        if (!validTeams.includes(venueClashTeam)) {
            return res.status(400).json({ error: 'Invalid team name' });
        }
        // Player must be confirmed in this game
        const regCheck = await pool.query(
            "SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'",
            [gameId, req.user.playerId]
        );
        if (!regCheck.rows.length) {
            return res.status(403).json({ error: 'You are not confirmed in this game' });
        }
        await pool.query(
            'UPDATE registrations SET venue_clash_team_preference = $1 WHERE game_id = $2 AND player_id = $3',
            [venueClashTeam, gameId, req.user.playerId]
        );
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'team_preference_updated',
            `Player set venue clash team preference: ${venueClashTeam}`));
        res.json({ ok: true, venueClashTeam });
    } catch (error) {
        console.error('Set team preference error:', error);
        res.status(500).json({ error: 'Failed to set team preference' });
    }
});

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
                   g.regularity, g.star_rating, g.min_rating_enabled,
                   g.refs_required, g.ref_pay, g.ref_review_ends,
                   g.is_venue_clash, g.venue_clash_team1_name, g.venue_clash_team2_name,
                   g.requires_organiser, g.lineup_enabled,
                   v.name as venue_name, v.address as venue_address, v.photo_url as venue_photo,
                   v.pitch_location as venue_pitch_location, v.facilities as venue_facilities, v.notes as venue_notes,
                   v.postcode as venue_postcode, v.parking_pin as venue_parking_pin,
                   v.pitch_pin as venue_pitch_pin, v.boot_type as venue_boot_type,
                   v.pitch_name as venue_pitch_name, v.special_instructions as venue_special_instructions, v.region as venue_region,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   (SELECT COUNT(*) FROM registrations r JOIN players p ON p.id = r.player_id WHERE r.game_id = g.id AND r.status = 'confirmed' AND p.is_organiser = true) as confirmed_organiser_count
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
            'Daimler Green - Astro': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green - Grass': 'https://totalfooty.co.uk/assets/Daimler_Green_Grass.webp',
            'Daimler Green': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/Corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Power League': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
                'Nuneaton Academy':        'https://totalfooty.co.uk/assets/nuneaton_academy.webp',
                'Tudor Grange Academy':     'https://totalfooty.co.uk/assets/Tudor-Grange-pitch.webp',
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
            venue_postcode: game.venue_postcode || null,
            venue_parking_pin: game.venue_parking_pin || null,
            venue_pitch_pin: game.venue_pitch_pin || null,
            venue_boot_type: game.venue_boot_type || null,
            venue_pitch_name: game.venue_pitch_name || null,
            venue_special_instructions: game.venue_special_instructions || null,
            venue_region: game.venue_region || null,
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
            star_rating: game.star_rating || null,
            min_rating_enabled:   game.min_rating_enabled || false,
            refs_required:         game.refs_required || 0,
            ref_pay:          parseFloat(game.ref_pay) || 0,
            ref_review_ends: game.ref_review_ends || null,
            seriesScoreline,
            is_venue_clash: game.is_venue_clash || false,
            show_venue_clash_teams: !!(game.is_venue_clash || game.venue_clash_team1_name),
            venue_clash_team1_name: game.venue_clash_team1_name || null,
            venue_clash_team2_name: game.venue_clash_team2_name || null,
            requires_organiser: game.requires_organiser || false,
            confirmed_organiser_count: parseInt(game.confirmed_organiser_count) || 0,
            lineup_enabled: game.lineup_enabled || false
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
                CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                p.squad_number ASC NULLS LAST,
                p.motm_wins DESC NULLS LAST,
                p.total_appearances DESC NULLS LAST
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

// Get player profile (public)
// GET /api/public/games — public games list for unauthenticated visitors
// Returns upcoming + recently completed games. No tier gating, no PII, no registration status.
app.get('/api/public/games', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT g.id, g.game_url, g.game_date, g.game_status, g.format,
                   g.max_players, g.team_selection_type, g.tournament_name,
                   g.winning_team, g.motm_winner_id, g.teams_confirmed,
                   g.is_venue_clash, g.venue_clash_team1_name, g.venue_clash_team2_name,
                   g.external_opponent, g.tf_kit_color, g.opp_kit_color,
                   g.exclusivity, g.star_rating, g.cost_per_player,
                   v.name AS venue_name, v.address AS venue_address, v.region AS venue_region,
                   gs.series_name,
                   TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'HH24:MI') AS game_time,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed')
                     + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id) AS current_players,
                   motm_p.alias AS motm_winner_alias, motm_p.full_name AS motm_winner_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN game_series gs ON gs.id = g.series_id
            LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
            WHERE g.exclusivity IS NULL OR g.exclusivity NOT IN ('clm','allstars','misfits')
            ORDER BY
                CASE WHEN g.game_status IN ('available','confirmed') THEN 0 ELSE 1 END,
                g.game_date ASC
            LIMIT 300
        `);
        const venuePhotoMap = {
            'Daimler Green - Astro': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green - Grass': 'https://totalfooty.co.uk/assets/Daimler_Green_Grass.webp',
            'Daimler Green': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Daimler Green Community Centre': 'https://totalfooty.co.uk/assets/Daimler_Green.jpg',
            'Corpus Christi': 'https://totalfooty.co.uk/assets/Corpus_Christi.jpg',
            'War Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Memorial Park': 'https://totalfooty.co.uk/assets/war_memorial_park.jpg',
            'Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Power League': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Coventry Powerleague': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Powerleague Coventry': 'https://totalfooty.co.uk/assets/Powerleague.jpeg',
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/Sidney_Stringer_Academy.jpg',
                'Nuneaton Academy':        'https://totalfooty.co.uk/assets/nuneaton_academy.webp',
                'Tudor Grange Academy':     'https://totalfooty.co.uk/assets/Tudor-Grange-pitch.webp',
        };
        const rows = result.rows.map(game => {
            game.venue_photo = (game.venue_name && venuePhotoMap[game.venue_name]) || null;
            return game;
        });
        res.json(rows);
    } catch (error) {
        console.error('Public games list error:', error);
        res.status(500).json({ error: 'Failed to load games' });
    }
});

// GET /api/public/games/completed — all completed games with MOTM winners (no exclusivity filter)
// Used by admin social graphics hub — MOTM card needs to see CLM/restricted games too
app.get('/api/public/games/completed', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT g.id, g.game_url, g.game_date, g.format,
                   COALESCE(g.motm_winner_id, tfa.tfa_winner_id) AS motm_winner_id,
                   g.exclusivity,
                   v.name AS venue_name,
                   TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'HH24:MI') AS game_time,
                   COALESCE(motm_p.alias,     tfa.tfa_alias)  AS motm_winner_alias,
                   COALESCE(motm_p.full_name, tfa.tfa_name)   AS motm_winner_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
            LEFT JOIN LATERAL (
                SELECT ga.recipient_player_id AS tfa_winner_id,
                       p2.alias              AS tfa_alias,
                       p2.full_name          AS tfa_name
                FROM game_awards ga
                JOIN players p2 ON p2.id = ga.recipient_player_id
                WHERE ga.game_id = g.id AND ga.award_type = 'motm'
                ORDER BY ga.vote_count DESC NULLS LAST, ga.id ASC
                LIMIT 1
            ) tfa ON TRUE
            WHERE g.game_status = 'completed'
              AND (g.motm_winner_id IS NOT NULL OR tfa.tfa_winner_id IS NOT NULL)
            ORDER BY g.game_date DESC
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Public completed games error:', error);
        res.status(500).json({ error: 'Failed to load completed games' });
    }
});

// GET /api/public/players/leaderboard — public leaderboard (no auth, no PII)
app.get('/api/public/players/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.alias, p.full_name, p.squad_number, p.photo_url,
                   p.total_appearances, p.total_wins, p.motm_wins,
                   CASE WHEN p.total_appearances > 0
                        THEN ROUND(p.total_wins::numeric / p.total_appearances * 100, 1)
                        ELSE 0 END AS win_percent,
                   CASE WHEN p.total_appearances > 0
                        THEN ROUND(p.motm_wins::numeric / p.total_appearances * 100, 1)
                        ELSE 0 END AS motm_percent,
                   (SELECT json_agg(json_build_object('name', b.name, 'icon', b.icon))
                    FROM player_badges pb JOIN badges b ON pb.badge_id = b.id
                    WHERE pb.player_id = p.id) AS badges
            FROM players p
            WHERE p.total_appearances > 0
            ORDER BY p.total_appearances DESC, p.total_wins DESC
            LIMIT 50
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Public leaderboard error:', error);
        res.status(500).json({ error: 'Failed to load leaderboard' });
    }
});

app.get('/api/public/player/:playerId', publicPlayerLimiter, async (req, res) => {
    try {
        const { playerId } = req.params;
        
        // Get player by ID or squad number
        let playerResult;
        if (isNaN(playerId)) {
            // UUID
            playerResult = await pool.query(
                `SELECT id, full_name, alias, squad_number, photo_url, reliability_tier,
                        total_appearances, total_wins, motm_wins, ai_bio
                 FROM players WHERE id = $1`,
                [playerId]
            );
        } else {
            // Squad number
            playerResult = await pool.query(
                `SELECT id, full_name, alias, squad_number, photo_url, reliability_tier,
                        total_appearances, total_wins, motm_wins, ai_bio
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
                motm_ratio: motmRatio,
                ai_bio: player.ai_bio || null
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

        const gameInfo = await pool.query(
            'SELECT team_selection_type, series_id FROM games WHERE id = $1', [gameId]
        );
        const isDraftMemory = gameInfo.rows[0]?.team_selection_type === 'draft_memory' && gameInfo.rows[0]?.series_id;
        const seriesId = isDraftMemory ? gameInfo.rows[0].series_id : null;

        const result = await pool.query(`
            SELECT
                r.id as registration_id,
                p.id as player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                p.overall_rating,
                p.goalkeeper_rating,
                p.referral_code,
                r.status,
                r.position_preference,
                r.tournament_team_preference,
                ${isDraftMemory ? 'pft.fixed_team,' : 'NULL::text AS fixed_team,'}
                array_agg(DISTINCT rp_pair.target_player_id)  FILTER (WHERE rp_pair.preference_type  = 'pair')  AS pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') AS avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            ${isDraftMemory ? 'LEFT JOIN player_fixed_teams pft ON pft.player_id = p.id AND pft.series_id = $2' : ''}
            LEFT JOIN registration_preferences rp_pair  ON rp_pair.registration_id  = r.id AND rp_pair.preference_type  = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1
            GROUP BY r.id, p.id, p.full_name, p.alias, p.squad_number,
                     p.overall_rating, p.goalkeeper_rating, p.referral_code, r.status,
                     r.position_preference, r.tournament_team_preference
                     ${isDraftMemory ? ', pft.fixed_team' : ''}
            ORDER BY p.squad_number ASC NULLS LAST
        `, isDraftMemory ? [gameId, seriesId] : [gameId]);
        
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

        // Block if player is a confirmed referee for this game
        const addPlayerRefConflict = await pool.query(
            `SELECT 1 FROM game_referees WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [gameId, playerId]
        );
        if (addPlayerRefConflict.rows.length > 0) {
            return res.status(400).json({ error: 'This player is already confirmed as a referee for this game' });
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
        
            const { realCharged: adminAddCharged } = await applyGameFee(txClient, playerId, cost, `Admin added to game ${gameId}`);
        
            // Add player — normalise 'goalkeeper' -> 'GK' to match all server-side position checks
            const normPosition = (position || 'outfield').toLowerCase() === 'goalkeeper'
                ? 'GK'
                : (position || 'outfield');
            await txClient.query(
                `INSERT INTO registrations (game_id, player_id, status, position_preference, amount_paid)
                 VALUES ($1, $2, 'confirmed', $3, $4)`,
                [gameId, playerId, normPosition, adminAddCharged]
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
            reviewDynamicStarRating(pool, gameId); // DYNSTAR: admin add triggers rating review
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
        
        // BUG-01: Use transaction client so credit deduction + INSERT are atomic
        const discountClient = await pool.connect();
        try {
            await discountClient.query('BEGIN');
            const { realCharged: customAddCharged } = await applyGameFee(discountClient, playerId, customCharge, `Game registration (custom charge: £${customCharge.toFixed(2)})`);
            const normPosition = (position || 'outfield').toLowerCase() === 'goalkeeper' ? 'GK' : (position || 'outfield');
            await discountClient.query(
                `INSERT INTO registrations (game_id, player_id, status, position_preference, amount_paid)
                 VALUES ($1, $2, 'confirmed', $3, $4)`,
                [gameId, playerId, normPosition, customAddCharged]
            );
            await discountClient.query('COMMIT');
        } catch (txErr) {
            await discountClient.query('ROLLBACK').catch(() => {});
            throw txErr;
        } finally {
            discountClient.release();
        }
        res.json({ message: 'Player added with custom charge' });
        setImmediate(() => {
            registrationEvent(pool, gameId, playerId, 'admin_added', `Added by admin (discount) ${req.user.playerId}`);
            gameAuditLog(pool, gameId, req.user.playerId, 'admin_player_added', `Player ID: ${playerId} | Custom charge: £${customAmount}`);
            reviewDynamicStarRating(pool, gameId); // DYNSTAR: discounted admin add
        });
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
            'SELECT player_id, status, backup_type, position_preference, registered_by_player_id, amount_paid FROM registrations WHERE id = $1 AND game_id = $2',
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
            const paidAmt = parseFloat(removedReg.amount_paid ?? cost);
            const freeAmt = Math.max(0, cost - paidAmt);
            const refundDesc = refundTargetId !== playerId
                ? `Admin removed ${playerId} from game — refund to original payer`
                : `Admin removed from game ${gameId}`;
            if (paidAmt > 0) {
                await pool.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [paidAmt, refundTargetId]);
                await recordCreditTransaction(pool, refundTargetId, paidAmt, 'refund', refundDesc);
            }
            if (freeAmt > 0) {
                await pool.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [freeAmt, refundTargetId]);
                await recordCreditTransaction(pool, refundTargetId, freeAmt, 'free_credit', `Free credit restored — admin removed from game ${gameId}`);
            }
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
                // BUG-01b: Use transaction so status update + credit deduction are atomic
                const promoClient = await pool.connect();
                try {
                    await promoClient.query('BEGIN');
                    await promoClient.query(
                        `UPDATE registrations SET status = 'confirmed', backup_type = NULL WHERE id = $1`,
                        [promotedPlayer.id]
                    );
                    if (promotedPlayer.backup_type !== 'confirmed_backup') {
                        await applyGameFee(promoClient, promotedPlayer.player_id, cost, `Promoted from backup - game ${gameId}`);
                    }
                    await promoClient.query('COMMIT');
                } catch (promoErr) {
                    await promoClient.query('ROLLBACK').catch(() => {});
                    throw promoErr;
                } finally {
                    promoClient.release();
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

// Admin endpoint — manual finalize (still available as fallback)
// Idempotent: computes final avg from referee_reviews, writes to game_referees.final_rating
// Called by: game completion, MOTM scheduler, and ref_review_ends scheduler
async function finaliseRefereeReviews(gameId) {
    try {
        // Fetch all confirmed platform refs for this game — skip external refs (player_id IS NOT NULL)
        // External refs have no platform account so reviews cannot be linked to them
        const refs = await pool.query(
            `SELECT player_id FROM game_referees
             WHERE game_id = $1 AND status = 'confirmed' AND player_id IS NOT NULL`,
            [gameId]
        );
        if (refs.rows.length === 0) return;

        const gameData = await pool.query(
            `SELECT g.game_date, v.name AS venue_name
             FROM games g LEFT JOIN venues v ON v.id = g.venue_id WHERE g.id = $1`,
            [gameId]
        );
        const gd = gameData.rows[0] || {};
        const day = gd.game_date
            ? new Date(gd.game_date).toLocaleDateString('en-GB', { weekday:'long', day:'numeric', month:'long' })
            : '';
        const venue = gd.venue_name || 'TBC';

        for (const ref of refs.rows) {
            // Check existing final_rating to avoid re-emailing on subsequent scheduler runs
            const existingRow = await pool.query(
                'SELECT final_rating FROM game_referees WHERE game_id = $1 AND player_id = $2',
                [gameId, ref.player_id]
            );
            const alreadyFinalised = existingRow.rows[0]?.final_rating !== null &&
                                     existingRow.rows[0]?.final_rating !== undefined;

            const agg = await pool.query(
                `SELECT ROUND(AVG(rating)::numeric, 2) AS avg_rating,
                        COUNT(*)                       AS cnt
                 FROM referee_reviews
                 WHERE game_id = $1 AND referee_player_id = $2`,
                [gameId, ref.player_id]
            );
            const avgRating  = agg.rows[0]?.avg_rating || null;
            const cnt        = parseInt(agg.rows[0]?.cnt || 0);

            await pool.query(
                `UPDATE game_referees
                 SET final_rating = $1, review_count = $2
                 WHERE game_id = $3 AND player_id = $4`,
                [avgRating, cnt, gameId, ref.player_id]
            );

            setImmediate(() => {
                gameAuditLog(pool, gameId, null, 'ref_score_finalised',
                    `Referee ${ref.player_id} final avg: ${avgRating} (${cnt} reviews)`).catch(() => {});
                auditLog(pool, null, 'ref_score_finalised', ref.player_id,
                    `Final referee rating game ${gameId}: ${avgRating} (${cnt} reviews)`).catch(() => {});
            });

            // Email the referee their rating on first finalisation only
            if (cnt > 0 && avgRating && !alreadyFinalised) {
                setImmediate(async () => {
                    try {
                        const pRow = await pool.query(
                            `SELECT p.alias, p.full_name, u.email
                             FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
                            [ref.player_id]
                        );
                        if (!pRow.rows[0]?.email) return;
                        const name      = pRow.rows[0].alias || pRow.rows[0].full_name;
                        const starsHtml = '&#9733;'.repeat(Math.round(avgRating)) +
                                          '&#9734;'.repeat(5 - Math.round(avgRating));
                        await emailTransporter.sendMail({
                            from: '"TotalFooty" <totalfooty19@gmail.com>',
                            to:   pRow.rows[0].email,
                            subject: `⭐ Your referee rating — ${day}`,
                            html: wrapEmailHtml(`
                                <p style="font-size:16px;font-weight:700;">Hi ${htmlEncode(name)},</p>
                                <p style="color:#888;">The review period has closed for your game on ${htmlEncode(day)} at ${htmlEncode(venue)}.</p>
                                <div style="text-align:center;padding:28px 0;">
                                    <div style="font-size:38px;color:#ffd700;letter-spacing:4px;">${starsHtml}</div>
                                    <div style="font-size:52px;font-weight:900;margin:8px 0;">${htmlEncode(String(avgRating))}</div>
                                    <div style="color:#888;">average from ${cnt} review${cnt > 1 ? 's' : ''}</div>
                                </div>
                                <p style="text-align:center;color:#666;font-size:13px;">Thanks for officiating. See you on the pitch! ⚽</p>
                            `)
                        });
                    } catch (e) {
                        console.error('Referee rating email failed:', e.message);
                    }
                });
            }
        }
    } catch (e) {
        console.error('finaliseRefereeReviews error:', e.message);
    }
}



// ═══════════════════════════════════════════════════════════════════════════════
// TF GAME AWARDS — helper functions
// ═══════════════════════════════════════════════════════════════════════════════

const AWARD_TYPES = ['motm','best_engine','brick_wall','reckless_tackler','mr_hollywood','the_moaner','howler','donkey','goalscorer','hattrick'];
const POSITIVE_AWARDS = ['motm','best_engine','brick_wall','goalscorer','hattrick'];
const BANTER_AWARDS   = ['reckless_tackler','mr_hollywood','the_moaner','howler','donkey'];
const MIN_VOTES_REQUIRED = 3; // default for all awards except MOTM
const AWARD_MIN_VOTES = { goalscorer: 2 }; // per-award overrides

// Send email to a player for an award win — fire-and-forget, never throws
async function sendAwardEmail(playerId, awardType, extraData = {}) {
    try {
        const playerResult = await pool.query(
            'SELECT p.full_name, p.alias, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
            [playerId]
        );
        if (playerResult.rows.length === 0) return;
        const player = playerResult.rows[0];
        const displayName = player.alias || player.full_name;
        const to = player.email;
        if (!to) return;

        const templateMap = {
            motm:           'award_motm',
            best_engine:    'award_engine',
            brick_wall:     'award_wall',
            reckless_tackler: 'award_reckless',
            mr_hollywood:   'award_hollywood',
            the_moaner:     'award_moaner',
            howler:         'award_howler',
            donkey:         'award_donkey',
            mr_day:         'award_mr_day',
            on_fire:        'award_on_fire',
            back_from_dead: 'award_back_from_dead',
            engine_badge:   'award_engine_badge',
            wall_badge:     'award_wall_badge',
        };
        const tmplKey = templateMap[awardType];
        if (!tmplKey || !NOTIF_TEMPLATES[tmplKey]) return;
        const { title, body } = NOTIF_TEMPLATES[tmplKey]({ ...extraData, winnerName: displayName });

        await emailTransporter.sendMail({
            from: '"TotalFooty" <totalfooty19@gmail.com>',
            to,
            subject: title,
            html: wrapEmailHtml(
                `<p style="color:#888;font-size:14px;margin:0 0 16px">${htmlEncode(title)}</p>` +
                `<p style="color:#ccc;font-size:15px;margin:0 0 24px">${htmlEncode(body)}</p>` +
                `<p style="color:#555;font-size:13px;">View the game: ` +
                `<a href="https://totalfooty.co.uk/game.html?url=${encodeURIComponent(extraData.gameUrl || '')}" ` +
                `style="color:#c0392b;">See game page</a></p>`
            ),
        });
    } catch (e) {
        console.warn(`sendAwardEmail(${awardType}, ${playerId}) failed (non-critical):`, e.message);
    }
}

// Check and grant Engine or Brick Wall badge after award confirmation
async function checkAndGrantAwardBadge(playerId, awardType) {
    try {
        const badgeNameMap = { best_engine: 'Engine', brick_wall: 'Brick Wall', donkey: 'Donkey' };
        const badgeName = badgeNameMap[awardType];
        if (!badgeName) return;

        const countResult = await pool.query(
            'SELECT COUNT(*) as cnt FROM game_awards WHERE recipient_player_id = $1 AND award_type = $2',
            [playerId, awardType]
        );
        const cnt = parseInt(countResult.rows[0].cnt);
        if (cnt < 5) return;

        // Check badge exists and player doesn't already have it
        const badgeResult = await pool.query('SELECT id FROM badges WHERE name = $1', [badgeName]);
        if (badgeResult.rows.length === 0) return;
        const badgeId = badgeResult.rows[0].id;

        const alreadyHas = await pool.query(
            'SELECT 1 FROM player_badges WHERE player_id = $1 AND badge_id = $2',
            [playerId, badgeId]
        );
        if (alreadyHas.rows.length > 0) return;

        await pool.query(
            'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [playerId, badgeId]
        );
        const badgeEmailMap = { best_engine: 'engine_badge', brick_wall: 'wall_badge', donkey: 'donkey_badge' };
        const emailType = badgeEmailMap[awardType];
        if (emailType) setImmediate(() => sendAwardEmail(playerId, emailType, {}));
        console.log(`✅ ${badgeName} badge auto-granted to player ${playerId}`);
    } catch (e) {
        console.warn(`checkAndGrantAwardBadge(${awardType}, ${playerId}) failed:`, e.message);
    }
}

// Close awards for a game — tally votes, confirm winners, handle ties, send emails
async function closeAwards(gameId) {
    try {
        // Get game info
        const gameResult = await pool.query(
            `SELECT g.awards_open, g.awards_close_at, g.game_url, g.star_rating,
                    g.team_selection_type,
                    TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'Day') as day_name,
                    v.name as venue_name
             FROM games g LEFT JOIN venues v ON v.id = g.venue_id
             WHERE g.id = $1`,
            [gameId]
        );
        if (gameResult.rows.length === 0) return;
        const game = gameResult.rows[0];
        const dayName = (game.day_name || '').trim();
        const venueName = game.venue_name || 'the match';
        const gameUrl = game.game_url || '';
        // S-class: vs_external and tournament games always get S regardless of star rating
        const starClass = (game.team_selection_type === 'vs_external' || game.team_selection_type === 'tournament')
            ? 'S' : starClassFromRating(game.star_rating);

        // Mark awards closed
        await pool.query(
            'UPDATE games SET awards_open = false WHERE id = $1',
            [gameId]
        );

        // Get all votes for this game
        const votesResult = await pool.query(
            `SELECT award_type, nominee_player_id, COUNT(*) as votes
             FROM game_award_votes
             WHERE game_id = $1
             GROUP BY award_type, nominee_player_id`,
            [gameId]
        );

        // Group by award type
        const votesByAward = {};
        for (const row of votesResult.rows) {
            if (!votesByAward[row.award_type]) votesByAward[row.award_type] = [];
            votesByAward[row.award_type].push({ playerId: row.nominee_player_id, votes: parseInt(row.votes) });
        }

        const confirmedWinners = [];

        for (const awardType of AWARD_TYPES) {
            const nominees = (votesByAward[awardType] || []).sort((a, b) => b.votes - a.votes);
            if (nominees.length === 0) continue;

            const maxVotes = nominees[0].votes;
            const minVotes = AWARD_MIN_VOTES[awardType] ?? MIN_VOTES_REQUIRED;
            if (awardType !== 'motm' && maxVotes < minVotes) continue;

            const winners = nominees.filter(n => n.votes === maxVotes);

            for (const winner of winners) {
                const motmValue = awardType === 'motm' ? (1.0 / winners.length) : 1.00;

                // Check not already inserted (idempotency)
                const exists = await pool.query(
                    'SELECT 1 FROM game_awards WHERE game_id = $1 AND recipient_player_id = $2 AND award_type = $3',
                    [gameId, winner.playerId, awardType]
                );
                if (exists.rows.length > 0) continue;

                await pool.query(
                    `INSERT INTO game_awards (game_id, recipient_player_id, award_type, award_source, motm_value, vote_count, star_class)
                     VALUES ($1, $2, $3, 'voted', $4, $5, $6)`,
                    [gameId, winner.playerId, awardType, motmValue, winner.votes, starClass]
                );

                // Update players.motm_wins for MOTM
                if (awardType === 'motm') {
                    const motmClassCol = `motm_wins_${starClass.toLowerCase()}`;
                    await pool.query(
                        `UPDATE players SET motm_wins = motm_wins + $1, ${motmClassCol} = ${motmClassCol} + $1 WHERE id = $2`,
                        [motmValue, winner.playerId]
                    );
                    // FIX-100: Also write winner back to games.motm_winner_id
                    // AND motm_winner_id IS NULL guards against overwriting in a tie
                    await pool.query(
                        'UPDATE games SET motm_winner_id = $1 WHERE id = $2 AND motm_winner_id IS NULL',
                        [winner.playerId, gameId]
                    );
                }

                confirmedWinners.push({ awardType, playerId: winner.playerId, votes: winner.votes, motmValue });

                // Send notification + email (non-critical, async)
                setImmediate(async () => {
                    try {
                        const notifTypeMap = {
                            motm: 'motm_winner', best_engine: 'teams_created',
                        };
                        await sendAwardEmail(winner.playerId, awardType, {
                            day: dayName, venue: venueName, gameUrl
                        });
                        if (awardType === 'motm') {
                            // Also send existing push notification for MOTM
                            const pResult = await pool.query(
                                'SELECT p.alias, p.full_name FROM players p WHERE p.id = $1', [winner.playerId]
                            );
                            const winnerName = pResult.rows[0]?.alias || pResult.rows[0]?.full_name || 'Player';
                            await sendNotification('motm_winner', winner.playerId, {
                                day: dayName, venue: venueName, winnerName
                            });
                            // Regenerate bio after MOTM win
                            setImmediate(() => regeneratePlayerBio(winner.playerId));
                        }
                        // Badge checks for Best Engine, Brick Wall and Donkey
                        if (awardType === 'best_engine' || awardType === 'brick_wall' || awardType === 'donkey') {
                            await checkAndGrantAwardBadge(winner.playerId, awardType);
                            // Regenerate bio after badge grant
                            setImmediate(() => regeneratePlayerBio(winner.playerId));
                        }
                    } catch (e) {
                        console.warn(`Post-close award processing failed (${awardType}):`, e.message);
                    }
                });
            }
        }

        // Admin summary email
        if (confirmedWinners.length > 0) {
            setImmediate(async () => {
                try {
                    // BUG-03: was missing await, pResult was a Promise — player names never resolved
                    const playerRows = await Promise.all(
                        confirmedWinners.map(w =>
                            pool.query('SELECT alias, full_name FROM players WHERE id = $1', [w.playerId])
                        )
                    );
                    const winnerLines = confirmedWinners.map((w, idx) => {
                        const p = playerRows[idx]?.rows[0];
                        const name = p?.alias || p?.full_name || `Player ${w.playerId}`;
                        return [w.awardType, `${name} (${w.votes} votes)`];
                    });
                    await notifyAdmin(`📋 TF Game Awards closed — ${dayName} at ${venueName}`, [
                        ['Game', `${dayName} at ${venueName}`],
                        ['Awards confirmed', String(confirmedWinners.length)],
                        ...winnerLines,
                    ]);
                } catch (e) { /* non-critical */ }
            });
        }

        console.log(`✅ Awards closed for game ${gameId}: ${confirmedWinners.length} award(s) confirmed`);
        return { confirmedWinners };
    } catch (e) {
        console.error(`closeAwards(${gameId}) failed:`, e.message);
    }
}


// ============================================================
// WS2: AI PLAYER BIOS
// ============================================================

const BIO_SYSTEM_PROMPT = `You are the TotalFooty bio writer for a grassroots football community across Coventry and Nuneaton.
Write a player bio that reads like a Football Manager scouting report crossed with WhatsApp group banter. Tone: factual, specific, readable, confident.
Do not be sycophantic. Do not use filler phrases like 'a true asset to the team'.
Do not mention specific scores or opponents. Do not invent facts. Do not mention or infer any player's overall rating, skill rating, or numerical skill level — these are not public knowledge.
Keep it to 3-4 sentences maximum. Use the player's alias (not full name).
Reference specific stats where they add colour — not just to pad the bio.
If the player is a goalkeeper, focus on GK stats. If outfield, focus on their strongest attributes and role. If they have notable awards, weave them in naturally.
Output plain text only — no markdown, no bullet points, no headers.`;

function buildAwardsText(player, awardsData) {
    if (!awardsData) return 'No awards yet';
    const parts = [];
    const c = awardsData.counts || {};
    if (parseFloat(awardsData.motmTotal) > 0) parts.push(`MOTM wins: ${awardsData.motmTotal}`);
    if (c.best_engine > 0) parts.push(`Best Engine wins: ${c.best_engine}`);
    if (c.brick_wall > 0) parts.push(`Brick Wall wins: ${c.brick_wall}`);
    if (c.donkey > 0) parts.push(`Donkey Award wins: ${c.donkey}`);
    const badges = (player.badges || []).map(b => b.name).filter(Boolean);
    if (badges.length > 0) parts.push(`Badges: ${badges.join(', ')}`);
    return parts.length > 0 ? parts.join('\n') : 'No awards yet';
}

async function generatePlayerBio(player, awardsData, recentForm) {
    if (!ANTHROPIC_API_KEY) return null;
    if ((player.total_appearances || 0) < 5) return null;

    try {
        const tfApps = awardsData?.tfApps || 0;
        const tfWins = awardsData?.tfWins || 0;
        const winPct  = tfApps > 0 ? ((tfWins / tfApps) * 100).toFixed(1) : '0.0';
        const motmPct = tfApps > 0
            ? ((player.motm_wins / tfApps) * 100).toFixed(1) : '0.0';
        const awardsText = buildAwardsText(player, awardsData);
        const formStr = recentForm.map(g => g.won ? 'W' : g.drew ? 'D' : 'L').join(' ');
        const year = new Date(player.created_at).getFullYear();
        const isGK = (player.position || '').toLowerCase() === 'goalkeeper';

        const userMessage = [
            `Write a bio for this TotalFooty player:`,
            `Name: ${player.alias || player.full_name}`,
            `Position: ${isGK ? 'Goalkeeper' : 'Outfield'}`,
            player.squad_number != null ? `Squad number: #${player.squad_number}` : null,
            ``,
            `Stats (TotalFooty games only, excluding external friendlies):`,
            `- TF Appearances: ${tfApps}`,
            `- Win rate: ${winPct}% (${tfWins} wins from ${tfApps} games)`,
            `- MOTM wins: ${player.motm_wins} (MOTM rate: ${motmPct}%)`,
            `- Member since: ${year}`,
            `- Reliability tier: ${player.reliability_tier || 'new'}`,
            recentForm.length > 0 ? `- Recent form (last 5 TF games): ${formStr}` : null,
            awardsData?.currentWinStreak >= 2 ? `- Current win streak: ${awardsData.currentWinStreak} games` : null,
            ``,
            `Awards:`,
            awardsText,
        ].filter(l => l !== null).join('\n');

        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-6',
                max_tokens: 300,
                system: BIO_SYSTEM_PROMPT,
                messages: [{ role: 'user', content: userMessage }],
            }),
        });

        if (!response.ok) {
            let errBody = '';
            try { errBody = JSON.stringify(await response.json()); } catch (_) {}
            console.error(`❌ Anthropic API error for player ${player.id}: HTTP ${response.status} — ${errBody}`);
            return null;
        }
        const data = await response.json();
        const bio = data.content?.[0]?.text?.trim() || null;
        if (!bio) {
            console.error(`❌ Anthropic returned empty bio for player ${player.id}:`, JSON.stringify(data));
        }
        return bio;

    } catch (e) {
        console.error(`❌ generatePlayerBio network/parse error for player ${player.id}:`, e.message);
        return null;
    }
}

// Fetch awards + recent form for a player, then generate + save bio
async function regeneratePlayerBioForce(playerId, force = false) {
    // Wrapper that bypasses the 5-appearance threshold when force=true
    if (force) {
        // Temporarily patch the player object to pass the threshold check
        try {
            const playerRes = await pool.query(
                `SELECT p.*,
                    (SELECT json_agg(json_build_object('name', b.name, 'icon', b.icon))
                     FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                     WHERE pb.player_id = p.id) as badges
                 FROM players p WHERE p.id = $1`, [playerId]
            );
            if (!playerRes.rows[0]) return;
            const player = { ...playerRes.rows[0], total_appearances: Math.max(playerRes.rows[0].total_appearances || 0, 5) };

            const [awardsRes, formRes, streakRes, tfStatsRes] = await Promise.all([
                pool.query(`SELECT award_type, motm_value, vote_count FROM game_awards WHERE recipient_player_id = $1`, [playerId]),
                pool.query(`SELECT g.winning_team, t.team_name FROM registrations r JOIN games g ON g.id = r.game_id LEFT JOIN team_players tp ON tp.player_id = r.player_id LEFT JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id WHERE r.player_id = $1 AND g.game_status = 'completed' AND g.team_selection_type != 'vs_external' ORDER BY g.game_date DESC LIMIT 5`, [playerId]),
                pool.query(`SELECT current_win_streak FROM player_streaks WHERE player_id = $1`, [playerId]).catch(() => ({ rows: [] })),
                pool.query(
                `SELECT
                    COUNT(*) FILTER (WHERE r.status = 'confirmed') AS tf_apps,
                    COUNT(*) FILTER (WHERE r.status = 'confirmed'
                        AND g.winning_team IS NOT NULL AND g.winning_team != 'draw'
                        AND EXISTS (
                            SELECT 1 FROM team_players tp2
                            JOIN teams t2 ON t2.id = tp2.team_id AND t2.game_id = g.id
                            WHERE tp2.player_id = r.player_id
                            AND LOWER(t2.team_name) = LOWER(g.winning_team)
                        )) AS tf_wins
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = $1 AND g.game_status = 'completed'
                 AND g.team_selection_type != 'vs_external'`, [playerId]
            )
            ]);

            const counts = {};
            let motmTotal = 0;
            for (const row of awardsRes.rows) {
                counts[row.award_type] = (counts[row.award_type] || 0) + 1;
                if (row.award_type === 'motm') motmTotal += parseFloat(row.motm_value || 1);
            }
            const tfApps = parseInt(tfStatsRes.rows[0]?.tf_apps || 0);
            const tfWins = parseInt(tfStatsRes.rows[0]?.tf_wins || 0);
            const awardsData = { counts, motmTotal: Math.round(motmTotal * 100) / 100, currentWinStreak: streakRes.rows[0]?.current_win_streak || 0, tfApps, tfWins };
            const recentForm = formRes.rows.map(r => ({
                won: r.winning_team === 'draw' ? false
                    : r.team_name
                        ? r.winning_team && r.winning_team.toLowerCase() === r.team_name.toLowerCase()
                        : r.winning_team === 'red', // no team_name = external game, red = TF wins
                drew: r.winning_team === 'draw',
            }));

            const bio = await generatePlayerBio(player, awardsData, recentForm);
            if (bio) {
                await pool.query(`UPDATE players SET ai_bio = $1, ai_bio_updated_at = NOW() WHERE id = $2`, [bio, playerId]);
                console.log(`✅ Bio force-generated for player ${playerId}`);
            } else {
                console.error(`❌ Bio force-regen returned null for player ${playerId} — check Anthropic API key and logs above`);
            }
        } catch (e) {
            console.error(`❌ regeneratePlayerBioForce(${playerId}) failed:`, e.message);
        }
        return;
    }
    return regeneratePlayerBio(playerId);
}

async function regeneratePlayerBio(playerId) {
    try {
        const playerRes = await pool.query(
            `SELECT p.*,
                (SELECT json_agg(json_build_object('name', b.name, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                 WHERE pb.player_id = p.id) as badges
             FROM players p WHERE p.id = $1`, [playerId]
        );
        if (!playerRes.rows[0]) return;
        const player = playerRes.rows[0];
        if ((player.total_appearances || 0) < 5) return;

        const [awardsRes, formRes, streakRes, tfStatsRes] = await Promise.all([
            pool.query(
                `SELECT award_type, motm_value, vote_count FROM game_awards WHERE recipient_player_id = $1`,
                [playerId]
            ),
            pool.query(
                `SELECT g.winning_team, t.team_name
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 LEFT JOIN team_players tp ON tp.player_id = r.player_id
                 LEFT JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                 WHERE r.player_id = $1 AND g.game_status = 'completed'
                 AND g.team_selection_type != 'vs_external'
                 ORDER BY g.game_date DESC LIMIT 5`, [playerId]
            ),
            pool.query(
                `SELECT current_win_streak FROM player_streaks WHERE player_id = $1`, [playerId]
            ).catch(() => ({ rows: [] })),
            pool.query(
                `SELECT
                    COUNT(*) FILTER (WHERE r.status = 'confirmed') AS tf_apps,
                    COUNT(*) FILTER (WHERE r.status = 'confirmed'
                        AND g.winning_team IS NOT NULL AND g.winning_team != 'draw'
                        AND EXISTS (
                            SELECT 1 FROM team_players tp2
                            JOIN teams t2 ON t2.id = tp2.team_id AND t2.game_id = g.id
                            WHERE tp2.player_id = r.player_id
                            AND LOWER(t2.team_name) = LOWER(g.winning_team)
                        )) AS tf_wins
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = $1 AND g.game_status = 'completed'
                 AND g.team_selection_type != 'vs_external'`, [playerId]
            )
        ]);

        const counts = {};
        let motmTotal = 0;
        for (const row of awardsRes.rows) {
            counts[row.award_type] = (counts[row.award_type] || 0) + 1;
            if (row.award_type === 'motm') motmTotal += parseFloat(row.motm_value || 1);
        }
        const tfApps = parseInt(tfStatsRes.rows[0]?.tf_apps || 0);
        const tfWins = parseInt(tfStatsRes.rows[0]?.tf_wins || 0);
        const awardsData = {
            counts,
            motmTotal: Math.round(motmTotal * 100) / 100,
            currentWinStreak: streakRes.rows[0]?.current_win_streak || 0,
            tfApps,
            tfWins,
        };

        const recentForm = formRes.rows.map(r => ({
            won: r.winning_team === 'draw' ? false
                : r.team_name
                    ? r.winning_team && r.winning_team.toLowerCase() === r.team_name.toLowerCase()
                    : r.winning_team === 'red', // no team_name = external game, red = TF wins
            drew: r.winning_team === 'draw',
        }));

        const bio = await generatePlayerBio(player, awardsData, recentForm);
        if (bio) {
            await pool.query(
                `UPDATE players SET ai_bio = $1, ai_bio_updated_at = NOW() WHERE id = $2`,
                [bio, playerId]
            );
            console.log(`✅ Bio generated for player ${playerId}`);
        } else {
            console.error(`❌ Bio regen returned null for player ${playerId} — check Anthropic API key and logs above`);
        }
    } catch (e) {
        console.error(`❌ regeneratePlayerBio(${playerId}) failed:`, e.message);
    }
}

// Check Mr [Day] — 7 consecutive appearances in same series
async function checkMrDay(gameId, playerIds, seriesId, dayName, starClass = 'D') {
    if (!seriesId || !playerIds.length || !dayName) return;
    const normalizedDay = dayName.trim().toLowerCase();
    const awardType = `mr_${normalizedDay}`; // e.g. mr_wednesday

    for (const playerId of playerIds) {
        try {
            // Get this player's streak row
            const streakResult = await pool.query(
                'SELECT series_streaks, mr_day_awarded FROM player_streaks WHERE player_id = $1',
                [playerId]
            );
            if (streakResult.rows.length === 0) continue;
            const streaks = streakResult.rows[0].series_streaks || {};
            const awarded = streakResult.rows[0].mr_day_awarded || {};

            // Check if already awarded for this series
            if (awarded[seriesId]) continue;

            // Count consecutive appearances in this series (check last game before this one)
            const prevGamesResult = await pool.query(
                `SELECT g.id FROM games g
                 JOIN registrations r ON r.game_id = g.id
                 WHERE g.series_id = $1
                   AND r.player_id = $2
                   AND r.status = 'confirmed'
                   AND g.game_status = 'completed'
                   AND g.id != $3
                 ORDER BY g.game_date DESC`,
                [seriesId, playerId, gameId]
            );

            // Count consecutive from most recent backwards
            let consecutive = 1; // include current game
            const prevIds = prevGamesResult.rows.map(r => r.id);

            // Get all series games in order to check for gaps
            const allSeriesGamesResult = await pool.query(
                `SELECT g.id,
                        EXISTS(SELECT 1 FROM registrations r2
                               WHERE r2.game_id = g.id AND r2.player_id = $1 AND r2.status = 'confirmed') as played
                 FROM games g
                 WHERE g.series_id = $2 AND g.game_status = 'completed' AND g.id != $3
                 ORDER BY g.game_date DESC
                 LIMIT 10`,
                [playerId, seriesId, gameId]
            );

            for (const row of allSeriesGamesResult.rows) {
                if (row.played) consecutive++;
                else break; // gap found
            }

            if (consecutive >= 7) {
                // Grant Mr Day award
                const exists = await pool.query(
                    'SELECT 1 FROM game_awards WHERE game_id = $1 AND recipient_player_id = $2 AND award_type = $3',
                    [gameId, playerId, awardType]
                );
                if (exists.rows.length === 0) {
                    await pool.query(
                        `INSERT INTO game_awards (game_id, recipient_player_id, award_type, award_source, series_day, star_class)
                         VALUES ($1, $2, $3, 'automated', $4, $5)`,
                        [gameId, playerId, awardType, normalizedDay, starClass]
                    );
                    // Mark as awarded for this series
                    awarded[seriesId] = true;
                    await pool.query(
                        'UPDATE player_streaks SET mr_day_awarded = $1 WHERE player_id = $2',
                        [JSON.stringify(awarded), playerId]
                    );
                    const capDay = normalizedDay.charAt(0).toUpperCase() + normalizedDay.slice(1);
                    setImmediate(() => sendAwardEmail(playerId, 'mr_day', { day: capDay }));
                    console.log(`✅ Mr ${capDay} awarded to player ${playerId} (${consecutive} consecutive)`);
                }
            } else {
                // Update streak count for info
                streaks[seriesId] = consecutive;
                await pool.query(
                    'UPDATE player_streaks SET series_streaks = $1 WHERE player_id = $2',
                    [JSON.stringify(streaks), playerId]
                );
            }
        } catch (e) {
            console.warn(`checkMrDay failed for player ${playerId}:`, e.message);
        }
    }
}

// Check On Fire — 4 consecutive wins (one award per streak, live counter always shown)
async function checkOnFire(gameId, playerIds, winningPlayerIds, starClass = 'D') {
    const winnerSet = new Set(winningPlayerIds);

    for (const playerId of playerIds) {
        try {
            const streakResult = await pool.query(
                'SELECT current_win_streak, on_fire_awarded FROM player_streaks WHERE player_id = $1',
                [playerId]
            );
            if (streakResult.rows.length === 0) continue;

            let streak = streakResult.rows[0].current_win_streak || 0;
            let onFireAwarded = streakResult.rows[0].on_fire_awarded || false;
            const isWinner = winnerSet.has(playerId);

            if (isWinner) {
                streak++;
                if (streak >= 4 && !onFireAwarded) {
                    // Grant On Fire award
                    const exists = await pool.query(
                        'SELECT 1 FROM game_awards WHERE game_id = $1 AND recipient_player_id = $2 AND award_type = $3',
                        [gameId, playerId, 'on_fire']
                    );
                    if (exists.rows.length === 0) {
                        await pool.query(
                            `INSERT INTO game_awards (game_id, recipient_player_id, award_type, award_source, star_class)
                             VALUES ($1, $2, 'on_fire', 'automated', $3)`,
                            [gameId, playerId, starClass]
                        );
                        onFireAwarded = true;
                        setImmediate(() => sendAwardEmail(playerId, 'on_fire', {}));
                        console.log(`✅ On Fire awarded to player ${playerId} (${streak} wins in a row)`);
                    }
                }
            } else {
                // Loss or draw — reset streak
                streak = 0;
                onFireAwarded = false;
            }

            await pool.query(
                'UPDATE player_streaks SET current_win_streak = $1, on_fire_awarded = $2, updated_at = NOW() WHERE player_id = $3',
                [streak, onFireAwarded, playerId]
            );
        } catch (e) {
            console.warn(`checkOnFire failed for player ${playerId}:`, e.message);
        }
    }
}

// Check Back from the Dead — 3 months absence, fires on registration day
async function checkBackFromDead(gameId, playerIds, starClass = 'D') {
    const THREE_MONTHS_MS = 90 * 24 * 60 * 60 * 1000;

    for (const playerId of playerIds) {
        try {
            const streakResult = await pool.query(
                'SELECT last_game_date FROM player_streaks WHERE player_id = $1',
                [playerId]
            );
            if (streakResult.rows.length === 0) continue;
            const lastGame = streakResult.rows[0].last_game_date;

            if (lastGame && (Date.now() - new Date(lastGame).getTime()) >= THREE_MONTHS_MS) {
                // Grant Back from the Dead
                const exists = await pool.query(
                    'SELECT 1 FROM game_awards WHERE game_id = $1 AND recipient_player_id = $2 AND award_type = $3',
                    [gameId, playerId, 'back_from_dead']
                );
                if (exists.rows.length === 0) {
                    await pool.query(
                        `INSERT INTO game_awards (game_id, recipient_player_id, award_type, award_source, star_class)
                         VALUES ($1, $2, 'back_from_dead', 'automated', $3)`,
                        [gameId, playerId, starClass]
                    );
                    setImmediate(() => sendAwardEmail(playerId, 'back_from_dead', {}));
                    console.log(`✅ Back from the Dead awarded to player ${playerId}`);
                }
            }

            // Update last_game_date for all players in this game
            await pool.query(
                'UPDATE player_streaks SET last_game_date = NOW(), updated_at = NOW() WHERE player_id = $1',
                [playerId]
            );
        } catch (e) {
            console.warn(`checkBackFromDead failed for player ${playerId}:`, e.message);
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// TF GAME AWARDS — API endpoints
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/games/:id/awards — live vote state (auth required)
app.get('/api/games/:gameId/awards', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const playerId = req.user.playerId;

        const gameResult = await pool.query(
            'SELECT awards_open, awards_close_at, game_status FROM games WHERE id = $1',
            [gameId]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const game = gameResult.rows[0];

        // Get all votes for this game
        const votesResult = await pool.query(
            `SELECT gav.award_type, gav.nominee_player_id, gav.voter_player_id,
                    COUNT(*) OVER (PARTITION BY gav.award_type, gav.nominee_player_id) as vote_count
             FROM game_award_votes gav
             WHERE gav.game_id = $1`,
            [gameId]
        );

        // Get confirmed awards (after close) — include player name for frontend rendering
        const awardsResult = await pool.query(
            `SELECT ga.award_type, ga.recipient_player_id, ga.motm_value, ga.vote_count, ga.award_source, ga.series_day,
                    p.alias, p.full_name
             FROM game_awards ga
             JOIN players p ON p.id = ga.recipient_player_id
             WHERE ga.game_id = $1
             ORDER BY ga.award_type,
                      CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                      p.squad_number ASC NULLS LAST,
                      p.motm_wins DESC NULLS LAST,
                      p.total_appearances DESC NULLS LAST`,
            [gameId]
        );

        // Get registered player count for participation counter
        const participantsResult = await pool.query(
            `SELECT COUNT(DISTINCT voter_player_id) as voted_count FROM game_award_votes WHERE game_id = $1`,
            [gameId]
        );
        const totalRegisteredResult = await pool.query(
            `SELECT COUNT(*) as total FROM registrations WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );

        // Check if this player has voted
        const myVotes = votesResult.rows.filter(v => v.voter_player_id === playerId);

        // Build vote counts per award per nominee
        const voteCounts = {};
        for (const row of votesResult.rows) {
            if (!voteCounts[row.award_type]) voteCounts[row.award_type] = {};
            voteCounts[row.award_type][row.nominee_player_id] = parseInt(row.vote_count);
        }

        res.json({
            awardsOpen: game.awards_open,
            awardsCloseAt: game.awards_close_at,
            gameStatus: game.game_status,
            votedCount: parseInt(participantsResult.rows[0].voted_count),
            totalPlayers: parseInt(totalRegisteredResult.rows[0].total),
            voteCounts,
            myVotes: myVotes.map(v => ({ awardType: v.award_type, nomineeId: v.nominee_player_id })),
            confirmedAwards: awardsResult.rows,
        });
    } catch (error) {
        console.error('GET awards error:', error);
        res.status(500).json({ error: 'Failed to fetch awards' });
    }
});

// POST /api/games/:id/awards/vote — cast or update a vote
app.post('/api/games/:gameId/awards/vote', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { awardType, nomineePlayerId } = req.body;
        const voterId = req.user.playerId;

        // Block guests — their IDs are not valid UUIDs and they have no registrations
        if (!voterId || typeof voterId !== 'string' || voterId.startsWith('guest_')) {
            return res.status(403).json({ error: 'Guests cannot vote for awards' });
        }

        // Validate award type
        if (!AWARD_TYPES.includes(awardType)) {
            return res.status(400).json({ error: 'Invalid award type' });
        }

        // Validate nominee ID is a non-empty string
        if (!nomineePlayerId || typeof nomineePlayerId !== 'string') {
            return res.status(400).json({ error: 'Invalid nominee' });
        }

        // Block self-nomination for positive awards
        if (POSITIVE_AWARDS.includes(awardType) && nomineePlayerId === voterId) {
            return res.status(400).json({ error: 'You cannot nominate yourself for this award' });
        }

        // Check awards are open
        const gameResult = await pool.query(
            'SELECT awards_open, awards_close_at FROM games WHERE id = $1',
            [gameId]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        if (!gameResult.rows[0].awards_open) {
            return res.status(400).json({ error: 'Award voting is not currently open for this game' });
        }

        // Check voter is confirmed-registered for this game
        const regResult = await pool.query(
            'SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = $3',
            [gameId, voterId, 'confirmed']
        );
        if (regResult.rows.length === 0) {
            return res.status(403).json({ error: 'You must be a confirmed player in this game to vote' });
        }

        // Check nominee is confirmed-registered for this game
        const nomineeRegResult = await pool.query(
            'SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = $3',
            [gameId, nomineePlayerId, 'confirmed']
        );
        if (nomineeRegResult.rows.length === 0) {
            return res.status(400).json({ error: 'Nominee is not a confirmed player in this game' });
        }

        // Upsert vote (insert or ignore if already exists — player can add more nominees per award)
        await pool.query(
            `INSERT INTO game_award_votes (game_id, voter_player_id, nominee_player_id, award_type)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (game_id, voter_player_id, nominee_player_id, award_type) DO NOTHING`,
            [gameId, voterId, nomineePlayerId, awardType]
        );

        res.json({ message: 'Vote recorded' });
    } catch (error) {
        console.error('POST awards vote error:', error);
        res.status(500).json({ error: 'Failed to record vote' });
    }
});

// DELETE /api/games/:id/awards/vote — retract a vote
app.delete('/api/games/:gameId/awards/vote', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { awardType, nomineePlayerId } = req.body;
        const voterId = req.user.playerId;

        // Check awards are still open
        const gameResult = await pool.query(
            'SELECT awards_open FROM games WHERE id = $1',
            [gameId]
        );
        if (!gameResult.rows[0]?.awards_open) {
            return res.status(400).json({ error: 'Voting is closed' });
        }

        await pool.query(
            `DELETE FROM game_award_votes
             WHERE game_id = $1 AND voter_player_id = $2 AND nominee_player_id = $3 AND award_type = $4`,
            [gameId, voterId, nomineePlayerId, awardType]
        );

        res.json({ message: 'Vote retracted' });
    } catch (error) {
        console.error('DELETE awards vote error:', error);
        res.status(500).json({ error: 'Failed to retract vote' });
    }
});

// GET /api/public/game/:gameUrl/awards — public confirmed results (no auth)
app.get('/api/public/game/:gameUrl/awards', async (req, res) => {
    try {
        const { gameUrl } = req.params;

        const gameResult = await pool.query(
            'SELECT id, awards_open, awards_close_at, game_status FROM games WHERE game_url = $1',
            [gameUrl]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const game = gameResult.rows[0];

        const awardsResult = await pool.query(
            `SELECT ga.award_type, ga.motm_value, ga.vote_count, ga.award_source, ga.series_day,
                    p.alias, p.full_name, p.id as player_id
             FROM game_awards ga
             JOIN players p ON p.id = ga.recipient_player_id
             WHERE ga.game_id = $1
             ORDER BY ga.award_type,
                      CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                      p.squad_number ASC NULLS LAST,
                      p.motm_wins DESC NULLS LAST,
                      p.total_appearances DESC NULLS LAST`,
            [game.id]
        );

        res.json({
            awardsOpen: game.awards_open,
            awardsCloseAt: game.awards_close_at,
            awards: awardsResult.rows.map(a => ({
                awardType: a.award_type,
                motmValue: a.motm_value,
                voteCount: a.vote_count,
                awardSource: a.award_source,
                seriesDay: a.series_day,
                playerId: a.player_id,
                playerAlias: a.alias || a.full_name,
            })),
        });
    } catch (error) {
        console.error('GET public awards error:', error);
        res.status(500).json({ error: 'Failed to fetch awards' });
    }
});

// GET /api/players/:id/awards — player award history (auth required)
app.get('/api/players/:playerId/awards', authenticateToken, async (req, res) => {
    try {
        const { playerId } = req.params;

        const awardsResult = await pool.query(
            `SELECT ga.award_type, ga.motm_value, ga.vote_count, ga.award_source,
                    ga.series_day, ga.created_at,
                    g.game_url, g.game_date,
                    TO_CHAR(g.game_date AT TIME ZONE 'Europe/London', 'Day') as day_name,
                    v.name as venue_name
             FROM game_awards ga
             JOIN games g ON g.id = ga.game_id
             LEFT JOIN venues v ON v.id = g.venue_id
             WHERE ga.recipient_player_id = $1
             ORDER BY ga.created_at DESC`,
            [playerId]
        );

        // Also get live streak
        const streakResult = await pool.query(
            'SELECT current_win_streak FROM player_streaks WHERE player_id = $1',
            [playerId]
        );

        // Count by type
        const counts = {};
        let motmTotal = 0;
        for (const row of awardsResult.rows) {
            counts[row.award_type] = (counts[row.award_type] || 0) + 1;
            if (row.award_type === 'motm') motmTotal += parseFloat(row.motm_value || 1);
        }

        res.json({
            awards: awardsResult.rows,
            counts,
            motmTotal: Math.round(motmTotal * 100) / 100,
            currentWinStreak: streakResult.rows[0]?.current_win_streak || 0,
        });
    } catch (error) {
        console.error('GET player awards error:', error);
        res.status(500).json({ error: 'Failed to fetch player awards' });
    }
});

// POST /api/admin/games/:gameId/awards/close — admin manual close
app.post('/api/admin/games/:gameId/awards/close', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        const result = await closeAwards(gameId);
        res.json({ message: 'Awards closed', confirmedWinners: result?.confirmedWinners?.length || 0 });
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'awards_closed_manually',
            `Confirmed: ${result?.confirmedWinners?.length || 0} award(s)`));
    } catch (error) {
        console.error('Admin close awards error:', error);
        res.status(500).json({ error: 'Failed to close awards' });
    }
});

// GET /api/public/players/leaderboard/awards — award count leaderboard (public)
app.get('/api/public/players/leaderboard/awards', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                p.id, p.alias, p.full_name,
                COALESCE(SUM(CASE WHEN ga.award_type = 'motm'        THEN ga.motm_value  ELSE 0 END), 0) as motm_total,
                COALESCE(SUM(CASE WHEN ga.award_type = 'best_engine' THEN 1              ELSE 0 END), 0) as engine_count,
                COALESCE(SUM(CASE WHEN ga.award_type = 'brick_wall'  THEN 1              ELSE 0 END), 0) as wall_count,
                COALESCE(SUM(CASE WHEN ga.award_type = 'howler'      THEN 1              ELSE 0 END), 0) as howler_count,
                COALESCE(COUNT(ga.id), 0) as total_awards
             FROM players p
             LEFT JOIN game_awards ga ON ga.recipient_player_id = p.id
             GROUP BY p.id, p.alias, p.full_name
             HAVING COALESCE(COUNT(ga.id), 0) > 0
             ORDER BY motm_total DESC, engine_count DESC`,
            []
        );
        res.json({ leaderboard: result.rows });
    } catch (error) {
        console.error('Awards leaderboard error:', error);
        res.status(500).json({ error: 'Failed to fetch leaderboard' });
    }
});

// ==========================================
// ==========================================
// REFERRAL ENDPOINTS
// ==========================================

// Get my referral info (code, link, who I referred)
// Returns the superadmin's player ID — used by feature request form
// POST /api/admin/players/:id/regenerate-bio — admin-triggered bio regen
app.post('/api/admin/players/:id/regenerate-bio', authenticateToken, requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const playerCheck = await pool.query('SELECT id, total_appearances FROM players WHERE id = $1', [id]);
        if (!playerCheck.rows[0]) return res.status(404).json({ error: 'Player not found' });
        const forceOverride = req.query.force === 'true' && req.user.role === 'superadmin';
        if (!forceOverride && (playerCheck.rows[0].total_appearances || 0) < 5)
            return res.status(400).json({ error: 'Player needs at least 5 appearances for a bio' });
        // Run async — respond immediately (bypass threshold if force=true and superadmin)
        setImmediate(() => regeneratePlayerBioForce(id, forceOverride));
        res.json({ message: 'Bio regeneration started' });
    } catch (e) {
        console.error('Admin regen bio error:', e.message);
        res.status(500).json({ error: 'Failed to start bio regeneration' });
    }
});

// GET /api/players/me/discipline/recent — last 10 games' discipline records for current player
// Used by the post-signup confirmation screen
app.get('/api/players/me/discipline/recent', authenticateToken, async (req, res) => {
    try {
        const playerId = req.user.playerId;
        // Fetch discipline records from last 10 completed games the player participated in
        const result = await pool.query(
            `SELECT dr.offense_type, dr.points, dr.created_at,
                    g.game_date, v.name as venue_name
             FROM discipline_records dr
             LEFT JOIN games g ON g.id = dr.game_id
             LEFT JOIN venues v ON v.id = g.venue_id
             WHERE dr.player_id = $1
               AND dr.game_id IS NOT NULL
               AND dr.points > 0
             ORDER BY dr.created_at DESC
             LIMIT 10`,
            [playerId]
        );
        // Current revolving points total — last 10 completed games the player confirmed for + manual entries
        const ptsRow = await pool.query(
            `SELECT COALESCE(SUM(dr.points),0) as total
             FROM discipline_records dr
             WHERE dr.player_id = $1
               AND (dr.game_id IS NULL OR dr.game_id IN (
                 SELECT r.game_id FROM registrations r
                 JOIN games g2 ON g2.id = r.game_id
                 WHERE r.player_id = $1 AND r.status = 'confirmed'
                 AND g2.game_status = 'completed'
                 ORDER BY g2.game_date DESC LIMIT 10
               ))`,
            [playerId]
        );
        res.json({
            records: result.rows,
            revolving_points: parseInt(ptsRow.rows[0]?.total || 0)
        });
    } catch (e) {
        console.error('Discipline recent error:', e.message);
        res.status(500).json({ error: 'Server error' });
    }
});

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
        
        // Get list of players I referred with RAF earnings
        const referred = await pool.query(
            `SELECT p.id, p.alias, p.full_name, p.created_at,
             p.total_appearances, p.reliability_tier,
             rr.activation_paid, rr.game_credits_paid, rr.game_credits_total,
             rr.total_paid, rr.cap_reached,
             (p.created_at + INTERVAL '1 year') as window_expires
             FROM players p
             LEFT JOIN raf_rewards rr ON rr.referrer_id = $1 AND rr.referred_id = p.id
             WHERE p.referred_by = $1
             ORDER BY p.created_at DESC`,
            [playerId]
        );

        const rafEnabled = await getRafEnabled();
        const totalEarned = referred.rows.reduce((sum, r) => sum + parseFloat(r.total_paid || 0), 0);

        res.json({
            referralCode: me.referral_code,
            referralLink: me.referral_code
                ? 'https://totalfooty.co.uk/?ref=' + me.referral_code
                : null,
            referredBy: me.referred_by ? { id: me.referred_by, alias: me.referred_by_alias } : null,
            rafEnabled,
            totalEarned: totalEarned.toFixed(2),
            referrals: referred.rows.map(r => ({
                id: r.id,
                alias: r.alias || r.full_name,
                joinedAt: r.created_at,
                appearances: r.total_appearances || 0,
                tier: r.reliability_tier,
                activationPaid: r.activation_paid || false,
                gamesCredited: parseInt(r.game_credits_paid || 0),
                gameCreditsTotal: parseFloat(r.game_credits_total || 0).toFixed(2),
                totalPaid: parseFloat(r.total_paid || 0).toFixed(2),
                capReached: r.cap_reached || false,
                windowExpires: r.window_expires
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
            'SELECT p.full_name, p.alias, p.player_number, p.squad_number, u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
            [playerId]
        );
        if (playerResult.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const player = playerResult.rows[0];
        const displayName = player.alias || player.full_name;
        const amountStr = amount ? `£${parseFloat(amount).toFixed(2)}` : 'Amount not specified';
        // Short payment reference: squad_number takes priority (1-999), else player_number (1000+)
        // Use squad_number if set (including 0='00'), else player_number, else N/A
        const paymentRef = (player.squad_number !== null && player.squad_number !== undefined)
            ? (player.squad_number === 0 ? '00' : player.squad_number)
            : (player.player_number ?? 'N/A');

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
                            <tr><td style="padding:6px 0;color:#888;">Payment Ref</td><td style="font-weight:900;font-size:18px;">${htmlEncode(String(paymentRef))}</td></tr>
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
                ? 'https://totalfooty.co.uk/?ref=' + p.referral_code
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

// ── RAF SYSTEM ENDPOINTS ──────────────────────────────────────────────────────

// GET /api/public/raf/status — frontend uses this to show/hide RAF signposts
app.get('/api/public/raf/status', async (req, res) => {
    try {
        const enabled = await getRafEnabled();
        res.json({ enabled });
    } catch (e) {
        res.json({ enabled: false });
    }
});

// GET /api/admin/raf/status — full stats for superadmin
app.get('/api/admin/raf/status', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const [setting, stats] = await Promise.all([
            pool.query("SELECT value FROM system_settings WHERE key='raf_enabled'"),
            pool.query(`
                SELECT
                    COUNT(*) as total_pairs,
                    COUNT(*) FILTER (WHERE activation_paid) as activations_paid,
                    COUNT(*) FILTER (WHERE cap_reached) as caps_reached,
                    COALESCE(SUM(total_paid), 0) as total_credited
                FROM raf_rewards
            `)
        ]);
        res.json({
            enabled: setting.rows[0]?.value === 'true',
            totalPairs: parseInt(stats.rows[0].total_pairs || 0),
            activationsPaid: parseInt(stats.rows[0].activations_paid || 0),
            capsReached: parseInt(stats.rows[0].caps_reached || 0),
            totalCredited: parseFloat(stats.rows[0].total_credited || 0).toFixed(2)
        });
    } catch (e) {
        console.error('RAF status error:', e.message);
        res.status(500).json({ error: 'Failed to get RAF status' });
    }
});

// PUT /api/admin/raf/toggle — enable or disable the RAF scheme
app.put('/api/admin/raf/toggle', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { enabled } = req.body;
        if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be boolean' });
        await pool.query(
            `INSERT INTO system_settings (key, value, updated_at) VALUES ('raf_enabled', $1, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
            [enabled ? 'true' : 'false']
        );
        await auditLog(pool, req.user.playerId, 'raf_toggle', null, `RAF scheme ${enabled ? 'ENABLED' : 'DISABLED'} by superadmin`);
        res.json({ enabled, message: `RAF scheme ${enabled ? 'enabled' : 'disabled'}` });
    } catch (e) {
        console.error('RAF toggle error:', e.message);
        res.status(500).json({ error: 'Failed to update RAF setting' });
    }
});

// POST /api/admin/raf/backfill — one-time backfill of existing referrals
// Credits activation bonuses and historic game sign-up credits to all existing referrers
app.post('/api/admin/raf/backfill', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        // BUG4-FIX: backfill credits real money — require RAF to be enabled (or explicit override)
        const { force } = req.body;
        const rafOn = await getRafEnabled();
        if (!rafOn && !force) {
            return res.status(400).json({ error: 'RAF scheme is currently disabled. Pass { force: true } in the request body to backfill anyway.' });
        }

        const referred = await pool.query(
            `SELECT p.id, p.referred_by, p.created_at, p.alias, p.full_name
             FROM players p WHERE p.referred_by IS NOT NULL`
        );

        let activationCredits = 0, gameCreditsCount = 0;
        let totalCredited = 0;

        for (const player of referred.rows) {
            const referrerId = player.referred_by;
            const referredId = player.id;

            // Upsert raf_rewards row
            await pool.query(
                `INSERT INTO raf_rewards (referrer_id, referred_id) VALUES ($1,$2)
                 ON CONFLICT (referrer_id, referred_id) DO NOTHING`,
                [referrerId, referredId]
            );

            const rr = await pool.query(
                'SELECT activation_paid, game_credits_paid, cap_reached FROM raf_rewards WHERE referrer_id=$1 AND referred_id=$2',
                [referrerId, referredId]
            );
            const row = rr.rows[0];

            // Activation bonus — check if player ever received a positive admin_adjustment
            if (!row.activation_paid) {
                const topupCheck = await pool.query(
                    `SELECT 1 FROM credit_transactions WHERE player_id=$1 AND type='admin_adjustment' AND amount>0 LIMIT 1`,
                    [referredId]
                );
                if (topupCheck.rows.length > 0) {
                    await pool.query(
                        'UPDATE credits SET balance=balance+2.00, last_updated=CURRENT_TIMESTAMP WHERE player_id=$1',
                        [referrerId]
                    );
                    await recordCreditTransaction(pool, referrerId, 2.00, 'raf_reward',
                        `RAF backfill: activation bonus — ${referredId} previously topped up`);
                    await pool.query(
                        `UPDATE raf_rewards SET activation_paid=TRUE, activation_paid_at=NOW(), total_paid=total_paid+2.00
                         WHERE referrer_id=$1 AND referred_id=$2`,
                        [referrerId, referredId]
                    );
                    activationCredits++;
                    totalCredited += 2;
                }
            }

            // Game credits — count confirmed registrations within 1-year window
            if (!row.cap_reached) {
                const windowEnd = new Date(player.created_at);
                windowEnd.setFullYear(windowEnd.getFullYear() + 1);

                const regCount = await pool.query(
                    `SELECT COUNT(*) as cnt FROM registrations
                     WHERE player_id=$1 AND status='confirmed' AND registered_at <= $2`,
                    [referredId, windowEnd]
                );
                const totalConfirmed = parseInt(regCount.rows[0].cnt || 0);
                const alreadyCredited = parseInt(row.game_credits_paid || 0);
                const toCredit = Math.min(totalConfirmed, 26) - alreadyCredited;

                if (toCredit > 0) {
                    const creditAmt = toCredit * 0.50;
                    const newCount = alreadyCredited + toCredit;
                    const capReached = newCount >= 26;
                    await pool.query(
                        'UPDATE credits SET balance=balance+$1, last_updated=CURRENT_TIMESTAMP WHERE player_id=$2',
                        [creditAmt, referrerId]
                    );
                    await recordCreditTransaction(pool, referrerId, creditAmt, 'raf_reward',
                        `RAF backfill: ${toCredit} game credit(s) for referred player ${referredId} (${alreadyCredited+1}-${newCount}/26)`);
                    await pool.query(
                        `UPDATE raf_rewards
                         SET game_credits_paid=$1, game_credits_total=game_credits_total+$2,
                             total_paid=total_paid+$2, cap_reached=$3,
                             cap_reached_at=CASE WHEN $3 THEN NOW() ELSE cap_reached_at END
                         WHERE referrer_id=$4 AND referred_id=$5`,
                        [newCount, creditAmt, capReached, referrerId, referredId]
                    );
                    gameCreditsCount += toCredit;
                    totalCredited += creditAmt;
                }
            }
        }

        await notifyAdmin('🔄 RAF Backfill Complete', [
            ['Players Processed', String(referred.rows.length)],
            ['Activation Bonuses', String(activationCredits)],
            ['Game Credits Issued', `${gameCreditsCount} × 50p`],
            ['Total Credited', `£${totalCredited.toFixed(2)}`],
        ]);

        res.json({
            message: 'RAF backfill complete',
            playersProcessed: referred.rows.length,
            activationCredits,
            gameCreditsCount,
            totalCredited: totalCredited.toFixed(2)
        });
    } catch (e) {
        console.error('RAF backfill error:', e.message);
        res.status(500).json({ error: 'Backfill failed: ' + e.message });
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
                COALESCE((SELECT SUM(COALESCE(NULLIF(r.amount_paid,0), CASE WHEN r.is_comped THEN 0 ELSE g.cost_per_player END))
                 FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) as confirmed_revenue,
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg WHERE gg.game_id = g.id), 0) as guest_revenue,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.is_comped = TRUE AND r.status = 'confirmed'), 0) as comped_count,
                (SELECT COUNT(*) FROM game_referees gr WHERE gr.game_id = g.id AND gr.status = 'pending')   AS pending_referee_applications,
                (SELECT COUNT(*) FROM game_referees gr WHERE gr.game_id = g.id AND gr.status = 'confirmed') AS confirmed_referees,
                COALESCE((SELECT SUM(g.cost_per_player - r.amount_paid)
                 FROM registrations r
                 WHERE r.game_id = g.id AND r.status = 'confirmed'
                 AND r.is_comped = FALSE AND r.amount_paid IS NOT NULL
                 AND r.amount_paid > 0 AND r.amount_paid < g.cost_per_player), 0) as discount_gap,
                ROUND((SELECT AVG(p.overall_rating)
                 FROM registrations r JOIN players p ON p.id = r.player_id
                 WHERE r.game_id = g.id AND r.status = 'confirmed'
                 AND p.overall_rating IS NOT NULL)::numeric, 1) as live_avg_ovr
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
                COALESCE((SELECT SUM(COALESCE(NULLIF(r.amount_paid,0), CASE WHEN r.is_comped THEN 0 ELSE g.cost_per_player END))
                 FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) as confirmed_revenue,
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg WHERE gg.game_id = g.id), 0) as guest_revenue,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.is_comped = TRUE AND r.status = 'confirmed'), 0) as comped_count,
                (SELECT COUNT(*) FROM game_referees gr WHERE gr.game_id = g.id AND gr.status = 'pending')   AS pending_referee_applications,
                (SELECT COUNT(*) FROM game_referees gr WHERE gr.game_id = g.id AND gr.status = 'confirmed') AS confirmed_referees,
                COALESCE((SELECT SUM(g.cost_per_player - r.amount_paid)
                 FROM registrations r
                 WHERE r.game_id = g.id AND r.status = 'confirmed'
                 AND r.is_comped = FALSE AND r.amount_paid IS NOT NULL
                 AND r.amount_paid > 0 AND r.amount_paid < g.cost_per_player), 0) as discount_gap,
                ROUND((SELECT AVG(p.overall_rating)
                 FROM registrations r JOIN players p ON p.id = r.player_id
                 WHERE r.game_id = g.id AND r.status = 'confirmed'
                 AND p.overall_rating IS NOT NULL)::numeric, 1) as live_avg_ovr
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
        const { teamA, teamB, teamAScore, teamBScore, force } = req.body;
        
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
        if (dupCheck.rows.length > 0 && !force) {
            return res.status(409).json({ isDuplicate: true, error: `A result already exists for ${teamA} vs ${teamB}.` });
        }
        
        // Insert result
        const result = await pool.query(
            `INSERT INTO tournament_results (game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [gameId, teamA, teamB, scoreA, scoreB, req.user.playerId]
        );
        
        // Return updated results + league table
        const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'tournament_result_added',
            `Result: ${teamA} ${teamAScore}–${teamBScore} ${teamB}`));
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
        const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'tournament_result_updated',
            `Result ${resultId} updated: ${teamAScore}–${teamBScore}`));
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
        const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
        const leagueTable = calculateLeagueTable(allResults.rows, validTeams);
        
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'tournament_result_deleted',
            `Result ${resultId} deleted`));
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
        const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [gameId]);
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
                SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, r.position_preference as position,
                       p.motm_wins, p.total_appearances
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                JOIN registrations r ON r.player_id = p.id AND r.game_id = $2
                WHERE tp.team_id = $1
                ORDER BY
                    CASE WHEN p.squad_number IS NOT NULL THEN 0 ELSE 1 END ASC,
                    p.squad_number ASC NULLS LAST,
                    p.motm_wins DESC NULLS LAST,
                    p.total_appearances DESC NULLS LAST
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
        const allResults = await pool.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1 ORDER BY entered_at', [game.id]);
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
        const allResults = await client.query('SELECT id, game_id, team_a_name, team_b_name, team_a_score, team_b_score, entered_by, entered_at FROM tournament_results WHERE game_id = $1', [gameId]);
        
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
                 motm_voting_ends = NOW() + INTERVAL '24 hours',
                 awards_open = true,
                 awards_close_at = NOW() + INTERVAL '24 hours',
                 ref_review_ends = NOW() + INTERVAL '24 hours'
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
        // FIX-102: Added ct.balance_before, ct.balance_after — were missing from SELECT,
        // causing audit.html to always render null for before→after balance arrows.
        const balance = await pool.query(`
            SELECT ct.created_at, ct.amount, ct.type, ct.description,
                   ct.balance_before, ct.balance_after,
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

        // 3b. Current pair/avoid preferences for this player (upcoming games only)
        const regPreferences = await pool.query(`
            SELECT
                r.game_id,
                g.game_date,
                g.game_url,
                v.name AS venue_name,
                rp.preference_type,
                COALESCE(tp.alias, tp.full_name) AS target_name
            FROM registrations r
            JOIN games g ON g.id = r.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            JOIN registration_preferences rp ON rp.registration_id = r.id
            JOIN players tp ON tp.id = rp.target_player_id
            WHERE r.player_id = $1
              AND g.game_status NOT IN ('completed', 'cancelled')
            ORDER BY g.game_date ASC, rp.preference_type, tp.alias, tp.full_name
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
            WHERE al.target_id = $1 AND al.action != 'login'
            ORDER BY al.created_at DESC
        `, [id]);

        // 8. Discipline records with IDs (for removal UI)
        const disciplineRecords = await pool.query(`
            SELECT dr.id, dr.points, dr.offense_type, dr.created_at,
                   g.game_date, v.name AS venue_name, g.game_url,
                   COALESCE(p.alias, p.full_name) AS recorded_by_name
            FROM discipline_records dr
            LEFT JOIN games g ON g.id = dr.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN users u ON u.id = dr.recorded_by
            LEFT JOIN players p ON p.user_id = u.id
            WHERE dr.player_id = $1
            ORDER BY dr.created_at DESC
        `, [id]);

        // 7. Login events (from audit_logs where action = 'login' and target = this player)
        const loginEvents = await pool.query(`
            SELECT al.created_at, al.detail
            FROM audit_logs al
            WHERE al.target_id = $1 AND al.action = 'login'
            ORDER BY al.created_at DESC
            LIMIT 100
        `, [id]);

        // 9a. Award votes CAST by this player
        const awardVotesCast = await pool.query(`
            SELECT gav.award_type, COALESCE(gav.created_at, g.game_date) AS created_at,
                   g.game_date, g.game_url, v.name AS venue_name,
                   p.alias AS nominee_alias, p.full_name AS nominee_name
            FROM game_award_votes gav
            JOIN games g ON g.id = gav.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            JOIN players p ON p.id = gav.nominee_player_id
            WHERE gav.voter_player_id = $1
            ORDER BY COALESCE(gav.created_at, g.game_date) DESC
        `, [id]);

        // 9b. Award votes RECEIVED by this player
        const awardVotesReceived = await pool.query(`
            SELECT gav.award_type, COALESCE(gav.created_at, g.game_date) AS created_at,
                   g.game_date, g.game_url, v.name AS venue_name,
                   p.alias AS voter_alias, p.full_name AS voter_name
            FROM game_award_votes gav
            JOIN games g ON g.id = gav.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            JOIN players p ON p.id = gav.voter_player_id
            WHERE gav.nominee_player_id = $1
            ORDER BY COALESCE(gav.created_at, g.game_date) DESC
        `, [id]);

        // 10. Game-linked stat changes for this player (from bulk post-game/wizard updates)
        const gameStatChanges = await pool.query(`
            SELECT gsc.created_at, gsc.game_id,
                   gsc.old_overall, gsc.new_overall,
                   gsc.old_gk,  gsc.new_gk,
                   gsc.old_def, gsc.new_def,
                   gsc.old_str, gsc.new_str,
                   gsc.old_fit, gsc.new_fit,
                   gsc.old_pac, gsc.new_pac,
                   gsc.old_dec, gsc.new_dec,
                   gsc.old_ass, gsc.new_ass,
                   gsc.old_sho, gsc.new_sho,
                   g.game_date, g.game_url, v.name AS venue_name,
                   cb.alias AS changed_by_alias, cb.full_name AS changed_by_name
            FROM game_stat_changes gsc
            JOIN games g ON g.id = gsc.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN players cb ON cb.id = gsc.changed_by
            WHERE gsc.player_id = $1
            ORDER BY gsc.created_at DESC
        `, [id]).catch(() => ({ rows: [] }));

        res.json({
            balance: balance.rows,
            stats: stats.rows,
            registrations: regEvents.rows,
            registrationPreferences: regPreferences.rows,
            motmReceived: motmReceived.rows,
            motmVotesCast: motmVotes.rows,
            awardVotesCast: awardVotesCast.rows,
            awardVotesReceived: awardVotesReceived.rows,
            adminActions: adminActions.rows,
            loginEvents: loginEvents.rows,
            disciplineRecords: disciplineRecords.rows,
            gameStatChanges: gameStatChanges.rows
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

        // 3. Registrations (signed up currently) with pair/avoid names
        const currentRegs = await pool.query(`
            SELECT r.registered_at, r.status, r.backup_type, r.position_preference,
                   p.alias, p.full_name, p.squad_number,
                   (
                       SELECT string_agg(COALESCE(tp.alias, tp.full_name), ', ' ORDER BY tp.alias, tp.full_name)
                       FROM registration_preferences rp
                       JOIN players tp ON tp.id = rp.target_player_id
                       WHERE rp.registration_id = r.id AND rp.preference_type = 'pair'
                   ) AS pair_names,
                   (
                       SELECT string_agg(COALESCE(tp.alias, tp.full_name), ', ' ORDER BY tp.alias, tp.full_name)
                       FROM registration_preferences rp
                       JOIN players tp ON tp.id = rp.target_player_id
                       WHERE rp.registration_id = r.id AND rp.preference_type = 'avoid'
                   ) AS avoid_names
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1
            ORDER BY r.registered_at ASC
        `, [id]);

        // 4. URL views for this game (who viewed the game page and when)
        const urlViews = await pool.query(`
            SELECT gv.viewed_at,
                   p.alias, p.full_name, p.squad_number,
                   CASE WHEN p.id IS NULL THEN 'Guest (not logged in)' ELSE NULL END as guest_label
            FROM game_url_views gv
            LEFT JOIN players p ON p.id = gv.player_id
            WHERE gv.game_id = $1
            ORDER BY gv.viewed_at DESC
            LIMIT 200
        `, [id]).catch(() => ({ rows: [] })); // graceful if table doesn't exist yet

        // 5. Award votes for this game (full breakdown — who voted for whom per award)
        const awardVotes = await pool.query(`
            SELECT gav.award_type,
                   vp.alias AS voter_alias, vp.full_name AS voter_name, vp.squad_number AS voter_squad,
                   np.alias AS nominee_alias, np.full_name AS nominee_name, np.squad_number AS nominee_squad,
                   COALESCE(gav.created_at, g.game_date) AS voted_at
            FROM game_award_votes gav
            JOIN games g ON g.id = gav.game_id
            JOIN players vp ON vp.id = gav.voter_player_id
            JOIN players np ON np.id = gav.nominee_player_id
            WHERE gav.game_id = $1
            ORDER BY gav.award_type ASC, COALESCE(gav.created_at, g.game_date) ASC
        `, [id]).catch(() => ({ rows: [] }));

        // 6. Stat changes — per-player before/after from game_stat_changes table
        const statChanges = await pool.query(`
            SELECT gsc.player_id, gsc.created_at,
                   gsc.old_overall, gsc.new_overall,
                   gsc.old_gk,  gsc.new_gk,
                   gsc.old_def, gsc.new_def,
                   gsc.old_str, gsc.new_str,
                   gsc.old_fit, gsc.new_fit,
                   gsc.old_pac, gsc.new_pac,
                   gsc.old_dec, gsc.new_dec,
                   gsc.old_ass, gsc.new_ass,
                   gsc.old_sho, gsc.new_sho,
                   p.alias, p.full_name, p.squad_number,
                   cb.alias AS changed_by_alias, cb.full_name AS changed_by_name
            FROM game_stat_changes gsc
            JOIN players p ON p.id = gsc.player_id
            LEFT JOIN players cb ON cb.id = gsc.changed_by
            WHERE gsc.game_id = $1
            ORDER BY COALESCE(p.alias, p.full_name)
        `, [id]).catch(() => ({ rows: [] })); // graceful if table not yet migrated

        res.json({
            gameLogs: gameLogs.rows,
            registrationEvents: regEvents.rows,
            currentRegistrations: currentRegs.rows,
            urlViews: urlViews.rows,
            awardVotes: awardVotes.rows,
            statChanges: statChanges.rows
        });
    } catch (error) {
        console.error('Game audit error:', error);
        res.status(500).json({ error: 'Failed to load game audit' });
    }
});

// ── ADMIN: DM INBOX / THREAD VIEW ────────────────────────────────────────────

// GET /api/admin/players/:playerId/dm-conversations
// Admin inbox view — list all conversations for a player with previews
app.get('/api/admin/players/:playerId/dm-conversations', authenticateToken, requireAdmin, async (req, res) => {
    const { playerId } = req.params;
    try {
        const check = await pool.query(
            'SELECT id, COALESCE(alias, full_name) AS name FROM players WHERE id = $1',
            [playerId]
        );
        if (check.rows.length === 0) return res.status(404).json({ error: 'Player not found' });

        const result = await pool.query(`
            SELECT other_player_id, other_name, other_alias, other_tier,
                   last_message, last_message_at, last_sender_id,
                   total_messages, unread_count
            FROM (
                SELECT
                    CASE WHEN dm.sender_id = $1 THEN dm.recipient_id
                         ELSE dm.sender_id END AS other_player_id,
                    p.full_name AS other_name, p.alias AS other_alias,
                    p.reliability_tier AS other_tier,
                    dm.message AS last_message, dm.created_at AS last_message_at,
                    dm.sender_id AS last_sender_id, dm.read_at,
                    COUNT(*) OVER (
                        PARTITION BY LEAST(dm.sender_id, dm.recipient_id),
                                     GREATEST(dm.sender_id, dm.recipient_id)
                    ) AS total_messages,
                    COUNT(*) FILTER (
                        WHERE dm.sender_id != $1 AND dm.read_at IS NULL
                    ) OVER (
                        PARTITION BY LEAST(dm.sender_id, dm.recipient_id),
                                     GREATEST(dm.sender_id, dm.recipient_id)
                    ) AS unread_count,
                    ROW_NUMBER() OVER (
                        PARTITION BY LEAST(dm.sender_id, dm.recipient_id),
                                     GREATEST(dm.sender_id, dm.recipient_id)
                        ORDER BY dm.created_at DESC
                    ) AS rn
                FROM direct_messages dm
                JOIN players p ON p.id = CASE WHEN dm.sender_id = $1
                    THEN dm.recipient_id ELSE dm.sender_id END
                WHERE (dm.sender_id = $1 OR dm.recipient_id = $1)
                  AND dm.deleted_at IS NULL
            ) sub
            WHERE rn = 1
            ORDER BY last_message_at DESC
        `, [playerId]);

        res.json({ playerName: check.rows[0].name, conversations: result.rows });
    } catch (error) {
        console.error('Admin DM conversations error:', error);
        res.status(500).json({ error: 'Failed to load conversations' });
    }
});

// GET /api/admin/dm/all-conversations
// Platform-wide admin view — all unique DM conversation pairs, most recent first
// GET /api/admin/dm/all-conversations?offset=0&limit=100
// Paginated: returns { conversations, total, hasMore }
app.get('/api/admin/dm/all-conversations', authenticateToken, requireAdmin, async (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit)  || 100, 200);
    const offset = Math.max(parseInt(req.query.offset) || 0,   0);
    try {
        // Count total unique conversations for hasMore
        const countRes = await pool.query(`
            SELECT COUNT(DISTINCT
                LEAST(sender_id, recipient_id)::text || '_' ||
                GREATEST(sender_id, recipient_id)::text
            ) AS total
            FROM direct_messages WHERE deleted_at IS NULL
        `);
        const total = parseInt(countRes.rows[0].total);

        // FIX: use a ranked subquery instead of correlated subqueries referencing
        // ungrouped outer columns — PostgreSQL strict GROUP BY rejects those.
        const result = await pool.query(`
            WITH ranked AS (
                SELECT
                    LEAST(sender_id, recipient_id)    AS player_a_id,
                    GREATEST(sender_id, recipient_id) AS player_b_id,
                    message,
                    sender_id                          AS last_sender_id,
                    created_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY LEAST(sender_id, recipient_id),
                                     GREATEST(sender_id, recipient_id)
                        ORDER BY created_at DESC
                    ) AS rn,
                    COUNT(*) OVER (
                        PARTITION BY LEAST(sender_id, recipient_id),
                                     GREATEST(sender_id, recipient_id)
                    ) AS total_messages
                FROM direct_messages
                WHERE deleted_at IS NULL
            )
            SELECT
                r.player_a_id,
                r.player_b_id,
                COALESCE(pa.alias, pa.full_name) AS player_a_name,
                COALESCE(pb.alias, pb.full_name) AS player_b_name,
                pa.reliability_tier              AS player_a_tier,
                pb.reliability_tier              AS player_b_tier,
                r.created_at                     AS last_message_at,
                r.total_messages,
                r.message                        AS last_message,
                r.last_sender_id
            FROM ranked r
            JOIN players pa ON pa.id = r.player_a_id
            JOIN players pb ON pb.id = r.player_b_id
            WHERE r.rn = 1
            ORDER BY r.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);
        res.json({
            conversations: result.rows,
            total,
            hasMore: offset + result.rows.length < total,
        });
    } catch (error) {
        console.error('Admin all-conversations error:', error);
        res.status(500).json({ error: 'Failed to load conversations' });
    }
});

// GET /api/admin/dm/recent-messages — latest individual messages platform-wide
app.get('/api/admin/dm/recent-messages', authenticateToken, requireAdmin, async (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
    const offset = Math.max(parseInt(req.query.offset) || 0,  0);
    try {
        const result = await pool.query(`
            SELECT
                dm.id,
                dm.sender_id,
                dm.recipient_id,
                dm.message,
                dm.created_at,
                dm.read_at,
                COALESCE(ps.alias, ps.full_name) AS sender_name,
                COALESCE(pr.alias, pr.full_name) AS receiver_name
            FROM direct_messages dm
            JOIN players ps ON ps.id = dm.sender_id
            JOIN players pr ON pr.id = dm.recipient_id
            WHERE dm.deleted_at IS NULL
            ORDER BY dm.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        const countRes = await pool.query(
            'SELECT COUNT(*) AS total FROM direct_messages WHERE deleted_at IS NULL'
        );
        const total = parseInt(countRes.rows[0].total);

        res.json({
            messages: result.rows,
            total,
            hasMore: offset + result.rows.length < total
        });
    } catch (error) {
        console.error('Recent messages error:', error);
        res.status(500).json({ error: 'Failed to load recent messages' });
    }
});

// GET /api/admin/dm-thread/:subjectId/:otherId
// Full thread view between two players — read-only admin view
app.get('/api/admin/dm-thread/:subjectId/:otherId', authenticateToken, requireAdmin, async (req, res) => {
    const { subjectId, otherId } = req.params;
    try {
        const check = await pool.query(
            'SELECT id, COALESCE(alias, full_name) AS name FROM players WHERE id = ANY($1)',
            [[subjectId, otherId]]
        );
        if (check.rows.length < 2) return res.status(404).json({ error: 'One or both players not found' });

        const result = await pool.query(`
            SELECT dm.id, dm.sender_id, dm.recipient_id, dm.message,
                   dm.read_at, dm.created_at,
                   COALESCE(p.alias, p.full_name, 'Unknown') AS sender_name,
                   p.squad_number AS sender_squad
            FROM direct_messages dm
            JOIN players p ON p.id = dm.sender_id
            WHERE (
                (dm.sender_id = $1 AND dm.recipient_id = $2)
                OR
                (dm.sender_id = $2 AND dm.recipient_id = $1)
            )
            AND dm.deleted_at IS NULL
            ORDER BY dm.created_at ASC
        `, [subjectId, otherId]);

        const names = {};
        check.rows.forEach(r => { names[r.id] = r.name; });
        res.json({
            messages:    result.rows,
            subjectName: names[subjectId] || 'Unknown',
            otherName:   names[otherId]   || 'Unknown',
            total:       result.rows.length
        });
    } catch (error) {
        console.error('Admin DM thread error:', error);
        res.status(500).json({ error: 'Failed to load thread' });
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
//
// IMPORTANT: DISC_TIER_THRESHOLDS below must match your calculate_player_tier DB function.
// Adjust these constants if tier behaviour doesn't match what you expect.
// These thresholds apply to the REVOLVING window (last 10 completed games + all manual entries).
const DISC_TIER_THRESHOLDS = { black: 15, white: 10, bronze: 4, silver: 1 };
function tierFromRevolvingPoints(pts) {
    if (pts >= DISC_TIER_THRESHOLDS.black)  return 'black';
    if (pts >= DISC_TIER_THRESHOLDS.white)  return 'white';
    if (pts >= DISC_TIER_THRESHOLDS.bronze) return 'bronze';
    if (pts >= DISC_TIER_THRESHOLDS.silver) return 'silver';
    return 'gold';
}

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
        `, [id, pts, req.user.userId]);

        // Compute revolving points inline — includes manual (game_id IS NULL) entries.
        // calculate_player_tier() is a DB function that filters game_id IS NOT NULL so it
        // never counts manual entries. We bypass it here and derive tier ourselves.
        const revolvingResult = await client.query(`
            SELECT COALESCE(SUM(dr.points), 0) AS revolving_pts
            FROM discipline_records dr
            WHERE dr.player_id = $1
            AND (dr.game_id IS NULL OR dr.game_id IN (
                SELECT r.game_id FROM registrations r
                JOIN games g ON g.id = r.game_id
                WHERE r.player_id = $1 AND r.status = 'confirmed'
                AND g.game_status = 'completed'
                ORDER BY g.game_date DESC LIMIT 10
            ))
        `, [id]);
        const revolvingPts = parseInt(revolvingResult.rows[0].revolving_pts);
        const newTier = tierFromRevolvingPoints(revolvingPts);
        await client.query('UPDATE players SET reliability_tier = $1 WHERE id = $2', [newTier, id]);

        await client.query('COMMIT');
        res.json({ success: true, newTier, pointsAdded: pts, revolvingTotal: revolvingPts });
        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'discipline_added', id,
                `${pts} point(s) added manually | revolving total: ${revolvingPts} | new tier: ${newTier}`);
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Add discipline points error:', error);
        res.status(500).json({ error: 'Failed to add discipline points' });
    } finally {
        client.release();
    }
});

// DELETE /api/admin/discipline/:recordId — remove a discipline record and recalculate tier
app.delete('/api/admin/discipline/:recordId', authenticateToken, requireAdmin, async (req, res) => {
    const { recordId } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Fetch the record before deleting so we can audit it
        const recordResult = await client.query(
            'SELECT id, player_id, points, offense_type FROM discipline_records WHERE id = $1',
            [recordId]
        );
        if (recordResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Discipline record not found' });
        }
        const record = recordResult.rows[0];
        const playerId = record.player_id;

        // Delete the record
        await client.query('DELETE FROM discipline_records WHERE id = $1', [recordId]);

        // Recalculate revolving points (last 10 completed games + manual entries)
        const revolvingResult = await client.query(`
            SELECT COALESCE(SUM(dr.points), 0) AS revolving_pts
            FROM discipline_records dr
            WHERE dr.player_id = $1
            AND (dr.game_id IS NULL OR dr.game_id IN (
                SELECT r.game_id FROM registrations r
                JOIN games g ON g.id = r.game_id
                WHERE r.player_id = $1 AND r.status = 'confirmed'
                AND g.game_status = 'completed'
                ORDER BY g.game_date DESC LIMIT 10
            ))
        `, [playerId]);
        const revolvingPts = parseInt(revolvingResult.rows[0].revolving_pts);
        const newTier = tierFromRevolvingPoints(revolvingPts);

        await client.query('UPDATE players SET reliability_tier = $1 WHERE id = $2', [newTier, playerId]);
        await client.query('COMMIT');

        res.json({ success: true, newTier, revolvingTotal: revolvingPts, removedPoints: record.points });

        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'discipline_removed', playerId,
                `${record.points} point(s) removed (${record.offense_type}) | new revolving total: ${revolvingPts} | new tier: ${newTier}`);
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Remove discipline record error:', error);
        res.status(500).json({ error: 'Failed to remove discipline record' });
    } finally {
        client.release();
    }
});

// POST /api/admin/players/:id/recalc-tier — force-recalculate a player's tier from their revolving points
// Fixes stale tiers caused by legacy code or manual corrections.
// Admin only. Uses same inline logic as the manual discipline endpoint.
app.post('/api/admin/players/:id/recalc-tier', authenticateToken, requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const revolvingResult = await pool.query(`
            SELECT COALESCE(SUM(dr.points), 0) AS revolving_pts
            FROM discipline_records dr
            WHERE dr.player_id = $1
            AND (dr.game_id IS NULL OR dr.game_id IN (
                SELECT r.game_id FROM registrations r
                JOIN games g ON g.id = r.game_id
                WHERE r.player_id = $1 AND r.status = 'confirmed'
                AND g.game_status = 'completed'
                ORDER BY g.game_date DESC LIMIT 10
            ))
        `, [id]);
        const revolvingPts = parseInt(revolvingResult.rows[0].revolving_pts);
        const newTier = tierFromRevolvingPoints(revolvingPts);
        await pool.query('UPDATE players SET reliability_tier = $1 WHERE id = $2', [newTier, id]);
        res.json({ success: true, newTier, revolvingTotal: revolvingPts });
        setImmediate(() => auditLog(pool, req.user.playerId, 'tier_recalculated', id,
            `Tier recalculated | revolving pts: ${revolvingPts} | new tier: ${newTier}`));
    } catch (error) {
        console.error('Recalc tier error:', error);
        res.status(500).json({ error: 'Failed to recalculate tier' });
    }
});

// POST /api/admin/players/:id/unban — superadmin only, clears discipline and resets to gold
// CRIT-14: requireSuperAdmin — admins must not be able to unban players the superadmin deliberately banned
app.post('/api/admin/players/:id/unban', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Clear all existing discipline records — clean slate, zero points
        await client.query('DELETE FROM discipline_records WHERE player_id = $1', [id]);

        // Force gold tier — player returns with a clean record
        await client.query(
            'UPDATE players SET reliability_tier = $1 WHERE id = $2',
            ['gold', id]
        );

        // Insert reinstatement notification for the player
        await client.query(`
            INSERT INTO notifications (player_id, type, message)
            VALUES ($1, 'account_reinstated', '✅ Your account has been reinstated. Welcome back.')
        `, [id]);

        await client.query('COMMIT');

        // Fire push notification (non-blocking)
        sendNotification('account_reinstated', id, {}).catch(() => {});

        res.json({ message: 'Player unbanned successfully', newTier: 'gold' });
        setImmediate(async () => {
            await auditLog(pool, req.user.playerId, 'player_unbanned', id,
                `Discipline cleared | new tier: gold`);
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

        sendNotification('new_dm', playerId, {
            preview: `${senderName}: ${preview}`,
            senderName,
        }).catch(() => {});

        res.status(201).json(newMsg);
    } catch (error) {
        console.error('Send DM error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// POST /api/dm/:playerId/report — report a conversation to superadmin
app.post('/api/dm/:playerId/report', authenticateToken, dmReportLimiter, async (req, res) => {
    try {
        const reporterId  = req.user.playerId;
        const { playerId } = req.params; // the other person in the conversation

        if (String(playerId) === String(reporterId)) {
            return res.status(400).json({ error: 'Cannot report yourself' });
        }

        // Fetch reporter info
        const reporterResult = await pool.query(
            'SELECT COALESCE(alias, full_name) AS name FROM players WHERE id = $1',
            [reporterId]
        );
        if (reporterResult.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const reporterName = reporterResult.rows[0].name;

        // Fetch sender info
        const senderResult = await pool.query(
            'SELECT COALESCE(alias, full_name) AS name FROM players WHERE id = $1',
            [playerId]
        );
        if (senderResult.rows.length === 0) return res.status(404).json({ error: 'Other player not found' });
        const senderName = senderResult.rows[0].name;

        // Get the most recent message sent FROM the other player TO the reporter
        const msgResult = await pool.query(`
            SELECT message, created_at
            FROM direct_messages
            WHERE sender_id = $1 AND recipient_id = $2 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
        `, [playerId, reporterId]);

        const latestMsg    = msgResult.rows[0];
        const messageText  = latestMsg ? latestMsg.message : '(no messages found)';
        const messageDate  = latestMsg
            ? new Date(latestMsg.created_at).toLocaleString('en-GB', {
                day: '2-digit', month: 'short', year: 'numeric',
                hour: '2-digit', minute: '2-digit', timeZone: 'Europe/London'
              })
            : 'Unknown';

        // Fire-and-forget email to superadmin
        setImmediate(async () => {
            try {
                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to: SUPERADMIN_EMAIL || 'totalfooty19@gmail.com',
                    subject: `🚨 Message Reported — ${htmlEncode(reporterName).replace(/[\r\n]/g, '')}`,
                    html: wrapEmailHtml(`
                        <p style="font-weight:700;font-size:16px;margin:0 0 16px;">Message Report</p>
                        <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;">
                            <tr><td style="padding:6px 0;color:#888;width:140px;">Reported by</td>
                                <td style="font-weight:900;">${htmlEncode(reporterName)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Message from</td>
                                <td style="font-weight:900;">${htmlEncode(senderName)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Sent at</td>
                                <td>${htmlEncode(messageDate)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;vertical-align:top;">Message</td>
                                <td style="background:#1a1a1a;padding:10px;border-radius:6px;border-left:3px solid #ff3366;">
                                    ${htmlEncode(messageText)}
                                </td></tr>
                        </table>
                        <p style="color:#888;font-size:13px;margin-top:16px;">
                            Log in to the admin panel to review the full conversation.
                        </p>
                    `)
                });
            } catch (e) {
                console.error('DM report email failed (non-critical):', e.message);
            }
        });

        setImmediate(() => auditLog(pool, reporterId, 'dm_reported', playerId,
            `${reporterName} reported a message from ${senderName}`));

        res.json({ message: 'Report submitted successfully' });
    } catch (error) {
        console.error('DM report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
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


// ══════════════════════════════════════════════════════════════════════════════
// REFEREE SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/games/:gameId/apply-ref — referee applies to officiate a game
app.post('/api/games/:gameId/apply-ref', authenticateToken, registrationLimiter, async (req, res) => {
    const { gameId } = req.params;
    try {
        // Must have Referee badge
        const badgeCheck = await pool.query(
            `SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
             WHERE pb.player_id = $1 AND b.name = 'Referee'`,
            [req.user.playerId]
        );
        if (!badgeCheck.rows.length) return res.status(403).json({ error: 'Referee badge required' });

        // Game must exist and require refs
        const game = await pool.query(
            'SELECT id, refs_required, game_status FROM games WHERE id = $1',
            [gameId]
        );
        if (!game.rows.length) return res.status(404).json({ error: 'Game not found' });
        if (game.rows[0].refs_required === 0) return res.status(400).json({ error: 'This game does not require a referee' });
        if (!['available','confirmed'].includes(game.rows[0].game_status)) {
            return res.status(400).json({ error: 'Cannot apply to referee a completed or cancelled game' });
        }

        await pool.query(
            `INSERT INTO game_referees (game_id, player_id, status, applied_at)
             VALUES ($1, $2, 'pending', NOW())
             ON CONFLICT (game_id, player_id)
             DO UPDATE SET status = 'pending', applied_at = NOW()
             WHERE game_referees.status = 'declined'`,
            [gameId, req.user.playerId]
        );

        setImmediate(async () => {
            try {
                gameAuditLog(pool, gameId, req.user.playerId, 'ref_applied',
                    `Player ${req.user.playerId} applied to referee`);
                auditLog(pool, req.user.playerId, 'ref_applied', gameId,
                    `Applied to referee game ${gameId}`);

                // Email the referee confirming their application was received
                const pRow = await pool.query(
                    `SELECT p.alias, p.full_name, u.email
                     FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
                    [req.user.playerId]
                );
                if (!pRow.rows[0]?.email) return;
                const name = pRow.rows[0].alias || pRow.rows[0].full_name;

                const gameData = await getGameDataForNotification(gameId);
                const gameUrl = `https://totalfooty.co.uk/game.html?url=${gameData.game_url || ''}`;

                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to:   pRow.rows[0].email,
                    subject: `👮 Referee Application Received — ${gameData.day}`,
                    html: wrapEmailHtml(`
                        <p style="font-size:16px;font-weight:700;color:#fff;">Hi ${htmlEncode(name)},</p>
                        <p style="color:#888;font-size:14px;margin:0 0 20px;">
                            We've received your referee application for the following game.
                            An organiser will review it shortly and confirm you.
                        </p>
                        <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;margin-bottom:24px;">
                            <tr><td style="padding:6px 0;color:#888;width:80px;">Date</td><td style="font-weight:900;">${htmlEncode(gameData.day)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Time</td><td style="font-weight:900;">${htmlEncode(gameData.time)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:900;">${htmlEncode(gameData.venue)}</td></tr>
                            ${gameData.cost > 0 ? `<tr><td style="padding:6px 0;color:#888;">Ref fee</td><td style="font-weight:900;color:#00cc66;">£${gameData.cost.toFixed(2)}</td></tr>` : ''}
                        </table>
                        <a href="${gameUrl}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;">VIEW GAME</a>
                        <p style="color:#555;font-size:12px;margin-top:24px;">If you no longer want to ref this game, you can withdraw your application from the game page.</p>
                    `)
                });
            } catch (e) {
                console.error('Ref application email failed (non-critical):', e.message);
            }
        });

        res.json({ ok: true, message: 'Application submitted — awaiting organiser confirmation' });
    } catch (error) {
        console.error('Apply ref error:', error);
        res.status(500).json({ error: 'Failed to apply' });
    }
});

// DELETE /api/games/:gameId/apply-ref — referee withdraws their application
app.delete('/api/games/:gameId/apply-ref', authenticateToken, registrationLimiter, async (req, res) => {
    const { gameId } = req.params;
    try {
        await pool.query(
            'DELETE FROM game_referees WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'ref_withdrawn',
            `Referee ${req.user.playerId} withdrew application`));
        res.json({ ok: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to withdraw application' });
    }
});

// GET /api/admin/games/:gameId/referees — list all referee applications for a game
// Accessible to game managers (organisers, CLM admins, admins)
// Returns { refs: [], game: {} } so the panel works even when no refs have been assigned yet
app.get('/api/admin/games/:gameId/referees', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId } = req.params;
    try {
        // Always fetch game meta first — so the panel title/slot display works with 0 refs
        const gameResult = await pool.query(
            `SELECT refs_required, ref_pay, game_status, ref_review_ends FROM games WHERE id = $1`,
            [gameId]
        );
        if (gameResult.rows.length === 0) return res.status(404).json({ error: 'Game not found' });
        const gameInfo = gameResult.rows[0];

        const confirmedCount = await pool.query(
            `SELECT COUNT(*) AS cnt FROM game_referees WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );

        const result = await pool.query(`
            SELECT gr.id, gr.player_id, gr.external_name, gr.status, gr.applied_at, gr.confirmed_at,
                   gr.final_rating, gr.review_count,
                   COALESCE(p.alias, p.full_name, gr.external_name) AS player_name,
                   p.photo_url, p.squad_number,
                   CASE WHEN gr.player_id IS NOT NULL THEN
                       (SELECT COUNT(*) FROM referee_reviews WHERE game_id = $1 AND referee_player_id = gr.player_id)
                   ELSE 0 END AS live_review_count,
                   CASE WHEN gr.player_id IS NOT NULL THEN
                       (SELECT ROUND(AVG(rating)::numeric,1) FROM referee_reviews WHERE game_id = $1 AND referee_player_id = gr.player_id)
                   ELSE NULL END AS live_avg_rating
            FROM game_referees gr
            LEFT JOIN players p ON p.id = gr.player_id
            WHERE gr.game_id = $1
            ORDER BY gr.status DESC, gr.applied_at ASC
        `, [gameId]);

        res.json({
            refs: result.rows,
            game: {
                refs_required:   parseInt(gameInfo.refs_required) || 0,
                ref_pay:         parseFloat(gameInfo.ref_pay) || 0,
                game_status:     gameInfo.game_status,
                ref_review_ends: gameInfo.ref_review_ends,
                confirmed_count: parseInt(confirmedCount.rows[0].cnt)
            }
        });
    } catch (error) {
        console.error('Get game referees error:', error);
        res.status(500).json({ error: 'Failed to fetch referees' });
    }
});

// POST /api/admin/games/:gameId/referees/:refPlayerId/confirm — confirm a referee
app.post('/api/admin/games/:gameId/referees/:refPlayerId/confirm', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId, refPlayerId } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // Lock game row to prevent race condition on slot count
        const game = await client.query('SELECT refs_required FROM games WHERE id = $1 FOR UPDATE', [gameId]);
        if (!game.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Game not found' }); }

        const confirmedCount = await client.query(
            'SELECT COUNT(*) AS cnt FROM game_referees WHERE game_id = $1 AND status = $2',
            [gameId, 'confirmed']
        );
        if (parseInt(confirmedCount.rows[0].cnt) >= game.rows[0].refs_required) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Maximum number of referees already confirmed for this game' });
        }

        const result = await client.query(
            `UPDATE game_referees SET status = 'confirmed', confirmed_at = NOW()
             WHERE game_id = $1 AND player_id = $2
             RETURNING id`,
            [gameId, refPlayerId]
        );
        if (!result.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Application not found' }); }
        await client.query('COMMIT');

        setImmediate(async () => {
            try {
                gameAuditLog(pool, gameId, req.user.playerId, 'ref_confirmed',
                    `Referee ${refPlayerId} confirmed`);
                auditLog(pool, req.user.playerId, 'ref_confirmed', refPlayerId,
                    `Confirmed as referee for game ${gameId}`);

                // In-app notification
                pool.query(
                    `INSERT INTO notifications (player_id, type, message)
                     VALUES ($1, 'ref_confirmed', '✅ You have been confirmed as a referee.')`,
                    [refPlayerId]
                ).catch(() => {});

                // Email the referee confirming they are confirmed
                const pRow = await pool.query(
                    `SELECT p.alias, p.full_name, u.email
                     FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
                    [refPlayerId]
                );
                if (!pRow.rows[0]?.email) return;
                const name = pRow.rows[0].alias || pRow.rows[0].full_name;

                const gameData = await getGameDataForNotification(gameId);
                const gameUrl = `https://totalfooty.co.uk/game.html?url=${gameData.game_url || ''}`;

                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to:   pRow.rows[0].email,
                    subject: `✅ You're confirmed to referee — ${gameData.day}`,
                    html: wrapEmailHtml(`
                        <p style="font-size:16px;font-weight:700;color:#fff;">Hi ${htmlEncode(name)},</p>
                        <p style="color:#888;font-size:14px;margin:0 0 20px;">
                            You have been confirmed as a referee for the following game.
                            Please arrive early to be ready for kick-off.
                        </p>
                        <table style="width:100%;border-collapse:collapse;font-size:15px;color:#ccc;margin-bottom:24px;">
                            <tr><td style="padding:6px 0;color:#888;width:80px;">Date</td><td style="font-weight:900;">${htmlEncode(gameData.day)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Time</td><td style="font-weight:900;">${htmlEncode(gameData.time)}</td></tr>
                            <tr><td style="padding:6px 0;color:#888;">Venue</td><td style="font-weight:900;">${htmlEncode(gameData.venue)}</td></tr>
                            ${gameData.cost > 0 ? `<tr><td style="padding:6px 0;color:#888;">Ref fee</td><td style="font-weight:900;color:#00cc66;">£${gameData.cost.toFixed(2)}</td></tr>` : ''}
                        </table>
                        <a href="${gameUrl}" style="display:inline-block;background:#fff;color:#000;padding:14px 28px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;text-decoration:none;">VIEW GAME</a>
                    `)
                });
            } catch (e) {
                console.error('Ref confirmed email failed (non-critical):', e.message);
            }
        });

        res.json({ ok: true });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Confirm ref error:', error);
        res.status(500).json({ error: 'Failed to confirm referee' });
    } finally {
        client.release();
    }
});

// POST /api/admin/games/:gameId/referees/:refPlayerId/unconfirm — remove confirmation
app.post('/api/admin/games/:gameId/referees/:refPlayerId/unconfirm', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId, refPlayerId } = req.params;
    try {
        await pool.query(
            `UPDATE game_referees SET status = 'pending', confirmed_at = NULL
             WHERE game_id = $1 AND player_id = $2`,
            [gameId, refPlayerId]
        );
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'ref_unconfirmed',
            `Referee ${refPlayerId} unconfirmed`));
        res.json({ ok: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to unconfirm referee' });
    }
});

// POST /api/admin/games/:gameId/referees/add — admin directly adds a referee
// Two paths:
//   { playerId }    — platform player with Referee badge, inserted as confirmed
//   { externalName } — non-platform referee, inserted by name only (no reviews linkable)
app.post('/api/admin/games/:gameId/referees/add', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId } = req.params;
    const { playerId, externalName } = req.body;

    if (!playerId && !externalName?.trim()) {
        return res.status(400).json({ error: 'Either playerId or externalName is required' });
    }

    try {
        // ── External referee path — create or reuse a ghost player profile ───
        if (!playerId) {
            const name = externalName.trim().slice(0, 100);

            // Check if a ghost player with this exact name already exists
            // Case-insensitive match — prevents duplicate "dave smith" / "Dave Smith" profiles
            let ghostId = null;
            const existing = await pool.query(
                `SELECT id FROM players WHERE is_external_ref = TRUE AND LOWER(full_name) = LOWER($1) LIMIT 1`,
                [name]
            );

            if (existing.rows.length > 0) {
                // Reuse the existing ghost profile
                ghostId = existing.rows[0].id;
            } else {
                // Create a new ghost player — no user_id, no credits, no stats
                const ghostResult = await pool.query(
                    `INSERT INTO players (user_id, full_name, first_name, last_name, alias, phone, position,
                                         reliability_tier, is_external_ref,
                                         overall_rating, goalkeeper_rating, defending_rating, strength_rating,
                                         fitness_rating, pace_rating, decisions_rating, assisting_rating, shooting_rating)
                     VALUES (NULL, $1, $1, '', $1, '', 'outfield', 'gold', TRUE,
                             0, 0, 0, 0, 0, 0, 0, 0, 0)
                     RETURNING id`,
                    [name]
                );
                ghostId = ghostResult.rows[0].id;

                // Create credits row (required by FK constraints)
                await pool.query(
                    'INSERT INTO credits (player_id, balance) VALUES ($1, 0.00)',
                    [ghostId]
                );

                // Grant Referee badge so they appear in ref searches automatically
                const refBadge = await pool.query("SELECT id FROM badges WHERE name = 'Referee'");
                if (refBadge.rows.length > 0) {
                    await pool.query(
                        'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [ghostId, refBadge.rows[0].id]
                    );
                }

                setImmediate(() => auditLog(pool, req.user.playerId, 'external_ref_created', ghostId,
                    `Ghost profile created for external referee: ${name}`));
            }

            // Check they're not already on this game
            const alreadyOn = await pool.query(
                'SELECT status FROM game_referees WHERE game_id = $1 AND player_id = $2',
                [gameId, ghostId]
            );
            if (alreadyOn.rows.length > 0 && alreadyOn.rows[0].status === 'confirmed') {
                return res.status(400).json({ error: `${name} is already a confirmed referee for this game` });
            }

            if (alreadyOn.rows.length > 0) {
                await pool.query(
                    `UPDATE game_referees SET status = 'confirmed', confirmed_at = NOW()
                     WHERE game_id = $1 AND player_id = $2`,
                    [gameId, ghostId]
                );
            } else {
                await pool.query(
                    `INSERT INTO game_referees (game_id, player_id, external_name, status, applied_at, confirmed_at)
                     VALUES ($1, $2, $3, 'confirmed', NOW(), NOW())`,
                    [gameId, ghostId, name]
                );
            }

            setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'ref_admin_added',
                `External referee "${name}" (ghost player ${ghostId}) added by admin`));
            return res.json({ ok: true, message: `${name} added as external referee` });
        }

        // ── Platform player path ─────────────────────────────────────────────
        const playerCheck = await pool.query(
            `SELECT p.id, COALESCE(p.alias, p.full_name) AS name,
             EXISTS(
                 SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                 WHERE pb.player_id = p.id AND b.name = 'Referee'
             ) AS has_ref_badge
             FROM players p WHERE p.id = $1`,
            [playerId]
        );
        if (playerCheck.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const player = playerCheck.rows[0];
        if (!player.has_ref_badge) {
            return res.status(400).json({ error: `${player.name} does not have the Referee badge` });
        }

        // Upsert — if they applied/were declined, upgrade to confirmed; otherwise insert fresh
        const existing = await pool.query(
            'SELECT status FROM game_referees WHERE game_id = $1 AND player_id = $2',
            [gameId, playerId]
        );
        if (existing.rows.length > 0) {
            if (existing.rows[0].status === 'confirmed') {
                return res.status(400).json({ error: `${player.name} is already a confirmed referee for this game` });
            }
            await pool.query(
                `UPDATE game_referees SET status = 'confirmed', confirmed_at = NOW()
                 WHERE game_id = $1 AND player_id = $2`,
                [gameId, playerId]
            );
        } else {
            await pool.query(
                `INSERT INTO game_referees (game_id, player_id, status, applied_at, confirmed_at)
                 VALUES ($1, $2, 'confirmed', NOW(), NOW())`,
                [gameId, playerId]
            );
        }

        // In-app notification (non-critical)
        pool.query(
            `INSERT INTO notifications (player_id, type, message)
             VALUES ($1, 'ref_confirmed', '\u2705 You have been added as a referee for an upcoming game.')`,
            [playerId]
        ).catch(() => {});

        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'ref_admin_added',
            `${player.name} (${playerId}) added as referee by admin`));

        res.json({ ok: true, message: `${player.name} added as referee` });
    } catch (error) {
        console.error('Admin add referee error:', error);
        res.status(500).json({ error: 'Failed to add referee' });
    }
});

// DELETE /api/admin/games/:gameId/referees/:entryId — hard-remove a referee entry by row id
// Uses the game_referees primary key (gr.id) so it works for both platform and external refs
app.delete('/api/admin/games/:gameId/referees/:entryId', authenticateToken, requireGameManager, async (req, res) => {
    const { gameId, entryId } = req.params;
    try {
        const result = await pool.query(
            'DELETE FROM game_referees WHERE id = $1 AND game_id = $2 RETURNING player_id, external_name',
            [entryId, gameId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Referee entry not found' });
        const removed = result.rows[0];
        const label = removed.external_name || removed.player_id || entryId;
        setImmediate(() => gameAuditLog(pool, gameId, req.user.playerId, 'ref_removed',
            `Referee ${label} removed from game`));
        res.json({ ok: true });
    } catch (error) {
        console.error('Remove referee error:', error);
        res.status(500).json({ error: 'Failed to remove referee' });
    }
});

// GET /api/public/game/:gameUrl/referees — public referee list + avg scores for game page
app.get('/api/public/game/:gameUrl/referees', async (req, res) => {
    const { gameUrl } = req.params;
    try {
        const gameRes = await pool.query(
            'SELECT id, ref_review_ends FROM games WHERE game_url = $1',
            [gameUrl]
        );
        if (!gameRes.rows.length) return res.status(404).json({ error: 'Game not found' });
        const { id: gameId, ref_review_ends } = gameRes.rows[0];

        const result = await pool.query(`
            SELECT gr.id AS entry_id,
                   gr.player_id,
                   gr.external_name,
                   COALESCE(p.alias, p.full_name, gr.external_name) AS name,
                   p.photo_url,
                   p.squad_number,
                   gr.status,
                   gr.final_rating  AS game_rating,
                   gr.review_count  AS game_review_count,
                   (gr.player_id IS NULL) AS is_external,
                   (SELECT COUNT(*) FROM game_referees gr2
                    WHERE gr2.player_id = gr.player_id
                      AND gr2.status = 'confirmed') AS appearances,
                   (SELECT ROUND(AVG(rr.rating), 1)
                    FROM referee_reviews rr
                    WHERE rr.referee_player_id = gr.player_id) AS career_avg_rating,
                   (SELECT COUNT(*)
                    FROM referee_reviews rr
                    WHERE rr.referee_player_id = gr.player_id) AS career_review_count
            FROM game_referees gr
            LEFT JOIN players p ON p.id = gr.player_id
            WHERE gr.game_id = $1 AND gr.status = 'confirmed'
            ORDER BY gr.confirmed_at ASC
        `, [gameId]);

        res.json({
            referees: result.rows,
            review_closes_at: ref_review_ends
        });
    } catch (error) {
        console.error('Public referees error:', error);
        res.status(500).json({ error: 'Failed to fetch referees' });
    }
});

// POST /api/games/:gameId/ref-review/:refPlayerId — submit or update a referee review
// SEC: only confirmed players for that game can review
app.post('/api/games/:gameId/ref-review/:refPlayerId', authenticateToken, fairnessLimiter, async (req, res) => {
    const { gameId, refPlayerId } = req.params;
    const { rating, comment } = req.body;

    if (!rating || ![1,2,3,4,5].includes(parseInt(rating))) {
        return res.status(400).json({ error: 'Rating must be 1–5' });
    }
    const safeComment = (typeof comment === 'string') ? comment.trim().slice(0, 500) : null;

    try {
        // Must be confirmed player in that game
        const playerCheck = await pool.query(
            `SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [gameId, req.user.playerId]
        );
        if (!playerCheck.rows.length) {
            return res.status(403).json({ error: 'Only confirmed players can review a referee' });
        }

        // Ref must be confirmed for this game
        const refCheck = await pool.query(
            `SELECT 1 FROM game_referees WHERE game_id = $1 AND player_id = $2 AND status = 'confirmed'`,
            [gameId, refPlayerId]
        );
        if (!refCheck.rows.length) return res.status(404).json({ error: 'Referee not found for this game' });

        // Review window must be open
        const gameCheck = await pool.query('SELECT ref_review_ends FROM games WHERE id = $1', [gameId]);
        const closesAt = gameCheck.rows[0]?.ref_review_ends;
        if (!closesAt || new Date() > new Date(closesAt)) {
            return res.status(400).json({ error: 'Referee review window has closed' });
        }

        // Cannot review yourself
        if (req.user.playerId === refPlayerId) {
            return res.status(400).json({ error: 'You cannot review yourself' });
        }

        const isUpdate = await pool.query(
            'SELECT id FROM referee_reviews WHERE game_id=$1 AND referee_player_id=$2 AND reviewer_player_id=$3',
            [gameId, refPlayerId, req.user.playerId]
        );
        const isEdit = isUpdate.rows.length > 0;

        await pool.query(
            `INSERT INTO referee_reviews (game_id, referee_player_id, reviewer_player_id, rating, comment)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (game_id, referee_player_id, reviewer_player_id)
             DO UPDATE SET rating = $4, comment = $5, updated_at = NOW()`,
            [gameId, refPlayerId, req.user.playerId, parseInt(rating), safeComment]
        );

        // Recalculate average and update audit
        const avgRes = await pool.query(
            `SELECT ROUND(AVG(rating), 1) AS avg, COUNT(*) AS cnt
             FROM referee_reviews WHERE game_id = $1 AND referee_player_id = $2`,
            [gameId, refPlayerId]
        );
        const avg = avgRes.rows[0].avg;
        const cnt = avgRes.rows[0].cnt;

        setImmediate(() => {
            const action = isEdit ? 'ref_review_updated' : 'ref_review_received';
            const detail = `rating:${rating}${safeComment ? ' comment:yes' : ''} avg_now:${avg} total_reviews:${cnt}`;
            gameAuditLog(pool, gameId, req.user.playerId, action,
                `Reviewer ${req.user.playerId} rated ref ${refPlayerId}: ${rating}★ — ${detail}`);
            auditLog(pool, req.user.playerId, action, refPlayerId,
                `Rated referee in game ${gameId}: ${rating}★${safeComment ? ` — "${safeComment}"` : ''}`);
            // Log comment separately if present
            if (safeComment) {
                gameAuditLog(pool, gameId, req.user.playerId, 'ref_review_comment',
                    `Comment for ref ${refPlayerId}: "${safeComment}"`);
                auditLog(pool, req.user.playerId, 'ref_review_comment', refPlayerId,
                    `Comment in game ${gameId}: "${safeComment}"`);
            }
            // Update ref_score_finalised flag when enough reviews
            if (parseInt(cnt) >= 3) {
                gameAuditLog(pool, gameId, null, 'ref_score_updated',
                    `Ref ${refPlayerId} current avg: ${avg}★ (${cnt} reviews)`);
            }
        });

        res.json({ ok: true, avg_rating: avg, review_count: cnt, is_edit: isEdit });
    } catch (error) {
        console.error('Ref review error:', error);
        res.status(500).json({ error: 'Failed to submit review' });
    }
});

// GET /api/games/:gameId/my-ref-review/:refPlayerId — get logged-in player's review for a ref
app.get('/api/games/:gameId/my-ref-review/:refPlayerId', authenticateToken, async (req, res) => {
    const { gameId, refPlayerId } = req.params;
    try {
        const result = await pool.query(
            `SELECT rating, comment FROM referee_reviews
             WHERE game_id = $1 AND referee_player_id = $2 AND reviewer_player_id = $3`,
            [gameId, refPlayerId, req.user.playerId]
        );
        res.json(result.rows[0] || null);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch review' });
    }
});

// GET /api/admin/audit/feed — platform-wide chronological feed of all audit events
// Supports cursor-based pagination (?before=ISO_TIMESTAMP) and group filtering (?group=X)
app.get('/api/admin/audit/feed', authenticateToken, requireAdmin, async (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit) || 100, 200);
    const before = req.query.before ? new Date(req.query.before) : null;
    const group  = req.query.group  || null;

    // Validate before param
    if (req.query.before && isNaN(before)) {
        return res.status(400).json({ error: 'Invalid before timestamp' });
    }

    // Group → action filter map
    const GROUP_ACTIONS = {
        players:    ['player_created','player_updated','player_deleted','account_updated','stats_updated','tier_recalculated','badges_updated','badge_auto_awarded','badge_auto_removed'],
        games:      ['game_created','game_confirmed','game_completed','game_locked','game_unlocked','teams_generated','teams_confirmed','teams_deleted','type_converted'],
        finance:    ['balance_adjustment','wonderful_initiated','wonderful_credited'],
        registrations: ['admin_player_added','admin_player_removed','guest_added','guest_removed'],
        referees:   ['ref_applied','ref_confirmed','ref_withdrawn','ref_unconfirmed','ref_review_received','ref_review_updated','ref_review_comment','ref_score_updated','ref_score_finalised','referee_invite_created'],
        moderation: ['dm_reported','discipline_added','player_unbanned'],
        admins:     ['admin_added','admin_removed','ref_admin_added'],
        motm:       ['motm_voting_started','motm_vote','motm_finalized'],
        awards:     ['award_vote'],
    };

    const allGroups = Object.keys(GROUP_ACTIONS);
    const filterActions = group && GROUP_ACTIONS[group] ? GROUP_ACTIONS[group] : null;

    try {
        // Build WHERE clauses
        const params = [];
        let wherePlayer = 'WHERE 1=1';
        let whereGame   = 'WHERE 1=1';
        // award_vote is synthetic (game_award_votes has no action col) — include unless filtering to another group
        let whereAward  = 'WHERE 1=1';

        if (before) {
            params.push(before);
            wherePlayer += ` AND al.created_at < $${params.length}`;
            whereGame   += ` AND gal.created_at < $${params.length}`;
            whereAward  += ` AND COALESCE(gav.created_at, g.game_date) < $${params.length}`;
        }
        if (filterActions) {
            params.push(filterActions);
            wherePlayer += ` AND al.action = ANY($${params.length})`;
            whereGame   += ` AND gal.action = ANY($${params.length})`;
            // If the active filter doesn't include award_vote, suppress the awards branch entirely
            if (!filterActions.includes('award_vote')) {
                whereAward = 'WHERE 1=0';
            }
        }
        params.push(limit);
        const limitParam = params.length;

        const result = await pool.query(`
            SELECT
                'player'            AS source,
                al.action,
                al.detail,
                al.created_at,
                al.target_id::text  AS target_id,
                NULL::text          AS game_id,
                COALESCE(ap.alias, ap.full_name) AS admin_name,
                COALESCE(tp.alias, tp.full_name) AS target_name
            FROM audit_logs al
            LEFT JOIN players ap ON ap.id = al.admin_id
            LEFT JOIN players tp ON tp.id::text = al.target_id::text
            ${wherePlayer}

            UNION ALL

            SELECT
                'game'              AS source,
                gal.action,
                gal.detail,
                gal.created_at,
                NULL::text          AS target_id,
                gal.game_id::text   AS game_id,
                COALESCE(ap.alias, ap.full_name) AS admin_name,
                NULL                AS target_name
            FROM game_audit_log gal
            LEFT JOIN players ap ON ap.id = gal.admin_id
            ${whereGame}

            UNION ALL

            SELECT
                'award'             AS source,
                'award_vote'        AS action,
                CONCAT(gav.award_type, ' | ',
                       COALESCE(vp.alias, vp.full_name), ' → ',
                       COALESCE(np.alias, np.full_name))  AS detail,
                COALESCE(gav.created_at, g.game_date)     AS created_at,
                gav.voter_player_id::text                 AS target_id,
                gav.game_id::text                         AS game_id,
                COALESCE(vp.alias, vp.full_name)          AS admin_name,
                COALESCE(np.alias, np.full_name)          AS target_name
            FROM game_award_votes gav
            JOIN games g ON g.id = gav.game_id
            JOIN players vp ON vp.id = gav.voter_player_id
            JOIN players np ON np.id = gav.nominee_player_id
            ${whereAward}

            ORDER BY created_at DESC
            LIMIT $${limitParam}
        `, params);

        const records = result.rows;
        const nextCursor = records.length === limit
            ? records[records.length - 1].created_at
            : null;

        res.json({
            records,
            nextCursor,
            groups: allGroups
        });
    } catch (error) {
        console.error('Audit feed error:', error);
        res.status(500).json({ error: 'Failed to load audit feed' });
    }
});

// GET /api/admin/audit/transactions — paginated credit transaction ledger (FIX-102)
// Query params: type (filter by transaction type), search (player name), limit, offset
app.get('/api/admin/audit/transactions', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
        const offset = Math.max(parseInt(req.query.offset) || 0,   0);
        const type   = req.query.type   || '';
        const search = req.query.search || '';

        const conditions = [];
        const params     = [];

        if (type) {
            params.push(type);
            conditions.push(`ct.type = $${params.length}`);
        }
        if (search) {
            params.push(`%${search}%`);
            conditions.push(`(pp.full_name ILIKE $${params.length} OR pp.alias ILIKE $${params.length})`);
        }

        const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

        // Total count for hasMore
        const countRes = await pool.query(`
            SELECT COUNT(*) FROM credit_transactions ct
            JOIN players pp ON pp.id = ct.player_id
            ${where}
        `, params);
        const total = parseInt(countRes.rows[0].count);

        params.push(limit);
        params.push(offset);

        const rows = await pool.query(`
            SELECT ct.id, ct.created_at, ct.amount, ct.type, ct.description,
                   ct.balance_before, ct.balance_after,
                   pp.id   AS player_id,
                   pp.alias AS player_alias, pp.full_name AS player_name,
                   ap.alias AS admin_alias,  ap.full_name AS admin_name
            FROM credit_transactions ct
            JOIN players pp ON pp.id = ct.player_id
            LEFT JOIN users  au ON au.id = ct.admin_id
            LEFT JOIN players ap ON ap.user_id = au.id
            ${where}
            ORDER BY ct.created_at DESC
            LIMIT $${params.length - 1} OFFSET $${params.length}
        `, params);

        res.json({
            transactions: rows.rows,
            total,
            hasMore: offset + limit < total
        });
    } catch (error) {
        console.error('Transactions audit error:', error);
        res.status(500).json({ error: 'Failed to load transactions' });
    }
});

// GET /api/admin/audit/ref-actions — paginated referee audit events from both logs
app.get('/api/admin/audit/ref-actions', authenticateToken, requireAdmin, async (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit)  || 100, 200);
    const offset = Math.max(parseInt(req.query.offset) || 0,   0);
    const allowedActions = [
        'ref_applied','ref_confirmed','ref_withdrawn','ref_unconfirmed',
        'ref_review_received','ref_review_updated','ref_review_comment','ref_score_updated','ref_score_finalised'
    ];
    try {
        // Combine game_audit_log and audit_logs for referee actions
        const result = await pool.query(`
            SELECT 'game' AS source, action, detail, game_id::text AS target_id,
                   admin_id, created_at
            FROM game_audit_log
            WHERE action = ANY($1)
            UNION ALL
            SELECT 'player', action, detail, target_id::text,
                   admin_id, created_at
            FROM audit_logs
            WHERE action = ANY($1)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        `, [allowedActions, limit, offset]);

        const countRes = await pool.query(
            `SELECT (
                SELECT COUNT(*) FROM game_audit_log WHERE action = ANY($1)
             ) + (
                SELECT COUNT(*) FROM audit_logs WHERE action = ANY($1)
             ) AS total`,
            [allowedActions]
        );
        const total = parseInt(countRes.rows[0].total);

        res.json({
            rows:    result.rows,
            total,
            hasMore: offset + result.rows.length < total
        });
    } catch (error) {
        console.error('Ref audit error:', error);
        res.status(500).json({ error: 'Failed to load referee audit log' });
    }
});


// ── REFEREE INVITE SYSTEM ─────────────────────────────────────────────────────

const refereeInviteLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    message: { error: 'Too many requests' }
});

// POST /api/admin/referee-invite — admin generates a one-time referee invite link
app.post('/api/admin/referee-invite', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const code      = 'REF' + crypto.randomBytes(8).toString('hex').toUpperCase();
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        await pool.query(
            `INSERT INTO referee_invites (code, created_by, expires_at) VALUES ($1, $2, $3)`,
            [code, req.user.playerId, expiresAt]
        );
        const link = `https://totalfooty.co.uk/?referee_invite=${code}`;
        setImmediate(() => auditLog(pool, req.user.playerId, 'referee_invite_created',
            req.user.playerId, `code: ${code}`));
        res.json({ code, link, expiresAt });
    } catch (error) {
        console.error('Generate referee invite error:', error);
        res.status(500).json({ error: 'Failed to generate invite link' });
    }
});

// GET /api/public/referee-invite/:code — validate an invite code (before registration)
app.get('/api/public/referee-invite/:code', refereeInviteLimiter, async (req, res) => {
    try {
        const { code } = req.params;
        if (!code || !/^[A-Z0-9]+$/.test(code)) return res.json({ valid: false });
        const result = await pool.query(
            `SELECT id FROM referee_invites
             WHERE code = $1 AND used_at IS NULL AND expires_at > NOW()`,
            [code.toUpperCase()]
        );
        res.json({ valid: result.rows.length > 0 });
    } catch (error) {
        res.json({ valid: false });
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

// GET /api/games/:gameId/my-team
// Returns the logged-in player's team for a game.
// Checks in order: confirmed team_players → draft_memory fixed_team → venue_clash preference.
// This means team chat is available as soon as a player has ANY team assignment,
// even before teams_confirmed is set — enabling early team chat for draft_memory series
// and venue clash games.
app.get('/api/games/:gameId/my-team', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    try {
        // 1. Check confirmed team_players (post-draft or confirmed teams)
        const teamResult = await pool.query(`
            SELECT t.id AS team_id, t.team_name
            FROM team_players tp
            JOIN teams t ON t.id = tp.team_id
            WHERE tp.player_id = $1 AND t.game_id = $2
            LIMIT 1
        `, [req.user.playerId, gameId]);
        if (teamResult.rows.length > 0) {
            return res.json({
                teamId:   teamResult.rows[0].team_id,
                teamName: teamResult.rows[0].team_name
            });
        }

        // 2. Check draft_memory fixed assignment (pre-confirmed)
        const gameInfo = await pool.query(
            'SELECT team_selection_type, series_id, is_venue_clash FROM games WHERE id = $1',
            [gameId]
        );
        const g = gameInfo.rows[0];
        if (!g) return res.json({ teamId: null, teamName: null });

        if (g.team_selection_type === 'draft_memory' && g.series_id) {
            const ftResult = await pool.query(
                'SELECT fixed_team FROM player_fixed_teams WHERE player_id = $1 AND series_id = $2',
                [req.user.playerId, g.series_id]
            );
            if (ftResult.rows.length > 0 && ftResult.rows[0].fixed_team) {
                const name = ftResult.rows[0].fixed_team; // 'red' or 'blue'
                return res.json({ teamId: `draft-${name}`, teamName: name });
            }
        }

        // 3. Check venue_clash team preference (pre-confirmed)
        if (g.is_venue_clash) {
            const vcResult = await pool.query(
                `SELECT r.venue_clash_team_preference,
                        g.venue_clash_team1_name, g.venue_clash_team2_name
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = $1 AND r.game_id = $2 AND r.status = 'confirmed'`,
                [req.user.playerId, gameId]
            );
            if (vcResult.rows.length > 0) {
                const row = vcResult.rows[0];
                let pref = row.venue_clash_team_preference;
                const t1Name = row.venue_clash_team1_name;
                const t2Name = row.venue_clash_team2_name;
                // Resolve positional keys stored by signup form → actual names
                if (pref === 'team1') pref = t1Name;
                else if (pref === 'team2') pref = t2Name;
                // 'both' and null mean no firm assignment yet
                if (pref && pref !== 'both') {
                    return res.json({ teamId: `vc-${pref}`, teamName: pref });
                }
            }
        }

        return res.json({ teamId: null, teamName: null });
    } catch (error) {
        console.error('My team error:', error);
        res.status(500).json({ error: 'Failed to fetch team assignment' });
    }
});


// Helper: resolve a player's pre-draft team name (draft_memory or venue_clash)
// Returns null if not applicable or not assigned.
async function resolvePreDraftTeam(playerId, gameId) {
    const gRes = await pool.query(
        'SELECT team_selection_type, series_id, is_venue_clash, venue_clash_team1_name, venue_clash_team2_name FROM games WHERE id = $1',
        [gameId]
    );
    const g = gRes.rows[0];
    if (!g) return null;
    if (g.team_selection_type === 'draft_memory' && g.series_id) {
        const ft = await pool.query(
            'SELECT fixed_team FROM player_fixed_teams WHERE player_id = $1 AND series_id = $2',
            [playerId, g.series_id]
        );
        if (ft.rows[0]?.fixed_team) return ft.rows[0].fixed_team; // 'red' or 'blue'
    }
    if (g.is_venue_clash) {
        const vc = await pool.query(
            "SELECT venue_clash_team_preference FROM registrations WHERE player_id = $1 AND game_id = $2 AND status = 'confirmed'",
            [playerId, gameId]
        );
        const pref = vc.rows[0]?.venue_clash_team_preference;
        if (pref) {
            // Map team name → 'red'/'blue' so scope stays within valid DB values
            // team1 → 'red', team2 → 'blue'
            return pref === g.venue_clash_team1_name ? 'red' : 'blue';
        }
    }
    return null;
}

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
        // Team messages filtered server-side: confirmed teams by team_id, pre-draft by scope.
        let myTeamId = null;
        let myPreDraftTeam = null; // 'red' or 'blue' for pre-confirmed team assignments
        if (req.user?.playerId) {
            const teamRes = await pool.query(`
                SELECT tp.team_id
                FROM team_players tp
                JOIN teams t ON t.id = tp.team_id
                WHERE tp.player_id = $1 AND t.game_id = $2
                LIMIT 1
            `, [req.user.playerId, gameId]);
            myTeamId = teamRes.rows[0]?.team_id || null;
            if (!myTeamId) {
                myPreDraftTeam = await resolvePreDraftTeam(req.user.playerId, gameId).catch(() => null);
            }
        }

        // Normalise pre-draft scope to lowercase so it matches stored message scopes.
        // Frontend always lowercases (team_corpus not team_Corpus) — this ensures they match.
        const preDraftScope = myPreDraftTeam ? `team_${myPreDraftTeam.toLowerCase()}` : null;
        // Build parameterised query — preDraftScope passed as $3/$4 not interpolated (SQL injection fix)
        let params, sinceClause, preDraftClause;
        if (preDraftScope && since) {
            params = [gameId, myTeamId, preDraftScope, since];
            preDraftClause = 'OR gm.scope = $3';
            sinceClause = 'AND gm.created_at > $4::timestamptz';
        } else if (preDraftScope) {
            params = [gameId, myTeamId, preDraftScope];
            preDraftClause = 'OR gm.scope = $3';
            sinceClause = '';
        } else if (since) {
            params = [gameId, myTeamId, since];
            preDraftClause = '';
            sinceClause = 'AND gm.created_at > $3::timestamptz';
        } else {
            params = [gameId, myTeamId];
            preDraftClause = '';
            sinceClause = '';
        }

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
                  OR (gm.scope = 'team' AND $2::uuid IS NOT NULL AND gm.team_id = $2::uuid)
                  ${preDraftClause}
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
app.post('/api/games/:gameId/messages', authenticateToken, gameChatLimiter, async (req, res) => {
    const { gameId } = req.params;
    const { message, scope = 'chat' } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
        return res.status(400).json({ error: 'Message is required' });
    }
    if (message.trim().length > 500) {
        return res.status(400).json({ error: 'Message must be 500 characters or fewer' });
    }
    // Accept 'chat', 'team', and any 'team_*' pre-draft scope (team_red, team_blue, team_corpus, etc.)
    if (scope !== 'chat' && scope !== 'team' && !scope.startsWith('team_')) {
        return res.status(400).json({ error: 'Invalid scope' });
    }

    let resolvedScope = scope; // declared outside try so catch can reference it safely
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
            // Confirmed team assignment
            const teamRes = await pool.query(`
                SELECT tp.team_id
                FROM team_players tp
                JOIN teams t ON t.id = tp.team_id
                WHERE tp.player_id = $1 AND t.game_id = $2
                LIMIT 1
            `, [req.user.playerId, gameId]);
            if (teamRes.rows.length > 0) {
                teamId = teamRes.rows[0].team_id;
            } else {
                // Fall back to pre-draft team — auto-resolve scope
                const preDraft = await resolvePreDraftTeam(req.user.playerId, gameId).catch(() => null);
                if (!preDraft) return res.status(403).json({ error: 'You are not assigned to a team in this game' });
                resolvedScope = `team_${preDraft}`;
            }
        } else if (scope.startsWith('team_')) {
            // Pre-draft scope (team_red, team_blue, team_<venue_clash_name>, etc.)
            // Verify server-side that player is actually on that team
            const preDraft = await resolvePreDraftTeam(req.user.playerId, gameId).catch(() => null);
            const expectedScope = preDraft ? 'team_' + preDraft.toLowerCase() : null;
            if (!expectedScope || scope !== expectedScope) {
                return res.status(403).json({ error: 'You are not on that team' });
            }
            resolvedScope = scope;
        }

        const insertResult = await pool.query(`
            INSERT INTO game_messages (game_id, player_id, team_id, scope, message)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, scope, message, created_at, player_id
        `, [gameId, req.user.playerId, teamId, resolvedScope, message.trim()]);

        const inserted = insertResult.rows[0];
        // Fetch player name separately — avoids correlated subqueries in RETURNING
        const playerRow = await pool.query(
            "SELECT COALESCE(alias, full_name, 'Unknown') AS player_alias, full_name AS player_name FROM players WHERE id = $1",
            [req.user.playerId]
        );
        const p = playerRow.rows[0] || { player_alias: 'Unknown', player_name: '' };

        res.status(201).json({
            id:           inserted.id,
            game_id:      gameId,
            player_id:    req.user.playerId,
            scope:        inserted.scope,
            message:      inserted.message,
            created_at:   inserted.created_at,
            player_alias: p.player_alias,
            player_name:  p.player_name
        });
    } catch (error) {
        console.error('Post message error — scope:', resolvedScope, 'gameId:', gameId, 'error:', error.message);
        res.status(500).json({ error: 'Failed to post message', detail: error.message });
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
            const resetLink = `https://totalfooty.co.uk/reset-password.html?token=${token}`;
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

        const hash = await bcrypt.hash(newPassword, 10);
        // HIGH-2: Bump token_version — all previously issued JWTs are now invalid
        await pool.query(
            'UPDATE users SET password_hash = $1, token_version = token_version + 1, force_password_change = FALSE WHERE id = $2',
            [hash, req.user.userId]
        );

        setImmediate(() => auditLog(pool, req.user.playerId, 'password_changed', req.user.playerId, 'Password changed via account settings'));
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// POST /api/auth/force-change-password — for players who must change on first sign-in
// No current password required — admin has already reset it. Clears force_password_change flag.
app.post('/api/auth/force-change-password', authenticateToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Verify this user actually has the flag set (prevents misuse)
        const userCheck = await pool.query(
            'SELECT force_password_change FROM users WHERE id = $1',
            [req.user.userId]
        );
        if (!userCheck.rows[0]?.force_password_change) {
            return res.status(403).json({ error: 'No password change required' });
        }

        const hash = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password_hash = $1, force_password_change = FALSE, token_version = token_version + 1 WHERE id = $2',
            [hash, req.user.userId]
        );

        // Issue a fresh cookie with updated token_version
        const playerRow = await pool.query(
            'SELECT p.id, p.is_clm_admin, p.is_organiser, u.role, u.token_version FROM players p JOIN users u ON u.id = p.user_id WHERE u.id = $1',
            [req.user.userId]
        );
        const pr = playerRow.rows[0];
        const newToken = jwt.sign(
            { userId: req.user.userId, playerId: pr.id, email: req.user.email,
              role: pr.role, isCLMAdmin: pr.is_clm_admin || false,
              isOrganiser: pr.is_organiser || false, tokenVersion: pr.token_version },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.cookie('tf_token', newToken, {
            httpOnly: true, secure: true, sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        setImmediate(() => auditLog(pool, req.user.playerId, 'force_password_changed', req.user.playerId,
            'Password changed after admin reset'));
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Force change password error:', error);
        res.status(500).json({ error: 'Failed to update password' });
    }
});

// POST /api/admin/players/:playerId/reset-password — superadmin only
// Resets player password to Totalfooty1 and forces change on next sign-in
app.post('/api/admin/players/:playerId/reset-password', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;

        // Resolve user_id from player
        const playerRow = await pool.query(
            'SELECT p.id, u.id AS user_id, COALESCE(p.alias, p.full_name) AS display_name FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1',
            [playerId]
        );
        if (playerRow.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const { user_id, display_name } = playerRow.rows[0];

        const hash = await bcrypt.hash('Totalfooty1', 10);
        await pool.query(
            'UPDATE users SET password_hash = $1, force_password_change = TRUE, token_version = token_version + 1 WHERE id = $2',
            [hash, user_id]
        );

        await auditLog(pool, req.user.userId, 'admin_password_reset', playerId,
            `Password reset to default by admin — force change on next login`);
        res.json({ message: `Password reset for ${display_name}. They will be prompted to change it on next sign-in.` });
    } catch (error) {
        console.error('Admin reset password error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
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
        const passwordHash = await bcrypt.hash(newPassword, 10);

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

        // Issue a fresh session cookie so the player is immediately logged in
        const freshPlayer = await pool.query(
            `SELECT p.id, p.is_clm_admin, p.is_organiser, u.id as user_id, u.email, u.role, u.token_version
             FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
            [resetToken.player_id]
        );
        if (freshPlayer.rows.length > 0) {
            const fp = freshPlayer.rows[0];
            const freshToken = jwt.sign(
                { userId: fp.user_id, playerId: fp.id, email: fp.email,
                  role: fp.role, isCLMAdmin: fp.is_clm_admin || false,
                  isOrganiser: fp.is_organiser || false, tokenVersion: fp.token_version },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            res.cookie('tf_token', freshToken, {
                httpOnly: true, secure: true, sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });
        }

        setImmediate(() => auditLog(pool, resetToken.player_id, 'password_reset', resetToken.player_id, 'Password reset via email token'));
        res.json({ message: 'Password updated successfully. You are now logged in.' });
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


// ── REPORTING ENDPOINTS ───────────────────────────────────────────────────────

app.get('/api/reports/games', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT g.id, g.game_date, g.format, g.exclusivity, g.max_players, g.cost_per_player,
                g.game_status, g.winning_team, g.game_url, v.name as venue_name,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) as signups,
                COALESCE((SELECT COUNT(*) FROM game_guests gg WHERE gg.game_id = g.id), 0) as guest_count,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.status = 'backup'), 0) as backup_count,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) +
                COALESCE((SELECT COUNT(*) FROM game_guests gg WHERE gg.game_id = g.id), 0) as total_players,
                COALESCE((SELECT SUM(COALESCE(NULLIF(r.amount_paid,0), CASE WHEN r.is_comped THEN 0 ELSE g.cost_per_player END))
                    FROM registrations r WHERE r.game_id = g.id AND r.status = 'confirmed'), 0) +
                COALESCE((SELECT SUM(gg.amount_paid) FROM game_guests gg WHERE gg.game_id = g.id), 0) as revenue,
                COALESCE((SELECT COUNT(*) FROM motm_votes mv WHERE mv.game_id = g.id), 0) as motm_votes_total,
                p.alias as motm_winner
            FROM games g LEFT JOIN venues v ON v.id = g.venue_id LEFT JOIN players p ON p.id = g.motm_winner_id
            ORDER BY g.game_date DESC
        `);
        res.json(result.rows);
    } catch (error) { console.error('Reports games error:', error); res.status(500).json({ error: 'Failed to load games report' }); }
});

app.get('/api/reports/players', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.squad_number, p.alias, p.full_name as name, p.reliability_tier as tier,
                p.total_appearances as appearances, p.motm_wins, p.overall_rating,
                COALESCE(c.balance, 0) as credit_balance,
                COALESCE((SELECT SUM(ABS(ct.amount)) FROM credit_transactions ct WHERE ct.player_id = p.id AND ct.type = 'game_fee'), 0) as revenue_spent,
                COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.player_id = p.id AND r.status = 'confirmed'), 0) as confirmed_games,
                COALESCE((SELECT COUNT(*) FROM discipline_records dr WHERE dr.player_id = p.id AND dr.offense_type = 'Late Drop Out'), 0) as late_dropouts,
                COALESCE((SELECT COUNT(*) FROM players ref WHERE ref.referred_by = p.id), 0) as referrals,
                COALESCE((SELECT COUNT(*) FROM game_guests gg WHERE gg.invited_by = p.id), 0) as guests_added,
                COALESCE((SELECT json_agg(b.name ORDER BY b.name) FROM player_badges pb JOIN badges b ON b.id = pb.badge_id WHERE pb.player_id = p.id), '[]'::json) as badge_names,
                u.email
            FROM players p LEFT JOIN credits c ON c.player_id = p.id LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.squad_number ASC NULLS LAST
        `);
        res.json(result.rows);
    } catch (error) { console.error('Reports players error:', error); res.status(500).json({ error: 'Failed to load players report' }); }
});

app.get('/api/reports/players/list', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, COALESCE(alias, full_name) as name, squad_number FROM players ORDER BY squad_number ASC NULLS LAST`);
        res.json(result.rows);
    } catch (error) { res.status(500).json({ error: 'Failed to load players list' }); }
});

app.get('/api/reports/player/:id/games', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(`
            SELECT g.id, g.game_date, g.format, g.game_url, v.name as venue_name,
                r.status, r.position_preference, r.tournament_team_preference,
                COALESCE(NULLIF(r.amount_paid,0), CASE WHEN r.is_comped THEN 0 ELSE g.cost_per_player END) as amount_paid,
                r.is_comped,
                CASE WHEN g.winning_team IS NOT NULL AND t.team_name = g.winning_team THEN 'W'
                     WHEN g.winning_team IS NOT NULL AND t.team_name IS NOT NULL THEN 'L'
                     ELSE NULL END as result,
                t.team_name,
                COALESCE((SELECT COUNT(*) FROM motm_votes mv WHERE mv.game_id = g.id AND mv.voted_for_player_id = p.id), 0) as motm_votes_received,
                COALESCE((SELECT COUNT(*) FROM motm_votes mv2 WHERE mv2.game_id = g.id AND mv2.voter_player_id = p.id), 0) as voted,
                COALESCE((SELECT COUNT(*) FROM game_guests gg WHERE gg.game_id = g.id AND gg.invited_by = p.id), 0) as guests_brought,
                (g.motm_winner_id = p.id) as won_motm
            FROM registrations r JOIN games g ON g.id = r.game_id JOIN players p ON p.id = r.player_id
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN team_players tp ON tp.player_id = p.id
            LEFT JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
            WHERE r.player_id = $1 AND r.status = 'confirmed' ORDER BY g.game_date DESC
        `, [id]);
        res.json(result.rows);
    } catch (error) { console.error('Reports player games error:', error); res.status(500).json({ error: 'Failed to load player game history' }); }
});

// FIX-043: Catch-all 404 handler moved to after coaching routes

// FIX-037: Global handlers — SEC-012: uncaughtException now exits to prevent undefined server state
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled Promise Rejection:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception — exiting:', err.message);
    process.exit(1);
});

// ═══════════════════════════════════════════════════════════════
// COACHING SYSTEM — S2 Endpoints
// Inserted before app.listen()
// ═══════════════════════════════════════════════════════════════

// ── Coaching helper: audit log ────────────────────────────────
async function logCoachingAudit(sessionId, requestId, actorPlayerId, action, detail) {
    try {
        await pool.query(
            `INSERT INTO coaching_audit_log
             (session_id, request_id, actor_player_id, action, detail)
             VALUES ($1, $2, $3, $4, $5)`,
            [sessionId || null, requestId || null, actorPlayerId || null, action, detail || null]
        );
    } catch (e) {
        console.error('coaching audit log failed:', e.message);
    }
}

// ── Coaching helper: venue availability check ─────────────────
// Returns true if venue is valid for the given session date + duration
function isVenueAvailable(rule, sessionDate, durationHours) {
    if (!sessionDate) return true; // no date yet — allow at creation time
    const d = new Date(sessionDate);
    const month = d.getMonth() + 1; // 1-indexed
    const day   = d.getDay();        // 0=Sun,6=Sat
    const hour  = d.getHours();

    if (rule === 'anytime') return true;

    if (rule === 'no_weekday_after_16_outside_may_aug') {
        const isSummer = month >= 5 && month <= 8;
        const isWeekday = day >= 1 && day <= 5;
        if (isWeekday && !isSummer && hour >= 16) return false;
        return true;
    }

    if (rule === 'weekend_only_before_15') {
        const isWeekend = day === 0 || day === 6;
        if (!isWeekend) return false;
        // session must start before 15:00
        if (hour >= 15) return false;
        return true;
    }

    return true;
}

// ── Coaching helper: price range calculator ───────────────────
// Returns { minPrice, maxPrice } across all candidate venues
function calcSessionPriceRange(venues, coachHourlyRate, durationHours, maxPlayers) {
    // Duration = how long coach is present. Players each get 1hr, so total player slots = maxPlayers * durationHours.
    // Price = fixed running costs / total slots + ppPlayer (flat per player, 1hr only).
    const TF_MARGIN_PER_HOUR = 20;
    const FLOOR = 13.50;

    let bestPrice = Infinity;

    for (const v of venues) {
        const pitchHire    = (parseFloat(v.coaching_cost_per_hour) || 0) * durationHours;
        const coachTotal   = coachHourlyRate * durationHours;
        const tfTotal      = TF_MARGIN_PER_HOUR * durationHours;
        const ppCoach      = (parseFloat(v.pay_and_play_coach_hourly) || 0) * durationHours;
        const ppPlayer     = parseFloat(v.pay_and_play_player_hourly) || 0;

        const sessionFixed = pitchHire + coachTotal + tfTotal + ppCoach;
        const totalSlots   = maxPlayers * durationHours;
        const pricePerPlayer = Math.max(FLOOR, sessionFixed / totalSlots + ppPlayer);

        if (pricePerPlayer < bestPrice) bestPrice = pricePerPlayer;
    }

    if (venues.length === 0) return { minPrice: null, maxPrice: null };
    const price = Math.round(bestPrice * 100) / 100;
    return { minPrice: price, maxPrice: price };
}

// ── Coaching helper: send email to list of players ────────────
async function sendCoachingEmail(playerIds, subject, htmlBody) {
    if (!playerIds || playerIds.length === 0) return;
    try {
        const result = await pool.query(
            'SELECT u.email FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = ANY($1) AND email IS NOT NULL',
            [playerIds]
        );
        const emails = result.rows.map(r => r.email);
        if (emails.length === 0) return;
        await emailTransporter.sendMail({
            from: '"TotalFooty" <totalfooty19@gmail.com>',
            bcc:  emails.join(', '),
            subject,
            html: wrapEmailHtml(htmlBody)
        });
    } catch (e) {
        console.error('sendCoachingEmail failed:', e.message);
    }
}

// ══════════════════════════════════════════════════════════════
// PUBLIC: GET /api/coaching/coaches
// List all players with Coach badge + coaching stats
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/coaches', optionalAuth, publicEndpointLimiter, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.full_name AS player_name, p.alias, p.photo_url AS profile_photo,
                   p.coach_certifications, p.coach_experience,
                   p.coach_min_hourly_rate, p.coaching_appearances,
                   COALESCE(AVG(cf.rating), 0)::NUMERIC(3,2) AS avg_rating,
                   COUNT(cf.id) AS review_count
            FROM players p
            JOIN player_badges pb ON pb.player_id = p.id
            JOIN badges b ON b.id = pb.badge_id AND b.name = 'Coach'
            LEFT JOIN coaching_feedback cf ON cf.coach_player_id = p.id
            GROUP BY p.id, p.full_name, p.alias, p.photo_url,
                     p.coach_certifications, p.coach_experience,
                     p.coach_min_hourly_rate, p.coaching_appearances
            ORDER BY p.coaching_appearances DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/coaching/coaches:', e.message);
        res.status(500).json({ error: 'Failed to fetch coaches' });
    }
});

// ══════════════════════════════════════════════════════════════
// PUBLIC: GET /api/coaching/sessions
// List upcoming open coaching sessions (public browse)
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/sessions', optionalAuth, publicEndpointLimiter, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT cs.id, cs.session_url, cs.activity_type, cs.group_type,
                   cs.max_players, cs.session_date, cs.status, cs.duration_hours,
                   cs.min_price, cs.max_price, cs.is_full,
                   cs.session_notes,
                   p.full_name AS coach_name, p.alias AS coach_alias,
                   p.photo_url AS coach_photo, p.coaching_appearances,
                   COALESCE(AVG(cf.rating), 0)::NUMERIC(3,2) AS coach_avg_rating,
                   v.name AS venue_name, v.address AS venue_address,
                   (SELECT COUNT(*) FROM coaching_registrations cr
                    WHERE cr.session_id = cs.id AND cr.status = 'registered') AS registered_count
            FROM coaching_sessions cs
            LEFT JOIN players p ON p.id = cs.coach_player_id
            LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
            LEFT JOIN coaching_feedback cf ON cf.coach_player_id = cs.coach_player_id
            WHERE cs.status IN ('open','coach_confirmed','venue_confirmed','finalised')
              AND (cs.session_date IS NULL OR cs.session_date > NOW())
            GROUP BY cs.id, p.id, v.id
            ORDER BY cs.session_date ASC NULLS LAST
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/coaching/sessions:', e.message);
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// ══════════════════════════════════════════════════════════════
// PUBLIC: GET /api/coaching/session/:url
// Full session details for session.html
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/session/:url', optionalAuth, publicEndpointLimiter, async (req, res) => {
    const { url } = req.params;
    if (!url || !/^[a-zA-Z0-9_-]{3,50}$/.test(url)) {
        return res.status(400).json({ error: 'Invalid session URL' });
    }
    try {
        const sResult = await pool.query(`
            SELECT cs.id, cs.session_url, cs.activity_type, cs.group_type,
                   cs.max_players, cs.session_date, cs.status, cs.duration_hours,
                   cs.min_price, cs.max_price, cs.is_full, cs.session_notes,
                   cs.coach_confirmed, cs.created_at, cs.pitch_number,
                   p.id AS coach_id, p.full_name AS coach_name,
                   p.alias AS coach_alias, p.photo_url AS coach_photo,
                   p.coach_certifications, p.coaching_appearances,
                   COALESCE(avg_sub.avg_rating, 0) AS coach_avg_rating,
                   v.id AS venue_id, v.name AS venue_name, v.address AS venue_address,
                   v.postcode AS venue_postcode, v.parking_pin AS venue_parking_pin,
                   v.pitch_pin AS venue_pitch_pin, v.boot_type AS venue_boot_type,
                   v.pitch_name AS venue_pitch_name,
                   v.special_instructions AS venue_special_instructions
            FROM coaching_sessions cs
            LEFT JOIN players p ON p.id = cs.coach_player_id
            LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
            LEFT JOIN (
                SELECT coach_player_id, AVG(rating)::NUMERIC(3,2) AS avg_rating
                FROM coaching_feedback GROUP BY coach_player_id
            ) avg_sub ON avg_sub.coach_player_id = cs.coach_player_id
            WHERE cs.session_url = $1
        `, [url]);

        if (sResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        const session = sResult.rows[0];

        // Registered players (only show names + start times if finalised)
        const regResult = await pool.query(`
            SELECT cr.id, cr.start_time, cr.activity_focus, cr.status,
                   p.full_name AS player_name, p.alias, p.photo_url AS profile_photo, p.id AS player_id
            FROM coaching_registrations cr
            JOIN players p ON p.id = cr.player_id
            WHERE cr.session_id = $1 AND cr.status = 'registered'
            ORDER BY cr.start_time ASC NULLS LAST, cr.registered_at ASC
        `, [session.id]);

        // Candidate venues (before confirmed)
        const venueResult = await pool.query(`
            SELECT v.id, v.name, v.address
            FROM coaching_session_venues csv
            JOIN venues v ON v.id = csv.venue_id
            WHERE csv.session_id = $1
        `, [session.id]);

        // Feedback (post-completion)
        const feedbackResult = await pool.query(`
            SELECT cf.rating, cf.comment, cf.created_at,
                   p.full_name AS player_name, p.alias
            FROM coaching_feedback cf
            JOIN players p ON p.id = cf.player_id
            WHERE cf.session_id = $1
            ORDER BY cf.created_at DESC
        `, [session.id]);

        // Has the calling player already given feedback?
        let playerRegistered = false;
        let playerFeedbackGiven = false;
        if (req.user) {
            const preg = await pool.query(
                `SELECT id FROM coaching_registrations
                 WHERE session_id=$1 AND player_id=$2 AND status='registered'`,
                [session.id, req.user.playerId]
            );
            playerRegistered = preg.rows.length > 0;
            const pfb = await pool.query(
                `SELECT id FROM coaching_feedback WHERE session_id=$1 AND player_id=$2`,
                [session.id, req.user.playerId]
            );
            playerFeedbackGiven = pfb.rows.length > 0;
        }

        res.json({
            id: session.id,
            session_url: session.session_url,
            activity_type: session.activity_type,
            group_type: session.group_type,
            max_players: session.max_players,
            session_date: session.session_date,
            status: session.status,
            duration_hours: session.duration_hours,
            min_price: session.min_price,
            max_price: session.max_price,
            is_full: session.is_full,
            session_notes: session.session_notes,
            coach_confirmed: session.coach_confirmed,
            coach: session.coach_id ? {
                id: session.coach_id,
                name: session.coach_name,
                alias: session.coach_alias,
                photo: session.coach_photo,
                certifications: session.coach_certifications,
                appearances: session.coaching_appearances,
                avg_rating: session.coach_avg_rating
            } : null,
            venue: session.venue_id ? {
                id: session.venue_id,
                name: session.venue_name,
                address: session.venue_address,
                postcode: session.venue_postcode,
                parking_pin: session.venue_parking_pin,
                pitch_pin: session.venue_pitch_pin,
                boot_type: session.venue_boot_type,
                pitch_name: session.venue_pitch_name,
                special_instructions: session.venue_special_instructions,
                pitch_number: session.pitch_number
            } : null,
            candidate_venues: venueResult.rows,
            registrations: regResult.rows,
            feedback: feedbackResult.rows,
            player_registered: playerRegistered,
            player_feedback_given: playerFeedbackGiven,
            registered_count: regResult.rows.length
        });
    } catch (e) {
        console.error('GET /api/coaching/session/:url:', e.message);
        res.status(500).json({ error: 'Failed to fetch session' });
    }
});

// ══════════════════════════════════════════════════════════════
// PUBLIC: GET /api/coaching/coach/:id/profile
// Full coach profile + stats + upcoming sessions
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/coach/:id/profile', optionalAuth, publicEndpointLimiter, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) {
        return res.status(400).json({ error: 'Invalid coach ID' });
    }
    try {
        const cResult = await pool.query(`
            SELECT p.id, p.full_name AS player_name, p.alias, p.photo_url AS profile_photo,
                   p.coach_certifications, p.coach_experience,
                   p.coach_min_hourly_rate, p.coaching_appearances,
                   p.created_at AS member_since,
                   COALESCE(AVG(cf.rating), 0)::NUMERIC(3,2) AS avg_rating,
                   COUNT(cf.id) AS review_count
            FROM players p
            JOIN player_badges pb ON pb.player_id = p.id
            JOIN badges b ON b.id = pb.badge_id AND b.name = 'Coach'
            LEFT JOIN coaching_feedback cf ON cf.coach_player_id = p.id
            WHERE p.id = $1
            GROUP BY p.id
        `, [id]);

        if (cResult.rows.length === 0) return res.status(404).json({ error: 'Coach not found' });

        const feedbackResult = await pool.query(`
            SELECT cf.rating, cf.comment, cf.created_at,
                   p.full_name AS player_name, p.alias
            FROM coaching_feedback cf
            JOIN players p ON p.id = cf.player_id
            WHERE cf.coach_player_id = $1
            ORDER BY cf.created_at DESC
            LIMIT 5
        `, [id]);

        const upcomingResult = await pool.query(`
            SELECT cs.id, cs.session_url, cs.activity_type, cs.group_type,
                   cs.session_date, cs.status, cs.min_price, cs.max_price,
                   v.name AS venue_name
            FROM coaching_sessions cs
            LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
            WHERE cs.coach_player_id = $1
              AND cs.status IN ('open','coach_confirmed','venue_confirmed','finalised')
              AND (cs.session_date IS NULL OR cs.session_date > NOW())
            ORDER BY cs.session_date ASC NULLS LAST
            LIMIT 5
        `, [id]);

        const coach = cResult.rows[0];
        res.json({
            id: coach.id,
            name: coach.player_name,
            alias: coach.alias,
            photo: coach.profile_photo,
            certifications: coach.coach_certifications,
            experience: coach.coach_experience,
            min_hourly_rate: coach.coach_min_hourly_rate,
            appearances: coach.coaching_appearances,
            member_since: coach.member_since,
            avg_rating: coach.avg_rating,
            review_count: coach.review_count,
            recent_feedback: feedbackResult.rows,
            upcoming_sessions: upcomingResult.rows
        });
    } catch (e) {
        console.error('GET /api/coaching/coach/:id/profile:', e.message);
        res.status(500).json({ error: 'Failed to fetch coach profile' });
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/sessions
// Create a coaching session (coach or superadmin)
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/sessions', authenticateToken, async (req, res) => {
    const { activity_type, group_type, duration_hours, session_date,
            session_notes, venue_ids } = req.body;

    const VALID_ACTIVITIES = ['fitness','ball_control','defending','shooting','positioning','goalkeeping','various'];
    const VALID_GROUPS     = ['one_to_one','small_group','large_group'];
    const GROUP_MAX        = { one_to_one: 1, small_group: 6, large_group: 15 };

    if (!VALID_ACTIVITIES.includes(activity_type))
        return res.status(400).json({ error: 'Invalid activity_type' });
    if (!VALID_GROUPS.includes(group_type))
        return res.status(400).json({ error: 'Invalid group_type' });
    if (!Number.isInteger(duration_hours) || duration_hours < 1 || duration_hours > 8)
        return res.status(400).json({ error: 'duration_hours must be 1–8' });
    if (!Array.isArray(venue_ids) || venue_ids.length === 0)
        return res.status(400).json({ error: 'At least one venue_id required' });
    if (venue_ids.length > 6)
        return res.status(400).json({ error: 'Maximum 6 candidate venues' });
    if (venue_ids.some(v => typeof v !== 'string' || !/^[0-9a-f-]{36}$/.test(v)))
        return res.status(400).json({ error: 'Invalid venue_id format' });
    if (session_notes && session_notes.length > 1000)
        return res.status(400).json({ error: 'session_notes too long' });
    if (session_date && isNaN(Date.parse(session_date)))
        return res.status(400).json({ error: 'Invalid session_date' });

    // Must be coach or superadmin
    const isCoach = await pool.query(
        `SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
         WHERE pb.player_id = $1 AND b.name = 'Coach'`,
        [req.user.playerId]
    );
    if (isCoach.rows.length === 0 && req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Coach badge required' });

    // Validate all venues exist + get coaching data for price calc
    const venueResult = await pool.query(
        `SELECT id, name, coaching_cost_per_hour, pay_and_play_coach_hourly,
                pay_and_play_player_hourly, availability_rule, coaching_suitable
         FROM venues WHERE id = ANY($1)`,
        [venue_ids]
    );
    if (venueResult.rows.length !== venue_ids.length)
        return res.status(400).json({ error: 'One or more venue IDs not found' });

    const unsuitable = venueResult.rows.filter(v => !v.coaching_suitable);
    if (unsuitable.length > 0)
        return res.status(400).json({ error: `Venue(s) not suitable for coaching: ${unsuitable.map(v => v.name).join(', ')}` });

    // Check availability rule against session date if provided
    if (session_date) {
        const blocked = venueResult.rows.filter(v =>
            !isVenueAvailable(v.availability_rule, session_date, duration_hours)
        );
        if (blocked.length > 0)
            return res.status(400).json({
                error: `Venue(s) not available at that time: ${blocked.map(v => v.name).join(', ')}`
            });
    }

    // Get coach rate for pricing
    const coachRate = isCoach.rows.length > 0
        ? (await pool.query('SELECT coach_min_hourly_rate FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.coach_min_hourly_rate || 0
        : 0;

    const maxPlayers = GROUP_MAX[group_type];
    const { minPrice, maxPrice } = calcSessionPriceRange(
        venueResult.rows, parseFloat(coachRate), duration_hours, maxPlayers
    );

    // Generate unique session URL
    const sessionUrl = 'cs' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Superadmin-selected coach always takes priority; fall back to req.user only if no explicit selection
    let assignedCoachId = null;
    if (req.user.role === 'superadmin' && req.body.assigned_coach_player_id) {
        const acId = req.body.assigned_coach_player_id;
        if (/^[0-9a-f-]{36}$/.test(acId)) {
            const acCheck = await pool.query(
                `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id WHERE pb.player_id=$1 AND b.name='Coach'`,
                [acId]
            );
            if (acCheck.rows.length > 0) assignedCoachId = acId;
        }
    }
    if (!assignedCoachId && isCoach.rows.length > 0) {
        assignedCoachId = req.user.playerId;
    }

    const sessionResult = await client.query(`
            INSERT INTO coaching_sessions
              (session_url, coach_player_id, created_by, duration_hours, activity_type,
               group_type, max_players, session_date, session_notes, min_price, max_price)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            RETURNING id
        `, [
            sessionUrl,
            assignedCoachId,
            req.user.playerId,
            duration_hours, activity_type, group_type, maxPlayers,
            session_date || null,
            session_notes || null,
            minPrice, maxPrice
        ]);
        const sessionId = sessionResult.rows[0].id;

        // Insert candidate venues
        for (const vid of venue_ids) {
            await client.query(
                'INSERT INTO coaching_session_venues (session_id, venue_id) VALUES ($1,$2)',
                [sessionId, vid]
            );
        }

        await client.query('COMMIT');

        await logCoachingAudit(sessionId, null, req.user.playerId, 'session_created',
            `Created by ${req.user.role}. Activity: ${activity_type}, group: ${group_type}, ${duration_hours}hr`);

        // Emails
        const coachName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A coach';
        const activityLabel = activity_type.replace(/_/g, ' ');

        if (req.user.role === 'superadmin') {
            // Email all coaches
            const coaches = await pool.query(
                `SELECT p.id FROM players p JOIN player_badges pb ON pb.player_id=p.id
                 JOIN badges b ON b.id=pb.badge_id AND b.name='Coach'`
            );
            await sendCoachingEmail(
                coaches.rows.map(r => r.id),
                'New Coaching Session Created',
                `<p style="color:#888">A new coaching session has been created by the TotalFooty admin.</p>
                 <table><tr><td style="color:#888;width:140px">Activity</td><td style="color:#fff;font-weight:700">${htmlEncode(activityLabel)}</td></tr>
                 <tr><td style="color:#888">Group Type</td><td style="color:#fff">${htmlEncode(group_type)}</td></tr>
                 <tr><td style="color:#888">Duration</td><td style="color:#fff">${duration_hours}hr</td></tr></table>
                 <p style="color:#888;margin-top:16px">Log in to TotalFooty to view details.</p>`
            );
        } else {
            // Email superadmin
            notifyAdmin(
                `New Coaching Session — ${htmlEncode(activityLabel)}`,
                [['Coach', htmlEncode(coachName)], ['Duration', `${duration_hours}hr`], ['Activity', htmlEncode(activityLabel)], ['Group', htmlEncode(group_type)]]
            );
        }

        // Email all coachable players
        const coachablePlayers = await pool.query(
            `SELECT id FROM players WHERE coachable=TRUE`
        );
        await sendCoachingEmail(
            coachablePlayers.rows.map(r => r.id),
            'New Coaching Session Available',
            `<p style="color:#888">A new coaching session is available on TotalFooty.</p>
             <table><tr><td style="color:#888;width:140px">Activity</td><td style="color:#fff;font-weight:700">${htmlEncode(activityLabel)}</td></tr>
             <tr><td style="color:#888">Group Type</td><td style="color:#fff">${htmlEncode(group_type)}</td></tr>
             <tr><td style="color:#888">Duration</td><td style="color:#fff">${duration_hours}hr</td></tr>
             <tr><td style="color:#888">Price Range</td><td style="color:#fff">£${minPrice?.toFixed(2) || 'TBC'} – £${maxPrice?.toFixed(2) || 'TBC'}</td></tr></table>
             <p style="color:#888;margin-top:16px"><a href="https://totalfooty.co.uk/session.html?url=${sessionUrl}" style="color:#C0392B">View Session →</a></p>`
        );

        res.status(201).json({ id: sessionId, session_url: sessionUrl, min_price: minPrice, max_price: maxPrice });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('POST /api/coaching/sessions:', e.message);
        res.status(500).json({ error: 'Failed to create session' });
    } finally {
        client.release();
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: GET /api/coaching/sessions/:id/edit-data
// Fetch all fields needed to pre-populate the edit modal
// Accessible by session coach or superadmin only
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/sessions/:id/edit-data', authenticateToken, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });
    try {
        const sRes = await pool.query(
            `SELECT cs.*, p.full_name AS coach_name
             FROM coaching_sessions cs
             LEFT JOIN players p ON p.id = cs.coach_player_id
             WHERE cs.id = $1`,
            [id]
        );
        if (sRes.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        const s = sRes.rows[0];

        // Auth: must be the session coach or superadmin
        const isSA = req.user.role === 'superadmin';
        if (!isSA && s.coach_player_id !== req.user.playerId)
            return res.status(403).json({ error: 'Not authorised to edit this session' });

        if (s.status === 'completed' || s.status === 'cancelled')
            return res.status(400).json({ error: 'Cannot edit a completed or cancelled session' });

        // Fetch candidate venues
        const venueRes = await pool.query(
            `SELECT csv.venue_id AS id, v.name
             FROM coaching_session_venues csv
             JOIN venues v ON v.id = csv.venue_id
             WHERE csv.session_id = $1`,
            [id]
        );
        const candidateVenueIds = venueRes.rows.map(v => v.id);
        const candidateVenues   = venueRes.rows.map(v => ({ id: v.id, name: v.name }));

        res.json({
            id: s.id,
            activity_type: s.activity_type,
            group_type: s.group_type,
            duration_hours: s.duration_hours,
            session_date: s.session_date,
            session_notes: s.session_notes,
            status: s.status,
            coach_player_id: s.coach_player_id,
            coach_name: s.coach_name,
            max_players: s.max_players,
            candidate_venue_ids: candidateVenueIds,
            candidate_venues: candidateVenues
        });
    } catch (e) {
        console.error('GET /api/coaching/sessions/:id/edit-data:', e.message);
        res.status(500).json({ error: 'Failed to fetch session edit data' });
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: PUT /api/coaching/sessions/:id
// Update core fields of an existing coaching session
// Accessible by session coach or superadmin only
// ══════════════════════════════════════════════════════════════
app.put('/api/coaching/sessions/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const { activity_type, group_type, duration_hours, venue_ids,
            session_date, session_notes, assigned_coach_player_id } = req.body;

    const VALID_ACTIVITIES = ['fitness','ball_control','defending','shooting','positioning','goalkeeping','various'];
    const VALID_GROUPS     = ['one_to_one','small_group','large_group'];
    const GROUP_MAX        = { one_to_one: 1, small_group: 6, large_group: 15 };

    if (!VALID_ACTIVITIES.includes(activity_type))
        return res.status(400).json({ error: 'Invalid activity_type' });
    if (!VALID_GROUPS.includes(group_type))
        return res.status(400).json({ error: 'Invalid group_type' });
    if (!Number.isInteger(duration_hours) || duration_hours < 1 || duration_hours > 8)
        return res.status(400).json({ error: 'duration_hours must be 1–8' });
    if (!Array.isArray(venue_ids) || venue_ids.length === 0)
        return res.status(400).json({ error: 'At least one venue_id required' });
    if (venue_ids.length > 6)
        return res.status(400).json({ error: 'Maximum 6 candidate venues' });
    if (venue_ids.some(v => typeof v !== 'string' || !/^[0-9a-f-]{36}$/.test(v)))
        return res.status(400).json({ error: 'Invalid venue_id format' });
    if (session_notes && session_notes.length > 1000)
        return res.status(400).json({ error: 'session_notes too long (max 1000 chars)' });
    if (session_date && isNaN(Date.parse(session_date)))
        return res.status(400).json({ error: 'Invalid session_date' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Fetch current session
        const sRes = await client.query(
            `SELECT id, coach_player_id, status, coach_confirmed, confirmed_venue_id,
                    activity_type, group_type, duration_hours, session_date, session_time,
                    min_price_per_player, max_price_per_player, notes, session_url
             FROM coaching_sessions WHERE id = $1 FOR UPDATE`,
            [id]
        );
        if (sRes.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Session not found' }); }
        const session = sRes.rows[0];

        // Auth: must be session coach or superadmin
        const isSA = req.user.role === 'superadmin';
        if (!isSA && session.coach_player_id !== req.user.playerId) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Not authorised to edit this session' });
        }
        if (session.status === 'completed' || session.status === 'cancelled') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Cannot edit a completed or cancelled session' });
        }

        // Validate venues exist and are coaching-suitable
        const venueResult = await client.query(
            `SELECT id, name, coaching_cost_per_hour, pay_and_play_coach_hourly,
                    pay_and_play_player_hourly, coaching_suitable
             FROM venues WHERE id = ANY($1)`,
            [venue_ids]
        );
        if (venueResult.rows.length !== venue_ids.length)
            { await client.query('ROLLBACK'); return res.status(400).json({ error: 'One or more venue IDs not found' }); }
        const unsuitable = venueResult.rows.filter(v => !v.coaching_suitable);
        if (unsuitable.length > 0)
            { await client.query('ROLLBACK'); return res.status(400).json({ error: `Venues not suitable: ${unsuitable.map(v => v.name).join(', ')}` }); }

        // Resolve new coach (SA only)
        let newCoachId = session.coach_player_id;
        if (isSA && assigned_coach_player_id && /^[0-9a-f-]{36}$/.test(assigned_coach_player_id)) {
            const coachCheck = await client.query(
                `SELECT 1 FROM player_badges pb JOIN badges b ON b.id = pb.badge_id
                 WHERE pb.player_id = $1 AND b.name = 'Coach'`,
                [assigned_coach_player_id]
            );
            if (coachCheck.rows.length === 0)
                { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Assigned player does not hold the Coach badge' }); }
            newCoachId = assigned_coach_player_id;
        }

        // Detect coach change → reset coach_confirmed
        const coachChanged = newCoachId !== session.coach_player_id;
        let newCoachConfirmed = coachChanged ? false : session.coach_confirmed;

        // Recalculate max_players + prices
        const maxPlayers = GROUP_MAX[group_type];
        const coachRateRes = await client.query('SELECT coach_min_hourly_rate FROM players WHERE id = $1', [newCoachId]);
        const coachRate = parseFloat(coachRateRes.rows[0]?.coach_min_hourly_rate || 0);
        const { minPrice, maxPrice } = calcSessionPriceRange(venueResult.rows, coachRate, duration_hours, maxPlayers);

        // Replace candidate venues atomically
        await client.query('DELETE FROM coaching_session_venues WHERE session_id = $1', [id]);
        for (const vid of venue_ids) {
            await client.query('INSERT INTO coaching_session_venues (session_id, venue_id) VALUES ($1, $2)', [id, vid]);
        }

        // Clear confirmed_venue_id if it is no longer a candidate
        let newConfirmedVenueId = session.confirmed_venue_id;
        if (newConfirmedVenueId && !venue_ids.includes(String(newConfirmedVenueId))) {
            newConfirmedVenueId = null;
        }

        // Recalculate status
        let newStatus = 'open';
        if (newConfirmedVenueId && newCoachConfirmed) newStatus = 'venue_confirmed';
        else if (newCoachConfirmed) newStatus = 'coach_confirmed';
        // Preserve finalised
        if (session.status === 'finalised') newStatus = 'finalised';

        await client.query(
            `UPDATE coaching_sessions SET
                activity_type     = $1,
                group_type        = $2,
                duration_hours    = $3,
                session_date      = $4,
                session_notes     = $5,
                max_players       = $6,
                min_price         = $7,
                max_price         = $8,
                coach_player_id   = $9,
                coach_confirmed   = $10,
                confirmed_venue_id = $11,
                status            = $12,
                updated_at        = NOW()
             WHERE id = $13`,
            [activity_type, group_type, duration_hours,
             session_date || null, session_notes || null,
             maxPlayers, minPrice, maxPrice,
             newCoachId, newCoachConfirmed, newConfirmedVenueId,
             newStatus, id]
        );

        await client.query('COMMIT');

        const editorRole = isSA ? 'superadmin' : 'coach';
        await logCoachingAudit(id, null, req.user.playerId, 'session_edited',
            `Edited by ${editorRole} — activity: ${activity_type}, group: ${group_type}, duration: ${duration_hours}h`
        ).catch(() => {});

        res.json({ ok: true });
    } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('PUT /api/coaching/sessions/:id:', e.message);
        res.status(500).json({ error: 'Failed to update session' });
    } finally {
        client.release();
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/sessions/:id/register
// Player signs up for a coaching session
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/sessions/:id/register', authenticateToken, registrationLimiter, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    try {
        const sessionResult = await pool.query(
            `SELECT id, max_players, is_full, status, coach_player_id, activity_type
             FROM coaching_sessions WHERE id=$1`,
            [id]
        );
        if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

        const session = sessionResult.rows[0];
        if (!['open','coach_confirmed','venue_confirmed','finalised'].includes(session.status))
            return res.status(400).json({ error: 'Session is not open for registration' });
        if (session.is_full)
            return res.status(400).json({ error: 'Session is full' });

        // Check not already registered
        const existing = await pool.query(
            `SELECT id FROM coaching_registrations WHERE session_id=$1 AND player_id=$2`,
            [id, req.user.playerId]
        );
        if (existing.rows.length > 0)
            return res.status(400).json({ error: 'Already registered' });

        await pool.query(
            `INSERT INTO coaching_registrations (session_id, player_id) VALUES ($1,$2)`,
            [id, req.user.playerId]
        );

        // Check if now full
        const countResult = await pool.query(
            `SELECT COUNT(*) AS cnt FROM coaching_registrations
             WHERE session_id=$1 AND status='registered'`,
            [id]
        );
        const count = parseInt(countResult.rows[0].cnt);
        if (count >= session.max_players) {
            await pool.query(`UPDATE coaching_sessions SET is_full=TRUE WHERE id=$1`, [id]);
            // Notify superadmin + coach
            const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
            notifyAdmin('Coaching Session Full', [['Details', `Session ${htmlEncode(id)} is now full (${session.max_players} players).`]]);
            if (session.coach_player_id) {
                await sendCoachingEmail([session.coach_player_id], 'Your Coaching Session Is Full',
                    `<p style="color:#888">Your ${htmlEncode(session.activity_type)} coaching session is now full with ${session.max_players} registered players.</p>`
                );
            }
        } else {
            // Notify coach + admin of new signup
            const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
            notifyAdmin('New Coaching Registration', [['Details', `${htmlEncode(playerName)} signed up for a coaching session (${htmlEncode(session.activity_type)}). ${count}/${session.max_players} players.`]]);
            if (session.coach_player_id) {
                await sendCoachingEmail([session.coach_player_id], 'New Coaching Sign-Up',
                    `<p style="color:#888">${htmlEncode(playerName)} has signed up for your ${htmlEncode(session.activity_type)} session. You now have ${count}/${session.max_players} players.</p>`
                );
            }
        }

        await logCoachingAudit(id, null, req.user.playerId, 'player_registered',
            `Player registered for session. ${count}/${session.max_players} spots filled.`);

        res.json({ success: true, registered_count: count });
    } catch (e) {
        console.error('POST /api/coaching/sessions/:id/register:', e.message);
        res.status(500).json({ error: 'Failed to register' });
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: DELETE /api/coaching/sessions/:id/register
// Player drops out of a coaching session
// ══════════════════════════════════════════════════════════════
app.delete('/api/coaching/sessions/:id/register', authenticateToken, registrationLimiter, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    try {
        const regResult = await pool.query(
            `SELECT cr.id FROM coaching_registrations cr
             JOIN coaching_sessions cs ON cs.id = cr.session_id
             WHERE cr.session_id=$1 AND cr.player_id=$2 AND cr.status='registered'
               AND cs.status NOT IN ('completed','cancelled')`,
            [id, req.user.playerId]
        );
        if (regResult.rows.length === 0)
            return res.status(404).json({ error: 'Registration not found or session already completed' });

        await pool.query(
            `UPDATE coaching_registrations SET status='dropped' WHERE id=$1`,
            [regResult.rows[0].id]
        );
        // Un-fill if was full
        await pool.query(
            `UPDATE coaching_sessions SET is_full=FALSE WHERE id=$1 AND is_full=TRUE`,
            [id]
        );

        const sessionResult = await pool.query(
            'SELECT coach_player_id, activity_type FROM coaching_sessions WHERE id=$1', [id]
        );
        const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';

        notifyAdmin('Coaching Drop-Out', [['Details', `${htmlEncode(playerName)} dropped out of a coaching session (${htmlEncode(sessionResult.rows[0]?.activity_type || 'unknown')}).`]]);
        if (sessionResult.rows[0]?.coach_player_id) {
            await sendCoachingEmail([sessionResult.rows[0].coach_player_id], 'Player Dropped Out',
                `<p style="color:#888">${htmlEncode(playerName)} has dropped out of your ${htmlEncode(sessionResult.rows[0].activity_type)} coaching session.</p>`
            );
        }

        await logCoachingAudit(id, null, req.user.playerId, 'player_dropped', `Player dropped out.`);
        res.json({ success: true });
    } catch (e) {
        console.error('DELETE /api/coaching/sessions/:id/register:', e.message);
        res.status(500).json({ error: 'Failed to drop out' });
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/requests
// Player submits a coaching session request
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/requests', authenticateToken, registrationLimiter, async (req, res) => {
    const { coach_player_id, activity_type, group_type, time_preference, notes } = req.body;

    const VALID_ACTIVITIES = ['fitness','ball_control','defending','shooting','positioning','goalkeeping','various'];
    const VALID_GROUPS     = ['one_to_one','small_group','large_group'];

    if (activity_type && !VALID_ACTIVITIES.includes(activity_type))
        return res.status(400).json({ error: 'Invalid activity_type' });
    if (group_type && !VALID_GROUPS.includes(group_type))
        return res.status(400).json({ error: 'Invalid group_type' });
    if (coach_player_id && !/^[0-9a-f-]{36}$/.test(coach_player_id))
        return res.status(400).json({ error: 'Invalid coach_player_id' });
    if (time_preference && time_preference.length > 500)
        return res.status(400).json({ error: 'time_preference too long' });
    if (notes && notes.length > 1000)
        return res.status(400).json({ error: 'notes too long' });

    // If specific coach, verify they have Coach badge
    if (coach_player_id) {
        const check = await pool.query(
            `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id
             WHERE pb.player_id=$1 AND b.name='Coach'`,
            [coach_player_id]
        );
        if (check.rows.length === 0) return res.status(400).json({ error: 'Specified player is not a coach' });
    }

    const result = await pool.query(
        `INSERT INTO coaching_requests
           (player_id, coach_player_id, activity_type, group_type, time_preference, notes)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
        [req.user.playerId, coach_player_id || null, activity_type || null,
         group_type || null, time_preference || null, notes || null]
    );
    const requestId = result.rows[0].id;

    await logCoachingAudit(null, requestId, req.user.playerId, 'session_request_submitted',
        `Activity: ${activity_type || 'any'}, group: ${group_type || 'any'}, coach: ${coach_player_id || 'any'}`);

    const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
    notifyAdmin('New Coaching Request', [['Details', `${htmlEncode(playerName)} submitted a coaching request. Activity: ${htmlEncode(activity_type || 'any')}.`]]);

    if (coach_player_id) {
        await sendCoachingEmail([coach_player_id], 'New Coaching Request For You',
            `<p style="color:#888">${htmlEncode(playerName)} has requested a coaching session with you.</p>
             <table>
             ${activity_type ? `<tr><td style="color:#888;width:140px">Activity</td><td style="color:#fff">${htmlEncode(activity_type.replace(/_/g,' '))}</td></tr>` : ''}
             ${group_type ? `<tr><td style="color:#888">Group Type</td><td style="color:#fff">${htmlEncode(group_type)}</td></tr>` : ''}
             ${time_preference ? `<tr><td style="color:#888">Time Pref</td><td style="color:#fff">${htmlEncode(time_preference)}</td></tr>` : ''}
             </table>
             <p style="color:#888;margin-top:16px">Log in to TotalFooty to respond.</p>`
        );
    } else {
        // Notify all coaches
        const allCoaches = await pool.query(
            `SELECT p.id FROM players p JOIN player_badges pb ON pb.player_id=p.id
             JOIN badges b ON b.id=pb.badge_id AND b.name='Coach'`
        );
        await sendCoachingEmail(
            allCoaches.rows.map(r => r.id),
            'New Coaching Request (Any Coach)',
            `<p style="color:#888">${htmlEncode(playerName)} is looking for any available coach.</p>
             ${activity_type ? `<p style="color:#888">Activity: ${htmlEncode(activity_type.replace(/_/g,' '))}</p>` : ''}
             <p style="color:#888;margin-top:16px">Log in to TotalFooty to respond.</p>`
        );
    }

    res.status(201).json({ id: requestId });
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/requests/:id/respond
// Coach or superadmin responds to a request (approve/reject/reply)
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/requests/:id/respond', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { action, message } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid request ID' });
    if (!['approve','reject','reply'].includes(action)) return res.status(400).json({ error: 'action must be approve / reject / reply' });
    if (message && message.length > 2000) return res.status(400).json({ error: 'message too long' });

    // Must be coach or superadmin
    const isCoach = await pool.query(
        `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id
         WHERE pb.player_id=$1 AND b.name='Coach'`,
        [req.user.playerId]
    );
    if (isCoach.rows.length === 0 && req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Coach badge required to respond' });

    const reqResult = await pool.query(
        `SELECT id, player_id, coach_player_id, activity_type, status FROM coaching_requests WHERE id=$1`,
        [id]
    );
    if (reqResult.rows.length === 0) return res.status(404).json({ error: 'Request not found' });

    const coachReq = reqResult.rows[0];
    if (coachReq.status !== 'pending')
        return res.status(400).json({ error: 'Request already actioned' });

    const newStatus = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'replied';
    await pool.query(`UPDATE coaching_requests SET status=$1 WHERE id=$2`, [newStatus, id]);

    await logCoachingAudit(null, id, req.user.playerId, `request_${newStatus}`,
        `${action} by ${req.user.role}. ${message ? 'Message included.' : ''}`);

    const actorName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'TotalFooty';
    const subjectMap = { approve: 'Your Coaching Request Was Approved ✅', reject: 'Update on Your Coaching Request', reply: 'Reply to Your Coaching Request' };
    const bodyMap = {
        approve: `<p style="color:#888">Your coaching request has been approved by ${htmlEncode(actorName)}. A session will be created for you shortly.</p>`,
        reject:  `<p style="color:#888">Unfortunately your coaching request could not be accommodated at this time.</p>${message ? `<p style="color:#888;margin-top:8px">${htmlEncode(message)}</p>` : ''}`,
        reply:   `<p style="color:#888">${htmlEncode(actorName)} replied to your coaching request:</p><p style="color:#fff;font-style:italic;margin-top:8px">${htmlEncode(message || '')}</p>`
    };

    await sendCoachingEmail([coachReq.player_id], subjectMap[action], bodyMap[action]);
    notifyAdmin(`Coaching Request ${newStatus}`, [['Details', `${htmlEncode(actorName)} ${action}d a coaching request.`]]);

    res.json({ success: true, status: newStatus });
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: POST /api/admin/coaching/sessions/:id/confirm
// Confirm venue and/or coach for a session
// ══════════════════════════════════════════════════════════════
app.post('/api/admin/coaching/sessions/:id/confirm', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { confirm_venue_id, confirm_coach, pitch_number } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });
    if (pitch_number !== undefined && pitch_number !== null && (!Number.isInteger(pitch_number) || pitch_number < 1 || pitch_number > 99))
        return res.status(400).json({ error: 'pitch_number must be an integer between 1 and 99' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, coach_confirmed, confirmed_venue_id, status,
                activity_type, duration_hours, group_type, max_players
         FROM coaching_sessions WHERE id=$1`,
        [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

    const session = sessionResult.rows[0];
    const updates = [];
    const params = [];
    let p = 1;

    if (confirm_venue_id) {
        if (!/^[0-9a-f-]{36}$/.test(confirm_venue_id)) return res.status(400).json({ error: 'Invalid venue ID' });
        // Verify it is a candidate venue for this session
        const csvCheck = await pool.query(
            `SELECT 1 FROM coaching_session_venues WHERE session_id=$1 AND venue_id=$2`,
            [id, confirm_venue_id]
        );
        if (csvCheck.rows.length === 0) return res.status(400).json({ error: 'Venue is not a candidate for this session' });
        updates.push(`confirmed_venue_id=$${p++}`); params.push(confirm_venue_id);
        if (pitch_number !== undefined && pitch_number !== null) {
            updates.push(`pitch_number=$${p++}`); params.push(pitch_number);
        }
        await logCoachingAudit(id, null, req.user.playerId, 'venue_confirmed', `Venue ${confirm_venue_id} confirmed${pitch_number ? `, pitch ${pitch_number}` : ''}.`);
    }

    if (confirm_coach === true) {
        if (!session.coach_player_id) return res.status(400).json({ error: 'No coach assigned to this session yet' });
        updates.push(`coach_confirmed=$${p++}`); params.push(true);
        await logCoachingAudit(id, null, req.user.playerId, 'coach_confirmed', `Coach confirmed.`);
    }

    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to confirm' });

    // Derive new status
    const newVenueId = confirm_venue_id || session.confirmed_venue_id;
    const newCoachConfirmed = confirm_coach === true ? true : session.coach_confirmed;
    let newStatus = session.status;
    if (newVenueId && newCoachConfirmed) newStatus = 'venue_confirmed';
    else if (newCoachConfirmed) newStatus = 'coach_confirmed';

    // Recalculate price with confirmed venue
    if (confirm_venue_id) {
        const vResult = await pool.query(
            `SELECT coaching_cost_per_hour, pay_and_play_coach_hourly, pay_and_play_player_hourly
             FROM venues WHERE id=$1`,
            [confirm_venue_id]
        );
        const coachRateResult = await pool.query(
            `SELECT coach_min_hourly_rate FROM players WHERE id=$1`,
            [session.coach_player_id]
        );
        if (vResult.rows.length > 0 && coachRateResult.rows.length > 0) {
            const { minPrice, maxPrice } = calcSessionPriceRange(
                vResult.rows,
                parseFloat(coachRateResult.rows[0].coach_min_hourly_rate) || 0,
                session.duration_hours,
                session.max_players
            );
            updates.push(`min_price=$${p++}`, `max_price=$${p++}`);
            params.push(minPrice, maxPrice);
        }
    }

    updates.push(`status=$${p++}`, `updated_at=NOW()`); params.push(newStatus);
    params.push(id);
    await pool.query(
        `UPDATE coaching_sessions SET ${updates.join(', ')} WHERE id=$${p}`,
        params
    );

    // Email coach when both confirmed
    if (newVenueId && newCoachConfirmed && session.coach_player_id) {
        await sendCoachingEmail([session.coach_player_id], 'Your Session Is Confirmed — Please Finalise',
            `<p style="color:#888">Both venue and coach have been confirmed for your ${htmlEncode(session.activity_type.replace(/_/g,' '))} session.</p>
             <p style="color:#888;margin-top:8px">Please log in to TotalFooty to finalise the session by assigning player time slots.</p>`
        );
    }

    res.json({ success: true, status: newStatus });
});

// ══════════════════════════════════════════════════════════════
// COACH: POST /api/coaching/sessions/:id/finalise
// Assign player start times + activity focus (or edit: PUT)
// ══════════════════════════════════════════════════════════════
async function handleFinalise(req, res) {
    const { id } = req.params;
    const { assignments } = req.body; // [{ player_id, start_time, activity_focus }]
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });
    if (!Array.isArray(assignments) || assignments.length === 0)
        return res.status(400).json({ error: 'assignments array required' });

    // Validate each assignment
    for (const a of assignments) {
        if (!a.player_id || !/^[0-9a-f-]{36}$/.test(a.player_id)) return res.status(400).json({ error: 'Invalid player_id in assignment' });
        if (a.start_time && !/^\d{2}:\d{2}$/.test(a.start_time)) return res.status(400).json({ error: 'start_time must be HH:MM' });
        if (a.activity_focus && a.activity_focus.length > 100) return res.status(400).json({ error: 'activity_focus too long' });
    }

    // Must be coach of this session or superadmin
    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status, activity_type, session_date FROM coaching_sessions WHERE id=$1`,
        [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

    const session = sessionResult.rows[0];
    if (session.coach_player_id !== req.user.playerId && req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Not your session' });
    if (!['coach_confirmed','venue_confirmed'].includes(session.status))
        return res.status(400).json({ error: 'Session must be confirmed before finalising' });
    if (session.status === 'completed') return res.status(400).json({ error: 'Session already completed' });

    // All assigned players must be registered
    const registeredResult = await pool.query(
        `SELECT player_id FROM coaching_registrations WHERE session_id=$1 AND status='registered'`, [id]
    );
    const registeredIds = registeredResult.rows.map(r => r.player_id);
    const invalidAssign = assignments.filter(a => !registeredIds.includes(a.player_id));
    if (invalidAssign.length > 0) return res.status(400).json({ error: 'Some players are not registered for this session' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const a of assignments) {
            await client.query(
                `UPDATE coaching_registrations
                 SET start_time=$1, activity_focus=$2
                 WHERE session_id=$3 AND player_id=$4 AND status='registered'`,
                [a.start_time || null, a.activity_focus || null, id, a.player_id]
            );
        }
        const isEdit = session.status === 'finalised';
        await client.query(
            `UPDATE coaching_sessions SET status='finalised', updated_at=NOW() WHERE id=$1`, [id]
        );
        await client.query('COMMIT');

        await logCoachingAudit(id, null, req.user.playerId,
            isEdit ? 'session_edited' : 'session_finalised',
            `${assignments.length} player(s) assigned time slots.`
        );

        // Email all registered players + superadmin
        const playerDetails = await pool.query(
            `SELECT cr.player_id, cr.start_time, cr.activity_focus, p.full_name AS player_name
             FROM coaching_registrations cr JOIN players p ON p.id=cr.player_id
             WHERE cr.session_id=$1 AND cr.status='registered'`,
            [id]
        );
        const actLabel = htmlEncode(session.activity_type.replace(/_/g,' '));
        for (const pd of playerDetails.rows) {
            await sendCoachingEmail([pd.player_id],
                `Your Coaching Session Is ${isEdit ? 'Updated' : 'Finalised'} ✅`,
                `<p style="color:#888">Your coaching session has been ${isEdit ? 'updated' : 'finalised'}.</p>
                 <table>
                 <tr><td style="color:#888;width:140px">Activity</td><td style="color:#fff;font-weight:700">${actLabel}</td></tr>
                 ${session.session_date ? `<tr><td style="color:#888">Date</td><td style="color:#fff">${new Date(session.session_date).toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}</td></tr>` : ''}
                 ${pd.start_time ? `<tr><td style="color:#888">Your Start Time</td><td style="color:#fff;font-weight:700">${htmlEncode(String(pd.start_time))}</td></tr>` : ''}
                 ${pd.activity_focus ? `<tr><td style="color:#888">Your Focus</td><td style="color:#fff">${htmlEncode(pd.activity_focus)}</td></tr>` : ''}
                 </table>
                 <p style="color:#888;margin-top:16px"><a href="https://totalfooty.co.uk/session.html?url=${session.session_url || ''}" style="color:#C0392B">View Session →</a></p>`
            );
        }
        notifyAdmin(`Session ${isEdit ? 'Re-Finalised' : 'Finalised'}`, [['Details', `${actLabel} coaching session finalised with ${assignments.length} player(s).`]]);

        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('handleFinalise:', e.message);
        res.status(500).json({ error: 'Failed to finalise session' });
    } finally {
        client.release();
    }
}

app.post('/api/coaching/sessions/:id/finalise', authenticateToken, handleFinalise);
app.put('/api/coaching/sessions/:id/finalise',  authenticateToken, handleFinalise);

// ══════════════════════════════════════════════════════════════
// COACH: POST /api/coaching/sessions/:id/complete
// Mark session as completed
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/sessions/:id/complete', authenticateToken, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status, activity_type FROM coaching_sessions WHERE id=$1`, [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

    const session = sessionResult.rows[0];
    if (session.coach_player_id !== req.user.playerId && req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Not your session' });
    if (session.status !== 'finalised') return res.status(400).json({ error: 'Session must be finalised before completing' });

    await pool.query(
        `UPDATE coaching_sessions SET status='completed', updated_at=NOW() WHERE id=$1`, [id]
    );

    // Increment coach appearances
    if (session.coach_player_id) {
        await pool.query(
            `UPDATE players SET coaching_appearances = COALESCE(coaching_appearances,0) + 1 WHERE id=$1`,
            [session.coach_player_id]
        );
    }

    await logCoachingAudit(id, null, req.user.playerId, 'session_completed',
        `Session marked complete by ${req.user.role}.`);

    // Email registered players — prompt for feedback
    const regResult = await pool.query(
        `SELECT cr.player_id FROM coaching_registrations cr
         WHERE cr.session_id=$1 AND cr.status='registered'`, [id]
    );
    const actLabel = htmlEncode(session.activity_type.replace(/_/g,' '));
    if (regResult.rows.length > 0) {
        await sendCoachingEmail(regResult.rows.map(r => r.player_id),
            'Rate Your Coach ⭐',
            `<p style="color:#888">Your ${actLabel} coaching session is now complete. Please take a moment to rate your coach.</p>
             <p style="color:#888;margin-top:12px"><a href="https://totalfooty.co.uk/session.html?url=${id}" style="color:#C0392B;font-weight:700">Rate Your Coach →</a></p>`
        );
    }
    notifyAdmin('Session Completed', [['Details', `${actLabel} coaching session completed.`]]);

    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/sessions/:id/feedback
// Player submits star rating + comment for coach
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/sessions/:id/feedback', authenticateToken, registrationLimiter, async (req, res) => {
    const { id } = req.params;
    const { rating, comment } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'rating must be 1–5' });
    if (comment && comment.length > 1000) return res.status(400).json({ error: 'comment too long' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status FROM coaching_sessions WHERE id=$1`, [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

    const session = sessionResult.rows[0];
    if (session.status !== 'completed') return res.status(400).json({ error: 'Session not yet completed' });
    if (!session.coach_player_id) return res.status(400).json({ error: 'No coach assigned to this session' });

    // Must have been registered
    const regCheck = await pool.query(
        `SELECT id FROM coaching_registrations WHERE session_id=$1 AND player_id=$2 AND status='registered'`,
        [id, req.user.playerId]
    );
    if (regCheck.rows.length === 0) return res.status(403).json({ error: 'Not registered for this session' });

    // Unique constraint handles duplicate — catch 23505
    try {
        await pool.query(
            `INSERT INTO coaching_feedback (session_id, player_id, coach_player_id, rating, comment)
             VALUES ($1,$2,$3,$4,$5)`,
            [id, req.user.playerId, session.coach_player_id, rating, comment || null]
        );
    } catch (e) {
        if (e.code === '23505') return res.status(400).json({ error: 'Feedback already submitted' });
        throw e;
    }

    await logCoachingAudit(id, null, req.user.playerId, 'feedback_submitted',
        `Rating: ${rating}/5.${comment ? ' Comment included.' : ''}`);

    const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
    await sendCoachingEmail([session.coach_player_id], `New Coach Feedback — ${rating}⭐`,
        `<p style="color:#888">${htmlEncode(playerName)} has left you feedback.</p>
         <p style="color:#fff;font-size:18px;margin:12px 0">${'⭐'.repeat(rating)}</p>
         ${comment ? `<p style="color:#aaa;font-style:italic">"${htmlEncode(comment)}"</p>` : ''}`
    );
    notifyAdmin('Coach Feedback Submitted', [['Details', `${htmlEncode(playerName)} gave ${rating}/5 stars for a coaching session.`]]);

    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
// ADMIN: GET /api/admin/coaching/sessions
// All sessions across all coaches (admin view)
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/coaching/sessions', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT cs.id, cs.session_url, cs.activity_type, cs.group_type,
                   cs.max_players, cs.session_date, cs.status, cs.duration_hours,
                   cs.min_price, cs.max_price, cs.is_full, cs.session_notes,
                   cs.coach_confirmed, cs.created_at, cs.updated_at,
                   p.full_name AS coach_name, p.id AS coach_id,
                   v.name AS venue_name, v.id AS venue_id,
                   (SELECT COUNT(*) FROM coaching_registrations cr
                    WHERE cr.session_id=cs.id AND cr.status='registered') AS registered_count,
                   (SELECT json_agg(json_build_object('id',ve.id,'name',ve.name))
                    FROM coaching_session_venues csv2
                    JOIN venues ve ON ve.id=csv2.venue_id
                    WHERE csv2.session_id=cs.id) AS candidate_venues
            FROM coaching_sessions cs
            LEFT JOIN players p ON p.id = cs.coach_player_id
            LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
            ORDER BY cs.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/admin/coaching/sessions:', e.message);
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// ══════════════════════════════════════════════════════════════
// ADMIN: GET /api/admin/coaching/requests
// All pending session requests
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/coaching/requests', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT cr.id, cr.activity_type, cr.group_type, cr.time_preference,
                   cr.notes, cr.status, cr.created_at,
                   p.full_name AS player_name, p.id AS player_id,
                   c.full_name AS coach_name, c.id AS coach_id
            FROM coaching_requests cr
            JOIN players p ON p.id = cr.player_id
            LEFT JOIN players c ON c.id = cr.coach_player_id
            ORDER BY cr.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/admin/coaching/requests:', e.message);
        res.status(500).json({ error: 'Failed to fetch requests' });
    }
});

// ══════════════════════════════════════════════════════════════
// ADMIN: GET /api/coaching/audit
// Coaching audit log
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/audit', authenticateToken, requireAdmin, async (req, res) => {
    const { limit = 100, offset = 0, action, player_id } = req.query;
    const lim = Math.min(parseInt(limit) || 100, 500);
    const off = Math.max(parseInt(offset) || 0, 0);

    const conditions = [];
    const params = [];
    let p = 1;

    if (action && /^[a-z_]{3,60}$/.test(action)) {
        conditions.push(`cal.action = $${p++}`); params.push(action);
    }
    if (player_id && /^[0-9a-f-]{36}$/.test(player_id)) {
        conditions.push(`cal.actor_player_id = $${p++}`); params.push(player_id);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    try {
        const result = await pool.query(`
            SELECT cal.id, cal.action, cal.detail, cal.created_at,
                   cal.session_id, cal.request_id,
                   p.full_name AS actor_name, p.id AS actor_id,
                   cs.activity_type, cs.session_url
            FROM coaching_audit_log cal
            LEFT JOIN players p ON p.id = cal.actor_player_id
            LEFT JOIN coaching_sessions cs ON cs.id = cal.session_id
            ${where}
            ORDER BY cal.created_at DESC
            LIMIT $${p++} OFFSET $${p++}
        `, [...params, lim, off]);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/coaching/audit:', e.message);
        res.status(500).json({ error: 'Failed to fetch audit log' });
    }
});

// ══════════════════════════════════════════════════════════════
// COACH MANAGE: GET /api/coaching/manage
// Coach's own view: requests + upcoming + confirmed + completed
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/manage', authenticateToken, async (req, res) => {
    // Must be coach or superadmin
    const isCoach = await pool.query(
        `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id
         WHERE pb.player_id=$1 AND b.name='Coach'`,
        [req.user.playerId]
    );
    if (isCoach.rows.length === 0 && req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Coach badge required' });

    const coachId = req.user.playerId;
    const isSuperadmin = req.user.role === 'superadmin';

    try {
        // Open requests directed to this coach (or all, for superadmin)
        const requestsResult = await pool.query(`
            SELECT cr.id, cr.activity_type, cr.group_type, cr.time_preference,
                   cr.notes, cr.status, cr.created_at,
                   p.full_name AS player_name, p.id AS player_id
            FROM coaching_requests cr
            JOIN players p ON p.id = cr.player_id
            WHERE cr.status = 'pending'
              AND (cr.coach_player_id = $1 OR cr.coach_player_id IS NULL OR $2)
            ORDER BY cr.created_at ASC
        `, [coachId, isSuperadmin]);

        // All my sessions grouped by status
        const sessionWhere = isSuperadmin ? '' : 'AND cs.coach_player_id = $1';
        const sessionParams = isSuperadmin ? [] : [coachId];

        const sessionsResult = await pool.query(`
            SELECT cs.id, cs.session_url, cs.activity_type, cs.group_type,
                   cs.max_players, cs.session_date, cs.status, cs.duration_hours,
                   cs.min_price, cs.max_price, cs.is_full, cs.coach_confirmed,
                   cs.cancel_requested, cs.pitch_number,
                   v.name AS venue_name,
                   (SELECT COUNT(*) FROM coaching_registrations cr
                    WHERE cr.session_id=cs.id AND cr.status='registered') AS registered_count,
                   (SELECT json_agg(json_build_object(
                       'player_id', cr.player_id,
                       'player_name', p2.full_name,
                       'start_time', cr.start_time,
                       'activity_focus', cr.activity_focus
                   ))
                    FROM coaching_registrations cr
                    JOIN players p2 ON p2.id = cr.player_id
                    WHERE cr.session_id=cs.id AND cr.status='registered') AS registrations
            FROM coaching_sessions cs
            LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
            WHERE cs.status != 'cancelled'
            ${sessionWhere}
            ORDER BY cs.session_date ASC NULLS LAST
        `, sessionParams);

        res.json({
            requests:   requestsResult.rows,
            sessions:   sessionsResult.rows
        });
    } catch (e) {
        console.error('GET /api/coaching/manage:', e.message);
        res.status(500).json({ error: 'Failed to fetch manage data' });
    }
});

// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/coaching/apply
// Player applies to become a coach
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/apply', authenticateToken, registrationLimiter, async (req, res) => {
    const { certifications, experience, min_hourly_rate, license_doc } = req.body;
    if (!certifications || certifications.length < 5 || certifications.length > 1000)
        return res.status(400).json({ error: 'certifications required (5–1000 chars)' });
    if (!experience || experience.length < 10 || experience.length > 2000)
        return res.status(400).json({ error: 'experience required (10–2000 chars)' });
    if (min_hourly_rate !== undefined && (isNaN(parseFloat(min_hourly_rate)) || parseFloat(min_hourly_rate) < 0))
        return res.status(400).json({ error: 'Invalid min_hourly_rate' });
    if (license_doc && license_doc.length > 3_000_000) return res.status(400).json({ error: 'license_doc too large. Max ~2MB.' });

    // Check not already a coach
    const alreadyCoach = await pool.query(
        `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id
         WHERE pb.player_id=$1 AND b.name='Coach'`,
        [req.user.playerId]
    );
    if (alreadyCoach.rows.length > 0) return res.status(400).json({ error: 'Already a coach' });

    // Check not already pending
    const pending = await pool.query(
        `SELECT id FROM pending_applications WHERE player_id=$1 AND application_type='coach' AND status='pending'`,
        [req.user.playerId]
    );
    if (pending.rows.length > 0) return res.status(400).json({ error: 'Application already pending' });

    const result = await pool.query(
        `INSERT INTO pending_applications
           (player_id, application_type, certifications, experience, min_hourly_rate, license_doc)
         VALUES ($1,'coach',$2,$3,$4,$5) RETURNING id`,
        [req.user.playerId, certifications, experience, min_hourly_rate || null, license_doc || null]
    );

    const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
    notifyAdmin('New Coach Application', [['Details', `${htmlEncode(playerName)} has applied to become a TotalFooty coach. Certifications: ${htmlEncode(certifications.substring(0,100))}`]]);

    await logCoachingAudit(null, null, req.user.playerId, 'coach_application_submitted',
        `Certifications: ${certifications.substring(0,100)}`);

    res.status(201).json({ id: result.rows[0].id });
});

// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: PUT /api/admin/players/:id/coaching
// Save coaching credentials from manage-players.html
// ══════════════════════════════════════════════════════════════
app.put('/api/admin/players/:id/coaching', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { coach_certifications, coach_experience, coach_min_hourly_rate, coachable } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid player ID' });
    if (coach_certifications && coach_certifications.length > 500) return res.status(400).json({ error: 'coach_certifications too long' });
    if (coach_experience && coach_experience.length > 2000) return res.status(400).json({ error: 'coach_experience too long' });
    if (coach_min_hourly_rate !== undefined && (isNaN(parseFloat(coach_min_hourly_rate)) || parseFloat(coach_min_hourly_rate) < 0))
        return res.status(400).json({ error: 'Invalid hourly rate' });
    try {
        await pool.query(`
            UPDATE players SET
                coach_certifications  = $1,
                coach_experience      = $2,
                coach_min_hourly_rate = $3,
                coachable             = $4
            WHERE id = $5
        `, [
            coach_certifications || null,
            coach_experience     || null,
            coach_min_hourly_rate !== undefined ? parseFloat(coach_min_hourly_rate) : null,
            coachable === true || coachable === 'true',
            id
        ]);
        setImmediate(() => auditLog(pool, req.user.playerId, 'coaching_credentials_updated', id,
            `Coach credentials updated by superadmin. coachable=${coachable}, rate=${coach_min_hourly_rate}`))
        res.json({ success: true });
    } catch (e) {
        console.error('PUT /api/admin/players/:id/coaching:', e.message);
        res.status(500).json({ error: 'Failed to update coaching credentials' });
    }
});


// ══════════════════════════════════════════════════════════════
// SUPERADMIN: PUT /api/admin/players/:id/ref-credentials
// Save referee credentials from manage-players.html
// ══════════════════════════════════════════════════════════════
app.put('/api/admin/players/:id/ref-credentials', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { ref_certifications, ref_experience } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid player ID' });
    if (ref_certifications && ref_certifications.length > 500) return res.status(400).json({ error: 'ref_certifications too long' });
    if (ref_experience && ref_experience.length > 2000) return res.status(400).json({ error: 'ref_experience too long' });
    try {
        await pool.query(
            `UPDATE players SET ref_certifications=$1, ref_experience=$2 WHERE id=$3`,
            [ref_certifications || null, ref_experience || null, id]
        );
        res.json({ success: true });
    } catch (e) {
        console.error('PUT /api/admin/players/:id/ref-credentials:', e.message);
        res.status(500).json({ error: 'Failed to update referee credentials' });
    }
});

// SUPERADMIN: GET /api/admin/coaching/applications
// View all pending coach applications
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/coaching/applications', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT pa.id, pa.certifications, pa.experience, pa.min_hourly_rate,
                   pa.license_doc, pa.status, pa.created_at, pa.notes,
                   p.full_name AS player_name, p.id AS player_id, p.alias,
                   r.full_name AS reviewed_by_name
            FROM pending_applications pa
            JOIN players p ON p.id = pa.player_id
            LEFT JOIN players r ON r.id = pa.reviewed_by
            WHERE pa.application_type = 'coach'
            ORDER BY pa.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/admin/coaching/applications:', e.message);
        res.status(500).json({ error: 'Failed to fetch applications' });
    }
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: POST /api/admin/coaching/applications/:id/review
// Approve (grants Coach badge) or reject an application
// ══════════════════════════════════════════════════════════════
app.post('/api/admin/coaching/applications/:id/review', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { decision, notes } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
    if (!['approve','reject'].includes(decision)) return res.status(400).json({ error: 'decision must be approve or reject' });
    if (notes && notes.length > 1000) return res.status(400).json({ error: 'notes too long' });

    const appResult = await pool.query(
        `SELECT pa.id, pa.player_id, pa.status, pa.certifications, pa.experience, pa.min_hourly_rate
         FROM pending_applications pa WHERE pa.id=$1 AND pa.application_type='coach'`,
        [id]
    );
    if (appResult.rows.length === 0) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].status !== 'pending') return res.status(400).json({ error: 'Application already reviewed' });

    const app = appResult.rows[0];
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        await client.query(
            `UPDATE pending_applications SET status=$1, reviewed_by=$2, reviewed_at=NOW(), notes=$3 WHERE id=$4`,
            [decision === 'approve' ? 'approved' : 'rejected', req.user.playerId, notes || null, id]
        );

        if (decision === 'approve') {
            // Grant Coach badge
            const badgeResult = await client.query(`SELECT id FROM badges WHERE name='Coach'`);
            if (badgeResult.rows.length > 0) {
                await client.query(
                    `INSERT INTO player_badges (player_id, badge_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                    [app.player_id, badgeResult.rows[0].id]
                );
            }
            // Copy coaching credentials to player record
            await client.query(
                `UPDATE players SET
                   coach_certifications=$1, coach_experience=$2, coach_min_hourly_rate=$3
                 WHERE id=$4`,
                [app.certifications, app.experience, app.min_hourly_rate || null, app.player_id]
            );
        }

        await client.query('COMMIT');

        await logCoachingAudit(null, null, req.user.playerId,
            decision === 'approve' ? 'coach_badge_assigned' : 'application_rejected',
            `Application ${decision}d for player ${app.player_id}.${notes ? ' Note: ' + notes.substring(0,100) : ''}`
        );

        const playerName = (await pool.query('SELECT p.full_name AS player_name FROM players p WHERE p.id=$1', [app.player_id])).rows[0];
        if (decision === 'approve') {
            await sendCoachingEmail([app.player_id], 'Welcome to TotalFooty Coaching! 🎓',
                `<p style="color:#888">Congratulations ${htmlEncode(playerName?.player_name || '')}! Your coach application has been approved.</p>
                 <p style="color:#888;margin-top:8px">You now have access to the <strong style="color:#fff">Manage Coaching</strong> section in TotalFooty. You can create sessions, respond to requests, and start coaching!</p>
                 ${notes ? `<p style="color:#888;margin-top:8px">Note from admin: ${htmlEncode(notes)}</p>` : ''}`
            );
        } else {
            await sendCoachingEmail([app.player_id], 'Update on Your Coaching Application',
                `<p style="color:#888">Thank you for your interest in coaching with TotalFooty. Unfortunately your application was not approved at this time.</p>
                 ${notes ? `<p style="color:#888;margin-top:8px">${htmlEncode(notes)}</p>` : ''}`
            );
        }

        res.json({ success: true, decision });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('POST /api/admin/coaching/applications/:id/review:', e.message);
        res.status(500).json({ error: 'Failed to process application' });
    } finally {
        client.release();
    }
});

// ══════════════════════════════════════════════════════════════
// PUBLIC: GET /api/coaching/venues/available
// Returns venues valid for a given date/time + duration
// Used by the session creation form to filter venue dropdown
// ══════════════════════════════════════════════════════════════
app.get('/api/coaching/venues/available', optionalAuth, publicEndpointLimiter, async (req, res) => {
    const { session_date, duration_hours } = req.query;
    const dur = parseInt(duration_hours) || 1;
    if (session_date && isNaN(Date.parse(session_date)))
        return res.status(400).json({ error: 'Invalid session_date' });

    try {
        const result = await pool.query(`
            SELECT id, name, address, coaching_cost_per_hour,
                   pay_and_play_coach_hourly, pay_and_play_player_hourly,
                   availability_rule, boot_type, pitch_name,
                   parking_pin, pitch_pin, special_instructions
            FROM venues
            WHERE coaching_suitable = TRUE
            ORDER BY name ASC
        `);

        const filtered = session_date
            ? result.rows.filter(v => isVenueAvailable(v.availability_rule, session_date, dur))
            : result.rows;

        res.json(filtered);
    } catch (e) {
        console.error('GET /api/coaching/venues/available:', e.message);
        res.status(500).json({ error: 'Failed to fetch venues' });
    }
});


// ══════════════════════════════════════════════════════════════
// AUTH: POST /api/ref/apply
// Player applies to become a TotalFooty referee
// ══════════════════════════════════════════════════════════════
app.post('/api/ref/apply', authenticateToken, registrationLimiter, async (req, res) => {
    const { certifications, experience, license_doc } = req.body;
    if (!certifications || certifications.length < 5 || certifications.length > 1000)
        return res.status(400).json({ error: 'certifications required (5–1000 chars)' });
    if (!experience || experience.length < 10 || experience.length > 2000)
        return res.status(400).json({ error: 'experience required (10–2000 chars)' });

    // Check not already a ref
    const alreadyRef = await pool.query(
        `SELECT 1 FROM player_badges pb JOIN badges b ON b.id=pb.badge_id
         WHERE pb.player_id=$1 AND b.name='Referee'`,
        [req.user.playerId]
    );
    if (alreadyRef.rows.length > 0) return res.status(400).json({ error: 'Already a referee' });

    // Check not already pending
    const pending = await pool.query(
        `SELECT id FROM pending_applications WHERE player_id=$1 AND application_type='referee' AND status='pending'`,
        [req.user.playerId]
    );
    if (pending.rows.length > 0) return res.status(400).json({ error: 'Application already pending' });

    const result = await pool.query(
        `INSERT INTO pending_applications
           (player_id, application_type, certifications, experience, license_doc)
         VALUES ($1,'referee',$2,$3,$4) RETURNING id`,
        [req.user.playerId, certifications, experience, license_doc || null]
    );

    const playerName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'A player';
    notifyAdmin('New Referee Application', [['Details', `${htmlEncode(playerName)} has applied to become a TotalFooty referee. Certifications: ${htmlEncode(certifications.substring(0,100))}`]]);

    await auditLog(pool, req.user.playerId, 'ref_application_submitted', null,
        `Certifications: ${certifications.substring(0,100)}`);

    res.status(201).json({ id: result.rows[0].id });
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: GET /api/admin/ref/applications
// View all referee applications
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/ref/applications', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT pa.id, pa.certifications, pa.experience, pa.license_doc,
                   pa.status, pa.created_at, pa.notes,
                   p.full_name AS player_name, p.id AS player_id, p.alias,
                   r.full_name AS reviewed_by_name
            FROM pending_applications pa
            JOIN players p ON p.id = pa.player_id
            LEFT JOIN players r ON r.id = pa.reviewed_by
            WHERE pa.application_type = 'referee'
            ORDER BY pa.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('GET /api/admin/ref/applications:', e.message);
        res.status(500).json({ error: 'Failed to fetch referee applications' });
    }
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: POST /api/admin/ref/applications/:id/review
// Approve (grants Referee badge) or reject a referee application
// ══════════════════════════════════════════════════════════════
app.post('/api/admin/ref/applications/:id/review', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { decision, notes } = req.body;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
    if (!['approve','reject'].includes(decision)) return res.status(400).json({ error: 'decision must be approve or reject' });
    if (notes && notes.length > 1000) return res.status(400).json({ error: 'notes too long' });

    const appResult = await pool.query(
        `SELECT pa.id, pa.player_id, pa.status, pa.certifications, pa.experience
         FROM pending_applications pa WHERE pa.id=$1 AND pa.application_type='referee'`,
        [id]
    );
    if (appResult.rows.length === 0) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].status !== 'pending') return res.status(400).json({ error: 'Application already reviewed' });

    const app = appResult.rows[0];
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        await client.query(
            `UPDATE pending_applications SET status=$1, reviewed_by=$2, reviewed_at=NOW(), notes=$3 WHERE id=$4`,
            [decision === 'approve' ? 'approved' : 'rejected', req.user.playerId, notes || null, id]
        );

        if (decision === 'approve') {
            // Grant Referee badge
            const refBadge = await client.query(`SELECT id FROM badges WHERE name='Referee'`);
            if (refBadge.rows.length > 0) {
                await client.query(
                    `INSERT INTO player_badges (player_id, badge_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                    [app.player_id, refBadge.rows[0].id]
                );
            }
            // Copy certifications to player record
            await client.query(
                `UPDATE players SET ref_certifications=$1, ref_experience=$2 WHERE id=$3`,
                [app.certifications, app.experience, app.player_id]
            );
        }

        await client.query('COMMIT');

        // Email the applicant
        const actorName = (await pool.query('SELECT full_name AS player_name FROM players WHERE id=$1', [req.user.playerId])).rows[0]?.player_name || 'TotalFooty';
        const subject = decision === 'approve'
            ? '🎉 Referee Application Approved!'
            : 'Update on Your Referee Application';
        const body = decision === 'approve'
            ? `<p style="color:#888">Congratulations! Your referee application has been approved by ${htmlEncode(actorName)}.</p>
               <p style="color:#888;margin-top:8px">You now have the <strong style="color:#fff">Referee</strong> badge and can apply to officiate games in TotalFooty.</p>
               <p style="color:#888;margin-top:8px">Head to the Referee section in the app to see available games.</p>`
            : `<p style="color:#888">Thank you for your interest in refereeing with TotalFooty. Unfortunately your application was not approved at this time.</p>
               ${notes ? `<p style="color:#888;margin-top:8px">${htmlEncode(notes)}</p>` : ''}`;

        try {
            const emailRow = await pool.query(
                'SELECT u.email FROM players p JOIN users u ON u.id=p.user_id WHERE p.id=$1',
                [app.player_id]
            );
            if (emailRow.rows[0]?.email) {
                await emailTransporter.sendMail({
                    from: '"TotalFooty" <totalfooty19@gmail.com>',
                    to:   emailRow.rows[0].email,
                    subject,
                    html: wrapEmailHtml(body)
                });
            }
        } catch (e) { console.error('Ref application email failed:', e.message); }

        await auditLog(pool, req.user.playerId, `ref_application_${decision}d`, app.player_id,
            `Ref application ${decision}d. ${notes ? 'Notes: ' + notes.substring(0,100) : ''}`);

        res.json({ success: true, decision });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('POST /api/admin/ref/applications/:id/review:', e.message);
        res.status(500).json({ error: 'Failed to process application' });
    } finally {
        client.release();
    }
});


// ══════════════════════════════════════════════════════════════
// COACH: POST /api/coaching/sessions/:id/cancel-request
// Request cancellation of a session (coach of session only, not completed)
// ══════════════════════════════════════════════════════════════
app.post('/api/coaching/sessions/:id/cancel-request', authenticateToken, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status, activity_type, session_date, cancel_requested
         FROM coaching_sessions WHERE id=$1`,
        [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const session = sessionResult.rows[0];

    // Only coach of this session or superadmin can request cancellation
    const isSA = req.user.role === 'superadmin';
    if (!isSA && session.coach_player_id !== req.user.playerId)
        return res.status(403).json({ error: 'Not authorised' });

    if (session.status === 'completed')
        return res.status(400).json({ error: 'Cannot cancel a completed session' });
    if (session.status === 'cancelled')
        return res.status(400).json({ error: 'Session is already cancelled' });
    if (session.cancel_requested)
        return res.status(400).json({ error: 'Cancellation already requested' });

    await pool.query(
        `UPDATE coaching_sessions SET cancel_requested=TRUE, updated_at=NOW() WHERE id=$1`,
        [id]
    );
    await logCoachingAudit(id, null, req.user.playerId, 'cancel_requested', 'Coach requested session cancellation.');

    // Notify superadmin
    const coachRow = await pool.query('SELECT full_name FROM players WHERE id=$1', [req.user.playerId]);
    const coachName = coachRow.rows[0]?.full_name || 'Coach';
    const activityLabel = session.activity_type ? session.activity_type.replace(/_/g,' ') : 'coaching';
    const dateStr = session.session_date
        ? new Date(session.session_date).toLocaleDateString('en-GB', { weekday:'short', day:'numeric', month:'short', year:'numeric', timeZone:'Europe/London' })
        : 'TBC';
    await notifyAdmin('⚠️ Coaching Session Cancellation Requested', [
        ['Coach',    coachName],
        ['Session',  activityLabel],
        ['Date',     dateStr],
        ['Action',   'Log in to approve or reject this cancellation request'],
    ]);

    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: POST /api/admin/coaching/sessions/:id/cancel-approve
// Approve a cancellation request — status → cancelled, email coach + players
// ══════════════════════════════════════════════════════════════
app.post('/api/admin/coaching/sessions/:id/cancel-approve', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status, cancel_requested, activity_type, session_date
         FROM coaching_sessions WHERE id=$1`,
        [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const session = sessionResult.rows[0];
    if (!session.cancel_requested) return res.status(400).json({ error: 'No cancellation request pending' });
    if (session.status === 'cancelled') return res.status(400).json({ error: 'Session already cancelled' });

    // Get registered players
    const regsResult = await pool.query(
        `SELECT cr.player_id FROM coaching_registrations cr
         WHERE cr.session_id=$1 AND cr.status='registered'`,
        [id]
    );
    const playerIds = regsResult.rows.map(r => r.player_id);
    // Include coach
    if (session.coach_player_id) playerIds.push(session.coach_player_id);
    const uniqueIds = [...new Set(playerIds)];

    await pool.query(
        `UPDATE coaching_sessions SET status='cancelled', cancel_requested=FALSE, updated_at=NOW() WHERE id=$1`,
        [id]
    );
    await logCoachingAudit(id, null, req.user.playerId, 'session_cancelled', 'Cancellation approved by superadmin.');

    // Email all affected players + coach
    if (uniqueIds.length > 0) {
        const activityLabel = htmlEncode(session.activity_type ? session.activity_type.replace(/_/g,' ') : 'coaching');
        const dateStr = session.session_date
            ? new Date(session.session_date).toLocaleDateString('en-GB', { weekday:'short', day:'numeric', month:'short', year:'numeric', timeZone:'Europe/London' })
            : 'TBC';
        try {
            await sendCoachingEmail(uniqueIds,
                'Coaching Session Cancelled',
                `<p style="color:#888">Unfortunately, the <strong style="color:#fff">${activityLabel}</strong> coaching session scheduled for <strong style="color:#fff">${htmlEncode(dateStr)}</strong> has been cancelled.</p>
                 <p style="color:#888;margin-top:8px">If you have any questions please contact TotalFooty.</p>`
            );
        } catch(e) { console.error('cancel-approve email failed:', e.message); }
    }

    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
// SUPERADMIN: POST /api/admin/coaching/sessions/:id/cancel-reject
// Reject a cancellation request — clears flag, emails coach
// ══════════════════════════════════════════════════════════════
app.post('/api/admin/coaching/sessions/:id/cancel-reject', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const sessionResult = await pool.query(
        `SELECT id, coach_player_id, status, cancel_requested, activity_type, session_date
         FROM coaching_sessions WHERE id=$1`,
        [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const session = sessionResult.rows[0];
    if (!session.cancel_requested) return res.status(400).json({ error: 'No cancellation request pending' });

    await pool.query(
        `UPDATE coaching_sessions SET cancel_requested=FALSE, updated_at=NOW() WHERE id=$1`,
        [id]
    );
    await logCoachingAudit(id, null, req.user.playerId, 'cancel_rejected', 'Cancellation request rejected by superadmin.');

    // Email coach
    if (session.coach_player_id) {
        const activityLabel = htmlEncode(session.activity_type ? session.activity_type.replace(/_/g,' ') : 'coaching');
        const dateStr = session.session_date
            ? new Date(session.session_date).toLocaleDateString('en-GB', { weekday:'short', day:'numeric', month:'short', year:'numeric', timeZone:'Europe/London' })
            : 'TBC';
        try {
            await sendCoachingEmail([session.coach_player_id],
                'Cancellation Request — Not Approved',
                `<p style="color:#888">Your request to cancel the <strong style="color:#fff">${activityLabel}</strong> session on <strong style="color:#fff">${htmlEncode(dateStr)}</strong> has not been approved.</p>
                 <p style="color:#888;margin-top:8px">The session will continue as planned. Please log in to TotalFooty if you have any questions.</p>`
            );
        } catch(e) { console.error('cancel-reject email failed:', e.message); }
    }

    res.json({ success: true });
});

// ════════════════════════════════════════════════════════════
// SUPERADMIN: DELETE /api/admin/coaching/sessions/:id
// Force-delete a session: notify registered players, then hard-delete.
// ════════════════════════════════════════════════════════════
app.delete('/api/admin/coaching/sessions/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid session ID' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const sessionResult = await client.query(
            `SELECT cs.id, cs.activity_type, cs.session_date, cs.coach_player_id,
                    cs.status, cs.session_url
             FROM coaching_sessions cs WHERE cs.id=$1`,
            [id]
        );
        if (sessionResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Session not found' });
        }
        const session = sessionResult.rows[0];
        const activityLabel = (session.activity_type || 'coaching').replace(/_/g, ' ');
        const dateStr = session.session_date
            ? new Date(session.session_date).toLocaleDateString('en-GB', { weekday:'short', day:'numeric', month:'short', year:'numeric' })
            : 'TBC';

        // Get all registered players before deletion
        const regResult = await client.query(
            `SELECT cr.player_id FROM coaching_registrations cr
             WHERE cr.session_id=$1 AND cr.status='registered'`,
            [id]
        );
        const registeredPlayerIds = regResult.rows.map(r => r.player_id);

        // Cascade delete all child records
        await client.query('DELETE FROM coaching_registrations  WHERE session_id=$1', [id]);
        await client.query('DELETE FROM coaching_session_venues WHERE session_id=$1', [id]);
        await client.query('DELETE FROM coaching_feedback        WHERE session_id=$1', [id]);
        await client.query('DELETE FROM coaching_audit_log       WHERE session_id=$1', [id]);
        await client.query('DELETE FROM coaching_sessions        WHERE id=$1',         [id]);

        await client.query('COMMIT');

        // Notify registered players
        if (registeredPlayerIds.length > 0) {
            try {
                await sendCoachingEmail(
                    registeredPlayerIds,
                    'Coaching Session Cancelled',
                    `<p style="color:#888">We're sorry, the following coaching session has been cancelled by TotalFooty admin.</p>
                     <table>
                       <tr><td style="color:#888;width:140px">Activity</td><td style="color:#fff;font-weight:700">${htmlEncode(activityLabel)}</td></tr>
                       <tr><td style="color:#888">Date</td><td style="color:#fff">${htmlEncode(dateStr)}</td></tr>
                     </table>
                     <p style="color:#888;margin-top:16px">If you paid in advance, a full refund will be issued shortly. Apologies for any inconvenience.</p>`
                );
            } catch(e) { console.error('delete session email failed:', e.message); }
        }

        // Notify coach if assigned
        if (session.coach_player_id) {
            try {
                await sendCoachingEmail(
                    [session.coach_player_id],
                    'Coaching Session Deleted by Admin',
                    `<p style="color:#888">Your <strong style="color:#fff">${htmlEncode(activityLabel)}</strong> session on <strong style="color:#fff">${htmlEncode(dateStr)}</strong> has been deleted by TotalFooty admin.</p>`
                );
            } catch(e) { console.error('delete session coach email failed:', e.message); }
        }

        await logCoachingAudit(id, null, req.user.playerId, 'session_deleted',
            `Session force-deleted by superadmin. ${registeredPlayerIds.length} player(s) notified.`);

        res.json({ success: true, notified: registeredPlayerIds.length });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('DELETE /api/admin/coaching/sessions/:id:', e.message);
        res.status(500).json({ error: 'Failed to delete session' });
    } finally {
        client.release();
    }
});

// ════════════════════════════════════════════════════════════
// END COACHING ENDPOINTS
// ════════════════════════════════════════════════════════════



// ============================================================
// SERIES TROPHIES — METRIC_CONFIG, HELPERS & ENDPOINTS
// ============================================================

const METRIC_CONFIG = {
    1:  { name: 'Win Percentage',     icon: '📊', category: 'core',  awardType: null,               validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'Win %',           supportingLabel: 'Wins' },
    2:  { name: 'Man of the Match',   icon: '⭐', category: 'core',  awardType: 'motm',             validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'MOTM Count',      supportingLabel: 'MOTM %' },
    3:  { name: 'Win Count',          icon: '✅', category: 'core',  awardType: null,               validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'Wins',            supportingLabel: 'Win %' },
    4:  { name: 'MOTM Percentage',    icon: '⭐', category: 'core',  awardType: 'motm',             validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'MOTM %',          supportingLabel: 'MOTM Count' },
    5:  { name: 'Appearances',        icon: '📅', category: 'core',  awardType: null,               validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'Appearances',     supportingLabel: null },
    6:  { name: 'Brick Wall',         icon: '🧱', category: 'award', awardType: 'brick_wall',       validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Brick Wall',      supportingLabel: 'Brick Wall %' },
    7:  { name: 'Best Engine',        icon: '🔋', category: 'award', awardType: 'best_engine',      validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Best Engine',     supportingLabel: 'Best Engine %' },
    8:  { name: 'Reckless Tackler',   icon: '🚑', category: 'award', awardType: 'reckless_tackler', validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Reckless',        supportingLabel: 'Reckless %' },
    9:  { name: 'Goal Scorer',        icon: '⚽', category: 'award', awardType: 'goalscorer',       validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Goals',           supportingLabel: 'Goal %' },
    10: { name: 'Mr Hollywood',       icon: '🎬', category: 'award', awardType: 'mr_hollywood',     validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Hollywood',       supportingLabel: 'Hollywood %' },
    11: { name: 'The Moaner',         icon: '😩', category: 'award', awardType: 'the_moaner',       validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Moans',           supportingLabel: 'Moan %' },
    12: { name: 'Howler',             icon: '🤦', category: 'award', awardType: 'howler',           validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Howlers',         supportingLabel: 'Howler %' },
    13: { name: 'Donkey',             icon: '🫏', category: 'award', awardType: 'donkey',           validCalcTypes: ['most','least','most_per_game','least_per_game','most_consecutive'],  primaryLabel: 'Donkey',          supportingLabel: 'Donkey %' },
    14: { name: 'Dropouts',           icon: '🚪', category: 'core',  awardType: null,               validCalcTypes: ['most','most_per_game','most_consecutive'],                           primaryLabel: 'Dropouts',        supportingLabel: 'Dropout %' },
    15: { name: 'Guest Signups',      icon: '👥', category: 'core',  awardType: null,               validCalcTypes: ['most','most_per_game','most_consecutive'],                           primaryLabel: 'Guest Signups',   supportingLabel: 'Per Game' },
    16: { name: 'Discipline Points',  icon: '⚖️', category: 'core',  awardType: null,               validCalcTypes: ['most','most_per_game','most_consecutive'],                           primaryLabel: 'Disc. Points',    supportingLabel: 'Per Game' },
    17: { name: 'Tournament Wins',    icon: '🏆', category: 'core',  awardType: null,               validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'Tournament Wins', supportingLabel: 'Win %' },
    18: { name: 'External Game Wins', icon: '🆚', category: 'core',  awardType: null,               validCalcTypes: ['most','least','most_consecutive'],                                  primaryLabel: 'External Wins',   supportingLabel: 'Win %' },
};

function deriveTier(seriesType, avgStarRating) {
    if (seriesType === 'tournament' || seriesType === 'vs_external') return 'S';
    const stars = Math.round(parseFloat(avgStarRating) || 0);
    if (stars >= 5) return 'A';
    if (stars >= 4) return 'B';
    if (stars >= 3) return 'C';
    if (stars >= 2) return 'D';
    return 'E';
}

async function calcSeriesLeaderboard(seriesId, metricId, calcType) {
    const id = parseInt(metricId);
    const cfg = METRIC_CONFIG[id];
    if (!cfg) return [];

    // Reusable appearances CTE (confirmed players in completed games)
    const appearancesCte = `
        app_counts AS (
            SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, COUNT(*) AS appearances
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            JOIN games g ON g.id = r.game_id
            WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
            GROUP BY r.player_id, COALESCE(p.alias, p.full_name)
        )`;

    // ── METRIC 5: Appearances ──────────────────────────────────────────────
    if (id === 5) {
        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH player_games AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                ),
                all_players AS (SELECT DISTINCT player_id, player_name FROM player_games),
                all_games   AS (SELECT id AS game_id, game_date FROM games WHERE series_id = $1 AND game_status = 'completed'),
                attendance  AS (
                    SELECT ag.game_id, ag.game_date, ap.player_id, ap.player_name,
                           CASE WHEN pg.player_id IS NOT NULL THEN 1 ELSE 0 END AS attended
                    FROM all_games ag CROSS JOIN all_players ap
                    LEFT JOIN player_games pg ON pg.player_id = ap.player_id AND pg.game_id = ag.game_id
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, attended ORDER BY game_date) AS g
                    FROM attendance
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN attended = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, attended, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, attended, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }
        const dir = calcType === 'least' ? 'ASC' : 'DESC';
        const r = await pool.query(`
            WITH ${appearancesCte}
            SELECT player_id, player_name, appearances, appearances AS primary_stat, NULL::numeric AS supporting_stat
            FROM app_counts ORDER BY appearances ${dir} LIMIT 10`, [seriesId]);
        return r.rows;
    }

    // ── METRICS 1, 3, 17, 18: Win-based ───────────────────────────────────
    if ([1, 3, 17, 18].includes(id)) {
        const typeFilter = id === 17 ? "AND g.team_selection_type = 'tournament'"
                         : id === 18 ? "AND g.team_selection_type = 'vs_external'" : '';

        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH pgr AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date,
                           CASE WHEN LOWER(t.team_name) = LOWER(g.winning_team) THEN 1 ELSE 0 END AS won
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    JOIN team_players tp ON tp.player_id = r.player_id
                    JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                    ${typeFilter}
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, won ORDER BY game_date) AS g
                    FROM pgr
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN won = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, won, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, won, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }

        const dir = calcType === 'least' ? 'ASC' : 'DESC';
        const tbDir = calcType === 'least' ? 'DESC' : 'ASC';
        const r = await pool.query(`
            WITH ${appearancesCte},
            pw AS (
                SELECT r.player_id, COUNT(*) AS win_count
                FROM registrations r
                JOIN games g ON g.id = r.game_id
                JOIN team_players tp ON tp.player_id = r.player_id
                JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                AND LOWER(t.team_name) = LOWER(g.winning_team)
                ${typeFilter}
                GROUP BY r.player_id
            )
            SELECT ac.player_id, ac.player_name, ac.appearances,
                   CASE WHEN ${id === 1 ? 'TRUE' : 'FALSE'}
                        THEN ROUND(COALESCE(pw.win_count,0)*100.0/NULLIF(ac.appearances,0),1)
                        ELSE COALESCE(pw.win_count,0)::numeric END AS primary_stat,
                   CASE WHEN ${id === 1 ? 'TRUE' : 'FALSE'}
                        THEN COALESCE(pw.win_count,0)::numeric
                        ELSE ROUND(COALESCE(pw.win_count,0)*100.0/NULLIF(ac.appearances,0),1) END AS supporting_stat
            FROM app_counts ac LEFT JOIN pw ON pw.player_id = ac.player_id
            ORDER BY primary_stat ${dir}, ac.appearances ${tbDir} LIMIT 10`, [seriesId]);
        return r.rows;
    }

    // ── METRICS 2 & 4: MOTM ───────────────────────────────────────────────
    if (id === 2 || id === 4) {
        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH pgm AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date,
                           CASE WHEN ga.recipient_player_id IS NOT NULL THEN 1 ELSE 0 END AS got_motm
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    LEFT JOIN game_awards ga ON ga.game_id = g.id
                        AND ga.recipient_player_id = r.player_id AND ga.award_type = 'motm'
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, got_motm ORDER BY game_date) AS g
                    FROM pgm
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN got_motm = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, got_motm, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, got_motm, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }
        const dir = calcType === 'least' ? 'ASC' : 'DESC';
        const tbDir = calcType === 'least' ? 'DESC' : 'ASC';
        const r = await pool.query(`
            WITH ${appearancesCte},
            pm AS (
                SELECT ga.recipient_player_id AS player_id, COUNT(*) AS motm_count
                FROM game_awards ga JOIN games g ON g.id = ga.game_id
                WHERE g.series_id = $1 AND g.game_status = 'completed' AND ga.award_type = 'motm'
                GROUP BY ga.recipient_player_id
            )
            SELECT ac.player_id, ac.player_name, ac.appearances,
                   CASE WHEN ${id === 2 ? 'TRUE' : 'FALSE'}
                        THEN COALESCE(pm.motm_count,0)::numeric
                        ELSE ROUND(COALESCE(pm.motm_count,0)*100.0/NULLIF(ac.appearances,0),1) END AS primary_stat,
                   CASE WHEN ${id === 2 ? 'TRUE' : 'FALSE'}
                        THEN ROUND(COALESCE(pm.motm_count,0)*100.0/NULLIF(ac.appearances,0),1)
                        ELSE COALESCE(pm.motm_count,0)::numeric END AS supporting_stat
            FROM app_counts ac LEFT JOIN pm ON pm.player_id = ac.player_id
            ORDER BY primary_stat ${dir}, ac.appearances ${tbDir} LIMIT 10`, [seriesId]);
        return r.rows;
    }

    // ── METRICS 6–13: Game Awards ──────────────────────────────────────────
    if (id >= 6 && id <= 13) {
        const awardType = cfg.awardType;

        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH pga AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date,
                           CASE WHEN ga.recipient_player_id IS NOT NULL THEN 1 ELSE 0 END AS got_award
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    LEFT JOIN game_awards ga ON ga.game_id = g.id
                        AND ga.recipient_player_id = r.player_id AND ga.award_type = $2
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, got_award ORDER BY game_date) AS g
                    FROM pga
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN got_award = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, got_award, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, got_award, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`,
                [seriesId, awardType]);
            return r.rows;
        }

        const usePct = calcType === 'most_per_game' || calcType === 'least_per_game';
        const dir = (calcType === 'least' || calcType === 'least_per_game') ? 'ASC' : 'DESC';
        const tbDir = (calcType === 'least' || calcType === 'least_per_game') ? 'DESC' : 'ASC';
        const r = await pool.query(`
            WITH ${appearancesCte},
            pa AS (
                SELECT ga.recipient_player_id AS player_id, COUNT(*) AS award_count
                FROM game_awards ga JOIN games g ON g.id = ga.game_id
                WHERE g.series_id = $1 AND g.game_status = 'completed' AND ga.award_type = $2
                GROUP BY ga.recipient_player_id
            )
            SELECT ac.player_id, ac.player_name, ac.appearances,
                   CASE WHEN ${usePct}
                        THEN ROUND(COALESCE(pa.award_count,0)*100.0/NULLIF(ac.appearances,0),1)
                        ELSE COALESCE(pa.award_count,0)::numeric END AS primary_stat,
                   CASE WHEN ${usePct}
                        THEN COALESCE(pa.award_count,0)::numeric
                        ELSE ROUND(COALESCE(pa.award_count,0)*100.0/NULLIF(ac.appearances,0),1) END AS supporting_stat
            FROM app_counts ac LEFT JOIN pa ON pa.player_id = ac.player_id
            ORDER BY primary_stat ${dir}, ac.appearances ${tbDir} LIMIT 10`,
            [seriesId, awardType]);
        return r.rows;
    }

    // ── METRIC 14: Dropouts ───────────────────────────────────────────────
    if (id === 14) {
        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH apg AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date,
                           CASE WHEN r.status = 'dropped_out' THEN 1 ELSE 0 END AS dropped
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    WHERE g.series_id = $1 AND g.game_status = 'completed'
                    AND r.status IN ('confirmed','dropped_out')
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, dropped ORDER BY game_date) AS g
                    FROM apg
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN dropped = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, dropped, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, dropped, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }
        const usePct = calcType === 'most_per_game';
        // Appearances = total signups (confirmed + dropped_out) for this metric.
        // Dropout % = dropout_count / total_signups so the rate is meaningful.
        const r = await pool.query(`
            WITH signup_counts AS (
                SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name,
                       COUNT(*) AS appearances,
                       COUNT(*) FILTER (WHERE r.status = 'dropped_out') AS dropout_count
                FROM registrations r
                JOIN players p ON p.id = r.player_id
                JOIN games g ON g.id = r.game_id
                WHERE g.series_id = $1 AND g.game_status = 'completed'
                AND r.status IN ('confirmed','dropped_out')
                GROUP BY r.player_id, COALESCE(p.alias, p.full_name)
            )
            SELECT player_id, player_name, appearances,
                   CASE WHEN ${usePct}
                        THEN ROUND(dropout_count*100.0/NULLIF(appearances,0),1)
                        ELSE dropout_count::numeric END AS primary_stat,
                   CASE WHEN ${usePct}
                        THEN dropout_count::numeric
                        ELSE ROUND(dropout_count*100.0/NULLIF(appearances,0),1) END AS supporting_stat
            FROM signup_counts
            WHERE dropout_count > 0
            ORDER BY primary_stat DESC, appearances ASC LIMIT 10`, [seriesId]);
        return r.rows;
    }

    // ── METRIC 15: Guest Signups ──────────────────────────────────────────
    if (id === 15) {
        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH pgg AS (
                    SELECT DISTINCT r.registered_by_player_id AS player_id, g.id AS game_id, g.game_date
                    FROM registrations r JOIN games g ON g.id = r.game_id
                    WHERE g.series_id = $1 AND g.game_status = 'completed'
                    AND r.registered_by_player_id IS NOT NULL AND r.registered_by_player_id != r.player_id
                ),
                apsg AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                ),
                pghg AS (
                    SELECT apsg.player_id, apsg.player_name, apsg.game_id, apsg.game_date,
                           CASE WHEN pgg.game_id IS NOT NULL THEN 1 ELSE 0 END AS signed_guest
                    FROM apsg LEFT JOIN pgg ON pgg.player_id = apsg.player_id AND pgg.game_id = apsg.game_id
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, signed_guest ORDER BY game_date) AS g
                    FROM pghg
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN signed_guest = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, signed_guest, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, signed_guest, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }
        const usePct = calcType === 'most_per_game';
        const r = await pool.query(`
            WITH ${appearancesCte},
            gs AS (
                SELECT r.registered_by_player_id AS player_id, COUNT(*) AS signup_count
                FROM registrations r JOIN games g ON g.id = r.game_id
                WHERE g.series_id = $1 AND g.game_status = 'completed'
                AND r.registered_by_player_id IS NOT NULL AND r.registered_by_player_id != r.player_id
                GROUP BY r.registered_by_player_id
            )
            SELECT ac.player_id, ac.player_name, ac.appearances,
                   CASE WHEN ${usePct}
                        THEN ROUND(COALESCE(gs.signup_count,0)*1.0/NULLIF(ac.appearances,0),2)
                        ELSE COALESCE(gs.signup_count,0)::numeric END AS primary_stat,
                   CASE WHEN ${usePct}
                        THEN COALESCE(gs.signup_count,0)::numeric
                        ELSE ROUND(COALESCE(gs.signup_count,0)*1.0/NULLIF(ac.appearances,0),2) END AS supporting_stat
            FROM app_counts ac LEFT JOIN gs ON gs.player_id = ac.player_id
            ORDER BY primary_stat DESC, ac.appearances ASC LIMIT 10`, [seriesId]);
        return r.rows;
    }

    // ── METRIC 16: Discipline Points ──────────────────────────────────────
    if (id === 16) {
        if (calcType === 'most_consecutive') {
            const r = await pool.query(`
                WITH pgd AS (
                    SELECT r.player_id, COALESCE(p.alias, p.full_name) AS player_name, g.id AS game_id, g.game_date,
                           CASE WHEN COALESCE(SUM(dr.points),0) > 0 THEN 1 ELSE 0 END AS got_disc
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    JOIN games g ON g.id = r.game_id
                    LEFT JOIN discipline_records dr ON dr.player_id = r.player_id AND dr.game_id = g.id
                    WHERE g.series_id = $1 AND g.game_status = 'completed' AND r.status = 'confirmed'
                    GROUP BY r.player_id, COALESCE(p.alias, p.full_name), g.id, g.game_date
                ),
                grp AS (
                    SELECT *,
                        ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY game_date) -
                        ROW_NUMBER() OVER (PARTITION BY player_id, got_disc ORDER BY game_date) AS g
                    FROM pgd
                ),
                max_str AS (
                    SELECT player_id, player_name,
                           MAX(CASE WHEN got_disc = 1 THEN cnt ELSE 0 END) AS primary_stat
                    FROM (SELECT player_id, player_name, got_disc, g, COUNT(*) AS cnt FROM grp
                          GROUP BY player_id, player_name, got_disc, g) s
                    GROUP BY player_id, player_name
                ),
                ${appearancesCte}
                SELECT ms.player_id, ms.player_name, COALESCE(ac.appearances,0) AS appearances,
                       ms.primary_stat, NULL::numeric AS supporting_stat
                FROM max_str ms LEFT JOIN app_counts ac ON ac.player_id = ms.player_id
                WHERE ms.primary_stat > 0 ORDER BY ms.primary_stat DESC, ac.appearances DESC LIMIT 10`, [seriesId]);
            return r.rows;
        }
        const usePct = calcType === 'most_per_game';
        const r = await pool.query(`
            WITH ${appearancesCte},
            pdisc AS (
                SELECT dr.player_id, SUM(dr.points) AS disc_total
                FROM discipline_records dr JOIN games g ON g.id = dr.game_id
                WHERE g.series_id = $1 AND g.game_status = 'completed'
                GROUP BY dr.player_id
            )
            SELECT ac.player_id, ac.player_name, ac.appearances,
                   CASE WHEN ${usePct}
                        THEN ROUND(COALESCE(pdisc.disc_total,0)*1.0/NULLIF(ac.appearances,0),2)
                        ELSE COALESCE(pdisc.disc_total,0)::numeric END AS primary_stat,
                   CASE WHEN ${usePct}
                        THEN COALESCE(pdisc.disc_total,0)::numeric
                        ELSE ROUND(COALESCE(pdisc.disc_total,0)*1.0/NULLIF(ac.appearances,0),2) END AS supporting_stat
            FROM app_counts ac LEFT JOIN pdisc ON pdisc.player_id = ac.player_id
            ORDER BY primary_stat DESC, ac.appearances ASC LIMIT 10`, [seriesId]);
        return r.rows;
    }

    return [];
}

// Helper: fetch series + leaderboards for a given series_id
async function _getSeriesTrophyPayload(seriesId, includeIds) {
    const seriesRow = await pool.query(`
        SELECT gs.id, gs.series_name, gs.series_type, gs.series_status,
               COALESCE(AVG(g.star_rating) FILTER (WHERE g.game_status = 'completed'), 0) AS avg_star_rating,
               COUNT(g.id) FILTER (WHERE g.game_status = 'completed') AS completed_games
        FROM game_series gs
        LEFT JOIN games g ON g.series_id = gs.id
        WHERE gs.id = $1
        GROUP BY gs.id, gs.series_name, gs.series_type, gs.series_status`, [seriesId]);
    if (!seriesRow.rows.length) return null;
    const series = seriesRow.rows[0];
    const completedGames = parseInt(series.completed_games) || 0;

    const trophiesRow = await pool.query(`
        SELECT id, metric_id, calculation_type, tier, created_at
        FROM series_trophies WHERE series_id = $1 ORDER BY metric_id, calculation_type`, [seriesId]);

    const trophies = [];
    for (const t of trophiesRow.rows) {
        const leaderboard = completedGames > 0
            ? await calcSeriesLeaderboard(seriesId, t.metric_id, t.calculation_type)
            : [];
        const cfg = METRIC_CONFIG[parseInt(t.metric_id)];
        const entry = {
            metric_id: t.metric_id,
            metric_name: cfg ? cfg.name : 'Unknown',
            metric_icon: cfg ? cfg.icon : '🏆',
            calculation_type: t.calculation_type,
            tier: t.tier,
            primary_label: cfg ? cfg.primaryLabel : 'Stat',
            supporting_label: cfg ? cfg.supportingLabel : null,
            leaderboard
        };
        if (includeIds) entry.id = t.id;
        trophies.push(entry);
    }

    return {
        series_id: series.id,
        series_name: series.series_name,
        series_type: series.series_type,
        series_status: series.series_status,
        completed_games: completedGames,
        avg_star_rating: parseFloat(series.avg_star_rating),
        locked: completedGames > 0,
        trophies
    };
}

// GET /api/public/series/:id/trophies — public, no auth
app.get('/api/public/series/:id/trophies', async (req, res) => {
    try {
        const payload = await _getSeriesTrophyPayload(req.params.id, false);
        if (!payload) return res.status(404).json({ error: 'Series not found' });
        res.json(payload);
    } catch (e) {
        console.error('GET /api/public/series/:id/trophies error:', e.message);
        res.status(500).json({ error: 'Failed to load series trophies' });
    }
});

// GET /api/admin/series/:id/trophies — admin auth, includes trophy IDs for delete
app.get('/api/admin/series/:id/trophies', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const payload = await _getSeriesTrophyPayload(req.params.id, true);
        if (!payload) return res.status(404).json({ error: 'Series not found' });
        res.json(payload);
    } catch (e) {
        console.error('GET /api/admin/series/:id/trophies error:', e.message);
        res.status(500).json({ error: 'Failed to load series trophies' });
    }
});

// POST /api/admin/series/:id/trophies — add trophy
app.post('/api/admin/series/:id/trophies', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const seriesId = req.params.id;
        const { metric_id, calculation_type } = req.body;

        const mid = parseInt(metric_id);
        if (!mid || !METRIC_CONFIG[mid]) return res.status(400).json({ error: 'Invalid metric_id' });
        const cfg = METRIC_CONFIG[mid];
        if (!cfg.validCalcTypes.includes(calculation_type)) {
            return res.status(400).json({ error: `Invalid calculation_type. Valid: ${cfg.validCalcTypes.join(', ')}` });
        }

        const seriesRow = await pool.query(`
            SELECT gs.id, gs.series_type, gs.series_status,
                   COUNT(g.id) FILTER (WHERE g.game_status = 'completed') AS completed_games,
                   COALESCE(AVG(g.star_rating) FILTER (WHERE g.game_status = 'completed'), 0) AS avg_star_rating
            FROM game_series gs
            LEFT JOIN games g ON g.series_id = gs.id
            WHERE gs.id = $1
            GROUP BY gs.id, gs.series_type, gs.series_status`, [seriesId]);
        if (!seriesRow.rows.length) return res.status(404).json({ error: 'Series not found' });
        const s = seriesRow.rows[0];

        if (s.series_status === 'completed') {
            return res.status(400).json({ error: 'Series is finalised — trophies cannot be added' });
        }
        if (parseInt(s.completed_games) > 0) {
            return res.status(400).json({ error: 'Trophies locked — first game has already been played' });
        }

        const tier = deriveTier(s.series_type, s.avg_star_rating);

        await pool.query(`
            INSERT INTO series_trophies (series_id, metric_id, calculation_type, tier)
            VALUES ($1, $2, $3, $4)`, [seriesId, mid, calculation_type, tier]);

        res.json({ ok: true, tier, message: `Trophy added — Tier ${tier}` });
    } catch (e) {
        if (e.code === '23505') return res.status(400).json({ error: 'This trophy already exists for this series' });
        console.error('POST /api/admin/series/:id/trophies error:', e.message);
        res.status(500).json({ error: 'Failed to add trophy' });
    }
});

// DELETE /api/admin/series/:id/trophies/:tid — remove trophy
app.delete('/api/admin/series/:id/trophies/:tid', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id: seriesId, tid } = req.params;

        const check = await pool.query(`
            SELECT gs.series_status,
                   COUNT(g.id) FILTER (WHERE g.game_status = 'completed') AS completed_games
            FROM game_series gs
            LEFT JOIN games g ON g.series_id = gs.id
            WHERE gs.id = $1
            GROUP BY gs.id, gs.series_status`, [seriesId]);
        if (!check.rows.length) return res.status(404).json({ error: 'Series not found' });
        if (check.rows[0].series_status === 'completed') {
            return res.status(400).json({ error: 'Series is finalised — trophies cannot be removed' });
        }
        if (parseInt(check.rows[0].completed_games) > 0) {
            return res.status(400).json({ error: 'Trophies locked — first game has already been played' });
        }

        const del = await pool.query(`
            DELETE FROM series_trophies WHERE id = $1 AND series_id = $2 RETURNING id`, [tid, seriesId]);
        if (!del.rows.length) return res.status(404).json({ error: 'Trophy not found' });

        res.json({ ok: true });
    } catch (e) {
        console.error('DELETE /api/admin/series/:id/trophies/:tid error:', e.message);
        res.status(500).json({ error: 'Failed to remove trophy' });
    }
});

// POST /api/admin/series/:id/finalize — lock results permanently
app.post('/api/admin/series/:id/finalize', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const seriesId = req.params.id;

        const seriesRow = await pool.query(
            `SELECT series_status FROM game_series WHERE id = $1`, [seriesId]);
        if (!seriesRow.rows.length) return res.status(404).json({ error: 'Series not found' });
        if (seriesRow.rows[0].series_status === 'completed') {
            return res.status(400).json({ error: 'Series already finalised' });
        }

        const trophiesRow = await pool.query(
            `SELECT id, metric_id, calculation_type FROM series_trophies WHERE series_id = $1`, [seriesId]);

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            for (const t of trophiesRow.rows) {
                console.log(`[finalize] Computing metric_id=${t.metric_id} calc=${t.calculation_type}`);
                const leaderboard = await calcSeriesLeaderboard(seriesId, t.metric_id, t.calculation_type);
                console.log(`[finalize] Leaderboard rows: ${leaderboard.length}`);
                await client.query('DELETE FROM series_trophy_results WHERE trophy_id = $1', [t.id]);
                for (let i = 0; i < Math.min(leaderboard.length, 3); i++) {
                    const row = leaderboard[i];
                    await client.query(`
                        INSERT INTO series_trophy_results (trophy_id, player_id, rank, primary_stat, supporting_stat)
                        VALUES ($1, $2, $3, $4, $5)`,
                        [t.id, row.player_id, i + 1, row.primary_stat, row.supporting_stat]);
                }
            }

            await client.query(`
                UPDATE game_series SET series_status = 'completed', finalized_at = NOW()
                WHERE id = $1`, [seriesId]);

            await client.query('COMMIT');
            res.json({ ok: true, message: 'Series finalised — trophy winners locked permanently' });
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (e) {
        console.error('POST /api/admin/series/:id/finalize error:', e.message);
        res.status(500).json({ error: 'Failed to finalise series' });
    }
});


// ══════════════════════════════════════════════════════════════════════════════
// WONDERFUL PAYMENTS — Open Banking top-up integration
// ══════════════════════════════════════════════════════════════════════════════

// Helper: call Wonderful REST API
async function wonderfulRequest(method, path, body = null) {
    const opts = {
        method,
        headers: {
            'Authorization': `Bearer ${WONDERFUL_API_KEY}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`https://api.wonderful.one${path}`, opts);
    const json = await res.json();
    if (!res.ok) throw Object.assign(new Error(json.message || 'Wonderful API error'), { status: res.status, body: json });
    return json;
}

// Shared helper — send top-up confirmation email after any successful Wonderful credit
async function sendWonderfulCreditEmail(playerId, pounds, ref) {
    try {
        const pRow = await pool.query(
            `SELECT p.alias, p.full_name, u.email
             FROM players p JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
            [playerId]
        );
        if (!pRow.rows[0]?.email) return;
        const name = pRow.rows[0].alias || pRow.rows[0].full_name;
        const balRow = await pool.query('SELECT balance FROM credits WHERE player_id = $1', [playerId]);
        const newBal = parseFloat(balRow.rows[0]?.balance || 0).toFixed(2);
        await emailTransporter.sendMail({
            from: '"TotalFooty" <totalfooty19@gmail.com>',
            to:   pRow.rows[0].email,
            subject: `✅ £${pounds.toFixed(2)} added to your TotalFooty balance`,
            html: wrapEmailHtml(`
                <p style="font-size:16px;font-weight:700;">Hi ${htmlEncode(name)},</p>
                <p style="color:#888;">Your payment has been confirmed and your credits have been added.</p>
                <div style="text-align:center;padding:28px 0;">
                    <div style="font-size:48px;font-weight:900;color:#00cc66;">£${pounds.toFixed(2)}</div>
                    <div style="font-size:14px;color:#888;margin-top:8px;">added to your balance</div>
                    <div style="font-size:20px;font-weight:900;margin-top:16px;">New balance: £${newBal}</div>
                </div>
                <p style="text-align:center;">
                    <a href="https://totalfooty.co.uk" style="display:inline-block;padding:14px 32px;background:#00cc66;color:#000;font-weight:900;border-radius:8px;text-decoration:none;font-size:15px;">SIGN UP FOR A GAME →</a>
                </p>
                <p style="color:#666;font-size:12px;text-align:center;margin-top:16px;">Payment ref: ${htmlEncode(ref)}</p>
            `)
        });
    } catch (e) {
        console.error('Wonderful credit email failed (non-critical):', e.message);
    }
}

// POST /api/payments/wonderful/initiate
// Authenticated — creates a Wonderful payment request and returns the pay_link
app.post('/api/payments/wonderful/initiate', authenticateToken, wonderfulInitiateLimiter, async (req, res) => {
    if (!WONDERFUL_API_KEY) return res.status(503).json({ error: 'Online payments are temporarily unavailable' });
    try {
        const { amount_pounds, game_id } = req.body;
        const playerId = req.user.playerId;

        // Validate amount: £1–£200 in whole pounds
        const pounds = parseFloat(amount_pounds);
        if (!pounds || pounds < 1 || pounds > 200 || pounds !== Math.floor(pounds)) {
            return res.status(400).json({ error: 'Amount must be a whole number between £1 and £200' });
        }
        const amountPence = Math.round(pounds * 100);

        // Fetch player email for Wonderful — LEFT JOIN so legacy accounts without user_id still resolve
        const playerRow = await pool.query(
            `SELECT p.id, COALESCE(u.email, '') AS email, p.alias, p.full_name
             FROM players p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = $1`,
            [playerId]
        );
        if (!playerRow.rows.length) return res.status(404).json({ error: 'Player not found' });
        const player = playerRow.rows[0];
        if (!player.email) return res.status(400).json({ error: 'No email address on account — contact support to top up.' });

        // Unique merchant reference — max 18 chars, only letters/numbers/dashes
        const tsShort = Date.now().toString(36).toUpperCase(); // base-36 timestamp ~8 chars
        const merchantRef = `TF-${playerId.slice(0, 5)}-${tsShort}`.slice(0, 18);

        // Create payment with Wonderful v2 API
        const wonderfulRes = await wonderfulRequest('POST', '/v2/quick-pay', {
            customer_email_address:  player.email,
            merchant_payment_reference: merchantRef,
            payment_description: `TotalFooty credit top-up £${pounds}`,
            amount:      amountPence,
            redirect_url: `https://totalfooty.co.uk/?wonderful_payment_id=${merchantRef}`,
            webhook_url: `https://totalfooty-api.onrender.com/api/webhooks/wonderful`,
        });

        const wpId   = wonderfulRes.data?.id;
        const payLink = wonderfulRes.data?.pay_link;
        if (!payLink) throw new Error('Wonderful returned no pay_link');

        // Store pending payment in DB
        await pool.query(
            `INSERT INTO wonderful_payments
                (wonderful_payment_id, merchant_reference, player_id, amount_pence, status, game_id, pay_link)
             VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
            [wpId, merchantRef, playerId, amountPence, game_id || null, payLink]
        );

        await auditLog(pool, playerId, 'wonderful_initiated', playerId,
            `Wonderful payment initiated: £${pounds.toFixed(2)} · Ref: ${merchantRef}`);

        res.json({ pay_link: payLink, merchant_reference: merchantRef });
    } catch (e) {
        console.error('Wonderful initiate error:', e.message, e.body || '');
        res.status(500).json({ error: 'Failed to create payment. Please try again.' });
    }
});

// POST /api/webhooks/wonderful
// Public — Wonderful calls this when payment status changes
// Security: we NEVER trust payload alone — always re-verify via GET
app.post('/api/webhooks/wonderful', async (req, res) => {
    // Respond immediately so Wonderful doesn't retry
    res.json({ received: true });

    try {
        // Log full body for debugging — harmless, no sensitive data
        console.log('[Wonderful webhook] body:', JSON.stringify(req.body));

        // Extract Wonderful's payment ID — cover all known field name variants
        const wpId = req.body?.id
            || req.body?.payment_id
            || req.body?.paymentId
            || req.body?.order_id
            || req.body?.data?.id
            || req.body?.data?.payment_id
            || req.body?.data?.order_id
            || null;

        // Extract merchant reference — cover all known variants
        const webhookRef = req.body?.merchant_payment_reference
            || req.body?.merchant_reference
            || req.body?.reference
            || req.body?.data?.merchant_payment_reference
            || req.body?.data?.merchant_reference
            || req.body?.data?.reference
            || null;

        // Must have at least one identifier to proceed
        console.log('[Wonderful webhook] extracted wpId:', wpId, 'webhookRef:', webhookRef);
        if (!wpId && !webhookRef) {
            return console.warn('[Wonderful webhook] no payment ID or merchant reference in body — cannot process');
        }

        // Fetch payment record — try wonderful_payment_id first, then merchant_reference
        // Wonderful sends order_id in webhook which may differ from payment id — resolve via API if needed
        let pmt = null;
        if (wpId) {
            const byId = await pool.query(
                `SELECT * FROM wonderful_payments WHERE wonderful_payment_id = $1`, [wpId]
            );
            pmt = byId.rows[0] || null;

            // order_id may not match wonderful_payment_id — try resolving via Wonderful API
            if (!pmt && WONDERFUL_API_KEY) {
                try {
                    // Try fetching payment list filtered by order_id, or search all pending
                    const searchRes = await pool.query(
                        `SELECT * FROM wonderful_payments WHERE status = 'pending' ORDER BY created_at DESC LIMIT 20`
                    );
                    // Find by verifying each pending payment until we match order_id
                    for (const candidate of searchRes.rows) {
                        if (!candidate.wonderful_payment_id) continue;
                        try {
                            const vRes = await wonderfulRequest('GET', `/v2/payments/${candidate.wonderful_payment_id}`);
                            if (vRes.data?.order_id === wpId || String(vRes.data?.id) === String(wpId)) {
                                pmt = candidate;
                                console.log('[Wonderful webhook] resolved order_id', wpId, '→ wonderful_payment_id', candidate.wonderful_payment_id);
                                break;
                            }
                        } catch (_) { continue; }
                    }
                } catch (e) {
                    console.warn('[Wonderful webhook] order_id resolution failed:', e.message);
                }
            }
        }
        if (!pmt && webhookRef) {
            const byRef = await pool.query(
                `SELECT * FROM wonderful_payments WHERE merchant_reference = $1`, [webhookRef]
            );
            pmt = byRef.rows[0] || null;
        }
        if (!pmt) {
            return console.warn('[Wonderful webhook] no matching payment record — wpId:', wpId, 'ref:', webhookRef);
        }
        if (pmt.status === 'credited') {
            return console.log('[Wonderful webhook] already credited, skipping:', pmt.merchant_reference);
        }

        // SECURITY: independently verify status with Wonderful API — never trust webhook payload alone
        if (!WONDERFUL_API_KEY) return;
        const verifyId = wpId || pmt.wonderful_payment_id;
        if (!verifyId) {
            return console.error('[Wonderful webhook] cannot verify — no wonderful_payment_id. merchant_ref:', pmt.merchant_reference);
        }
        let verified;
        try {
            const verifyRes = await wonderfulRequest('GET', `/v2/payments/${verifyId}`);
            verified = verifyRes.data?.status;
        } catch (e) {
            return console.error('Wonderful webhook: verify GET failed', e.message);
        }

        // v2 API: payment status can be 'paid' or 'accepted' for successful payments
        console.log('[Wonderful webhook] verify status:', verified, '| wpId:', wpId, '| ref:', pmt.merchant_reference);
        if (verified !== 'paid' && verified !== 'accepted') {
            // Update status but don't credit
            await pool.query(
                `UPDATE wonderful_payments SET status = $1, wonderful_payment_id = COALESCE(wonderful_payment_id, $2) WHERE id = $3`,
                [verified || 'pending', wpId, pmt.id]
            );
            return;
        }

        // Idempotency: mark as credited atomically
        const claim = await pool.query(
            `UPDATE wonderful_payments
             SET status = 'credited', confirmed_at = NOW(), credited_at = NOW(),
                 wonderful_payment_id = COALESCE(wonderful_payment_id, $1)
             WHERE id = $2 AND status != 'credited'
             RETURNING *`,
            [wpId, pmt.id]
        );
        if (!claim.rows.length) return; // another webhook beat us to it

        const pounds = pmt.amount_pence / 100;

        // Read balance BEFORE credit for audit trail
        const balBeforeRow = await pool.query('SELECT COALESCE(balance, 0) AS balance FROM credits WHERE player_id = $1', [pmt.player_id]);
        const balBefore = parseFloat(balBeforeRow.rows[0]?.balance || 0);

        // Credit the player's balance — RETURNING gives us confirmed new balance
        const creditResult = await pool.query(
            `UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2`,
            [pounds, pmt.player_id]
        );
        const balAfter = balBefore + pounds;

        await recordCreditTransaction(pool, pmt.player_id, pounds, 'wonderful_topup',
            `Wonderful bank payment — ref ${pmt.merchant_reference}`, null);

        await auditLog(pool, pmt.player_id, 'wonderful_credited', pmt.player_id,
            `£${pounds.toFixed(2)} credited via Wonderful · Balance: £${balBefore.toFixed(2)} → £${balAfter.toFixed(2)} · Ref: ${pmt.merchant_reference}`);

        // Trigger RAF activation bonus if this is the referred player's first top-up
        setImmediate(() => triggerRafActivation(pmt.player_id).catch(() => {}));

        // Send confirmation email to player
        setImmediate(() => sendWonderfulCreditEmail(pmt.player_id, pounds, pmt.merchant_reference));

        // If payment was linked to a specific game, auto-register the player
        if (pmt.game_id) {
            setImmediate(async () => {
                try {
                    const gameRow = await pool.query(
                        `SELECT g.id, g.cost_per_player, g.game_status, g.team_selection_type,
                                g.max_players, g.requires_organiser,
                                (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') AS confirmed_count
                         FROM games g WHERE g.id = $1`,
                        [pmt.game_id]
                    );
                    const game = gameRow.rows[0];
                    if (!game || game.game_status !== 'available' || parseInt(game.confirmed_count) >= parseInt(game.max_players)) return;
                    // Check not already registered
                    const already = await pool.query(
                        `SELECT 1 FROM registrations WHERE game_id = $1 AND player_id = $2`, [pmt.game_id, pmt.player_id]
                    );
                    if (already.rows.length) return;
                    // Deduct game fee and register
                    const client = await pool.connect();
                    try {
                        await client.query('BEGIN');
                        const { realCharged } = await applyGameFee(client, pmt.player_id, game.cost_per_player, `Registration for game ${pmt.game_id} (via Wonderful)`);
                        await client.query(
                            `INSERT INTO registrations (game_id, player_id, status, position_preference, amount_paid, registered_at)
                             VALUES ($1, $2, 'confirmed', 'No Preference', $3, NOW())`,
                            [pmt.game_id, pmt.player_id, realCharged]
                        );
                        await client.query('COMMIT');
                        await gameAuditLog(pool, pmt.game_id, pmt.player_id, 'player_signed_up',
                            `Auto-registered after Wonderful payment ${pmt.merchant_reference}`);
                    } catch (e) {
                        await client.query('ROLLBACK').catch(() => {});
                        console.error('Wonderful auto-register failed (non-critical):', e.message);
                    } finally {
                        client.release();
                    }
                } catch (e) {
                    console.error('Wonderful game auto-register error (non-critical):', e.message);
                }
            });
        }
    } catch (e) {
        console.error('Wonderful webhook processing error:', e.message);
    }
});

// GET /api/payments/wonderful/status/:ref — player polls for confirmation after redirect
// Used by the success screen to show confirmed/pending state
app.get('/api/payments/wonderful/status/:ref', authenticateToken, async (req, res) => {
    try {
        const { ref } = req.params;
        const row = await pool.query(
            `SELECT status, amount_pence, game_id, credited_at, wonderful_payment_id
             FROM wonderful_payments
             WHERE merchant_reference = $1 AND player_id = $2`,
            [ref, req.user.playerId]
        );
        if (!row.rows.length) return res.status(404).json({ error: 'Payment not found' });
        const p = row.rows[0];

        // COLD-START RECOVERY: if our DB says pending but Wonderful confirms paid,
        // credit the player now. This handles webhook misses due to Render cold starts.
        console.log('[Wonderful status-poll] ref:', ref, 'db_status:', p.status, 'wp_id:', p.wonderful_payment_id || 'NULL');
        if (p.status === 'pending' && p.wonderful_payment_id && WONDERFUL_API_KEY) {
            try {
                const verifyRes = await wonderfulRequest('GET', `/v2/payments/${p.wonderful_payment_id}`);
                const verifiedStatus = verifyRes.data?.status;
                console.log('[Wonderful status-poll] verify result:', verifiedStatus, 'full data keys:', Object.keys(verifyRes.data || {}));
                if (verifiedStatus === 'paid' || verifiedStatus === 'accepted') {
                    console.log('[Wonderful status poll] cold-start recovery — crediting via status poll for ref:', ref);
                    // Atomic claim — prevents double-credit if webhook also fires
                    const client = await pool.connect();
                    try {
                        await client.query('BEGIN');
                        const claim = await client.query(
                            `UPDATE wonderful_payments
                             SET status = 'credited', confirmed_at = NOW(), credited_at = NOW()
                             WHERE merchant_reference = $1 AND player_id = $2 AND status != 'credited'
                             RETURNING *`,
                            [ref, req.user.playerId]
                        );
                        if (claim.rows.length > 0) {
                            const pounds = p.amount_pence / 100;
                            const balBeforeRow2 = await client.query('SELECT COALESCE(balance, 0) AS balance FROM credits WHERE player_id = $1', [req.user.playerId]);
                            const balBefore2 = parseFloat(balBeforeRow2.rows[0]?.balance || 0);
                            await client.query(
                                `UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2`,
                                [pounds, req.user.playerId]
                            );
                            const balAfter2 = balBefore2 + pounds;
                            await client.query('COMMIT');
                            // Post-commit logging — uses pool (outside transaction intentionally)
                            await recordCreditTransaction(pool, req.user.playerId, pounds, 'wonderful_topup',
                                `Wonderful bank payment (status-poll recovery) — ref ${ref}`, null);
                            await auditLog(pool, req.user.playerId, 'wonderful_credited', req.user.playerId,
                                `£${pounds.toFixed(2)} credited via Wonderful (recovery) · Balance: £${balBefore2.toFixed(2)} → £${balAfter2.toFixed(2)} · Ref: ${ref}`);
                            // Trigger RAF activation if this is the player's first top-up
                            setImmediate(() => triggerRafActivation(req.user.playerId).catch(() => {}));
                            setImmediate(() => sendWonderfulCreditEmail(req.user.playerId, pounds, ref));
                            return res.json({ status: 'credited', amount: pounds.toFixed(2), game_id: p.game_id, credited_at: new Date() });
                        }
                        await client.query('ROLLBACK');
                    } catch (creditErr) {
                        await client.query('ROLLBACK').catch(() => {});
                        console.error('[Wonderful status poll] recovery credit failed:', creditErr.message);
                    } finally {
                        client.release();
                    }
                }
            } catch (verifyErr) {
                // Verify failed — return current DB status, don't error the poll
                console.warn('[Wonderful status poll] verify failed:', verifyErr.message);
            }
        }

        res.json({
            status:      p.status,
            amount:      (p.amount_pence / 100).toFixed(2),
            game_id:     p.game_id,
            credited_at: p.credited_at,
        });
    } catch (e) {
        console.error('Wonderful status error:', e.message);
        res.status(500).json({ error: 'Failed to check payment status' });
    }
});

// GET /api/admin/payments/wonderful/pending — list all non-credited payments for admin review
app.get('/api/admin/payments/wonderful/pending', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const rows = await pool.query(`
            SELECT wp.id, wp.merchant_reference, wp.wonderful_payment_id,
                   wp.amount_pence, wp.status, wp.created_at, wp.credited_at,
                   p.alias, p.full_name, p.id as player_id
            FROM wonderful_payments wp
            JOIN players p ON p.id = wp.player_id
            ORDER BY wp.created_at DESC
            LIMIT 100
        `);
        res.json({ payments: rows.rows });
    } catch (e) {
        console.error('GET wonderful pending error:', e.message);
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

// POST /api/admin/payments/wonderful/manual-credit
// Superadmin only — manually credit a player for a Wonderful payment that the webhook missed
// Typical cause: Render cold start meant webhook was received but processing failed silently
app.post('/api/admin/payments/wonderful/manual-credit', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { merchant_reference } = req.body;
    if (!merchant_reference) return res.status(400).json({ error: 'merchant_reference required' });
    try {
        // Look up payment by merchant reference
        const pmtRow = await pool.query(
            `SELECT * FROM wonderful_payments WHERE merchant_reference = $1`,
            [merchant_reference]
        );
        if (!pmtRow.rows.length) return res.status(404).json({ error: 'Payment not found for that reference' });
        const pmt = pmtRow.rows[0];

        if (pmt.status === 'credited') {
            return res.status(409).json({ error: 'Already credited', payment: pmt });
        }

        // Verify with Wonderful API before crediting
        if (!WONDERFUL_API_KEY) return res.status(503).json({ error: 'WONDERFUL_API_KEY not set' });
        const verifyId = pmt.wonderful_payment_id;
        if (!verifyId) return res.status(400).json({ error: 'No wonderful_payment_id on record — cannot verify. Check Wonderful dashboard manually.' });

        let verified;
        try {
            const verifyRes = await wonderfulRequest('GET', `/v2/payments/${verifyId}`);
            verified = verifyRes.data?.status;
        } catch (e) {
            return res.status(502).json({ error: 'Wonderful API verify failed: ' + e.message });
        }

        if (verified !== 'paid' && verified !== 'accepted') {
            return res.status(400).json({ error: `Wonderful payment status is '${verified}' — not creditable`, verified_status: verified });
        }

        // Idempotency claim
        const claim = await pool.query(
            `UPDATE wonderful_payments
             SET status = 'credited', confirmed_at = NOW(), credited_at = NOW()
             WHERE id = $1 AND status != 'credited'
             RETURNING *`,
            [pmt.id]
        );
        if (!claim.rows.length) return res.status(409).json({ error: 'Race condition — already credited' });

        const pounds = pmt.amount_pence / 100;

        const balBeforeRow3 = await pool.query('SELECT COALESCE(balance, 0) AS balance FROM credits WHERE player_id = $1', [pmt.player_id]);
        const balBefore3 = parseFloat(balBeforeRow3.rows[0]?.balance || 0);
        const creditResult3 = await pool.query(
            `UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2`,
            [pounds, pmt.player_id]
        );
        const balAfter3 = balBefore3 + pounds;
        await recordCreditTransaction(pool, pmt.player_id, pounds, 'wonderful_topup',
            `Manual credit by superadmin — Wonderful ref ${pmt.merchant_reference}`, null);
        await auditLog(pool, pmt.player_id, 'wonderful_credited', req.user.playerId,
            `MANUAL CREDIT: £${pounds.toFixed(2)} via Wonderful · Balance: £${balBefore3.toFixed(2)} → £${balAfter3.toFixed(2)} · Ref: ${pmt.merchant_reference}`);

        const balRow = await pool.query('SELECT balance FROM credits WHERE player_id = $1', [pmt.player_id]);
        const newBal = parseFloat(balRow.rows[0]?.balance || 0).toFixed(2);

        // Send confirmation email + trigger RAF activation
        setImmediate(() => sendWonderfulCreditEmail(pmt.player_id, pounds, pmt.merchant_reference));
        setImmediate(() => triggerRafActivation(pmt.player_id).catch(() => {}));

        res.json({ success: true, amount: pounds.toFixed(2), player_id: pmt.player_id, new_balance: newBal });
    } catch (e) {
        console.error('Manual Wonderful credit error:', e.message);
        res.status(500).json({ error: 'Server error: ' + e.message });
    }
});

// FIX-043: Catch-all 404 — MUST be last, after all routes including Wonderful
app.use((req, res) => { res.status(404).json({ error: 'Not found' }); });

app.listen(PORT, () => {
    console.log(`🚀 Total Footy API running on port ${PORT} — build: web39-fix2`);
    
    // Keep database AND backend warm (ping every 5 minutes)
    setInterval(async () => {
        try {
            await pool.query('SELECT 1');
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

    // TF Game Awards — auto-close expired voting every 10 minutes
    setInterval(async () => {
        try {
            const expiredAwards = await pool.query(`
                SELECT id FROM games
                WHERE awards_open = true
                  AND awards_close_at IS NOT NULL
                  AND awards_close_at < NOW()
                  AND game_status = 'completed'
            `);

            if (expiredAwards.rows.length === 0) return;

            console.log(`⏰ Auto-closing TF Game Awards for ${expiredAwards.rows.length} game(s)...`);
            for (const row of expiredAwards.rows) {
                try {
                    const result = await closeAwards(row.id);
                    const count = result?.confirmedWinners?.length || 0;
                    console.log(`✅ Awards auto-closed for game ${row.id}: ${count} award(s) confirmed`);
                    await gameAuditLog(pool, row.id, null, 'awards_auto_closed',
                        `${count} award(s) confirmed`).catch(() => {});
                } catch (e) {
                    console.error(`✗ Awards auto-close failed for game ${row.id}:`, e.message);
                }
            }
        } catch (error) {
            console.error('✗ Awards scheduler error:', error.message);
        }
    }, 10 * 60 * 1000); // 10 minutes

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
                        await gameAuditLog(pool, row.id, null, 'motm_finalized',
                            `Auto-finalized | Winner(s): ${names} | Votes: ${result.winners[0]?.votes ?? '?'}`).catch(() => {});
                    }
                    // Always run ref finalize — MOTM and refs are independent
                    await finaliseRefereeReviews(row.id).catch(e =>
                        console.error(`Ref review finalize failed ${row.id}:`, e.message));
                } catch (e) {
                    console.error(`✗ MOTM auto-finalize failed for game ${row.id}:`, e.message);
                }
            }
        } catch (error) {
            console.error('✗ MOTM scheduler error:', error.message);
        }
    }, 10 * 60 * 1000); // 10 minutes

    // Ref review window close scheduler — runs every 10 minutes
    // Handles games that have no MOTM (e.g. external losses) so ref reviews still finalise
    setInterval(async () => {
        try {
            const expiredRefs = await pool.query(`
                SELECT DISTINCT gr.game_id
                FROM game_referees gr
                JOIN games g ON g.id = gr.game_id
                WHERE g.ref_review_ends < NOW()
                  AND g.game_status = 'completed'
                  AND gr.status = 'confirmed'
                  AND gr.final_rating IS NULL
            `);
            for (const row of expiredRefs.rows) {
                await finaliseRefereeReviews(row.game_id).catch(e =>
                    console.error(`Scheduled ref review finalize failed ${row.game_id}:`, e.message));
            }
        } catch (e) {
            console.error('Ref review scheduler error:', e.message);
        }
    }, 10 * 60 * 1000); // 10 minutes

        // Min-rating auto-drop scheduler — runs every 5 minutes
    // Updates min_rating_drop_sent flag. effectiveMinOvr() uses game_date vs Date.now()
    // so the actual gate drops automatically; this flag just prevents double-firing.
    let minRatingDropRunning = false;
    setInterval(async () => {
        if (minRatingDropRunning) return;
        minRatingDropRunning = true;
        try {
            // 48h drop: games 47h55m–48h5m away, not yet dropped once
            const drop48 = await pool.query(`
                SELECT id FROM games
                WHERE min_rating_enabled = TRUE
                  AND star_rating >= 2
                  AND min_rating_drop_sent = 0
                  AND game_date BETWEEN NOW() + INTERVAL '47 hours 55 minutes'
                                   AND NOW() + INTERVAL '48 hours 5 minutes'
                  AND game_status NOT IN ('cancelled','completed')
            `);
            for (const row of drop48.rows) {
                const claimed = await pool.query(
                    `UPDATE games SET min_rating_drop_sent = 1
                      WHERE id = $1 AND min_rating_drop_sent = 0 RETURNING id`,
                    [row.id]
                );
                if (claimed.rowCount > 0)
                    console.log(`⏰ Min-rating 48h drop: game ${row.id}`);
            }
            // 24h drop: games 23h55m–24h5m away, dropped once but not twice
            const drop24 = await pool.query(`
                SELECT id FROM games
                WHERE min_rating_enabled = TRUE
                  AND star_rating >= 2
                  AND min_rating_drop_sent = 1
                  AND game_date BETWEEN NOW() + INTERVAL '23 hours 55 minutes'
                                   AND NOW() + INTERVAL '24 hours 5 minutes'
                  AND game_status NOT IN ('cancelled','completed')
            `);
            for (const row of drop24.rows) {
                const claimed = await pool.query(
                    `UPDATE games SET min_rating_drop_sent = 2
                      WHERE id = $1 AND min_rating_drop_sent = 1 RETURNING id`,
                    [row.id]
                );
                if (claimed.rowCount > 0)
                    console.log(`⏰ Min-rating 24h drop: game ${row.id}`);
            }
        } catch (e) {
            console.error('✗ Min-rating drop scheduler error:', e.message);
        } finally {
            minRatingDropRunning = false;
        }
    }, 5 * 60 * 1000);

    // ── AI Bio: Sunday 2am batch regeneration ──
    let bioRunning = false;
    setInterval(async () => {
        if (bioRunning) return;
        const now = new Date();
        // Sunday (0) at 2am
        // Render runs UTC — UK is UTC+0 (GMT) or UTC+1 (BST). Check hours 1-2 UTC to cover both.
        if (now.getDay() !== 0 || (now.getHours() !== 1 && now.getHours() !== 2)) return;
        bioRunning = true;
        console.log('🤖 Starting weekly AI bio generation...');
        try {
            const players = await pool.query(
                `SELECT id FROM players WHERE total_appearances >= 5 ORDER BY total_appearances DESC`
            );
            for (const row of players.rows) {
                try {
                    await regeneratePlayerBio(row.id);
                    // 1 second delay between players — respects API rate limits
                    await new Promise(r => setTimeout(r, 1000));
                } catch (e) {
                    console.warn(`Bio batch failed for player ${row.id}:`, e.message);
                }
            }
            console.log(`🤖 Bio batch complete: ${players.rows.length} players processed`);
        } catch (e) {
            console.error('Bio cron failed:', e.message);
        } finally {
            bioRunning = false;
        }
    }, 60 * 1000); // Check every minute, run only at Sunday 2am


    // ── Coaching session reminder — 24 hours before ──────────────
    // Email: coach + all registered players + superadmin
    let coachingReminderRunning = false;
    setInterval(async () => {
        if (coachingReminderRunning) return;
        coachingReminderRunning = true;
        try {
            // Find sessions starting in 23h55m–24h05m that haven't had reminder sent
            const sessions = await pool.query(`
                SELECT cs.id, cs.session_url, cs.activity_type, cs.session_date,
                       cs.coach_player_id, v.name AS venue_name
                FROM coaching_sessions cs
                LEFT JOIN venues v ON v.id = cs.confirmed_venue_id
                WHERE cs.session_date BETWEEN NOW() + INTERVAL '23 hours 55 minutes'
                  AND NOW() + INTERVAL '24 hours 5 minutes'
                  AND cs.status IN ('finalised','venue_confirmed','coach_confirmed')
                  AND cs.reminder_sent IS NOT TRUE
            `);
            for (const sess of sessions.rows) {
                // Atomic claim
                const claimed = await pool.query(
                    `UPDATE coaching_sessions SET reminder_sent=TRUE WHERE id=$1 AND (reminder_sent IS NOT TRUE) RETURNING id`,
                    [sess.id]
                );
                if (claimed.rowCount === 0) continue;

                const dateStr = sess.session_date
                    ? new Date(sess.session_date).toLocaleString('en-GB', {
                        weekday:'long', day:'numeric', month:'long', hour:'2-digit', minute:'2-digit', timeZone:'Europe/London'
                      })
                    : 'TBC';
                const actLabel = (sess.activity_type || '').replace(/_/g, ' ');
                const sessionLink = `https://totalfooty.co.uk/session.html?url=${sess.session_url}`;
                const emailBody = `
                    <p style="color:#888">This is a reminder that you have a coaching session tomorrow.</p>
                    <table style="margin:12px 0;">
                        <tr><td style="color:#888;width:120px;">Date &amp; Time</td><td style="color:#fff;font-weight:700;">${htmlEncode(dateStr)}</td></tr>
                        <tr><td style="color:#888;">Activity</td><td style="color:#fff;">${htmlEncode(actLabel)}</td></tr>
                        ${sess.venue_name ? `<tr><td style="color:#888;">Venue</td><td style="color:#fff;">${htmlEncode(sess.venue_name)}</td></tr>` : ''}
                    </table>
                    <p style="color:#888;margin-top:12px;"><a href="${sessionLink}" style="color:#C0392B;">View Session Details →</a></p>`;

                // Get registered players
                const players = await pool.query(
                    `SELECT player_id FROM coaching_registrations WHERE session_id=$1 AND status='registered'`,
                    [sess.id]
                );
                const recipientIds = players.rows.map(r => r.player_id);
                if (sess.coach_player_id) recipientIds.push(sess.coach_player_id);

                await sendCoachingEmail(recipientIds, `Coaching Session Tomorrow — ${actLabel}`, emailBody);
                notifyAdmin('Coaching Session Reminder Sent', [['Details', `${actLabel} session on ${dateStr} — ${recipientIds.length} reminder(s) sent.`]]);
                console.log(`⏰ Coaching reminder sent for session ${sess.id} (${recipientIds.length} recipients)`);
            }
        } catch (e) {
            console.error('Coaching reminder scheduler error:', e.message);
        } finally {
            coachingReminderRunning = false;
        }
    }, 5 * 60 * 1000); // Check every 5 minutes

});
