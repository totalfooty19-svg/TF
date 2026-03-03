// TOTAL FOOTY - COMPLETE BACKEND API V2
// Core functionality - Ready to deploy

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

// Twilio WhatsApp setup
const twilio = require('twilio');
const twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);
const TWILIO_WHATSAPP_NUMBER = process.env.TWILIO_WHATSAPP_NUMBER || 'whatsapp:+447864872538';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.connect((err, client, done) => {
    if (err) console.error('❌ Database error:', err);
    else { console.log('✅ Database connected'); done(); }
});

const JWT_SECRET = process.env.JWT_SECRET || 'totalfooty2024SecureRandomString';
const SUPERADMIN_EMAIL = 'totalfooty19@gmail.com';

// ==========================================
// MIDDLEWARE
// ==========================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
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

        // Check if email already exists
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Determine role
        let role = 'player';
        if (email.toLowerCase() === SUPERADMIN_EMAIL) role = 'superadmin';

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

        // Create player - simple insert with just the fields we know exist
        const playerResult = await pool.query(
            `INSERT INTO players (user_id, full_name, first_name, last_name, alias, phone, position, reliability_tier) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'silver') RETURNING id`,
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
        
        // Handle referral: look up referrer by code or direct CLM link
        if (ref) {
            try {
                if (ref.toLowerCase() === 'clm') {
                    // Direct CLM link - just assign CLM badge
                    const clmBadge = await pool.query("SELECT id FROM badges WHERE name = 'CLM'");
                    if (clmBadge.rows.length > 0) {
                        await pool.query(
                            'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                            [playerId, clmBadge.rows[0].id]
                        );
                        console.log('CLM badge assigned via direct link to player ' + playerId);
                    }
                } else {
                    // Look up referrer by code: try players.referral_code first, fall back to referrals table
                    let referrerId = null;
                    const pRef = await pool.query('SELECT id FROM players WHERE referral_code = $1', [ref.toUpperCase()]);
                    if (pRef.rows.length > 0) {
                        referrerId = pRef.rows[0].id;
                    } else {
                        const rRef = await pool.query('SELECT referrer_id FROM referrals WHERE referral_code = $1', [ref.toUpperCase()]);
                        if (rRef.rows.length > 0) referrerId = rRef.rows[0].referrer_id;
                    }
                    
                    if (referrerId) {
                        // Set referred_by on new player
                        await pool.query('UPDATE players SET referred_by = $1 WHERE id = $2', [referrerId, playerId]);
                        console.log('Player ' + playerId + ' referred by ' + referrerId);
                        
                        // CLM badge inheritance: if referrer has CLM badge, new player gets it too
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
                                console.log('CLM badge inherited from referrer ' + referrerId + ' to ' + playerId);
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
    } catch (error) {
        console.error('Registration error:', error);
        console.error('Error message:', error.message);
        res.status(500).json({ 
            error: 'Registration failed', 
            details: error.message 
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const playerResult = await pool.query(
            `SELECT p.*, c.balance as credits,
             (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
              FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
             p.referral_code
             FROM players p 
             LEFT JOIN credits c ON c.player_id = p.id 
             WHERE p.user_id = $1`,
            [user.id]
        );

        const player = playerResult.rows[0];

        const token = jwt.sign(
            { userId: user.id, playerId: player.id, email: user.email, role: user.role, isCLMAdmin: player.is_clm_admin || false, isOrganiser: player.is_organiser || false },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
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
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get current user info (for game.html auth check)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const playerResult = await pool.query(
            `SELECT p.id, p.full_name, p.alias, p.squad_number, u.role,
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
        console.log('Fetching player data for playerId:', req.user.playerId);
        
        // Start with absolute basics
        const result = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.phone
            FROM players p
            WHERE p.id = $1
        `, [req.user.playerId]);
        
        console.log('Query result:', result.rows);
        
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
                    c.balance as credits,
                    u.email
                FROM players p
                LEFT JOIN credits c ON c.player_id = p.id
                LEFT JOIN users u ON u.id = p.user_id
                WHERE p.id = $1
            `, [req.user.playerId]);
            
            if (detailsResult.rows.length > 0) {
                Object.assign(player, detailsResult.rows[0]);
            }
        } catch (detailsError) {
            console.error('Error fetching details:', detailsError.message);
            // Continue with basic info
        }
        
        // Set badges to empty array
        player.badges = [];
        
        console.log('Returning player:', player);
        res.json(player);
    } catch (error) {
        console.error('Error fetching player data:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Failed to fetch player data', 
            details: error.message,
            playerId: req.user?.playerId
        });
    }
});

app.get('/api/players', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                p.reliability_tier, p.total_appearances, p.motm_wins, p.total_wins,
                p.phone, u.email,
                p.is_clm_admin, p.is_organiser,
                c.balance as credits,
                p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                p.goalkeeper_rating,
                (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
                
                -- Last 3 months stats
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id 
                 AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND g.game_date >= NOW() - INTERVAL '3 months') as apps_3m,
                
                (SELECT COUNT(*)
                 FROM games g
                 WHERE g.motm_winner_id = p.id
                 AND g.game_date >= NOW() - INTERVAL '3 months') as motm_3m,
                
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 JOIN team_players tp ON tp.player_id = r.player_id
                 JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                 WHERE r.player_id = p.id
                 AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND LOWER(g.winning_team) = LOWER(t.team_name)
                 AND g.game_date >= NOW() - INTERVAL '3 months') as wins_3m,
                
                -- Calendar year stats
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 WHERE r.player_id = p.id 
                 AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as apps_year,
                
                (SELECT COUNT(*)
                 FROM games g
                 WHERE g.motm_winner_id = p.id
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as motm_year,
                
                (SELECT COUNT(DISTINCT r.game_id)
                 FROM registrations r
                 JOIN games g ON g.id = r.game_id
                 JOIN team_players tp ON tp.player_id = r.player_id
                 JOIN teams t ON t.id = tp.team_id AND t.game_id = g.id
                 WHERE r.player_id = p.id
                 AND r.status = 'confirmed'
                 AND g.game_status = 'completed'
                 AND LOWER(g.winning_team) = LOWER(t.team_name)
                 AND g.game_date >= DATE_TRUNC('year', NOW())) as wins_year
                
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.squad_number NULLS LAST, p.full_name
        `);
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        if (isAdmin) {
            res.json(result.rows);
        } else {
            // Strip sensitive fields for non-admin users
            const safeRows = result.rows.map(p => {
                const { phone, email, credits, is_clm_admin, is_organiser, ...safe } = p;
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
                p.reliability_tier,
                p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                p.goalkeeper_rating,
                p.is_clm_admin, p.is_organiser,
                u.role as user_role,
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
                 AND g.game_date >= DATE_TRUNC('year', NOW())), 0) as clm_revenue_year

            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.squad_number NULLS LAST, p.full_name
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

app.get('/api/players/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.*, c.balance as credits, u.email,
            (SELECT json_agg(json_build_object('id', b.id, 'name', b.name, 'color', b.color, 'icon', b.icon))
             FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges
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
        
        if (isOwnProfile || isAdmin) {
            res.json(player); // Full data
        } else {
            // Public view - limited data
            res.json({
                id: player.id,
                alias: player.alias,
                squad_number: player.squad_number,
                photo_url: player.photo_url,
                total_appearances: player.total_appearances,
                motm_wins: player.motm_wins,
                total_wins: player.total_wins,
                reliability_tier: player.reliability_tier,
                badges: player.badges
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
    try {
        const { fullName, alias, email, phone } = req.body;
        
        // Split name into first and last
        const nameParts = fullName.trim().split(/\s+/);
        const firstName = nameParts[0];
        const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : firstName;
        
        // Update player
        await pool.query(
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
            await pool.query(
                'UPDATE users SET email = $1 WHERE id = $2',
                [email.toLowerCase(), req.user.userId]
            );
        }
        
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Update failed' });
    }
});

// Upload profile photo (base64)
app.post('/api/players/me/photo', authenticateToken, async (req, res) => {
    try {
        const { photoData } = req.body; // Base64 string
        
        if (!photoData) {
            return res.status(400).json({ error: 'No photo data provided' });
        }
        
        // In production, you'd upload to S3/Cloudinary
        // For now, just save the base64 string (not recommended for production)
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
    } catch (error) {
        console.error('Update stats error:', error);
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/admin/players/:id/credits', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const { amount, description } = req.body;
        
        await pool.query(
            'UPDATE credits SET balance = balance + $1, last_updated = CURRENT_TIMESTAMP WHERE player_id = $2',
            [amount, req.params.id]
        );
        
        await pool.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description, admin_id) VALUES ($1, $2, $3, $4, $5)',
            [req.params.id, amount, 'admin_adjustment', description, req.user.userId]
        );
        
        res.json({ message: 'Credits adjusted' });
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
            total_wins, squad_number, phone, balance
        } = req.body;
        
        // Calculate overall rating
        const overall_rating = (defending_rating || 0) + (strength_rating || 0) + (fitness_rating || 0) + 
                              (pace_rating || 0) + (decisions_rating || 0) + (assisting_rating || 0) + (shooting_rating || 0);
        
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
                phone = $12
            WHERE id = $13
        `, [goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            overall_rating, total_wins, squad_number, phone, playerId]);
        
        // Update balance if changed
        if (balance !== undefined) {
            await pool.query('UPDATE credits SET balance = $1 WHERE player_id = $2', [balance, playerId]);
        }
        
        res.json({ message: 'Player updated successfully' });
    } catch (error) {
        console.error('Update player error:', error);
        res.status(500).json({ error: 'Failed to update player' });
    }
});

// Delete player (admin only)
app.delete('/api/admin/players/:playerId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.params;
        
        // Start transaction
        await pool.query('BEGIN');
        
        // Delete player (cascade will handle related records)
        const result = await pool.query('DELETE FROM players WHERE id = $1 RETURNING full_name, alias', [playerId]);
        
        if (result.rows.length === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ error: 'Player not found' });
        }
        
        await pool.query('COMMIT');
        
        res.json({ 
            message: 'Player deleted successfully',
            player: result.rows[0]
        });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Delete player error:', error);
        res.status(500).json({ error: 'Failed to delete player' });
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
    try {
        const { playerId } = req.params;
        const { badgeIds } = req.body;
        
        // Start transaction
        await pool.query('BEGIN');
        
        // Remove all existing badges
        await pool.query('DELETE FROM player_badges WHERE player_id = $1', [playerId]);
        
        // Add new badges
        for (const badgeId of badgeIds) {
            await pool.query(
                'INSERT INTO player_badges (player_id, badge_id) VALUES ($1, $2)',
                [playerId, badgeId]
            );
        }
        
        await pool.query('COMMIT');
        
        res.json({ message: 'Badges updated successfully' });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Update badges error:', error);
        res.status(500).json({ error: 'Failed to update badges' });
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
        }
        
        // Remove "New" badge if no longer applicable
        for (const badgeId of badgesToRemove) {
            await pool.query(
                'DELETE FROM player_badges WHERE player_id = $1 AND badge_id = $2',
                [playerId, badgeId]
            );
        }
        
        return { awarded: badgesToAward.length, removed: badgesToRemove.length };
        
    } catch (error) {
        console.error('Auto allocate badges error:', error);
        return null;
    }
}

async function checkBadgeCriteria(badgeName, player) {
    switch (badgeName) {
        case '50 Apps':
            return player.total_appearances >= 50;
            
        case '100 Apps':
            return player.total_appearances >= 100;
            
        case '250 Apps':
            return player.total_appearances >= 250;
            
        case '500 Apps':
            return player.total_appearances >= 500;
            
        case '5 MOTM':
            return player.motm_wins >= 5;
            
        case '15 MOTM':
            return player.motm_wins >= 15;
            
        case '30 MOTM':
            return player.motm_wins >= 30;
            
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

// Bulk upload / update players from CSV
app.post('/api/admin/players/bulk-upload', authenticateToken, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { players } = req.body;
        
        if (!players || !Array.isArray(players) || players.length === 0) {
            return res.status(400).json({ error: 'No player data provided' });
        }
        
        await client.query('BEGIN');
        
        let created = 0;
        let updated = 0;
        let errors = [];
        
        for (const p of players) {
            try {
                const name = (p.name || '').trim();
                if (!name) {
                    errors.push(`Skipped empty row`);
                    continue;
                }
                
                // Parse ratings (Mental = decisions_rating)
                const defending = parseInt(p.defence) || 0;
                const strength = parseInt(p.strength) || 0;
                const pace = parseInt(p.pace) || 0;
                const fitness = parseInt(p.fitness) || 0;
                const decisions = parseInt(p.mental) || 0;
                const assisting = parseInt(p.assisting) || 0;
                const shooting = parseInt(p.shooting) || 0;
                const goalkeeper = parseInt(p.gk) || 0;
                const overall = defending + strength + pace + fitness + decisions + assisting + shooting;
                const credits = parseFloat(p.credits) || 0;
                const tier = (p.tier || 'silver').toLowerCase();
                const position = (p.position || 'outfield').toLowerCase();
                
                // Try to find existing player by full_name
                const existing = await client.query(
                    'SELECT id FROM players WHERE LOWER(full_name) = LOWER($1)',
                    [name]
                );
                
                if (existing.rows.length > 0) {
                    // Update existing player
                    const playerId = existing.rows[0].id;
                    await client.query(`
                        UPDATE players SET
                            defending_rating = $1, strength_rating = $2, pace_rating = $3,
                            fitness_rating = $4, decisions_rating = $5, assisting_rating = $6,
                            shooting_rating = $7, goalkeeper_rating = $8, overall_rating = $9,
                            reliability_tier = $10, position = $11
                        WHERE id = $12
                    `, [defending, strength, pace, fitness, decisions, assisting, shooting,
                        goalkeeper, overall, tier, position, playerId]);
                    
                    // Update credits
                    await client.query(
                        'UPDATE credits SET balance = $1 WHERE player_id = $2',
                        [credits, playerId]
                    );
                    
                    updated++;
                } else {
                    // Create new user + player
                    const nameParts = name.split(/\s+/);
                    const firstName = nameParts[0];
                    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : firstName;
                    const safeEmail = name.toLowerCase().replace(/[^a-z0-9]/g, '.') + '@totalfooty.import';
                    const tempPassword = await bcrypt.hash('TotalFooty2026!', 10);
                    
                    const userResult = await client.query(
                        'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
                        [safeEmail, tempPassword, 'player']
                    );
                    
                    const playerResult = await client.query(`
                        INSERT INTO players (user_id, full_name, first_name, last_name, alias, position,
                            defending_rating, strength_rating, pace_rating, fitness_rating,
                            decisions_rating, assisting_rating, shooting_rating, goalkeeper_rating,
                            overall_rating, reliability_tier)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                        RETURNING id
                    `, [userResult.rows[0].id, name, firstName, lastName, firstName, position,
                        defending, strength, pace, fitness, decisions, assisting, shooting,
                        goalkeeper, overall, tier]);
                    
                    await client.query(
                        'INSERT INTO credits (player_id, balance) VALUES ($1, $2)',
                        [playerResult.rows[0].id, credits]
                    );
                    
                    // Generate referral code
                    const referralCode = 'TF' + crypto.randomBytes(4).toString('hex').toUpperCase();
                    await client.query(
                        'UPDATE players SET referral_code = $1 WHERE id = $2',
                        [referralCode, playerResult.rows[0].id]
                    );
                    
                    created++;
                }
            } catch (rowError) {
                errors.push(`${p.name || 'Unknown'}: ${rowError.message}`);
            }
        }
        
        await client.query('COMMIT');
        
        res.json({
            message: `Import complete: ${created} created, ${updated} updated`,
            created,
            updated,
            errors: errors.length > 0 ? errors : undefined
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Bulk upload error:', error);
        res.status(500).json({ error: 'Bulk upload failed: ' + error.message });
    } finally {
        client.release();
    }
});

// ==========================================
// WHATSAPP SERVICE
// ==========================================

// Helper function to replace placeholders in message templates
function replacePlaceholders(template, data) {
    let message = template;
    
    // Replace all placeholders with actual data
    message = message.replace(/\[Name\]/g, data.name || '');
    message = message.replace(/\[Day\]/g, data.day || '');
    message = message.replace(/\[Time\]/g, data.time || '');
    message = message.replace(/\[Venue\]/g, data.venue || '');
    message = message.replace(/\[gameurl\]/g, data.gameurl || '');
    message = message.replace(/\[Balance\]/g, data.balance || '0.00');
    message = message.replace(/\[generic_game_url\]/g, data.generic_game_url || 'https://totalfooty.co.uk/vibecoding/');
    message = message.replace(/\[profile_url\]/g, data.profile_url || 'https://totalfooty.co.uk/vibecoding/');
    
    return message;
}

// Helper function to format game data for WhatsApp messages
async function getGameDataForMessage(gameId) {
    const gameResult = await pool.query(`
        SELECT g.*, v.name as venue_name, g.game_url
        FROM games g
        LEFT JOIN venues v ON v.id = g.venue_id
        WHERE g.id = $1
    `, [gameId]);
    
    if (gameResult.rows.length === 0) return null;
    
    const game = gameResult.rows[0];
    const gameDate = new Date(game.game_date);
    
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const day = days[gameDate.getDay()];
    
    const hours = gameDate.getHours().toString().padStart(2, '0');
    const minutes = gameDate.getMinutes().toString().padStart(2, '0');
    const time = `${hours}:${minutes}`;
    
    const gameurl = `https://totalfooty.co.uk/vibecoding/game.html?url=${game.game_url}`;
    
    return {
        day,
        time,
        venue: game.venue_name,
        gameurl
    };
}

// Send WhatsApp message via Twilio
async function sendWhatsAppMessage(playerPhone, message, notificationType, playerId = null) {
    try {
        // Format phone number to E.164 format
        let formattedPhone = playerPhone.replace(/\s+/g, '');
        if (!formattedPhone.startsWith('+')) {
            if (formattedPhone.startsWith('0')) {
                formattedPhone = '+44' + formattedPhone.substring(1);
            } else if (formattedPhone.startsWith('44')) {
                formattedPhone = '+' + formattedPhone;
            } else {
                formattedPhone = '+44' + formattedPhone;
            }
        }
        
        const twilioMessage = await twilioClient.messages.create({
            body: message,
            from: TWILIO_WHATSAPP_NUMBER,
            to: `whatsapp:${formattedPhone}`
        });
        
        // Log successful send
        await pool.query(`
            INSERT INTO whatsapp_logs (player_id, notification_type, phone_number, message_content, status, twilio_sid)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [playerId, notificationType, formattedPhone, message, 'sent', twilioMessage.sid]);
        
        return { success: true, sid: twilioMessage.sid };
        
    } catch (error) {
        console.error('WhatsApp send error:', error);
        
        // Log failed send
        await pool.query(`
            INSERT INTO whatsapp_logs (player_id, notification_type, phone_number, message_content, status, error_message)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [playerId, notificationType, playerPhone, message, 'failed', error.message]);
        
        return { success: false, error: error.message };
    }
}

// Send notification based on type
async function sendNotification(notificationType, playerId, additionalData = {}) {
    try {
        // Get player data
        const playerResult = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.phone, c.balance as credits
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            WHERE p.id = $1
        `, [playerId]);
        
        if (playerResult.rows.length === 0) {
            return { success: false, error: 'Player not found' };
        }
        
        const player = playerResult.rows[0];
        
        if (!player.phone) {
            return { success: false, error: 'Player has no phone number' };
        }
        
        // Get message template
        const templateResult = await pool.query(`
            SELECT message_template 
            FROM whatsapp_templates 
            WHERE notification_type = $1 AND is_active = TRUE
        `, [notificationType]);
        
        if (templateResult.rows.length === 0) {
            return { success: false, error: 'Message template not found' };
        }
        
        const template = templateResult.rows[0].message_template;
        
        // Prepare data for placeholder replacement
        const messageData = {
            name: player.alias || player.full_name,
            balance: player.credits ? parseFloat(player.credits).toFixed(2) : '0.00',
            generic_game_url: 'https://totalfooty.co.uk/vibecoding/',
            profile_url: 'https://totalfooty.co.uk/vibecoding/',
            ...additionalData
        };
        
        // Replace placeholders
        const message = replacePlaceholders(template, messageData);
        
        // Send message
        return await sendWhatsAppMessage(player.phone, message, notificationType, playerId);
        
    } catch (error) {
        console.error('Send notification error:', error);
        return { success: false, error: error.message };
    }
}

// ==========================================
// DISCIPLINE SYSTEM
// ==========================================

// Add discipline points
app.post('/api/admin/discipline', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId, gameId, points, reason } = req.body;
        
        // Add discipline record
        await pool.query(
            `INSERT INTO discipline_records (player_id, game_id, points, reason, recorded_by)
             VALUES ($1, $2, $3, $4, $5)`,
            [playerId, gameId, points, reason, req.user.userId]
        );
        
        // Tier is auto-updated by database trigger
        
        res.json({ message: 'Discipline points added. Tier updated automatically.' });
    } catch (error) {
        console.error('Add discipline error:', error);
        res.status(500).json({ error: 'Failed to add discipline points' });
    }
});

// Get player discipline history
app.get('/api/players/:playerId/discipline', authenticateToken, async (req, res) => {
    try {
        const { playerId } = req.params;
        
        // Get last 10 games worth of discipline
        const result = await pool.query(`
            SELECT 
                dr.id,
                dr.points,
                dr.reason,
                dr.recorded_at,
                g.game_date,
                g.format,
                v.name as venue_name,
                admin.email as recorded_by_email
            FROM discipline_records dr
            JOIN games g ON g.id = dr.game_id
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN users admin ON admin.id = dr.recorded_by
            WHERE dr.player_id = $1
            ORDER BY g.game_date DESC
            LIMIT 10
        `, [playerId]);
        
        // Calculate current points
        const pointsSum = result.rows.reduce((sum, r) => sum + (r.points || 0), 0);
        
        // Get current tier
        const tierResult = await pool.query(
            'SELECT reliability_tier FROM players WHERE id = $1',
            [playerId]
        );
        
        res.json({
            records: result.rows,
            totalPoints: pointsSum,
            currentTier: tierResult.rows[0]?.reliability_tier || 'silver',
            nextTierAt: getNextTierThreshold(pointsSum)
        });
    } catch (error) {
        console.error('Get discipline error:', error);
        res.status(500).json({ error: 'Failed to fetch discipline history' });
    }
});

// Helper function
function getNextTierThreshold(currentPoints) {
    if (currentPoints === 0) return { points: 1, tier: 'silver', direction: 'down' };
    if (currentPoints <= 3) return { points: 0, tier: 'gold', direction: 'up' };
    if (currentPoints <= 6) return { points: 3, tier: 'silver', direction: 'up' };
    if (currentPoints <= 11) return { points: 6, tier: 'bronze', direction: 'up' };
    return { points: 11, tier: 'white', direction: 'up' };
}

// Recalculate all player tiers (admin utility)
app.post('/api/admin/recalculate-tiers', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const playersResult = await pool.query('SELECT id FROM players');
        
        for (const player of playersResult.rows) {
            const tierResult = await pool.query(
                'SELECT calculate_player_tier($1) as new_tier',
                [player.id]
            );
            
            const newTier = tierResult.rows[0].new_tier;
            
            await pool.query(
                'UPDATE players SET reliability_tier = $1 WHERE id = $2',
                [newTier, player.id]
            );
        }
        
        res.json({ message: `Recalculated tiers for ${playersResult.rows.length} players` });
    } catch (error) {
        console.error('Recalculate tiers error:', error);
        res.status(500).json({ error: 'Failed to recalculate tiers' });
    }
});

// Continuing in next message due to length...

// ==========================================
// ==========================================
// VENUES
// ==========================================

app.get('/api/venues', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT DISTINCT ON (name) id, name, address, postcode FROM venues ORDER BY name, id');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching venues:', error);
        res.status(500).json({ error: 'Failed to fetch venues' });
    }
});

// GAMES
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
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'backup') as backup_count,
                   EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1) as is_registered,
                   (SELECT status FROM registrations WHERE game_id = g.id AND player_id = $1) as my_status,
                   (SELECT backup_type FROM registrations WHERE game_id = g.id AND player_id = $1) as my_backup_type,
                   motm_p.alias as motm_winner_alias, motm_p.full_name as motm_winner_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
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
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name,
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   p.full_name as motm_winner_name,
                   p.alias as motm_winner_alias
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN players p ON p.id = g.motm_winner_id
            WHERE g.game_status = 'completed'
            ORDER BY g.game_date DESC
        `);
        
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
                   ((SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') + (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed' AND UPPER(TRIM(position_preference)) = 'GK') as gk_count
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [req.params.id]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        game.max_gk_slots = game.team_selection_type === 'vs_external' ? 1 : 2;
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
            'Sidney Stringer': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg',
            'Sidney Stringer Academy': 'https://totalfooty.co.uk/assets/sidney_stringer.jpg'
        };
        
        if (game.venue_name && venuePhotoMap[game.venue_name]) {
            game.venue_photo = venuePhotoMap[game.venue_name];
        }
        
        // Check if current user has a +1 guest on this game
        if (req.user && req.user.playerId) {
            try {
                const guestCheck = await pool.query(
                    'SELECT id, guest_name FROM game_guests WHERE game_id = $1 AND invited_by = $2',
                    [req.params.id, req.user.playerId]
                );
                game.my_guest = guestCheck.rows.length > 0 ? guestCheck.rows[0] : null;
            } catch (guestErr) {
                game.my_guest = null; // Table may not exist yet
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
            exclusivity, positionType, teamSelectionType, externalOpponent, tfKitColor, oppKitColor 
        } = req.body;
        
        // CLM admins can only create CLM-exclusive games
        const isCLMAdminOnly = req.user.role !== 'admin' && req.user.role !== 'superadmin';
        const gameExclusivity = isCLMAdminOnly ? 'clm' : (exclusivity || 'everyone');
        
        const createdGames = [];
        
        if (regularity === 'weekly') {
            // Generate series ID (e.g., "TF0001")
            const countResult = await pool.query('SELECT COUNT(*) FROM game_series');
            const seriesCount = parseInt(countResult.rows[0].count) + 1;
            const seriesIdValue = `TF${String(seriesCount).padStart(4, '0')}`;
            
            // Create series record for draft_memory and vs_external games
            let seriesUuid = null;
            const selType = teamSelectionType || 'normal';
            if (selType === 'draft_memory' || selType === 'vs_external') {
                const seriesResult = await pool.query(
                    'INSERT INTO game_series (series_name, series_type) VALUES ($1, $2) RETURNING id',
                    [seriesIdValue, selType]
                );
                seriesUuid = seriesResult.rows[0].id;
            }
            
            // Create 26 weeks of games (6 months)
            for (let week = 0; week < 26; week++) {
                const weekDate = new Date(gameDate);
                weekDate.setDate(weekDate.getDate() + (week * 7));
                
                const gameUrl = crypto.randomBytes(6).toString('hex');
                const gameNumber = String(week + 1).padStart(2, '0');
                const fullSeriesId = `${seriesIdValue}-${gameNumber}`; // e.g., "TF0001-01"
                
                const result = await pool.query(
                    `INSERT INTO games (
                        venue_id, game_date, max_players, cost_per_player, format, regularity, 
                        exclusivity, position_type, game_url, series_id, 
                        team_selection_type, external_opponent, tf_kit_color, opp_kit_color
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    RETURNING id`,
                    [
                        venueId, weekDate.toISOString(), maxPlayers, costPerPlayer, format, 'weekly', 
                        gameExclusivity, positionType || 'outfield_gk', gameUrl, 
                        seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null
                    ]
                );
                
                createdGames.push({ id: result.rows[0].id, gameUrl, date: weekDate, seriesId: fullSeriesId });
            }
            
            res.json({ 
                message: `Created 26 weekly games (series ${seriesIdValue})`,
                seriesId: seriesIdValue,
                games: createdGames 
            });
        } else {
            // Create single one-off game
            const gameUrl = crypto.randomBytes(6).toString('hex');
            const selType = teamSelectionType || 'normal';
            
            // Create series record for one-off draft_memory or vs_external (for scoreline tracking)
            let seriesUuid = null;
            if (selType === 'draft_memory' || selType === 'vs_external') {
                const countResult = await pool.query('SELECT COUNT(*) FROM game_series');
                const seriesCount = parseInt(countResult.rows[0].count) + 1;
                const seriesIdValue = `TF${String(seriesCount).padStart(4, '0')}`;
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
                    team_selection_type, external_opponent, tf_kit_color, opp_kit_color
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                RETURNING id`,
                [
                    venueId, gameDate, maxPlayers, costPerPlayer, format, 'one-off', 
                    gameExclusivity, positionType || 'outfield_gk', gameUrl,
                    seriesUuid, selType, externalOpponent || null, tfKitColor || null, oppKitColor || null
                ]
            );
            
            res.json({ id: result.rows[0].id, gameUrl });
        }
    } catch (error) {
        console.error('Create game error:', error);
        res.status(500).json({ error: 'Failed to create game', details: error.message });
    }
});

// Get players registered for a specific game
app.get('/api/games/:id/players', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.id as player_id,
                p.full_name,
                p.alias,
                p.squad_number,
                r.position_preference as positions,
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY p.id, p.full_name, p.alias, p.squad_number, r.position_preference
            ORDER BY p.squad_number NULLS LAST, p.alias
        `, [req.params.id]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Get game players error:', error);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

app.post('/api/games/:id/register', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const { position, positions, pairs, avoids, backupType } = req.body;
        const gameId = req.params.id;
        const positionValue = positions || position || 'outfield';
        
        await client.query('BEGIN');
        
        // Lock the game row to prevent race conditions
        const gameLock = await client.query(`
            SELECT max_players, cost_per_player, exclusivity, 
                   player_editing_locked, team_selection_type, position_type
            FROM games
            WHERE id = $1
            FOR UPDATE
        `, [gameId]);
        
        if (gameLock.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameLock.rows[0];
        
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
                await client.query('ROLLBACK');
                return res.status(403).json({ 
                    error: 'This is a CLM exclusive game. You need the CLM badge to register.',
                    requiresBadge: 'CLM'
                });
            }
        }
        
        if (game.exclusivity === 'misfits') {
            const badgeCheck = await client.query(`
                SELECT 1 FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'Misfits'
            `, [req.user.playerId]);
            
            if (badgeCheck.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(403).json({ 
                    error: 'This is a Misfits game. You need the Misfits badge to register.',
                    requiresBadge: 'Misfits'
                });
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
            const maxGKSlots = game.team_selection_type === 'vs_external' ? 1 : 2;
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
            
            // For confirmed backup, deduct credits immediately
            if (backupType === 'confirmed_backup') {
                const creditResult = await client.query(
                    'SELECT balance FROM credits WHERE player_id = $1',
                    [req.user.playerId]
                );
                
                if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < parseFloat(game.cost_per_player)) {
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
        } else {
            // Game has space - confirm registration
            status = 'confirmed';
            
            // Deduct credits
            const creditResult = await client.query(
                'SELECT balance FROM credits WHERE player_id = $1',
                [req.user.playerId]
            );
            
            if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < parseFloat(game.cost_per_player)) {
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
        
        // Register player
        const regResult = await client.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference, backup_type)
             VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [gameId, req.user.playerId, status, positionValue, regBackupType]
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
        
        // Build response
        let message;
        if (status === 'confirmed') {
            message = 'Registered successfully';
        } else if (regBackupType === 'confirmed_backup') {
            message = `You're on the confirmed backup list. £${parseFloat(game.cost_per_player).toFixed(2)} has been deducted and you'll be first in line if a spot opens. If you don't get on, you'll be refunded after the game.`;
        } else if (regBackupType === 'gk_backup') {
            message = "You're on the GK backup list. You'll be notified if a GK spot becomes available.";
        } else {
            message = "You're on the backup list. You'll be notified if a space becomes available.";
        }
        
        res.json({ message, status, backupType: regBackupType });
        
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
        const { guestName } = req.body;
        const playerId = req.user.playerId;

        if (!guestName || guestName.trim().length < 2) {
            client.release();
            return res.status(400).json({ error: "Please provide the guest's name (at least 2 characters)" });
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

        // Check player hasn't already added a guest to this game
        const existingGuest = await client.query(
            'SELECT id FROM game_guests WHERE game_id = $1 AND invited_by = $2',
            [gameId, playerId]
        );
        if (existingGuest.rows.length > 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(400).json({ error: 'You have already added a +1 to this game' });
        }

        // Lock game row and check capacity
        const gameLock = await client.query(
            'SELECT max_players, cost_per_player, player_editing_locked FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        if (gameLock.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameLock.rows[0];

        if (game.player_editing_locked) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(423).json({ error: 'Game is currently being edited by an admin. Please try again shortly.' });
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
            return res.status(400).json({ error: 'Game is full - no space for a +1' });
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
            return res.status(400).json({ error: `Insufficient credits. You need ${cost.toFixed(2)} to add a +1.` });
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

        // Get player's overall rating, guest gets -1
        const playerRating = await client.query(
            'SELECT overall_rating FROM players WHERE id = $1',
            [playerId]
        );
        const guestRating = Math.max(0, (playerRating.rows[0]?.overall_rating || 0) - 1);

        // Insert guest record
        await client.query(
            `INSERT INTO game_guests (game_id, invited_by, guest_name, overall_rating, amount_paid)
             VALUES ($1, $2, $3, $4, $5)`,
            [gameId, playerId, guestName.trim(), guestRating, cost]
        );

        // Get player's referral code for the refer-a-friend prompt
        const refResult = await client.query(
            'SELECT referral_code FROM players WHERE id = $1',
            [playerId]
        );
        const referralCode = refResult.rows[0]?.referral_code;

        await client.query('COMMIT');

        res.json({
            message: `${guestName.trim()} has been added as your +1!`,
            guestRating,
            amountCharged: cost,
            referralLink: referralCode ? `https://totalfooty.co.uk/vibecoding/register.html?ref=${referralCode}` : null,
            referralPrompt: 'Refer a friend for future rewards as they join and play with Total Footy! Here is your personalised link - send it to them now!'
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

        // Find and delete guest
        const guestResult = await client.query(
            'DELETE FROM game_guests WHERE game_id = $1 AND invited_by = $2 RETURNING guest_name, amount_paid',
            [gameId, playerId]
        );
        if (guestResult.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(404).json({ error: 'No +1 guest found for this game' });
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
                [playerId, refundAmt, 'refund', `+1 guest (${guest.guest_name}) removed - refund`]
            );
        }

        await client.query('COMMIT');

        res.json({
            message: `${guest.guest_name} removed. ${refundAmt.toFixed(2)} refunded to your balance.`
        });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Remove guest error:', error);
        res.status(500).json({ error: 'Failed to remove guest' });
    } finally {
        client.release();
    }
});

// Check GK slot availability for a game
app.get('/api/games/:id/gk-slots', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        
        const result = await pool.query(`
            SELECT g.team_selection_type,
                   COUNT(r.id) FILTER (WHERE r.status = 'confirmed' AND UPPER(TRIM(r.position_preference)) = 'GK') as gk_count
            FROM games g
            LEFT JOIN registrations r ON r.game_id = g.id
            WHERE g.id = $1
            GROUP BY g.id
        `, [gameId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const maxGKSlots = result.rows[0].team_selection_type === 'vs_external' ? 1 : 2;
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
app.post('/api/games/:id/drop-out', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        const gameId = req.params.id;
        
        await client.query('BEGIN');
        
        // Lock the game row
        const gameCheck = await client.query(
            'SELECT player_editing_locked, teams_generated, cost_per_player, team_selection_type FROM games WHERE id = $1 FOR UPDATE',
            [gameId]
        );
        
        if (gameCheck.rows[0]?.player_editing_locked) {
            await client.query('ROLLBACK');
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        if (gameCheck.rows[0]?.teams_generated) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Cannot drop out - teams already generated' });
        }
        
        const cost = parseFloat(gameCheck.rows[0].cost_per_player);
        
        // Get the dropping player's registration
        const regResult = await client.query(
            'SELECT id, status, backup_type, position_preference FROM registrations WHERE game_id = $1 AND player_id = $2',
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
        
        // Refund if they paid (confirmed players or confirmed backups)
        if (wasConfirmed || wasConfirmedBackup) {
            await client.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [cost, req.user.playerId]
            );
            
            await client.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [req.user.playerId, cost, 'refund', `Dropped out of game - refund`]
            );
        }
        
        // Remove guest if this player had a +1, and refund the guest fee
        const guestCheck = await client.query(
            'DELETE FROM game_guests WHERE game_id = $1 AND invited_by = $2 RETURNING guest_name, amount_paid',
            [gameId, req.user.playerId]
        );
        let guestRefunded = null;
        if (guestCheck.rows.length > 0) {
            const guestRefundAmt = parseFloat(guestCheck.rows[0].amount_paid || 0);
            if (guestRefundAmt > 0) {
                await client.query(
                    'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                    [guestRefundAmt, req.user.playerId]
                );
                await client.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                    [req.user.playerId, guestRefundAmt, 'refund', '+1 guest removed - dropout refund']
                );
            }
            guestRefunded = { name: guestCheck.rows[0].guest_name, amount: guestRefundAmt };
        }
        
        // Delete registration (cascade deletes preferences)
        await client.query('DELETE FROM registrations WHERE id = $1', [droppingReg.id]);
        
        // If a confirmed player dropped out, try to promote a backup
        let promotedPlayer = null;
        if (wasConfirmed) {
            // If a GK dropped out, first check for GK backups
            if (wasGKOnly) {
                const gkBackup = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'gk_backup'
                    ORDER BY r.registered_at ASC
                    LIMIT 1
                `, [gameId]);
                
                if (gkBackup.rows.length > 0) {
                    promotedPlayer = gkBackup.rows[0];
                }
            }
            
            // If no GK backup was promoted, check confirmed backups (first come first served)
            if (!promotedPlayer) {
                const confirmedBackup = await client.query(`
                    SELECT r.id, r.player_id, r.backup_type, p.full_name, p.alias
                    FROM registrations r
                    JOIN players p ON p.id = r.player_id
                    WHERE r.game_id = $1 AND r.status = 'backup' AND r.backup_type = 'confirmed_backup'
                    ORDER BY r.registered_at ASC
                    LIMIT 1
                `, [gameId]);
                
                if (confirmedBackup.rows.length > 0) {
                    promotedPlayer = confirmedBackup.rows[0];
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
        
        await client.query('COMMIT');
        
        let message = wasConfirmed || wasConfirmedBackup 
            ? `Successfully dropped out. £${cost.toFixed(2)} refunded to your balance.`
            : 'Successfully removed from backup list.';
            
        if (promotedPlayer) {
            message += ` ${promotedPlayer.alias || promotedPlayer.full_name} has been promoted from the backup list.`;
        }
        
        res.json({ message, promotedPlayer: promotedPlayer ? { name: promotedPlayer.alias || promotedPlayer.full_name } : null });
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
    try {
        const gameId = req.params.id;
        const { positions, pairs, avoids } = req.body;
        
        // Get registration
        const regResult = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (regResult.rows.length === 0) {
            return res.status(404).json({ error: 'Not registered for this game' });
        }
        
        const registrationId = regResult.rows[0].id;
        
        // Update positions
        await pool.query(
            'UPDATE registrations SET position_preference = $1 WHERE id = $2',
            [positions, registrationId]
        );
        
        // Delete old preferences
        await pool.query('DELETE FROM registration_preferences WHERE registration_id = $1', [registrationId]);
        
        // Add new pairs
        if (pairs && pairs.length > 0) {
            for (const pairPlayerId of pairs) {
                await pool.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        
        // Add new avoids
        if (avoids && avoids.length > 0) {
            for (const avoidPlayerId of avoids) {
                await pool.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid')`,
                    [registrationId, avoidPlayerId]
                );
            }
        }
        
        res.json({ message: 'Preferences updated successfully' });
    } catch (error) {
        console.error('Update preferences error:', error);
        res.status(500).json({ error: 'Failed to update preferences' });
    }
});

// Generate teams with algorithm
app.post('/api/admin/games/:gameId/generate-teams', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
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
                p.fitness_rating,
                r.position_preference,
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pairs,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoids
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY r.id, p.id, p.full_name, p.alias, p.squad_number, p.overall_rating, p.goalkeeper_rating, p.defending_rating, p.fitness_rating, r.position_preference
            ORDER BY p.overall_rating DESC
        `, [gameId]);
        
        const players = playersResult.rows;
        
        // Also fetch +1 guests for this game
        const guestsResult = await pool.query(`
            SELECT g.id as guest_id, g.guest_name, g.overall_rating, g.invited_by
            FROM game_guests g
            WHERE g.game_id = $1
        `, [gameId]);
        
        // Merge guests into player pool (as outfield, no preferences)
        for (const guest of guestsResult.rows) {
            players.push({
                reg_id: null,
                player_id: `guest_${guest.guest_id}`,
                full_name: guest.guest_name,
                alias: `${guest.guest_name} (+1)`,
                squad_number: null,
                overall_rating: guest.overall_rating || 0,
                goalkeeper_rating: 0,
                defending_rating: 0,
                fitness_rating: 0,
                position_preference: 'outfield',
                pairs: [guest.invited_by],  // pair guest with their inviter
                avoids: [],
                is_guest: true
            });
        }
        
        if (players.length < 2) {
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
        
        // ALGORITHM - PRIORITY ORDER
        const redTeam = [];
        const blueTeam = [];
        
        // PRIORITY 1: Assign 1 GK to each team
        const goalkeepers = players.filter(p => p.position_preference?.toLowerCase().includes('gk'));
        const outfield = players.filter(p => !p.position_preference?.toLowerCase().includes('gk'));
        
        if (goalkeepers.length >= 1) redTeam.push(goalkeepers[0]);
        if (goalkeepers.length >= 2) blueTeam.push(goalkeepers[1]);
        if (goalkeepers.length >= 3) outfield.push(...goalkeepers.slice(2)); // Extra GKs as outfield
        
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
        
        // Allocate outfield players
        console.log(`Starting allocation for ${outfield.length} outfield players`);
        console.log(`Red starts with ${redTeam.length}, Blue starts with ${blueTeam.length}`);
        
        for (const player of outfield) {
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
        
        // Calculate stats
        const redStats = {
            overall: redTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0),
            defense: redTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0),
            fitness: redTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0)
        };
        
        const blueStats = {
            overall: blueTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0),
            defense: blueTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0),
            fitness: blueTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0)
        };
        
        res.json({
            message: 'Teams generated successfully',
            redTeam: redTeam.map(p => ({
                id: p.player_id,
                name: p.alias || p.full_name,
                squadNumber: p.squad_number,
                overall: p.overall_rating,
                defense: p.defending_rating || 0,
                fitness: p.fitness_rating || 0,
                isGK: p.position_preference?.toLowerCase().includes('gk')
            })),
            blueTeam: blueTeam.map(p => ({
                id: p.player_id,
                name: p.alias || p.full_name,
                squadNumber: p.squad_number,
                overall: p.overall_rating,
                defense: p.defending_rating || 0,
                fitness: p.fitness_rating || 0,
                isGK: p.position_preference?.toLowerCase().includes('gk')
            })),
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
    } catch (error) {
        console.error('Generate teams error:', error);
        res.status(500).json({ error: 'Failed to generate teams', details: error.message });
    }
});

// Delete single game with refunds (transaction-protected)
app.delete('/api/admin/games/:gameId', authenticateToken, requireCLMAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        await client.query('BEGIN');
        const registrations = await client.query(
            `SELECT player_id, status, backup_type, amount_paid FROM registrations WHERE game_id = $1 AND (status = 'confirmed' OR (status = 'backup' AND backup_type = 'confirmed_backup'))`,
            [gameId]
        );
        const gameResult = await client.query('SELECT cost_per_player FROM games WHERE id = $1', [gameId]);
        const fallbackCost = parseFloat(gameResult.rows[0]?.cost_per_player || 0);
        let totalRefunded = 0;
        for (const reg of registrations.rows) {
            const refundAmt = parseFloat(reg.amount_paid || fallbackCost);
            if (refundAmt > 0) {
                await client.query('UPDATE credits SET balance = balance + $1 WHERE player_id = $2', [refundAmt, reg.player_id]);
                await client.query('INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)', [reg.player_id, refundAmt, 'refund', 'Game cancelled - refund']);
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
        await client.query('DELETE FROM games WHERE id = $1', [gameId]);
        await client.query('COMMIT');
        res.json({ message: 'Game deleted. Refunded ' + totalRefunded + ' players and ' + guests.rows.length + ' guest fees.' });
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
                `SELECT player_id, amount_paid FROM registrations WHERE game_id = $1 
                 AND (status = 'confirmed' OR (status = 'backup' AND backup_type = 'confirmed_backup'))`,
                [gid]
            );
            for (const reg of registrations.rows) {
                const refundAmt = parseFloat(reg.amount_paid || cost);
                if (refundAmt > 0) {
                    await client.query(
                        'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                        [refundAmt, reg.player_id]
                    );
                    await client.query(
                        'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                        [reg.player_id, refundAmt, 'refund', 'Series ' + seriesName + ' cancelled - refund']
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
        
        // Delete only FUTURE games in series (cascade handles registrations + game_guests)
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

// Update game settings (venue, max players, price)
app.put('/api/admin/games/:gameId/settings', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { game_date, venue_id, max_players, cost_per_player } = req.body;
        
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
        
        // Update the game (include game_date if provided)
        if (game_date) {
            await pool.query(`
                UPDATE games 
                SET game_date = $1,
                    venue_id = $2, 
                    max_players = $3, 
                    cost_per_player = $4
                WHERE id = $5
            `, [game_date, venue_id, max_players, cost_per_player, gameId]);
            
            res.json({ 
                message: 'Game settings updated successfully',
                updated: { game_date, venue_id, max_players, cost_per_player }
            });
        } else {
            await pool.query(`
                UPDATE games 
                SET venue_id = $1, 
                    max_players = $2, 
                    cost_per_player = $3
                WHERE id = $4
            `, [venue_id, max_players, cost_per_player, gameId]);
            
            res.json({ 
                message: 'Game settings updated successfully',
                updated: { venue_id, max_players, cost_per_player }
            });
        }
        
    } catch (error) {
        console.error('Update game settings error:', error);
        res.status(500).json({ error: 'Failed to update game settings' });
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
    try {
        const { gameId } = req.params;
        const { redTeam, blueTeam } = req.body;
        
        // Get game info
        const gameResult = await pool.query('SELECT series_id, team_selection_type FROM games WHERE id = $1', [gameId]);
        const game = gameResult.rows[0];
        
        if ((game.team_selection_type === 'fixed_draft' || game.team_selection_type === 'draft_memory' || game.team_selection_type === 'vs_external') && game.series_id) {
            // Save fixed team assignments for the series
            for (const playerId of redTeam) {
                await pool.query(`
                    INSERT INTO player_fixed_teams (player_id, series_id, fixed_team)
                    VALUES ($1, $2, 'red')
                    ON CONFLICT (player_id, series_id) DO UPDATE SET fixed_team = 'red'
                `, [playerId, game.series_id]);
            }
            
            for (const playerId of blueTeam) {
                await pool.query(`
                    INSERT INTO player_fixed_teams (player_id, series_id, fixed_team)
                    VALUES ($1, $2, 'blue')
                    ON CONFLICT (player_id, series_id) DO UPDATE SET fixed_team = 'blue'
                `, [playerId, game.series_id]);
            }
        }
        
        // Create/update teams for this specific game
        await pool.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        await pool.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
        
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
        
        // Add players to teams
        for (const playerId of redTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [redTeamId, playerId]
            );
        }
        
        for (const playerId of blueTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [blueTeamId, playerId]
            );
        }
        
        // Mark teams as generated and confirmed
        await pool.query(
            'UPDATE games SET teams_generated = true, teams_confirmed = true, game_status = $1 WHERE id = $2',
            ['confirmed', gameId]
        );
        
        // Get full game details for response
        const fullGameResult = await pool.query(`
            SELECT g.*, v.name as venue_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [gameId]);
        
        res.json({ 
            message: 'Teams saved successfully',
            game: fullGameResult.rows[0]
        });
    } catch (error) {
        console.error('Save manual teams error:', error);
        res.status(500).json({ error: 'Failed to save manual teams' });
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
        
        // Insert red team players
        for (const playerId of redTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [redTeamId, playerId]
            );
        }
        
        // Insert blue team players
        for (const playerId of blueTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [blueTeamId, playerId]
            );
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
        
        // Get team IDs
        const teamsResult = await pool.query(
            'SELECT id, team_name FROM teams WHERE game_id = $1 ORDER BY team_name',
            [gameId]
        );
        
        if (teamsResult.rows.length === 0) {
            return res.status(404).json({ error: 'Teams not found' });
        }
        
        const redTeamId = teamsResult.rows.find(t => t.team_name === 'Red')?.id;
        const blueTeamId = teamsResult.rows.find(t => t.team_name === 'Blue')?.id;
        
        // Get players for each team
        const [redTeamResult, blueTeamResult] = await Promise.all([
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                WHERE tp.team_id = $1
                ORDER BY p.full_name
            `, [redTeamId]),
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                WHERE tp.team_id = $1
                ORDER BY p.full_name
            `, [blueTeamId])
        ]);
        
        res.json({
            redTeam: redTeamResult.rows,
            blueTeam: blueTeamResult.rows
        });
        
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
        
        const game = gameResult.rows[0];
        if (!game.motm_voting_ends || new Date() > new Date(game.motm_voting_ends)) {
            return res.status(400).json({ error: 'Voting is closed' });
        }
        
        // Insert vote (ON CONFLICT will update if already voted)
        await pool.query(
            `INSERT INTO motm_votes (game_id, voter_id, voted_for_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (game_id, voter_id) DO UPDATE SET voted_for_id = $3`,
            [gameId, req.user.playerId, votedForId]
        );
        
        res.json({ message: 'Vote recorded' });
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
    try {
        const { gameId } = req.params;
        const { reason, removedPlayers } = req.body;
        
        // Get game details
        const gameResult = await pool.query(
            'SELECT cost_per_player, format FROM games WHERE id = $1',
            [gameId]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        const gameCost = parseFloat(game.cost_per_player);
        
        // Start transaction
        await pool.query('BEGIN');
        
        try {
            // Handle player removals if reason is player_dropout
            if (reason === 'player_dropout' && removedPlayers && removedPlayers.length > 0) {
                for (const removal of removedPlayers) {
                    const { playerId, registrationId, refundAmount, isLateDropout } = removal;
                    
                    // Remove player registration
                    await pool.query(
                        'DELETE FROM registrations WHERE id = $1',
                        [registrationId]
                    );
                    
                    // Process refund if amount > 0
                    if (refundAmount > 0) {
                        await pool.query(
                            `UPDATE credits 
                             SET balance = balance + $1 
                             WHERE player_id = $2`,
                            [refundAmount, playerId]
                        );
                        
                        // Log the refund
                        await pool.query(
                            `INSERT INTO credit_transactions (player_id, amount, type, description)
                             VALUES ($1, $2, 'refund', $3)`,
                            [playerId, refundAmount, `Removed from game - £${refundAmount.toFixed(2)} refund`]
                        );
                    }
                    
                    // Award discipline points if late dropout
                    if (isLateDropout) {
                        const disciplinePoints = game.format === '11-a-side' ? 3 : 2;
                        
                        await pool.query(
                            `INSERT INTO discipline_records (player_id, game_id, offense_type, points, warning_level)
                             VALUES ($1, $2, 'Late Drop Out', $3, 0)`,
                            [playerId, gameId, disciplinePoints]
                        );
                    }
                }
            }
            
            // Delete teams
            const teamsResult = await pool.query(
                'SELECT id FROM teams WHERE game_id = $1',
                [gameId]
            );
            
            for (const team of teamsResult.rows) {
                await pool.query('DELETE FROM team_players WHERE team_id = $1', [team.id]);
            }
            
            await pool.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        await pool.query("UPDATE game_guests SET team_name = NULL WHERE game_id = $1", [gameId]);
            
            // Revert game status
            await pool.query(`
                UPDATE games 
                SET game_status = 'available',
                    teams_confirmed = FALSE,
                    teams_generated = FALSE
                WHERE id = $1
            `, [gameId]);
            
            await pool.query('COMMIT');
            
            res.json({ 
                message: 'Game unconfirmed successfully',
                playersRemoved: removedPlayers?.length || 0
            });
            
        } catch (error) {
            await pool.query('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.error('Unconfirm game error:', error);
        res.status(500).json({ error: 'Failed to unconfirm game' });
    }
});

app.post('/api/admin/games/:gameId/complete', authenticateToken, requireGameManager, async (req, res) => {
    const client = await pool.connect();
    try {
        const { gameId } = req.params;
        const { winningTeam, disciplineRecords, beefEntries, motmNominees } = req.body;
        
        console.log('Complete game request:', {
            gameId,
            winningTeam,
            disciplineRecordsCount: disciplineRecords?.length || 0,
            beefEntriesCount: beefEntries?.length || 0,
            motmNomineesCount: motmNominees?.length || 0,
            motmNomineeIds: motmNominees
        });
        
        await client.query('BEGIN');
        
        // 1. Update game winning team and status
        console.log('Step 1: Updating game status...');
        await client.query(
            `UPDATE games 
             SET winning_team = $1, 
                 game_status = 'completed',
                 motm_voting_ends = NOW() + INTERVAL '24 hours'
             WHERE id = $2`,
            [winningTeam, gameId]
        );
        
        // 2. Get all players in the game
        console.log('Step 2: Getting players and updating stats...');
        const playersResult = await client.query(
            `SELECT DISTINCT player_id FROM registrations 
             WHERE game_id = $1 AND status = 'confirmed'`,
            [gameId]
        );
        const allPlayerIds = playersResult.rows.map(r => r.player_id);
        
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
            console.log(`Updated appearances for ${showedUpPlayerIds.length} players`);
        }
        
        // Update wins for winning team players (from actual team assignment, NOT motm nominees)
        if (winningTeam && winningTeam !== 'draw') {
            const winningTeamName = winningTeam === 'red' ? 'Red' : 'Blue';
            const winningPlayersResult = await client.query(`
                SELECT tp.player_id FROM team_players tp
                JOIN teams t ON t.id = tp.team_id
                WHERE t.game_id = $1 AND t.team_name = $2
            `, [gameId, winningTeamName]);
            
            const winningPlayerIds = winningPlayersResult.rows.map(r => r.player_id);
            
            if (winningPlayerIds.length > 0) {
                await client.query(
                    `UPDATE players 
                     SET total_wins = total_wins + 1
                     WHERE id = ANY($1)`,
                    [winningPlayerIds]
                );
                console.log(`Updated wins for ${winningPlayerIds.length} winning team players (${winningTeamName})`);
            }
        } else if (winningTeam === 'draw') {
            console.log('Game was a draw - no wins awarded');
        }
        
        // 3. Save discipline records (only for offenses, not on_time)
        console.log('Step 3: Saving discipline records...');
        for (const record of disciplineRecords || []) {
            if (record.points > 0) {
                const offenseTypes = {
                    'on_time': 'On Time',
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
        
        // 4. Save beef entries (bidirectional)
        console.log('Step 4: Saving beef entries...');
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
        
        // 5. Create MOTM nominees
        console.log('Step 5: Creating MOTM nominees...');
        let nomineesInserted = 0;
        for (const playerId of motmNominees || []) {
            await client.query(
                `INSERT INTO motm_nominees (game_id, player_id)
                 VALUES ($1, $2)
                 ON CONFLICT DO NOTHING`,
                [gameId, playerId]
            );
            nomineesInserted++;
        }
        console.log(`Inserted ${nomineesInserted} MOTM nominees`);
        
        // Verify nominees were saved
        const nomineeCheck = await client.query(
            'SELECT COUNT(*) as count FROM motm_nominees WHERE game_id = $1',
            [gameId]
        );
        console.log(`Verified ${nomineeCheck.rows[0].count} nominees in database for game ${gameId}`);
        
        await client.query('COMMIT');
        console.log('Complete game transaction committed successfully!');
        
        // 6. Auto-allocate badges OUTSIDE transaction (non-critical)
        for (const playerId of allPlayerIds) {
            try {
                await autoAllocateBadges(playerId);
            } catch (badgeError) {
                console.error(`Failed to auto-allocate badges for player ${playerId}:`, badgeError.message);
            }
        }
        
        // 7. Update series scoreline (non-critical, outside transaction)
        try {
            const seriesCheck = await pool.query(
                'SELECT series_id, team_selection_type FROM games WHERE id = $1',
                [gameId]
            );
            const seriesUuid = seriesCheck.rows[0]?.series_id;
            const selType = seriesCheck.rows[0]?.team_selection_type;
            
            if (seriesUuid && (selType === 'draft_memory' || selType === 'vs_external')) {
                if (winningTeam === 'red') {
                    await pool.query('UPDATE game_series SET red_wins = red_wins + 1 WHERE id = $1', [seriesUuid]);
                } else if (winningTeam === 'blue') {
                    await pool.query('UPDATE game_series SET blue_wins = blue_wins + 1 WHERE id = $1', [seriesUuid]);
                } else if (winningTeam === 'draw') {
                    await pool.query('UPDATE game_series SET draws = draws + 1 WHERE id = $1', [seriesUuid]);
                }
                console.log(`Updated series ${seriesUuid} scoreline: ${winningTeam}`);
            }
        } catch (seriesErr) {
            console.error('Series scoreline update failed (non-critical):', seriesErr.message);
        }
        
        res.json({ 
            message: 'Game completed successfully',
            motmNominees: nomineesInserted,
            motmVotingEnds: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });
        
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('Complete game error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Failed to complete game', 
            details: error.message
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
        
        res.json({
            nominees: result.rows,
            votingOpen: votingOpen,
            votingEnds: game.motm_voting_ends,
            winner: game.motm_winner_id
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

// PUBLIC endpoint - Get game details for registration/sharing (no auth required)
app.get('/api/public/game/:gameUrl/details', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game details
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address, v.photo_url as venue_photo,
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
            format: game.format,
            max_players: game.max_players,
            current_players: game.current_players,
            cost_per_player: game.cost_per_player,
            game_status: game.game_status,
            teams_confirmed: game.teams_confirmed,
            team_selection_type: game.team_selection_type,
            external_opponent: game.external_opponent,
            tf_kit_color: game.tf_kit_color,
            opp_kit_color: game.opp_kit_color,
            winning_team: game.winning_team,
            motm_voting_ends: game.motm_voting_ends,
            motm_winner_id: game.motm_winner_id,
            seriesScoreline
        });
        
    } catch (error) {
        console.error('Get public game details error:', error);
        res.status(500).json({ error: 'Failed to get game details' });
    }
});

// Get MOTM data for public game view (no auth required)
app.get('/api/public/game/:gameUrl/motm', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        console.log('Public MOTM request for game URL:', gameUrl);
        
        // Get game ID and status from URL
        const gameResult = await pool.query(
            'SELECT id, game_status, motm_voting_ends FROM games WHERE game_url = $1',
            [gameUrl]
        );
        
        if (gameResult.rows.length === 0) {
            console.log('MOTM: Game not found for URL:', gameUrl);
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        console.log('MOTM: Game found:', { id: game.id, status: game.game_status, votingEnds: game.motm_voting_ends });
        
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
                COUNT(v.id) as vote_count
            FROM motm_nominees mn
            JOIN players p ON p.id = mn.player_id
            LEFT JOIN motm_votes v ON v.voted_for_id = mn.player_id AND v.game_id = mn.game_id
            WHERE mn.game_id = $1
            GROUP BY p.id, p.full_name, p.alias, p.squad_number
            ORDER BY vote_count DESC
        `, [game.id]);
        
        console.log('MOTM: Found', nomineesResult.rows.length, 'nominees for game', game.id);
        
        // Check if voting is still open
        const votingEnds = game.motm_voting_ends ? new Date(game.motm_voting_ends) : new Date(0);
        const now = new Date();
        const votingOpen = votingEnds > now;
        
        res.json({
            nominees: nomineesResult.rows,
            votingEnds: game.motm_voting_ends,
            votingOpen,
            userHasVoted: false
        });
        
    } catch (error) {
        console.error('Get public MOTM error:', error);
        console.error('MOTM error details:', error.message);
        res.status(500).json({ error: 'Failed to get MOTM data', details: error.message });
    }
});

// Get registered players for public game view
app.get('/api/public/game/:gameUrl/players', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game ID first
        const gameResult = await pool.query(
            'SELECT id FROM games WHERE game_url = $1',
            [gameUrl]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const gameId = gameResult.rows[0].id;
        
        // Get registered players with pair/avoid info
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
                (SELECT json_agg(json_build_object('name', b.name, 'icon', b.icon))
                 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
                array_agg(DISTINCT rp_pair.target_player_id) FILTER (WHERE rp_pair.preference_type = 'pair') as pair_with,
                array_agg(DISTINCT rp_avoid.target_player_id) FILTER (WHERE rp_avoid.preference_type = 'avoid') as avoid_with
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            LEFT JOIN registration_preferences rp_pair ON rp_pair.registration_id = r.id AND rp_pair.preference_type = 'pair'
            LEFT JOIN registration_preferences rp_avoid ON rp_avoid.registration_id = r.id AND rp_avoid.preference_type = 'avoid'
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            GROUP BY p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                     p.total_appearances, p.motm_wins, p.total_wins, p.reliability_tier,
                     r.position_preference, r.registered_at
            ORDER BY r.registered_at ASC
        `, [gameId]);
        
        res.json(playersResult.rows);
        
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
        
        // Cast vote (upsert)
        await pool.query(
            `INSERT INTO motm_votes (game_id, voter_id, voted_for_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (game_id, voter_id)
             DO UPDATE SET voted_for_id = $3, voted_at = NOW()`,
            [gameId, voterId, nomineeId]
        );
        
        res.json({ message: 'Vote recorded' });
        
    } catch (error) {
        console.error('MOTM vote error:', error);
        res.status(500).json({ error: 'Failed to record vote' });
    }
});

// Get player profile (public)
app.get('/api/public/player/:playerId', async (req, res) => {
    try {
        const { playerId } = req.params;
        
        // Get player by ID or squad number
        let playerResult;
        if (isNaN(playerId)) {
            // UUID
            playerResult = await pool.query(
                'SELECT * FROM players WHERE id = $1',
                [playerId]
            );
        } else {
            // Squad number
            playerResult = await pool.query(
                'SELECT * FROM players WHERE squad_number = $1',
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
        
        // Check if already locked by someone else
        const lockCheck = await pool.query(
            'SELECT player_editing_locked, locked_by FROM games WHERE id = $1',
            [gameId]
        );
        
        if (lockCheck.rows[0]?.player_editing_locked && 
            lockCheck.rows[0]?.locked_by !== req.user.playerId) {
            return res.status(409).json({ error: 'Game is being edited by another admin' });
        }
        
        // Lock the game
        await pool.query(
            `UPDATE games 
             SET player_editing_locked = TRUE,
                 locked_by = $1,
                 locked_at = NOW()
             WHERE id = $2`,
            [req.user.playerId, gameId]
        );
        
        res.json({ message: 'Game locked for editing' });
        
    } catch (error) {
        console.error('Lock game error:', error);
        res.status(500).json({ error: 'Failed to lock game' });
    }
});

// Unlock game
app.post('/api/admin/games/:gameId/unlock', authenticateToken, requireCLMAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        await pool.query(
            `UPDATE games 
             SET player_editing_locked = FALSE,
                 locked_by = NULL,
                 locked_at = NULL
             WHERE id = $1`,
            [gameId]
        );
        
        res.json({ message: 'Game unlocked' });
        
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
                r.position_preference
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1
            ORDER BY p.squad_number ASC NULLS LAST
        `, [gameId]);
        
        res.json(result.rows);
        
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
        
        // Get game cost
        const gameResult = await pool.query(
            'SELECT cost_per_player FROM games WHERE id = $1',
            [gameId]
        );
        const cost = parseFloat(gameResult.rows[0].cost_per_player);
        
        // Check/deduct credits
        const creditResult = await pool.query(
            'SELECT balance FROM credits WHERE player_id = $1',
            [playerId]
        );
        
        if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < cost) {
            return res.status(400).json({ error: 'Player has insufficient credits' });
        }
        
        // Deduct credits
        await pool.query(
            'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
            [cost, playerId]
        );
        
        await pool.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
            [playerId, -cost, 'game_fee', `Admin added to game ${gameId}`]
        );
        
        // Add player
        await pool.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference)
             VALUES ($1, $2, 'confirmed', $3)`,
            [gameId, playerId, position || 'outfield']
        );
        
        res.json({ message: 'Player added successfully' });
        
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
            `INSERT INTO registrations (game_id, player_id, status, position_preference)
             VALUES ($1, $2, 'confirmed', $3)`,
            [gameId, playerId, position || 'outfield']
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
        
        // Check if game is locked by this admin
        const lockCheck = await pool.query(
            'SELECT locked_by FROM games WHERE id = $1 AND player_editing_locked = TRUE',
            [gameId]
        );
        
        if (lockCheck.rows.length === 0 || lockCheck.rows[0].locked_by !== req.user.playerId) {
            return res.status(403).json({ error: 'Game must be locked by you to edit players' });
        }
        
        // Get registration details
        const regResult = await pool.query(
            'SELECT player_id FROM registrations WHERE id = $1 AND game_id = $2',
            [registrationId, gameId]
        );
        
        if (regResult.rows.length === 0) {
            return res.status(404).json({ error: 'Registration not found' });
        }
        
        const playerId = regResult.rows[0].player_id;
        
        // Get game cost
        const gameResult = await pool.query(
            'SELECT cost_per_player FROM games WHERE id = $1',
            [gameId]
        );
        const cost = parseFloat(gameResult.rows[0].cost_per_player);
        
        // Refund credits
        await pool.query(
            'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
            [cost, playerId]
        );
        
        await pool.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
            [playerId, cost, 'refund', `Admin removed from game ${gameId}`]
        );
        
        // Delete registration
        await pool.query(
            'DELETE FROM registrations WHERE id = $1',
            [registrationId]
        );
        
        res.json({ message: 'Player removed successfully' });
        
    } catch (error) {
        console.error('Remove player error:', error);
        res.status(500).json({ error: 'Failed to remove player' });
    }
});

// Finalize MOTM voting - called manually or by cron job
app.post('/api/admin/games/:gameId/finalize-motm', authenticateToken, requireGameManager, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Get game and check if voting has ended
        const gameResult = await pool.query(
            'SELECT motm_voting_ends, motm_winner_id FROM games WHERE id = $1',
            [gameId]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        if (game.motm_winner_id) {
            return res.status(400).json({ error: 'MOTM already finalized' });
        }
        
        // Get vote counts for all nominees
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
        
        if (votesResult.rows.length === 0) {
            return res.status(400).json({ error: 'No MOTM nominees found' });
        }
        
        // Find the highest vote count
        const maxVotes = parseInt(votesResult.rows[0].votes);
        
        // Get all players with the max votes (handles ties)
        const winners = votesResult.rows.filter(r => parseInt(r.votes) === maxVotes);
        
        // Calculate MOTM increment (1 divided by number of winners for ties)
        const motmIncrement = 1.0 / winners.length;
        
        console.log(`MOTM finalization: ${winners.length} winner(s) with ${maxVotes} votes each`);
        console.log(`MOTM increment: ${motmIncrement} per winner`);
        
        // Update MOTM wins for all winners
        for (const winner of winners) {
            await pool.query(
                `UPDATE players 
                 SET motm_wins = motm_wins + $1
                 WHERE id = $2`,
                [motmIncrement, winner.player_id]
            );
        }
        
        // Set the first winner as the "official" winner (for display purposes)
        await pool.query(
            'UPDATE games SET motm_winner_id = $1 WHERE id = $2',
            [winners[0].player_id, gameId]
        );
        
        res.json({ 
            message: 'MOTM voting finalized',
            winners: winners.map(w => ({
                playerId: w.player_id,
                name: w.full_name || w.alias,
                votes: maxVotes,
                motmIncrement: motmIncrement
            }))
        });
        
    } catch (error) {
        console.error('Finalize MOTM error:', error);
        res.status(500).json({ error: 'Failed to finalize MOTM voting' });
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
                ? 'https://totalfooty.co.uk/vibecoding/register.html?ref=' + me.referral_code
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

// Public: Validate a referral code (for registration page)
app.get('/api/public/referral/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        // Look up in players table first, then referrals
        let referrer = null;
        const pRef = await pool.query(
            `SELECT p.id, p.alias, p.full_name,
             EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'CLM') as has_clm
             FROM players p WHERE p.referral_code = $1`,
            [code.toUpperCase()]
        );
        
        if (pRef.rows.length > 0) {
            referrer = pRef.rows[0];
        } else {
            const rRef = await pool.query(
                `SELECT p.id, p.alias, p.full_name,
                 EXISTS(SELECT 1 FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id AND b.name = 'CLM') as has_clm
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
            message: referrer.has_clm
                ? 'You have been referred by ' + (referrer.alias || referrer.full_name) + '! You will receive CLM access upon registration.'
                : 'You have been referred by ' + (referrer.alias || referrer.full_name) + '! Welcome to Total Footy.'
        });
    } catch (error) {
        console.error('Validate referral error:', error);
        res.status(500).json({ error: 'Failed to validate referral code' });
    }
});

// Public: Get any player's referral link (for profile/directory pages)
app.get('/api/public/player/:playerId/referral', async (req, res) => {
    try {
        const { playerId } = req.params;
        const result = await pool.query(
            'SELECT referral_code, alias, full_name FROM players WHERE id = $1',
            [playerId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
        const p = result.rows[0];
        res.json({
            referralCode: p.referral_code,
            referralLink: p.referral_code
                ? 'https://totalfooty.co.uk/vibecoding/register.html?ref=' + p.referral_code
                : null,
            playerName: p.alias || p.full_name
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
                 (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players, motm_p.alias as motm_winner_alias
                FROM games g LEFT JOIN venues v ON v.id = g.venue_id LEFT JOIN players motm_p ON motm_p.id = g.motm_winner_id
                ORDER BY g.game_date DESC LIMIT 50`;
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
                 (SELECT COUNT(*) FROM game_guests WHERE game_id = g.id)) as current_players, motm_p.alias as motm_winner_alias
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

// Get all message templates
app.get('/api/admin/whatsapp/templates', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT * FROM whatsapp_templates 
            ORDER BY notification_type
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Get templates error:', error);
        res.status(500).json({ error: 'Failed to get templates' });
    }
});

// Update message template
app.put('/api/admin/whatsapp/templates/:notificationType', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { notificationType } = req.params;
        const { message_template, trigger_description, is_active } = req.body;
        
        await pool.query(`
            UPDATE whatsapp_templates 
            SET message_template = $1, 
                trigger_description = $2,
                is_active = $3,
                updated_at = NOW()
            WHERE notification_type = $4
        `, [message_template, trigger_description, is_active, notificationType]);
        
        res.json({ message: 'Template updated successfully' });
    } catch (error) {
        console.error('Update template error:', error);
        res.status(500).json({ error: 'Failed to update template' });
    }
});

// Send test message
app.post('/api/admin/whatsapp/test', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { phoneNumber, message } = req.body;
        
        const result = await sendWhatsAppMessage(phoneNumber, message, 'test', null);
        
        if (result.success) {
            res.json({ message: 'Test message sent successfully', sid: result.sid });
        } else {
            res.status(500).json({ error: result.error });
        }
    } catch (error) {
        console.error('Send test message error:', error);
        res.status(500).json({ error: 'Failed to send test message' });
    }
});

// Send notification to player
app.post('/api/admin/whatsapp/send', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId, notificationType, additionalData } = req.body;
        
        const result = await sendNotification(notificationType, playerId, additionalData);
        
        if (result.success) {
            res.json({ message: 'Notification sent successfully' });
        } else {
            res.status(500).json({ error: result.error });
        }
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// Get WhatsApp logs
app.get('/api/admin/whatsapp/logs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { limit = 50, offset = 0 } = req.query;
        
        const result = await pool.query(`
            SELECT 
                wl.*,
                p.full_name,
                p.alias
            FROM whatsapp_logs wl
            LEFT JOIN players p ON p.id = wl.player_id
            ORDER BY wl.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Get WhatsApp logs error:', error);
        res.status(500).json({ error: 'Failed to get logs' });
    }
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
});
