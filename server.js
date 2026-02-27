// TOTAL FOOTY - COMPLETE BACKEND API V2
// Core functionality - Ready to deploy

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

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

// ==========================================
// AUTHENTICATION
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, alias, email, password, phone } = req.body;

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

        // Generate referral code
        const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        await pool.query(
            'INSERT INTO referrals (referrer_id, referral_code) VALUES ($1, $2)',
            [playerId, referralCode]
        );

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
             (SELECT json_agg(json_build_object('name', b.name, 'color', b.color, 'icon', b.icon))
              FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges,
             (SELECT referral_code FROM referrals WHERE referrer_id = p.id LIMIT 1) as referral_code
             FROM players p 
             LEFT JOIN credits c ON c.player_id = p.id 
             WHERE p.user_id = $1`,
            [user.id]
        );

        const player = playerResult.rows[0];

        const token = jwt.sign(
            { userId: user.id, playerId: player.id, email: user.email, role: user.role },
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
            SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                   p.reliability_tier, p.total_appearances, p.motm_wins, p.total_wins,
                   c.balance as credits,
                   p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                   p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                   p.goalkeeper_rating,
                   (SELECT json_agg(json_build_object('name', b.name, 'color', b.color, 'icon', b.icon))
                    FROM player_badges pb JOIN badges b ON pb.badge_id = b.id WHERE pb.player_id = p.id) as badges
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            ORDER BY p.squad_number NULLS LAST, p.full_name
        `);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching players:', error);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

app.get('/api/players/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.*, c.balance as credits, u.email,
            (SELECT json_agg(json_build_object('name', b.name, 'color', b.color, 'icon', b.icon))
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
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players
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
        
        // Tier-based visibility (exact requirements)
        let hoursAhead = 72; // silver default (72 hours = 3 days)
        if (tier === 'gold') hoursAhead = 28 * 24; // 28 days
        if (tier === 'bronze') hoursAhead = 24; // 24 hours
        if (tier === 'white' || tier === 'black') hoursAhead = 0; // banned - no games visible
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address,
                   g.teams_generated,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players,
                   EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1) as is_registered
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE (
                (g.game_status = 'available' AND g.game_date >= CURRENT_TIMESTAMP)
                OR (g.game_status = 'confirmed')
            )
            ${isAdmin ? '' : hoursAhead > 0 ? 'AND g.game_date <= CURRENT_TIMESTAMP + INTERVAL \'' + hoursAhead + ' hours\'' : 'AND 1 = 0'}
            AND g.status != 'cancelled'
            ${!isAdmin && !hasAllStarBadge ? 'AND (g.all_star_only IS NULL OR g.all_star_only = FALSE)' : ''}
            ORDER BY g.game_date ASC
        `, [req.user.playerId]);
        
        // Try to add venue photos if column exists
        const gamesWithPhotos = await Promise.all(result.rows.map(async (game) => {
            if (game.venue_id) {
                try {
                    const venueResult = await pool.query(
                        'SELECT photo_url FROM venues WHERE id = $1',
                        [game.venue_id]
                    );
                    if (venueResult.rows[0]?.photo_url) {
                        game.venue_photo = venueResult.rows[0].photo_url;
                    }
                } catch (e) {
                    // Column doesn't exist yet, skip silently
                }
            }
            return game;
        }));
        
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
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players,
                   p.full_name as motm_winner_name,
                   p.alias as motm_winner_alias
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN players p ON p.id = g.motm_winner_id
            WHERE g.game_status = 'completed'
            ORDER BY g.game_date DESC
            LIMIT 50
        `);
        
        // Format the response to include winner name
        const games = result.rows.map(game => ({
            ...game,
            motm_winner_name: game.motm_winner_name || game.motm_winner_alias
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
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [req.params.id]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        // Get registered players
        const playersResult = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.squad_number, p.reliability_tier, 
                   r.position_preference, r.status
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            ORDER BY r.registered_at
        `, [req.params.id]);
        
        game.registered_players = playersResult.rows;
        
        res.json(game);
    } catch (error) {
        console.error('Error fetching game:', error);
        res.status(500).json({ error: 'Failed to fetch game' });
    }
});

app.post('/api/admin/games', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { 
            venueId, gameDate, maxPlayers, costPerPlayer, format, regularity, 
            exclusivity, positionType, teamSelectionType, externalOpponent 
        } = req.body;
        
        const createdGames = [];
        
        if (regularity === 'weekly') {
            // Generate series ID (e.g., "TF0001")
            const countResult = await pool.query('SELECT COUNT(*) FROM game_series');
            const seriesCount = parseInt(countResult.rows[0].count) + 1;
            const seriesIdValue = `TF${String(seriesCount).padStart(4, '0')}`;
            
            // Create series record for fixed_draft games
            let seriesUuid = null;
            if (teamSelectionType === 'fixed_draft') {
                const seriesResult = await pool.query(
                    'INSERT INTO game_series (series_name) VALUES ($1) RETURNING id',
                    [seriesIdValue]
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
                        exclusivity, position_type, game_url, status, series_id, 
                        team_selection_type, external_opponent
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', $10, $11, $12)
                    RETURNING id`,
                    [
                        venueId, weekDate.toISOString(), maxPlayers, costPerPlayer, format, 'weekly', 
                        exclusivity || 'everyone', positionType || 'outfield_gk', gameUrl, 
                        seriesUuid, teamSelectionType || 'normal', externalOpponent
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
            // Create single one-off game (no series_id)
            const gameUrl = crypto.randomBytes(6).toString('hex');
            
            const result = await pool.query(
                `INSERT INTO games (
                    venue_id, game_date, max_players, cost_per_player, format, regularity, 
                    exclusivity, position_type, game_url, status, team_selection_type, external_opponent
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', $10, $11)
                RETURNING id`,
                [
                    venueId, gameDate, maxPlayers, costPerPlayer, format, 'one-off', 
                    exclusivity || 'everyone', positionType || 'outfield_gk', gameUrl,
                    teamSelectionType || 'normal', externalOpponent
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
    try {
        const { position, pairs, avoids } = req.body;
        const gameId = req.params.id;
        
        // Check if game is All Star only
        const gameTypeCheck = await pool.query(
            'SELECT all_star_only, player_editing_locked FROM games WHERE id = $1',
            [gameId]
        );
        
        // Check if game is locked for editing
        if (gameTypeCheck.rows[0]?.player_editing_locked) {
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        if (gameTypeCheck.rows[0]?.all_star_only) {
            // Check if player has TF All Star badge
            const badgeCheck = await pool.query(`
                SELECT 1 FROM player_badges pb
                JOIN badges b ON b.id = pb.badge_id
                WHERE pb.player_id = $1 AND b.name = 'TF All Star'
            `, [req.user.playerId]);
            
            if (badgeCheck.rows.length === 0) {
                return res.status(403).json({ 
                    error: 'This is an All Star game. You need the TF All Star badge to register.',
                    requiresBadge: 'TF All Star'
                });
            }
        }
        
        // Check if already registered
        const existingReg = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (existingReg.rows.length > 0) {
            return res.status(400).json({ error: 'Already registered' });
        }
        
        // Check game capacity
        const gameCheck = await pool.query(`
            SELECT g.max_players, g.cost_per_player,
                   COUNT(r.id) FILTER (WHERE r.status = 'confirmed') as current_players
            FROM games g
            LEFT JOIN registrations r ON r.game_id = g.id
            WHERE g.id = $1
            GROUP BY g.id
        `, [gameId]);
        
        const game = gameCheck.rows[0];
        const isFull = parseInt(game.current_players) >= parseInt(game.max_players);
        const status = isFull ? 'backup' : 'confirmed';
        
        // Check credits
        if (status === 'confirmed') {
            const creditResult = await pool.query(
                'SELECT balance FROM credits WHERE player_id = $1',
                [req.user.playerId]
            );
            
            if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < parseFloat(game.cost_per_player)) {
                return res.status(400).json({ error: 'Insufficient credits' });
            }
            
            // Deduct credits
            await pool.query(
                'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                [game.cost_per_player, req.user.playerId]
            );
            
            await pool.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [req.user.playerId, -game.cost_per_player, 'game_fee', `Registration for game ${gameId}`]
            );
        }
        
        // Register player
        const regResult = await pool.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference)
             VALUES ($1, $2, $3, $4) RETURNING id`,
            [gameId, req.user.playerId, status, position || 'outfield']
        );
        
        const registrationId = regResult.rows[0].id;
        
        // Insert pair preferences
        if (pairs && Array.isArray(pairs)) {
            for (const pairPlayerId of pairs) {
                await pool.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'pair')`,
                    [registrationId, pairPlayerId]
                );
            }
        }
        
        // Insert avoid preferences
        if (avoids && Array.isArray(avoids)) {
            for (const avoidPlayerId of avoids) {
                await pool.query(
                    `INSERT INTO registration_preferences (registration_id, target_player_id, preference_type)
                     VALUES ($1, $2, 'avoid')`,
                    [registrationId, avoidPlayerId]
                );
            }
        }
        
        res.json({ message: status === 'confirmed' ? 'Registered successfully' : 'Added to backup list', status });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Drop out of game with refund
app.post('/api/games/:id/drop-out', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        
        // Check if game is locked for editing
        const lockCheck = await pool.query(
            'SELECT player_editing_locked FROM games WHERE id = $1',
            [gameId]
        );
        
        if (lockCheck.rows[0]?.player_editing_locked) {
            return res.status(423).json({ 
                error: 'Game is currently being edited by an admin. Please try again in a few minutes.'
            });
        }
        
        // Check if teams already generated
        const gameCheck = await pool.query('SELECT teams_generated FROM games WHERE id = $1', [gameId]);
        if (gameCheck.rows[0]?.teams_generated) {
            return res.status(400).json({ error: 'Cannot drop out - teams already generated' });
        }
        
        // Get registration
        const regResult = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, req.user.playerId]
        );
        
        if (regResult.rows.length === 0) {
            return res.status(404).json({ error: 'Not registered for this game' });
        }
        
        // Get game cost
        const costResult = await pool.query('SELECT cost_per_player FROM games WHERE id = $1', [gameId]);
        const cost = parseFloat(costResult.rows[0].cost_per_player);
        
        // Refund player
        await pool.query(
            'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
            [cost, req.user.playerId]
        );
        
        await pool.query(
            'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
            [req.user.playerId, cost, 'refund', `Dropped out of game - refund`]
        );
        
        // Delete registration (cascade deletes preferences)
        await pool.query('DELETE FROM registrations WHERE id = $1', [regResult.rows[0].id]);
        
        res.json({ message: `Successfully dropped out. £${cost.toFixed(2)} refunded to your balance.` });
    } catch (error) {
        console.error('Drop out error:', error);
        res.status(500).json({ error: 'Failed to drop out' });
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
app.post('/api/admin/games/:gameId/generate-teams', authenticateToken, requireAdmin, async (req, res) => {
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
        
        // Add players to teams
        for (const player of redTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [redTeamId, player.player_id]
            );
        }
        
        for (const player of blueTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [blueTeamId, player.player_id]
            );
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

// Delete single game with refunds
app.delete('/api/admin/games/:gameId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Get all registrations for this game
        const registrations = await pool.query(
            'SELECT player_id, status FROM registrations WHERE game_id = $1 AND status = $2',
            [gameId, 'confirmed']
        );
        
        // Get game cost
        const gameResult = await pool.query('SELECT cost_per_player FROM games WHERE id = $1', [gameId]);
        const cost = parseFloat(gameResult.rows[0]?.cost_per_player || 0);
        
        // Refund all registered players
        for (const reg of registrations.rows) {
            await pool.query(
                'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                [cost, reg.player_id]
            );
            
            await pool.query(
                'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                [reg.player_id, cost, 'refund', `Game cancelled - refund for ${cost}`]
            );
        }
        
        // Delete the game (cascade will delete registrations)
        await pool.query('DELETE FROM games WHERE id = $1', [gameId]);
        
        res.json({ 
            message: `Game deleted. Refunded ${registrations.rows.length} players £${cost.toFixed(2)} each.` 
        });
    } catch (error) {
        console.error('Delete game error:', error);
        res.status(500).json({ error: 'Failed to delete game' });
    }
});

// Delete entire weekly series with refunds (FUTURE games only)
app.delete('/api/admin/games/:gameId/delete-series', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        
        // Get the game's series_id
        const gameResult = await pool.query(
            'SELECT series_id, cost_per_player FROM games WHERE id = $1',
            [gameId]
        );
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        if (!game.series_id) {
            return res.status(400).json({ error: 'This is not part of a weekly series' });
        }
        
        // Extract base series ID (e.g., "TF0001" from "TF0001-05")
        const baseSeriesId = game.series_id.split('-')[0];
        
        // Find all FUTURE games in this series
        const seriesGames = await pool.query(`
            SELECT id FROM games 
            WHERE series_id LIKE $1
            AND game_date > CURRENT_TIMESTAMP
        `, [`${baseSeriesId}%`]);
        
        const gameIds = seriesGames.rows.map(g => g.id);
        
        if (gameIds.length === 0) {
            return res.json({ message: 'No future games to delete in this series' });
        }
        
        let totalRefunded = 0;
        const cost = parseFloat(game.cost_per_player);
        
        // Refund all registrations for FUTURE games only
        for (const gid of gameIds) {
            const registrations = await pool.query(
                'SELECT player_id FROM registrations WHERE game_id = $1 AND status = $2',
                [gid, 'confirmed']
            );
            
            for (const reg of registrations.rows) {
                await pool.query(
                    'UPDATE credits SET balance = balance + $1 WHERE player_id = $2',
                    [cost, reg.player_id]
                );
                
                await pool.query(
                    'INSERT INTO credit_transactions (player_id, amount, type, description) VALUES ($1, $2, $3, $4)',
                    [reg.player_id, cost, 'refund', `Series ${baseSeriesId} cancelled - refund`]
                );
                
                totalRefunded++;
            }
        }
        
        // Delete only FUTURE games in series
        await pool.query(
            'DELETE FROM games WHERE id = ANY($1::uuid[])',
            [gameIds]
        );
        
        res.json({ 
            message: `Deleted ${gameIds.length} future games from series ${baseSeriesId}. Refunded ${totalRefunded} registrations. Past games preserved.` 
        });
    } catch (error) {
        console.error('Delete series error:', error);
        res.status(500).json({ error: 'Failed to delete series' });
    }
});

// Get fixed team assignments for a game's series
app.get('/api/admin/games/:gameId/fixed-teams', authenticateToken, requireAdmin, async (req, res) => {
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

// Save manual team assignments (for fixed_draft games)
app.post('/api/admin/games/:gameId/save-manual-teams', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { redTeam, blueTeam } = req.body;
        
        // Get game info
        const gameResult = await pool.query('SELECT series_id, team_selection_type FROM games WHERE id = $1', [gameId]);
        const game = gameResult.rows[0];
        
        if (game.team_selection_type === 'fixed_draft' && game.series_id) {
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

// Confirm teams (saves to database, sets teams_generated = true)
app.post('/api/admin/games/:gameId/confirm-teams', authenticateToken, requireAdmin, async (req, res) => {
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
app.get('/api/admin/games/:gameId/teams', authenticateToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/games/:gameId/start-motm', authenticateToken, requireAdmin, async (req, res) => {
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
            `UPDATE games SET motm_voting_open = true, motm_voting_ends_at = $1 WHERE id = $2`,
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
            'SELECT motm_voting_open, motm_voting_ends_at FROM games WHERE id = $1',
            [gameId]
        );
        
        const game = gameResult.rows[0];
        if (!game.motm_voting_open || new Date() > new Date(game.motm_voting_ends_at)) {
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
app.post('/api/admin/games/:gameId/complete', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { winningTeam, disciplineRecords, beefEntries, motmNominees } = req.body;
        
        console.log('Complete game request:', {
            gameId,
            winningTeam,
            disciplineRecordsCount: disciplineRecords?.length || 0,
            beefEntriesCount: beefEntries?.length || 0,
            motmNomineesCount: motmNominees?.length || 0
        });
        
        // Start transaction
        await pool.query('BEGIN');
        
        // 1. Update game winning team and status
        console.log('Step 1: Updating game status...');
        await pool.query(
            `UPDATE games 
             SET winning_team = $1, 
                 game_completed = TRUE, 
                 game_status = 'completed',
                 motm_voting_ends = NOW() + INTERVAL '24 hours'
             WHERE id = $2`,
            [winningTeam, gameId]
        );
        
        // 2. Get all players in the game
        console.log('Step 2: Getting players and updating stats...');
        const playersResult = await pool.query(
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
            await pool.query(
                `UPDATE players 
                 SET total_appearances = total_appearances + 1
                 WHERE id = ANY($1)`,
                [showedUpPlayerIds]
            );
            console.log(`Updated appearances for ${showedUpPlayerIds.length} players`);
        }
        
        // Update wins for MOTM nominees (players eligible for MOTM voting)
        if (motmNominees && motmNominees.length > 0) {
            await pool.query(
                `UPDATE players 
                 SET total_wins = total_wins + 1
                 WHERE id = ANY($1)`,
                [motmNominees]
            );
            console.log(`Updated wins for ${motmNominees.length} MOTM nominees`);
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
                
                console.log('Inserting discipline record:', record);
                await pool.query(
                    `INSERT INTO discipline_records (player_id, game_id, offense_type, points, warning_level)
                     VALUES ($1, $2, $3, $4, $5)`,
                    [record.playerId, gameId, offenseTypes[record.offense] || 'Unknown', record.points, record.warning]
                );
            }
        }
        
        // 4. Save beef entries (bidirectional)
        console.log('Step 4: Saving beef entries...');
        for (const beef of beefEntries || []) {
            console.log('Inserting beef:', beef);
            // Player 1 -> Player 2
            await pool.query(
                `INSERT INTO beef (player_id, target_player_id, rating)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (player_id, target_player_id) 
                 DO UPDATE SET rating = $3`,
                [beef.player1, beef.player2, beef.level]
            );
            
            // Player 2 -> Player 1 (bidirectional)
            await pool.query(
                `INSERT INTO beef (player_id, target_player_id, rating)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (player_id, target_player_id) 
                 DO UPDATE SET rating = $3`,
                [beef.player2, beef.player1, beef.level]
            );
        }
        
        // 5. Create MOTM nominees
        console.log('Step 5: Creating MOTM nominees...');
        for (const playerId of motmNominees || []) {
            console.log('Inserting MOTM nominee:', playerId);
            try {
                await pool.query(
                    `INSERT INTO motm_nominees (game_id, player_id)
                     VALUES ($1, $2)`,
                    [gameId, playerId]
                );
            } catch (nomineeError) {
                // If duplicate, skip
                if (nomineeError.code !== '23505') { // Not a unique violation
                    throw nomineeError;
                }
            }
        }
        
        await pool.query('COMMIT');
        console.log('Complete game successful!');
        
        res.json({ 
            message: 'Game completed successfully',
            motmVotingEnds: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });
        
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Complete game error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Failed to complete game', 
            details: error.message,
            step: error.step || 'unknown'
        });
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
        
        // Get game by URL
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1 AND g.game_status IN ('confirmed', 'completed')
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found or not confirmed yet' });
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
                SELECT p.id, p.full_name, p.alias, p.squad_number, tp.position
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                WHERE tp.team_id = $1
                ORDER BY tp.position, p.full_name
            `, [redTeamId]),
            pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, tp.position
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                WHERE tp.team_id = $1
                ORDER BY tp.position, p.full_name
            `, [blueTeamId])
        ]);
        
        res.json({
            game: game,
            redTeam: redTeamResult.rows,
            blueTeam: blueTeamResult.rows
        });
        
    } catch (error) {
        console.error('Get public team sheet error:', error);
        res.status(500).json({ error: 'Failed to get team sheet' });
    }
});

// Vote for MOTM
app.post('/api/games/:gameId/motm/vote', authenticateToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const { nomineeId } = req.body;
        const voterId = req.user.playerId;
        
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

// ==========================================
// PUBLIC GAME PAGES
// ==========================================

// Get public team sheet for completed game
app.get('/api/public/game/:gameUrl/teams', async (req, res) => {
    try {
        const { gameUrl } = req.params;
        
        // Get game details
        const gameResult = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_url = $1
        `, [gameUrl]);
        
        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }
        
        const game = gameResult.rows[0];
        
        // Check if voting is still open
        const votingEnds = new Date(game.motm_voting_ends);
        const now = new Date();
        const votingOpen = votingEnds > now;
        const votingFinalized = game.motm_winner_id !== null;
        
        // Get teams
        const teamsResult = await pool.query(
            'SELECT id, team_name FROM teams WHERE game_id = $1',
            [game.id]
        );
        
        const teams = {};
        for (const team of teamsResult.rows) {
            const playersResult = await pool.query(`
                SELECT p.id, p.full_name, p.alias, p.squad_number, 
                       tp.position, p.goalkeeper_rating, p.overall_rating
                FROM team_players tp
                JOIN players p ON p.id = tp.player_id
                WHERE tp.team_id = $1
                ORDER BY 
                    CASE WHEN tp.position = 'goalkeeper' THEN 1 ELSE 2 END,
                    p.squad_number ASC
            `, [team.id]);
            
            teams[team.team_name.toLowerCase()] = playersResult.rows;
        }
        
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
        
        // Get players who played (for voting eligibility check)
        const playersResult = await pool.query(
            `SELECT player_id FROM registrations 
             WHERE game_id = $1 AND status = 'confirmed'`,
            [game.id]
        );
        const playerIds = playersResult.rows.map(r => r.player_id);
        
        // Get next game in series if exists
        let nextGame = null;
        if (game.series_id) {
            const nextGameResult = await pool.query(`
                SELECT g.id, g.game_url, g.game_date, g.cost_per_player, g.format,
                       v.name as venue_name,
                       (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players,
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
        }
        
        res.json({
            game: {
                id: game.id,
                date: game.game_date,
                venue: game.venue_name,
                format: game.format,
                winning_team: game.winning_team,
                motm_winner_id: game.motm_winner_id,
                game_url: game.game_url,
                motm_voting_ends: game.motm_voting_ends,
                votingOpen,
                votingFinalized
            },
            teams,
            motm: motmResult.rows,
            eligibleVoters: playerIds,
            nextGame
        });
        
    } catch (error) {
        console.error('Public team sheet error:', error);
        res.status(500).json({ error: 'Failed to load team sheet' });
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
                alias: player.alias,
                full_name: player.full_name,
                squad_number: player.squad_number,
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
app.post('/api/admin/games/:gameId/lock', authenticateToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/games/:gameId/unlock', authenticateToken, requireAdmin, async (req, res) => {
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
app.get('/api/admin/games/:gameId/players', authenticateToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/games/:gameId/add-player', authenticateToken, requireAdmin, async (req, res) => {
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

// Remove player from game (admin)
app.delete('/api/admin/games/:gameId/remove-player/:registrationId', authenticateToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/games/:gameId/finalize-motm', authenticateToken, requireAdmin, async (req, res) => {
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
// START SERVER
// ==========================================

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
