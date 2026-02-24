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
                goals: player.total_goals || 0,
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
        const result = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.squad_number, p.phone, p.photo_url, 
                   p.reliability_tier, p.total_appearances, p.motm_wins, p.total_goals,
                   c.balance as credits,
                   u.email,
                   p.overall_rating, p.defending_rating, p.strength_rating, p.fitness_rating,
                   p.pace_rating, p.decisions_rating, p.assisting_rating, p.shooting_rating,
                   p.goalkeeper_rating
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            WHERE p.id = $1
        `, [req.user.playerId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching player data:', error);
        res.status(500).json({ error: 'Failed to fetch player data' });
    }
});

app.get('/api/players', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.full_name, p.alias, p.squad_number, p.photo_url, 
                   p.reliability_tier, p.total_appearances, p.motm_wins, p.total_goals,
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
                total_goals: player.total_goals,
                reliability_tier: player.reliability_tier,
                badges: player.badges
            });
        }
    } catch (error) {
        console.error('Error fetching player:', error);
        res.status(500).json({ error: 'Failed to fetch player' });
    }
});

app.put('/api/players/me', authenticateToken, async (req, res) => {
    try {
        const { fullName, alias, phone, photoUrl } = req.body;
        
        await pool.query(
            `UPDATE players SET full_name = $1, alias = $2, phone = $3, photo_url = $4, updated_at = CURRENT_TIMESTAMP
             WHERE id = $5`,
            [fullName, alias, phone, photoUrl, req.user.playerId]
        );
        
        res.json({ message: 'Profile updated' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Update failed' });
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
            total_goals, squad_number, phone, balance
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
                total_goals = $10,
                squad_number = $11,
                phone = $12
            WHERE id = $13
        `, [goalkeeper_rating, defending_rating, strength_rating, fitness_rating,
            pace_rating, decisions_rating, assisting_rating, shooting_rating,
            overall_rating, total_goals, squad_number, phone, playerId]);
        
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
        
        // Tier-based visibility (exact requirements)
        let hoursAhead = 72; // silver default (72 hours = 3 days)
        if (tier === 'gold') hoursAhead = 28 * 24; // 28 days
        if (tier === 'bronze') hoursAhead = 24; // 24 hours
        if (tier === 'white' || tier === 'black') hoursAhead = 0; // banned - no games visible
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players,
                   EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1) as is_registered
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_date >= CURRENT_TIMESTAMP
            ${isAdmin ? '' : hoursAhead > 0 ? 'AND g.game_date <= CURRENT_TIMESTAMP + INTERVAL \'' + hoursAhead + ' hours\'' : 'AND 1 = 0'}
            AND g.status != 'cancelled'
            ORDER BY g.game_date ASC
        `, [req.user.playerId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching games:', error);
        res.status(500).json({ error: 'Failed to fetch games' });
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
        const { venueId, gameDate, maxPlayers, costPerPlayer, format, regularity, exclusivity, positionType } = req.body;
        
        const createdGames = [];
        
        if (regularity === 'weekly') {
            // Generate series ID (e.g., "TF0001")
            const countResult = await pool.query('SELECT COUNT(*) FROM games WHERE series_id IS NOT NULL');
            const seriesCount = parseInt(countResult.rows[0].count) + 1;
            const seriesId = `TF${String(seriesCount).padStart(4, '0')}`;
            
            // Create 26 weeks of games (6 months)
            for (let week = 0; week < 26; week++) {
                const weekDate = new Date(gameDate);
                weekDate.setDate(weekDate.getDate() + (week * 7));
                
                const gameUrl = crypto.randomBytes(6).toString('hex');
                const gameNumber = String(week + 1).padStart(2, '0');
                const fullSeriesId = `${seriesId}-${gameNumber}`; // e.g., "TF0001-01"
                
                const result = await pool.query(
                    `INSERT INTO games (venue_id, game_date, max_players, cost_per_player, format, regularity, exclusivity, position_type, game_url, status, series_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', $10)
                     RETURNING id`,
                    [venueId, weekDate.toISOString(), maxPlayers, costPerPlayer, format, 'weekly', exclusivity || 'everyone', positionType || 'outfield_gk', gameUrl, fullSeriesId]
                );
                
                createdGames.push({ id: result.rows[0].id, gameUrl, date: weekDate, seriesId: fullSeriesId });
            }
            
            res.json({ 
                message: `Created 26 weekly games (series ${seriesId})`,
                seriesId: seriesId,
                games: createdGames 
            });
        } else {
            // Create single one-off game (no series_id)
            const gameUrl = crypto.randomBytes(6).toString('hex');
            
            const result = await pool.query(
                `INSERT INTO games (venue_id, game_date, max_players, cost_per_player, format, regularity, exclusivity, position_type, game_url, status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open')
                 RETURNING id`,
                [venueId, gameDate, maxPlayers, costPerPlayer, format, 'one-off', exclusivity || 'everyone', positionType || 'outfield_gk', gameUrl]
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
        
        // Get beef relationships (rating 3+)
        const beefsResult = await pool.query(`
            SELECT player_id, target_player_id, rating
            FROM beef
            WHERE rating >= 3
        `);
        
        const highBeefs = new Map();
        const lowBeefs = new Map();
        
        beefsResult.rows.forEach(beef => {
            if (beef.rating >= 3) {
                if (!highBeefs.has(beef.player_id)) highBeefs.set(beef.player_id, []);
                highBeefs.get(beef.player_id).push(beef.target_player_id);
            } else if (beef.rating >= 2) {
                if (!lowBeefs.has(beef.player_id)) lowBeefs.set(beef.player_id, []);
                lowBeefs.get(beef.player_id).push(beef.target_player_id);
            }
        });
        
        // ALGORITHM
        const redTeam = [];
        const blueTeam = [];
        
        // PRIORITY 1: Assign 1 GK to each team
        const goalkeepers = players.filter(p => p.position_preference?.toLowerCase().includes('gk'));
        const outfield = players.filter(p => !p.position_preference?.toLowerCase().includes('gk'));
        
        if (goalkeepers.length >= 1) redTeam.push(goalkeepers[0]);
        if (goalkeepers.length >= 2) blueTeam.push(goalkeepers[1]);
        if (goalkeepers.length >= 3) outfield.push(...goalkeepers.slice(2)); // Extra GKs as outfield
        
        // Helper: Check if player has high beef with team
        const hasHighBeef = (player, team) => {
            const beefs = highBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        
        // Helper: Check if player has low beef with team
        const hasLowBeef = (player, team) => {
            const beefs = lowBeefs.get(player.player_id) || [];
            return team.some(tp => beefs.includes(tp.player_id));
        };
        
        // Helper: Check pair preferences
        const wantsToPairWith = (player, team) => {
            return (player.pairs || []).some(pid => team.find(tp => tp.player_id === pid));
        };
        
        // Helper: Check avoid preferences
        const wantsToAvoid = (player, team) => {
            return (player.avoids || []).some(pid => team.find(tp => tp.player_id === pid));
        };
        
        // Snake draft with constraints
        let assignToRed = true;
        for (const player of outfield) {
            // PRIORITY 2: Avoid high beefs (3+)
            const redBeef = hasHighBeef(player, redTeam);
            const blueBeef = hasHighBeef(player, blueTeam);
            
            if (redBeef && !blueBeef) {
                blueTeam.push(player);
                continue;
            }
            if (blueBeef && !redBeef) {
                redTeam.push(player);
                continue;
            }
            
            // PRIORITY 3: Balance overall stats
            const redTotal = redTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0);
            const blueTotal = blueTeam.reduce((sum, p) => sum + (p.overall_rating || 0), 0);
            
            // Add to weaker team
            if (Math.abs(redTotal - blueTotal) > 10) {
                if (redTotal < blueTotal) {
                    redTeam.push(player);
                } else {
                    blueTeam.push(player);
                }
                continue;
            }
            
            // PRIORITY 4: Pair preferences
            const redPair = wantsToPairWith(player, redTeam);
            const bluePair = wantsToPairWith(player, blueTeam);
            
            if (redPair && !bluePair && !wantsToAvoid(player, redTeam)) {
                redTeam.push(player);
                continue;
            }
            if (bluePair && !redPair && !wantsToAvoid(player, blueTeam)) {
                blueTeam.push(player);
                continue;
            }
            
            // PRIORITY 5: Avoid preferences
            const redAvoid = wantsToAvoid(player, redTeam);
            const blueAvoid = wantsToAvoid(player, blueTeam);
            
            if (redAvoid && !blueAvoid) {
                blueTeam.push(player);
                continue;
            }
            if (blueAvoid && !redAvoid) {
                redTeam.push(player);
                continue;
            }
            
            // PRIORITY 6: Balance defense & fitness within 5%
            const redDef = redTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0);
            const blueDef = blueTeam.reduce((sum, p) => sum + (p.defending_rating || 0), 0);
            const redFit = redTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0);
            const blueFit = blueTeam.reduce((sum, p) => sum + (p.fitness_rating || 0), 0);
            
            if (redDef < blueDef || redFit < blueFit) {
                redTeam.push(player);
                continue;
            }
            if (blueDef < redDef || blueFit < redFit) {
                blueTeam.push(player);
                continue;
            }
            
            // PRIORITY 7: Avoid low beefs (2)
            const redLowBeef = hasLowBeef(player, redTeam);
            const blueLowBeef = hasLowBeef(player, blueTeam);
            
            if (redLowBeef && !blueLowBeef) {
                blueTeam.push(player);
                continue;
            }
            if (blueLowBeef && !redLowBeef) {
                redTeam.push(player);
                continue;
            }
            
            // Default: Snake draft
            if (assignToRed) {
                redTeam.push(player);
            } else {
                blueTeam.push(player);
            }
            assignToRed = !assignToRed;
        }
        
        // Delete existing teams if any
        await pool.query('DELETE FROM teams WHERE game_id = $1', [gameId]);
        
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
                isGK: p.position_preference?.toLowerCase().includes('gk')
            })),
            blueTeam: blueTeam.map(p => ({
                id: p.player_id,
                name: p.alias || p.full_name,
                squadNumber: p.squad_number,
                overall: p.overall_rating,
                isGK: p.position_preference?.toLowerCase().includes('gk')
            })),
            redStats,
            blueStats
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

app.post('/api/admin/games/:gameId/add-player', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { playerId } = req.body;
        
        await pool.query(
            `INSERT INTO registrations (game_id, player_id, status, position_preference)
             VALUES ($1, $2, 'confirmed', 'outfield')`,
            [req.params.gameId, playerId]
        );
        
        res.json({ message: 'Player added' });
    } catch (error) {
        console.error('Add player error:', error);
        res.status(500).json({ error: 'Failed to add player' });
    }
});

app.delete('/api/admin/games/:gameId/remove-player/:playerId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM registrations WHERE game_id = $1 AND player_id = $2',
            [req.params.gameId, req.params.playerId]
        );
        
        res.json({ message: 'Player removed' });
    } catch (error) {
        console.error('Remove player error:', error);
        res.status(500).json({ error: 'Failed to remove player' });
    }
});

// ==========================================
// TEAMS
// ==========================================

app.post('/api/admin/games/:gameId/generate-teams', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const gameId = req.params.gameId;
        
        // Get registered players with stats
        const playersResult = await pool.query(`
            SELECT p.id, p.full_name, p.overall_rating, p.defending_rating, p.fitness_rating,
                   p.goalkeeper_rating, r.position_preference
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1 AND r.status = 'confirmed'
            ORDER BY RANDOM()
        `, [gameId]);
        
        const players = playersResult.rows;
        
        if (players.length < 2) {
            return res.status(400).json({ error: 'Need at least 2 players' });
        }
        
        // Simple team balancing algorithm
        // Sort by overall rating (use GK rating if goalkeeper preference)
        const sortedPlayers = players.map(p => ({
            ...p,
            effective_rating: p.position_preference === 'goalkeeper' ? p.goalkeeper_rating : p.overall_rating
        })).sort((a, b) => b.effective_rating - a.effective_rating);
        
        // Alternate allocation (snake draft)
        const redTeam = [];
        const blueTeam = [];
        
        sortedPlayers.forEach((player, index) => {
            if (index % 2 === 0) {
                redTeam.push(player);
            } else {
                blueTeam.push(player);
            }
        });
        
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
                [redTeamId, player.id]
            );
        }
        
        for (const player of blueTeam) {
            await pool.query(
                'INSERT INTO team_players (team_id, player_id) VALUES ($1, $2)',
                [blueTeamId, player.id]
            );
        }
        
        // Mark teams as generated
        await pool.query(
            'UPDATE games SET teams_generated = TRUE WHERE id = $1',
            [gameId]
        );
        
        res.json({ 
            message: 'Teams generated',
            redTeam: redTeam.map(p => ({ id: p.id, name: p.full_name, rating: p.effective_rating })),
            blueTeam: blueTeam.map(p => ({ id: p.id, name: p.full_name, rating: p.effective_rating }))
        });
    } catch (error) {
        console.error('Generate teams error:', error);
        res.status(500).json({ error: 'Failed to generate teams' });
    }
});

app.get('/api/games/:gameId/teams', authenticateToken, async (req, res) => {
    try {
        const teamsResult = await pool.query(`
            SELECT t.*, 
                   json_agg(json_build_object(
                       'id', p.id,
                       'name', p.full_name,
                       'alias', p.alias,
                       'squadNumber', p.squad_number,
                       'goals', tp.goals
                   )) as players
            FROM teams t
            LEFT JOIN team_players tp ON tp.team_id = t.id
            LEFT JOIN players p ON p.id = tp.player_id
            WHERE t.game_id = $1
            GROUP BY t.id
            ORDER BY t.team_name
        `, [req.params.gameId]);
        
        res.json(teamsResult.rows);
    } catch (error) {
        console.error('Get teams error:', error);
        res.status(500).json({ error: 'Failed to get teams' });
    }
});

// ==========================================
// BEEF TRACKING
// ==========================================

app.get('/api/admin/beef', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT pb.*, 
                   p1.full_name as player1_name, p1.alias as player1_alias,
                   p2.full_name as player2_name, p2.alias as player2_alias
            FROM player_beef pb
            JOIN players p1 ON pb.player_1_id = p1.id
            JOIN players p2 ON pb.player_2_id = p2.id
            ORDER BY pb.beef_level DESC
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching beef:', error);
        res.status(500).json({ error: 'Failed to fetch beef' });
    }
});

app.post('/api/admin/beef', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { player1Id, player2Id, beefLevel, notes } = req.body;
        
        const [p1, p2] = player1Id < player2Id ? [player1Id, player2Id] : [player2Id, player1Id];
        
        await pool.query(
            `INSERT INTO player_beef (player_1_id, player_2_id, beef_level, notes, created_by)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (player_1_id, player_2_id) 
             DO UPDATE SET beef_level = $3, notes = $4, updated_at = CURRENT_TIMESTAMP`,
            [p1, p2, beefLevel, notes, req.user.userId]
        );
        
        res.json({ message: 'Beef recorded' });
    } catch (error) {
        console.error('Beef tracking error:', error);
        res.status(500).json({ error: 'Failed to track beef' });
    }
});

// ==========================================
// CONTACT FORM
// ==========================================

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, message, playerId } = req.body;
        
        await pool.query(
            'INSERT INTO contact_submissions (name, email, phone, message, player_id) VALUES ($1, $2, $3, $4, $5)',
            [name, email, phone, message, playerId || null]
        );
        
        res.json({ message: 'Message sent' });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// ==========================================
// HEALTH CHECK (Public - no auth needed)
// ==========================================

app.get('/health', async (req, res) => {
    try {
        // Test database connection
        const dbStart = Date.now();
        await pool.query('SELECT 1');
        const dbTime = Date.now() - dbStart;
        
        res.json({ 
            status: 'ok', 
            timestamp: new Date().toISOString(),
            database: 'connected',
            dbResponseTime: `${dbTime}ms`,
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            database: 'disconnected',
            error: error.message 
        });
    }
});

app.get('/', (req, res) => {
    res.json({ 
        service: 'Total Footy API',
        status: 'running',
        version: '4.0',
        health: `${req.protocol}://${req.get('host')}/health`
    });
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
