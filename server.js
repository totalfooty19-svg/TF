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
        const { fullName, alias, email, password, phone, referralCode } = req.body;

        if (!fullName || !email || !password || !phone) {
            return res.status(400).json({ error: 'Full name, email, password, and phone required' });
        }

        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        let role = 'player';
        if (email.toLowerCase() === SUPERADMIN_EMAIL) role = 'superadmin';

        const userResult = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [email.toLowerCase(), passwordHash, role]
        );

        const userId = userResult.rows[0].id;

        const playerResult = await pool.query(
            `INSERT INTO players (user_id, full_name, alias, phone, reliability_tier) 
             VALUES ($1, $2, $3, $4, 'silver') RETURNING id`,
            [userId, fullName, alias || fullName.split(' ')[0], phone]
        );

        const playerId = playerResult.rows[0].id;
        await pool.query('INSERT INTO credits (player_id, balance) VALUES ($1, 0.00)', [playerId]);

        // Handle referral
        if (referralCode) {
            const referralResult = await pool.query(
                'SELECT referrer_id FROM referrals WHERE referral_code = $1 AND referred_id IS NULL',
                [referralCode]
            );
            if (referralResult.rows.length > 0) {
                await pool.query(
                    'UPDATE referrals SET referred_id = $1 WHERE referral_code = $2',
                    [playerId, referralCode]
                );
            }
        }

        // Generate referral code for new player
        const newReferralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        await pool.query(
            'INSERT INTO referrals (referrer_id, referral_code) VALUES ($1, $2)',
            [playerId, newReferralCode]
        );

        res.status(201).json({ message: 'Account created successfully', userId });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
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

// Continuing in next message due to length...

// ==========================================
// ==========================================
// VENUES
// ==========================================

app.get('/api/venues', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, address, postcode FROM venues ORDER BY name');
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
        
        const tier = playerResult.rows[0]?.reliability_tier || 'bronze';
        
        // Tier-based visibility
        let daysAhead = 1; // bronze default
        if (tier === 'silver') daysAhead = 3;
        if (tier === 'gold') daysAhead = 28;
        if (tier === 'white' || tier === 'black') daysAhead = 0;
        
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
        
        const result = await pool.query(`
            SELECT g.*, v.name as venue_name, v.address as venue_address,
                   (SELECT COUNT(*) FROM registrations WHERE game_id = g.id AND status = 'confirmed') as current_players,
                   EXISTS(SELECT 1 FROM registrations WHERE game_id = g.id AND player_id = $1) as is_registered
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.game_date >= CURRENT_TIMESTAMP
            ${isAdmin ? '' : 'AND g.game_date <= CURRENT_TIMESTAMP + INTERVAL \'' + daysAhead + ' days\''}
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
        const { venueId, gameDate, maxPlayers, costPerPlayer, format, regularity, exclusivity } = req.body;
        
        const gameUrl = crypto.randomBytes(6).toString('hex');
        
        const result = await pool.query(
            `INSERT INTO games (venue_id, game_date, max_players, cost_per_player, format, regularity, exclusivity, game_url, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open')
             RETURNING id`,
            [venueId, gameDate, maxPlayers, costPerPlayer, format, regularity || 'one-off', exclusivity || 'everyone', gameUrl]
        );
        
        res.json({ id: result.rows[0].id, gameUrl });
    } catch (error) {
        console.error('Create game error:', error);
        res.status(500).json({ error: 'Failed to create game', details: error.message });
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
// HEALTH CHECK
// ==========================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(`🚀 Total Footy API running on port ${PORT}`);
});
