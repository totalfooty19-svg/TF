// server.js - Total Footy Backend API
// This handles all database operations, authentication, and business logic

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Allow requests from your frontend
app.use(express.json());

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, done) => {
    if (err) {
        console.error('Error connecting to database:', err);
    } else {
        console.log('✅ Database connected successfully');
        done();
    }
});

// Email configuration (using Gmail SMTP)
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'totalfooty19@gmail.com',
        pass: process.env.EMAIL_PASSWORD // App-specific password
    }
});

// Test email connection
emailTransporter.verify((error, success) => {
    if (error) {
        console.log('⚠️ Email configuration error:', error);
    } else {
        console.log('✅ Email server ready');
    }
});

// JWT Secret (change this in production!)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Admin email (change to your email)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'your-admin-email@totalfooty.co.uk';

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, position, phone } = req.body;

        // Validate input
        if (!name || !email || !password || !position || !phone) {
            return res.status(400).json({ error: 'Name, email, password, position, and phone number are required' });
        }

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create user
        const userResult = await pool.query(
            `INSERT INTO users (email, password_hash, role) 
             VALUES ($1, $2, $3) 
             RETURNING id`,
            [email.toLowerCase(), passwordHash, email.toLowerCase() === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'player']
        );

        const userId = userResult.rows[0].id;

        // Create player profile
        const nameParts = name.trim().split(' ');
        const firstName = nameParts[0];
        const lastName = nameParts.slice(1).join(' ') || '';

        await pool.query(
            `INSERT INTO players (
                user_id, first_name, last_name, phone, default_position,
                defense_rating, strength_rating, pace_rating,
                fitness_rating, mental_rating, assisting_rating, shooting_rating,
                outfield_overall, gk_rating, gk_overall, reliability_tier
            ) VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'bronze')`,
            [userId, firstName, lastName, phone, position]
        );

        // Create credit account with £0 balance
        await pool.query(
            'INSERT INTO credits (player_id, balance) VALUES ((SELECT id FROM players WHERE user_id = $1), 0.00)',
            [userId]
        );

        res.status(201).json({ 
            message: 'Account created successfully',
            userId: userId
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Get user
        const userResult = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];

        // Check password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Get player profile
        const playerResult = await pool.query(
            `SELECT p.*, c.balance as credits 
             FROM players p 
             LEFT JOIN credits c ON c.player_id = p.id 
             WHERE p.user_id = $1`,
            [user.id]
        );

        const player = playerResult.rows[0];

        // Check if admin by email OR role
        const isAdmin = user.email.toLowerCase() === ADMIN_EMAIL.toLowerCase() || user.role === 'admin';

        // Create JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email, role: isAdmin ? 'admin' : 'player' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: `${player.first_name} ${player.last_name}`,
                isAdmin: isAdmin,
                defaultPosition: player.default_position || player.position || 'outfield',
                tier: player.reliability_tier,
                credits: parseFloat(player.credits || 0),
                squadNumber: player.squad_number,
                photoUrl: player.photo_url,
                // Everyone has BOTH sets of stats
                outfieldStats: {
                    overall: player.outfield_overall || player.overall_rating || 0,
                    defence: player.defense_rating || 0,
                    strength: player.strength_rating || 0,
                    pace: player.pace_rating || 0,
                    fitness: player.fitness_rating || 0,
                    mental: player.mental_rating || 0,
                    assisting: player.assisting_rating || 0,
                    shooting: player.shooting_rating || 0
                },
                gkStats: {
                    rating: player.gk_rating || 0,
                    overall: player.gk_overall || player.gk_rating || 0
                },
                appearances: player.total_appearances || 0,
                motmWins: player.motm_wins || 0,
                goals: player.total_goals || 0
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        // Check if user exists
        const userResult = await pool.query(
            'SELECT id, email FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            // Don't reveal if email exists or not (security)
            return res.json({ message: 'If that email exists, a reset link has been sent' });
        }

        const user = userResult.rows[0];

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

        // Store in database (you'll need to add these columns)
        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3',
            [resetTokenHash, resetTokenExpiry, user.id]
        );

        // Send email
        const resetUrl = `https://totalfooty.co.uk/vibecoding/reset-password.html?token=${resetToken}`;
        
        await emailTransporter.sendMail({
            from: '"Total Footy" <totalfooty19@gmail.com>',
            to: email,
            subject: 'Password Reset - Total Footy',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h1 style="color: #00ff41;">Total Footy</h1>
                    <h2>Password Reset Request</h2>
                    <p>You requested a password reset. Click the link below to reset your password:</p>
                    <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background: #00ff41; color: #000; text-decoration: none; border-radius: 4px; font-weight: bold;">
                        Reset Password
                    </a>
                    <p style="margin-top: 20px; color: #666;">This link expires in 1 hour.</p>
                    <p style="color: #666;">If you didn't request this, please ignore this email.</p>
                </div>
            `
        });

        res.json({ message: 'If that email exists, a reset link has been sent' });

    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password required' });
        }

        // Hash the provided token
        const resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Find user with valid token
        const userResult = await pool.query(
            'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()',
            [resetTokenHash]
        );

        if (userResult.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        const user = userResult.rows[0];

        // Hash new password
        const passwordHash = await bcrypt.hash(newPassword, 10);

        // Update password and clear reset token
        await pool.query(
            'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
            [passwordHash, user.id]
        );

        res.json({ message: 'Password reset successful' });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Middleware to verify admin
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==========================================
// GAME ENDPOINTS
// ==========================================

// Get all games
app.get('/api/games', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                g.*,
                v.name as venue_name,
                v.address as venue_address,
                v.image_urls as venue_images,
                COUNT(r.id) FILTER (WHERE r.status = 'confirmed') as current_players
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            LEFT JOIN registrations r ON r.game_id = g.id
            WHERE g.game_date >= CURRENT_DATE
            GROUP BY g.id, v.id
            ORDER BY g.game_date ASC
        `);

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching games:', error);
        res.status(500).json({ error: 'Failed to fetch games' });
    }
});

// Get single game with details
app.get('/api/games/:id', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;

        const gameResult = await pool.query(`
            SELECT 
                g.*,
                v.name as venue_name,
                v.address as venue_address,
                v.postcode as venue_postcode,
                v.image_urls as venue_images
            FROM games g
            LEFT JOIN venues v ON v.id = g.venue_id
            WHERE g.id = $1
        `, [gameId]);

        if (gameResult.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameResult.rows[0];

        // Get registered players
        const playersResult = await pool.query(`
            SELECT 
                p.id,
                p.first_name,
                p.last_name,
                p.position,
                p.squad_number,
                p.reliability_tier,
                r.status,
                r.pair_with_player_id,
                r.avoid_player_id
            FROM registrations r
            JOIN players p ON p.id = r.player_id
            WHERE r.game_id = $1
            ORDER BY r.registered_at ASC
        `, [gameId]);

        game.registered_players = playersResult.rows;

        res.json(game);
    } catch (error) {
        console.error('Error fetching game:', error);
        res.status(500).json({ error: 'Failed to fetch game' });
    }
});

// Register for game
app.post('/api/games/:id/register', authenticateToken, async (req, res) => {
    try {
        const gameId = req.params.id;
        const { position, pairs, avoids } = req.body; // pairs and avoids are arrays

        // Get player ID
        const playerResult = await pool.query(
            'SELECT id, reliability_tier FROM players WHERE user_id = $1',
            [req.user.userId]
        );

        if (playerResult.rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }

        const player = playerResult.rows[0];

        // Check if already registered
        const existingReg = await pool.query(
            'SELECT id FROM registrations WHERE game_id = $1 AND player_id = $2',
            [gameId, player.id]
        );

        if (existingReg.rows.length > 0) {
            return res.status(400).json({ error: 'Already registered for this game' });
        }

        // Check game capacity
        const gameCheck = await pool.query(`
            SELECT 
                g.max_players,
                COUNT(r.id) FILTER (WHERE r.status = 'confirmed') as current_players,
                g.cost_per_player
            FROM games g
            LEFT JOIN registrations r ON r.game_id = g.id
            WHERE g.id = $1
            GROUP BY g.id
        `, [gameId]);

        if (gameCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Game not found' });
        }

        const game = gameCheck.rows[0];

        // Check if game is full
        const isFull = parseInt(game.current_players) >= parseInt(game.max_players);
        const status = isFull ? 'backup' : 'confirmed';

        // Check credits
        if (status === 'confirmed') {
            const creditResult = await pool.query(
                'SELECT balance FROM credits WHERE player_id = $1',
                [player.id]
            );

            if (creditResult.rows.length === 0 || parseFloat(creditResult.rows[0].balance) < parseFloat(game.cost_per_player)) {
                return res.status(400).json({ error: 'Insufficient credits' });
            }

            // Deduct credits
            await pool.query(
                'UPDATE credits SET balance = balance - $1 WHERE player_id = $2',
                [game.cost_per_player, player.id]
            );
        }

        // Register player
        const regResult = await pool.query(`
            INSERT INTO registrations (
                game_id, player_id, status, position_preference
            ) VALUES ($1, $2, $3, $4)
            RETURNING id
        `, [gameId, player.id, status, position || 'outfield']);

        const registrationId = regResult.rows[0].id;

        // Insert pair preferences
        if (pairs && Array.isArray(pairs) && pairs.length > 0) {
            for (const pairPlayerId of pairs) {
                await pool.query(`
                    INSERT INTO registration_preferences (
                        registration_id, target_player_id, preference_type
                    ) VALUES ($1, $2, 'pair')
                `, [registrationId, pairPlayerId]);
            }
        }

        // Insert avoid preferences
        if (avoids && Array.isArray(avoids) && avoids.length > 0) {
            for (const avoidPlayerId of avoids) {
                await pool.query(`
                    INSERT INTO registration_preferences (
                        registration_id, target_player_id, preference_type
                    ) VALUES ($1, $2, 'avoid')
                `, [registrationId, avoidPlayerId]);
            }
        }

        res.json({ 
            message: status === 'confirmed' ? 'Successfully registered' : 'Added to backup list',
            status: status
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to register' });
    }
});

// ==========================================
// ADMIN ENDPOINTS
// ==========================================

// Create game (admin only)
app.post('/api/admin/games', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { venueId, gameDate, maxPlayers, costPerPlayer, format, skillLevel } = req.body;

        const result = await pool.query(`
            INSERT INTO games (
                venue_id, game_date, max_players, cost_per_player, 
                format, skill_level, status
            ) VALUES ($1, $2, $3, $4, $5, $6, 'open')
            RETURNING *
        `, [venueId, gameDate, maxPlayers, costPerPlayer, format, skillLevel]);

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating game:', error);
        res.status(500).json({ error: 'Failed to create game' });
    }
});

// Update game (admin only)
app.put('/api/admin/games/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const gameId = req.params.id;
        const { maxPlayers, costPerPlayer, format, skillLevel, status } = req.body;

        const result = await pool.query(`
            UPDATE games 
            SET max_players = $1, cost_per_player = $2, format = $3, 
                skill_level = $4, status = $5, updated_at = CURRENT_TIMESTAMP
            WHERE id = $6
            RETURNING *
        `, [maxPlayers, costPerPlayer, format, skillLevel, status, gameId]);

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating game:', error);
        res.status(500).json({ error: 'Failed to update game' });
    }
});

// Get all players (admin only)
app.get('/api/admin/players', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.*,
                c.balance as credits,
                u.email
            FROM players p
            LEFT JOIN credits c ON c.player_id = p.id
            LEFT JOIN users u ON u.id = p.user_id
            ORDER BY p.first_name, p.last_name
        `);

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching players:', error);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

// Update player (admin only)
app.put('/api/admin/players/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const playerId = req.params.id;
        const { 
            firstName, lastName, position, squadNumber, reliabilityTier,
            defence, strength, pace, fitness, mental, assisting, shooting, gk, credits
        } = req.body;

        // Calculate overall for outfield players
        let overall = 0;
        if (position === 'outfield') {
            overall = (defence || 0) + (strength || 0) + (pace || 0) + 
                     (fitness || 0) + (mental || 0) + (assisting || 0) + (shooting || 0);
        }

        // Update player
        await pool.query(`
            UPDATE players 
            SET first_name = $1, last_name = $2, position = $3, squad_number = $4,
                reliability_tier = $5, defense_rating = $6, strength_rating = $7,
                pace_rating = $8, fitness_rating = $9, mental_rating = $10,
                assisting_rating = $11, shooting_rating = $12, gk_rating = $13,
                overall_rating = $14, updated_at = CURRENT_TIMESTAMP
            WHERE id = $15
        `, [firstName, lastName, position, squadNumber, reliabilityTier,
            defence, strength, pace, fitness, mental, assisting, shooting, gk, overall, playerId]);

        // Update credits
        if (credits !== undefined) {
            await pool.query(
                'UPDATE credits SET balance = $1 WHERE player_id = $2',
                [credits, playerId]
            );
        }

        res.json({ message: 'Player updated successfully' });
    } catch (error) {
        console.error('Error updating player:', error);
        res.status(500).json({ error: 'Failed to update player' });
    }
});

// Bulk import players (admin only)
app.post('/api/admin/players/bulk-import', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { players } = req.body;

        let imported = 0;
        let failed = 0;

        for (const player of players) {
            try {
                // Create user account with random password (they'll need to reset)
                const tempPassword = Math.random().toString(36).slice(-8);
                const passwordHash = await bcrypt.hash(tempPassword, 10);

                const userResult = await pool.query(
                    'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
                    [player.email || `player${Date.now()}${imported}@temp.local`, passwordHash, 'player']
                );

                const userId = userResult.rows[0].id;

                // Calculate overall
                let overall = 0;
                if (player.position === 'outfield') {
                    overall = (player.defence || 0) + (player.strength || 0) + (player.pace || 0) +
                             (player.fitness || 0) + (player.mental || 0) + (player.assisting || 0) + 
                             (player.shooting || 0);
                }

                // Create player
                const playerResult = await pool.query(`
                    INSERT INTO players (
                        user_id, first_name, last_name, position, squad_number,
                        defense_rating, strength_rating, pace_rating, fitness_rating,
                        mental_rating, assisting_rating, shooting_rating, gk_rating,
                        overall_rating, reliability_tier
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                    RETURNING id
                `, [
                    userId, player.firstName, player.lastName, player.position, player.squadNumber,
                    player.defence || 0, player.strength || 0, player.pace || 0, player.fitness || 0,
                    player.mental || 0, player.assisting || 0, player.shooting || 0, player.gk || 0,
                    overall, player.tier || 'bronze'
                ]);

                // Create credit account
                await pool.query(
                    'INSERT INTO credits (player_id, balance) VALUES ($1, $2)',
                    [playerResult.rows[0].id, player.credits || 0]
                );

                imported++;
            } catch (err) {
                console.error('Failed to import player:', player, err);
                failed++;
            }
        }

        res.json({ 
            message: `Imported ${imported} players, ${failed} failed`,
            imported,
            failed
        });
    } catch (error) {
        console.error('Bulk import error:', error);
        res.status(500).json({ error: 'Failed to import players' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Total Footy API running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
});
