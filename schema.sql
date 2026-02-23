-- Total Footy Database Schema
-- Run this SQL to create all necessary tables

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'player',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Players table
CREATE TABLE players (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    photo_url TEXT,
    default_position VARCHAR(20) DEFAULT 'outfield', -- Their preferred position
    squad_number INTEGER,
    
    -- Outfield Stats (out of 20 each)
    defense_rating INTEGER DEFAULT 0,
    strength_rating INTEGER DEFAULT 0,
    pace_rating INTEGER DEFAULT 0,
    fitness_rating INTEGER DEFAULT 0,
    mental_rating INTEGER DEFAULT 0,
    assisting_rating INTEGER DEFAULT 0,
    shooting_rating INTEGER DEFAULT 0,
    outfield_overall INTEGER DEFAULT 0, -- Sum of above 7 stats (max 140)
    
    -- Goalkeeper Stats (out of 100)
    gk_rating INTEGER DEFAULT 0,
    gk_overall INTEGER DEFAULT 0, -- Overall rating when playing as GK (out of 100)
    
    -- Performance Stats
    total_goals INTEGER DEFAULT 0,
    
    -- Reliability tracking
    reliability_tier VARCHAR(20) DEFAULT 'bronze',
    on_time_streak INTEGER DEFAULT 0,
    late_count_recent INTEGER DEFAULT 0,
    no_show_count_recent INTEGER DEFAULT 0,
    
    -- Engagement stats
    total_appearances INTEGER DEFAULT 0,
    motm_wins INTEGER DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Credits table
CREATE TABLE credits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    balance DECIMAL(10,2) DEFAULT 0.00,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Credit transactions table
CREATE TABLE credit_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    player_id UUID REFERENCES players(id),
    amount DECIMAL(10,2) NOT NULL,
    type VARCHAR(50) NOT NULL,
    description TEXT,
    admin_id UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Venues table
CREATE TABLE venues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    address TEXT,
    postcode VARCHAR(20),
    style VARCHAR(50),
    parking VARCHAR(50),
    facilities TEXT[],
    map_link TEXT,
    image_urls TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Games table
CREATE TABLE games (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    venue_id UUID REFERENCES venues(id),
    game_date TIMESTAMP NOT NULL,
    max_players INTEGER NOT NULL,
    cost_per_player DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'open',
    format VARCHAR(100),
    skill_level INTEGER,
    teams_generated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Registrations table
CREATE TABLE registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    game_id UUID REFERENCES games(id) ON DELETE CASCADE,
    player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'confirmed',
    position_preference VARCHAR(20), -- 'outfield' or 'goalkeeper' for THIS game
    
    -- Attendance tracking
    checked_in BOOLEAN DEFAULT FALSE,
    attendance_status VARCHAR(50),
    checked_in_at TIMESTAMP,
    
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(game_id, player_id)
);

-- Player preferences table (for pair/avoid)
CREATE TABLE registration_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registration_id UUID REFERENCES registrations(id) ON DELETE CASCADE,
    target_player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    preference_type VARCHAR(10) NOT NULL, -- 'pair' or 'avoid'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(registration_id, target_player_id)
);

-- Teams table
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    game_id UUID REFERENCES games(id) ON DELETE CASCADE,
    team_name VARCHAR(50) NOT NULL,
    total_overall INTEGER,
    total_defense INTEGER,
    total_fitness INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Team players table
CREATE TABLE team_players (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    UNIQUE(team_id, player_id)
);

-- MOTM votes table
CREATE TABLE motm_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    game_id UUID REFERENCES games(id) ON DELETE CASCADE,
    voter_id UUID REFERENCES players(id),
    voted_for_player_id UUID REFERENCES players(id),
    winning_team VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(game_id, voter_id)
);

-- Notifications table
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    game_id UUID REFERENCES games(id),
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Reliability history table
CREATE TABLE reliability_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    player_id UUID REFERENCES players(id) ON DELETE CASCADE,
    game_id UUID REFERENCES games(id),
    previous_tier VARCHAR(20),
    new_tier VARCHAR(20),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default venues (Coventry locations)
INSERT INTO venues (name, address, postcode, style, parking, facilities, image_urls) VALUES
('Corpus Christi', 'Langbank Avenue, Coventry', 'CV3 2PN', '3G', 'Yes', ARRAY['Changing rooms', 'Toilets', 'Floodlights'], ARRAY['https://totalfooty.co.uk/assets/corpuschristi.jpg']),
('Sidney Stringer Academy', 'Cox Street, Coventry', 'CV1 5RN', '3G', 'Limited', ARRAY['Changing rooms', 'Toilets'], ARRAY['https://totalfooty.co.uk/assets/sidneystringer.jpg']),
('Powerleague Coventry', 'Coventry', 'CV5 7FF', '4G', 'Yes', ARRAY['Changing rooms', 'Toilets'], ARRAY['https://totalfooty.co.uk/assets/powerleague.jpg']),
('Daimler Green Community Centre', 'Coventry', 'CV6 1FQ', '3G', 'Yes', ARRAY['Toilets'], ARRAY['https://totalfooty.co.uk/assets/daimlergreen.jpg']),
('War Memorial Park', 'Coventry', 'CV3 6PT', 'Grass', 'Yes', ARRAY['Outdoor pitch'], ARRAY['https://totalfooty.co.uk/assets/warmemorialpark.jpg']);

-- Create indexes for better performance
CREATE INDEX idx_players_user_id ON players(user_id);
CREATE INDEX idx_registrations_game_id ON registrations(game_id);
CREATE INDEX idx_registrations_player_id ON registrations(player_id);
CREATE INDEX idx_games_date ON games(game_date);
CREATE INDEX idx_users_email ON users(email);
