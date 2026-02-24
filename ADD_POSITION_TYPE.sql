-- Add position_type column to games table
ALTER TABLE games ADD COLUMN IF NOT EXISTS position_type VARCHAR(20) DEFAULT 'outfield_gk';

-- Check it was added
SELECT id, format, position_type, series_id FROM games LIMIT 5;
