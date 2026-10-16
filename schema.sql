-- SB-MS-2026 schema (PostgreSQL). Safe to run repeatedly. PAPER ONLY: nothing here records a real bet.
-- Runs with search_path = sbms (set in db.connect), so every table and view below is created in the `sbms` schema,
-- apart from the TotalFooty app's own tables in `public`.
CREATE TABLE IF NOT EXISTS runs (
  id bigserial PRIMARY KEY, kind text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
  n_events int, n_priced int, n_suggestions int, n_settled int, notes jsonb, error text);

CREATE TABLE IF NOT EXISTS competitions_seen (
  slug text PRIMARY KEY, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
  n_events int NOT NULL DEFAULT 0, mapped_to text, how text);

CREATE TABLE IF NOT EXISTS model_params (
  league text NOT NULL, fitted_at timestamptz NOT NULL DEFAULT now(), engine text, n_matches int, source text, params jsonb NOT NULL,
  PRIMARY KEY (league, fitted_at));

CREATE TABLE IF NOT EXISTS fixtures (
  id bigserial PRIMARY KEY, event_id text UNIQUE NOT NULL, slug text, league text, home text, away text, kickoff timestamptz,
  home_model text, away_model text, match_note text, markets jsonb,          -- markets: {market_id: {type, param, contracts:{cid:key}}}
  outcome_1x2 text, settled_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS predictions (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), made_at timestamptz NOT NULL DEFAULT now(), model text NOT NULL,
  lam_h double precision, lam_a double precision, rho double precision, probs jsonb NOT NULL, band text);

CREATE TABLE IF NOT EXISTS quotes (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), read_at timestamptz NOT NULL DEFAULT now(), is_close boolean NOT NULL DEFAULT false,
  rows jsonb NOT NULL);                                                       -- {key: {back, lay, mid, spread_pts, volume, cid, mid_novig}}

CREATE TABLE IF NOT EXISTS suggestions (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), made_at timestamptz NOT NULL DEFAULT now(), model text NOT NULL,
  key text NOT NULL, contract_id text, market_id text, price double precision NOT NULL, resting_price double precision,
  p_model double precision, p_market double precision, p_work double precision, ev double precision, resting_ev double precision,
  featured boolean NOT NULL DEFAULT false, status text NOT NULL DEFAULT 'open',
  close_novig double precision, clv double precision, outcome text, paper_pnl double precision, settled_at timestamptz,
  UNIQUE (fixture_id, model));

-- L-1 (29 Sep): 'take' = the back price on offer; 'rest' = an order resting at the floor price, counted only if filled
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS order_type text NOT NULL DEFAULT 'take';
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS filled boolean;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS spread_pts double precision;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS volume double precision;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS layer_notes jsonb;
ALTER TABLE predictions ADD COLUMN IF NOT EXISTS layer_notes jsonb;

-- Bets v resting orders (Mitch, 29 Sep 2026: "rests are treated like bets, they are rarely bets, especially illiquid. The 4
-- picks should be the best 4 bets available to take there and then"). A take is a bet; a rest is an order that is not a
-- bet unless matched, recorded apart. One take and one rest may exist per fixture and model, so an earlier rest can never
-- block a price that becomes takeable later. Only takes are featured.
ALTER TABLE suggestions DROP CONSTRAINT IF EXISTS suggestions_fixture_id_model_key;
CREATE UNIQUE INDEX IF NOT EXISTS suggestions_one_per_type ON suggestions (fixture_id, model, order_type);
UPDATE suggestions SET featured = false WHERE featured AND order_type = 'rest';

-- Manager changes for the manager_change layer, filled from the chat's research (never guessed by the bot)
CREATE TABLE IF NOT EXISTS manager_changes (
  id bigserial PRIMARY KEY, league text NOT NULL, team text NOT NULL, manager text, changed_on date NOT NULL,
  source text, UNIQUE (league, team, changed_on));

CREATE TABLE IF NOT EXISTS name_misses (
  id bigserial PRIMARY KEY, seen_at timestamptz NOT NULL DEFAULT now(), league text, name text, detail text, UNIQUE (league, name));

CREATE TABLE IF NOT EXISTS backtest_results (
  id bigserial PRIMARY KEY, run_at timestamptz NOT NULL DEFAULT now(), league text, season text, n int,
  ll_model double precision, ll_market double precision, n_bets int, roi double precision, detail jsonb);

-- The working behind each fixture's latest price, per model variant (every market row, the gate it failed or the order it
-- made). One row per fixture and variant, overwritten each run, so it stays small. Read by the live page (/model).
CREATE TABLE IF NOT EXISTS working (
  fixture_id bigint REFERENCES fixtures(id), model text NOT NULL, made_at timestamptz NOT NULL DEFAULT now(), band text,
  rows jsonb NOT NULL, pick text, PRIMARY KEY (fixture_id, model));

-- Self-tuning decisions (tuning.py): one row per decision, newest in force. kind: 'recipe' | 'calibration' | 'anchor'.
-- adopted = false rows are reviews that kept what was in force, with the evidence.
CREATE TABLE IF NOT EXISTS league_tuning (
  id bigserial PRIMARY KEY, league text NOT NULL, kind text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now(),
  adopted boolean NOT NULL, value jsonb NOT NULL, evidence jsonb, source text);
CREATE INDEX IF NOT EXISTS league_tuning_idx ON league_tuning (league, kind, decided_at DESC);

-- One prediction per fixture and model variant, overwritten each run until kick-off (the scoreboard uses the last one
-- before kick-off; the price a bet was made at is kept on the bet). Running variations hourly would otherwise fill the
-- 1 GB disk. On the first run after this change, older duplicate rows are removed, keeping the latest.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'predictions_one_per_model') THEN
    DELETE FROM predictions p USING predictions q
      WHERE p.fixture_id = q.fixture_id AND p.model = q.model AND (p.made_at, p.id) < (q.made_at, q.id);
    CREATE UNIQUE INDEX predictions_one_per_model ON predictions (fixture_id, model);
  END IF;
END $$;

-- Indexes: the page and the scoreboard look rows up by fixture; without these they slow down as the tables grow.
CREATE INDEX IF NOT EXISTS predictions_fixture_idx ON predictions (fixture_id, model, made_at);
CREATE INDEX IF NOT EXISTS quotes_fixture_idx ON quotes (fixture_id, read_at);
CREATE INDEX IF NOT EXISTS suggestions_fixture_idx ON suggestions (fixture_id);
CREATE INDEX IF NOT EXISTS fixtures_kickoff_idx ON fixtures (kickoff);

-- The scoreboard: the last prediction before kick-off v the closing no-vig 1X2 price, on every settled fixture.
CREATE OR REPLACE VIEW v_scoreboard AS
WITH last_pred AS (
  SELECT DISTINCT ON (p.fixture_id, p.model) p.* FROM predictions p JOIN fixtures f ON f.id = p.fixture_id
  WHERE p.made_at <= f.kickoff ORDER BY p.fixture_id, p.model, p.made_at DESC),
last_close AS (
  SELECT DISTINCT ON (q.fixture_id) q.* FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
  WHERE q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC)
SELECT f.league, lp.model, count(*) AS n,
  avg(-ln((lp.probs ->> f.outcome_1x2)::float)) AS ll_model,
  avg(-ln(((lc.rows -> f.outcome_1x2) ->> 'mid_novig')::float)) AS ll_market
FROM fixtures f JOIN last_pred lp ON lp.fixture_id = f.id JOIN last_close lc ON lc.fixture_id = f.id
WHERE f.outcome_1x2 IS NOT NULL AND (lc.rows -> f.outcome_1x2) ->> 'mid_novig' IS NOT NULL AND lp.probs ? f.outcome_1x2
GROUP BY ROLLUP (f.league), lp.model;

-- The paper record. Bets (takes) and resting orders are kept apart: a rest is not a bet (29 Sep).
DROP VIEW IF EXISTS v_paper;
CREATE VIEW v_paper AS
SELECT model,
  count(*) FILTER (WHERE order_type = 'take' AND status = 'settled') AS bets_settled,
  count(*) FILTER (WHERE order_type = 'take' AND status = 'open') AS bets_open,
  sum(paper_pnl) FILTER (WHERE order_type = 'take' AND status = 'settled') AS bets_pnl,
  avg(clv) FILTER (WHERE order_type = 'take') AS bets_mean_clv,
  avg((clv > 0)::int) FILTER (WHERE order_type = 'take' AND clv IS NOT NULL) AS bets_beat_close,
  count(*) FILTER (WHERE order_type = 'take' AND featured AND status = 'settled') AS featured_settled,
  sum(paper_pnl) FILTER (WHERE order_type = 'take' AND featured AND status = 'settled') AS featured_pnl,
  count(*) FILTER (WHERE order_type = 'rest') AS rests,
  count(*) FILTER (WHERE order_type = 'rest' AND status = 'settled') AS rests_filled,
  count(*) FILTER (WHERE order_type = 'rest' AND status = 'unfilled') AS rests_unfilled,
  sum(paper_pnl) FILTER (WHERE order_type = 'rest' AND status = 'settled') AS rests_filled_pnl,
  sum(paper_pnl) FILTER (WHERE order_type = 'rest' AND status = 'unfilled') AS rests_unfilled_pnl_as_if,
  avg(clv) FILTER (WHERE order_type = 'rest') AS rests_mean_clv
FROM suggestions GROUP BY model;

-- Idea 25: flags on a fixture (e.g. a sharp price move), recorded by the job.
ALTER TABLE fixtures ADD COLUMN IF NOT EXISTS flags jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Ideas 2 and 20: each settled fixture's prices and order-book depth at 48, 24, 12, 6, 3 and 1 hours before kick-off and
-- at the close, kept after the hourly quotes are pruned (training data for predicting the closing price).
CREATE TABLE IF NOT EXISTS price_path (
  fixture_id bigint REFERENCES fixtures(id), hours int NOT NULL, read_at timestamptz, key text NOT NULL, p double precision,
  back double precision, lay double precision, back_depth3 double precision, lay_depth3 double precision, volume double precision,
  PRIMARY KEY (fixture_id, hours, key));

-- Idea 8: what is at stake in each English fixture (season simulation), refreshed about daily.
CREATE TABLE IF NOT EXISTS stakes (
  fixture_id bigint PRIMARY KEY REFERENCES fixtures(id), computed_at timestamptz NOT NULL DEFAULT now(), data jsonb NOT NULL,
  headline_team text, headline_zone text, swing double precision);

-- Idea 9: every football event seen on Smarkets (cups, Europe, internationals too), for each team's rest days.
CREATE TABLE IF NOT EXISTS events_seen (
  event_id text PRIMARY KEY, name text, home text, away text, slug text, kickoff timestamptz NOT NULL, seen_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS events_seen_home_idx ON events_seen (home, kickoff);
CREATE INDEX IF NOT EXISTS events_seen_away_idx ON events_seen (away, kickoff);

-- Idea 10: each team's home ground (Wikidata, or 'manual' rows to correct it) and each fixture's weather.
CREATE TABLE IF NOT EXISTS venues (
  league text NOT NULL, team text NOT NULL, venue text, lat double precision, lon double precision, source text,
  updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (league, team));

-- Idea 11: in-play. Snapshots of each live fixture (score, minute, model and book) and in-play paper bets, kept apart
-- from the pre-match record. One bet per fixture, selection and score, so a price is not bet again at the same score.
CREATE TABLE IF NOT EXISTS inplay_snapshots (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), at timestamptz NOT NULL DEFAULT now(), minute double precision,
  sh int, sa int, probs jsonb, rows jsonb);
CREATE INDEX IF NOT EXISTS inplay_snapshots_fixture_idx ON inplay_snapshots (fixture_id, at);
CREATE TABLE IF NOT EXISTS inplay_bets (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), at timestamptz NOT NULL DEFAULT now(), minute double precision,
  sh int, sa int, key text NOT NULL, contract_id text, price double precision NOT NULL, p_model double precision,
  p_market double precision, p_work double precision, ev double precision, status text NOT NULL DEFAULT 'open', outcome text,
  paper_pnl double precision, settled_at timestamptz, UNIQUE (fixture_id, key, sh, sa));

-- Idea 5: team-news adjustments recorded by the scheduled news analyst (through sbms-page's /adjust, with NEWS_KEY).
-- Multipliers on one side's goals scored (attack) and conceded (defence), each with its reason and source; priced by
-- the 'news' layer as a testing variant, so they must beat the model without them to count.
CREATE TABLE IF NOT EXISTS news_adjustments (
  id bigserial PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now(), fixture_id bigint REFERENCES fixtures(id), league text,
  team text, side text NOT NULL, attack double precision NOT NULL DEFAULT 1, defence double precision NOT NULL DEFAULT 1,
  reason text NOT NULL, source text, expires_at timestamptz NOT NULL, author text);

-- Goal reaction (Mitch, 30 Sep): each sharp in-play jump of the result market (a goal or a red card), the book for
-- the next few minutes, and the paper trades worked out from it (back then lay = trade out; back and hold).
CREATE TABLE IF NOT EXISTS inplay_events (
  id bigserial PRIMARY KEY, fixture_id bigint REFERENCES fixtures(id), at timestamptz NOT NULL DEFAULT now(), minute double precision,
  key text, before double precision, after double precision, move double precision, path jsonb NOT NULL DEFAULT '[]'::jsonb,
  trades jsonb, complete boolean NOT NULL DEFAULT false);
ALTER TABLE inplay_events ADD COLUMN IF NOT EXISTS up_key text;
ALTER TABLE inplay_events ADD COLUMN IF NOT EXISTS kind text;
ALTER TABLE inplay_events ADD COLUMN IF NOT EXISTS suspended_s double precision;
ALTER TABLE inplay_events ADD COLUMN IF NOT EXISTS pre jsonb;
ALTER TABLE inplay_events ADD COLUMN IF NOT EXISTS plan jsonb;          -- idea 35: the reaction model's paper trade on this event   -- the reads just before a suspension (pre-goal drift)
CREATE INDEX IF NOT EXISTS inplay_events_open_idx ON inplay_events (complete, at);

-- Idea 16: every Smarkets market type the bot has seen, so the extra markets are wired to their real names.
CREATE TABLE IF NOT EXISTS market_types_seen (
  name text NOT NULL, param text NOT NULL DEFAULT '', n bigint NOT NULL DEFAULT 0, first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (name, param));

-- ---------------------------------------------------------------- Research (29 Sep 2026; the page's Research tab)
-- Idea 3: are resting orders picked off? Filled v unfilled resting orders v bets: closing-line value and results.
DROP VIEW IF EXISTS v_research_fills;
CREATE VIEW v_research_fills AS
SELECT model, order_type, coalesce(filled, false) AS filled, count(*) AS n, avg(clv) AS mean_clv, avg((clv > 0)::int) AS beat_close,
  sum(paper_pnl) AS pnl, avg((outcome = 'winner')::int) AS win_rate, avg(1 / price) AS implied_at_price
FROM suggestions WHERE status IN ('settled', 'unfilled') GROUP BY model, order_type, coalesce(filled, false);

-- Idea 12: is the closing price biased? Every settled fixture's result market at its last read before kick-off, the
-- no-vig probability against what happened, split by price band, by how busy the market was, and by home / draw / away.
DROP VIEW IF EXISTS v_research_close;
CREATE VIEW v_research_close AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
x AS (SELECT f.id, k.key, ((lc.rows -> k.key) ->> 'mid_novig')::float AS p, ((lc.rows -> 'H') ->> 'volume')::float AS vol,
             (f.outcome_1x2 = k.key)::int AS won
      FROM fixtures f JOIN lc ON lc.fixture_id = f.id CROSS JOIN (VALUES ('H'), ('D'), ('A')) AS k(key)
      WHERE (lc.rows -> k.key) ->> 'mid_novig' IS NOT NULL),
v AS (SELECT x.*, ntile(3) OVER (ORDER BY vol NULLS FIRST) AS vol_tier FROM x)
SELECT 'price band' AS dimension, (floor(p * 5) / 5)::text || '–' || ((floor(p * 5) + 1) / 5)::text AS bucket, count(*) AS n, avg(p) AS implied, avg(won) AS actual
  FROM v GROUP BY floor(p * 5)
UNION ALL
SELECT 'market busyness', CASE vol_tier WHEN 1 THEN 'quietest third' WHEN 2 THEN 'middle third' ELSE 'busiest third' END, count(*), avg(p), avg(won)
  FROM v GROUP BY vol_tier
UNION ALL
SELECT 'selection', CASE key WHEN 'H' THEN 'home' WHEN 'D' THEN 'draw' ELSE 'away' END, count(*), avg(p), avg(won)
  FROM v GROUP BY key;

-- Idea 23: kick-off slots (UK time). The live model's log loss v the closing market's, by slot.
DROP VIEW IF EXISTS v_research_slots;
CREATE VIEW v_research_slots AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
x AS (SELECT f.kickoff AT TIME ZONE 'Europe/London' AS uk, (p.probs ->> f.outcome_1x2)::float AS pm,
             ((lc.rows -> f.outcome_1x2) ->> 'mid_novig')::float AS pk
      FROM fixtures f JOIN predictions p ON p.fixture_id = f.id AND p.model = 'dixon_coles' JOIN lc ON lc.fixture_id = f.id
      WHERE (lc.rows -> f.outcome_1x2) ->> 'mid_novig' IS NOT NULL),
s AS (SELECT CASE
        WHEN extract(isodow FROM uk) BETWEEN 2 AND 4 THEN 'midweek (Tue–Thu)'
        WHEN extract(isodow FROM uk) = 5 THEN 'Friday'
        WHEN extract(isodow FROM uk) = 1 THEN 'Monday'
        WHEN extract(isodow FROM uk) = 6 AND extract(hour FROM uk) < 14 THEN 'Saturday early'
        WHEN extract(isodow FROM uk) = 6 AND extract(hour FROM uk) < 17 THEN 'Saturday 3pm'
        WHEN extract(isodow FROM uk) = 6 THEN 'Saturday evening'
        ELSE 'Sunday' END AS slot, pm, pk FROM x)
SELECT slot, count(*) AS n, avg(-ln(pm)) AS ll_model, avg(-ln(pk)) AS ll_market FROM s GROUP BY slot;

-- Idea 25: were the flagged sharp moves informed? The largest move on each settled fixture: the probability before and
-- after it, against how often that outcome happened. Informed money: the result tracks the new price (or beyond).
DROP VIEW IF EXISTS v_research_moves;
CREATE VIEW v_research_moves AS
WITH x AS (SELECT (f.flags -> 'sharp_move' ->> 'key') AS key, (f.flags -> 'sharp_move' ->> 'before')::float AS before,
                  (f.flags -> 'sharp_move' ->> 'after')::float AS after, (f.flags -> 'sharp_move' ->> 'hours_to_kickoff')::float AS hrs,
                  f.outcome_1x2, f.id
           FROM fixtures f WHERE f.flags ? 'sharp_move' AND f.outcome_1x2 IS NOT NULL AND (f.flags -> 'sharp_move' ->> 'key') IN ('H', 'D', 'A'))
SELECT CASE WHEN after > before THEN 'shortened (money for it)' ELSE 'drifted (money against it)' END AS direction,
       CASE WHEN hrs <= 1.5 THEN 'last 90 minutes (team news)' ELSE 'earlier' END AS timing,
       count(*) AS n, avg(before) AS p_before, avg(after) AS p_after, avg((outcome_1x2 = key)::int) AS happened
FROM x GROUP BY 1, 2;

-- Ideas 2 and 20: how much sharper is the price at each point before kick-off? The result market's log loss at 48, 24,
-- 12, 6, 3, 1 hours before and at the close, and the average move still to come.
DROP VIEW IF EXISTS v_research_drift;
CREATE VIEW v_research_drift AS
WITH r AS (SELECT pp.fixture_id, pp.hours, max(CASE WHEN pp.key = f.outcome_1x2 THEN pp.p END) AS p_out,
                  sum(pp.p) FILTER (WHERE pp.key IN ('H', 'D', 'A')) AS s, max(CASE WHEN pp.key = 'H' THEN pp.p END) AS ph
           FROM price_path pp JOIN fixtures f ON f.id = pp.fixture_id WHERE f.outcome_1x2 IS NOT NULL GROUP BY pp.fixture_id, pp.hours),
c AS (SELECT fixture_id, ph AS ph_close FROM r WHERE hours = 0)
SELECT r.hours, count(*) AS n, avg(-ln(r.p_out / r.s)) AS ll, avg(abs(r.ph - c.ph_close)) AS move_to_close
FROM r LEFT JOIN c ON c.fixture_id = r.fixture_id WHERE r.p_out IS NOT NULL AND r.s > 0 GROUP BY r.hours;

-- Idea 9: fatigue. Days since each side's previous match of any kind (events_seen), and whether the market (and the
-- model) got fixtures with a rest-day gap right: how often the home side won against what the closing price said.
DROP VIEW IF EXISTS v_research_rest;
CREATE VIEW v_research_rest AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
r AS (SELECT f.id, f.outcome_1x2,
        (SELECT extract(epoch FROM f.kickoff - max(e.kickoff)) / 86400 FROM events_seen e
          WHERE (e.home = f.home OR e.away = f.home) AND e.kickoff < f.kickoff - interval '12 hours' AND e.kickoff > f.kickoff - interval '21 days') AS rest_h,
        (SELECT extract(epoch FROM f.kickoff - max(e.kickoff)) / 86400 FROM events_seen e
          WHERE (e.home = f.away OR e.away = f.away) AND e.kickoff < f.kickoff - interval '12 hours' AND e.kickoff > f.kickoff - interval '21 days') AS rest_a,
        ((lc.rows -> 'H') ->> 'mid_novig')::float AS p_home, ((lc.rows -> f.outcome_1x2) ->> 'mid_novig')::float AS p_out,
        (SELECT (p.probs ->> f.outcome_1x2)::float FROM predictions p WHERE p.fixture_id = f.id AND p.model = 'dixon_coles') AS m_out
      FROM fixtures f JOIN lc ON lc.fixture_id = f.id)
SELECT CASE WHEN rest_h IS NULL OR rest_a IS NULL THEN 'unknown (no earlier match seen)'
            WHEN rest_h - rest_a >= 2 THEN 'home side 2+ days fresher'
            WHEN rest_a - rest_h >= 2 THEN 'away side 2+ days fresher' ELSE 'similar rest' END AS rest,
       count(*) AS n, avg(p_home) AS home_price, avg((outcome_1x2 = 'H')::int) AS home_won,
       avg(-ln(m_out)) AS ll_model, avg(-ln(p_out)) AS ll_market
FROM r WHERE p_home IS NOT NULL GROUP BY 1;

-- Idea 31 (30 Sep): how much the variants disagreed about a suggestion's selection (highest minus lowest probability)
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS disagreement double precision;

-- Idea 33 (30 Sep): the data guardian's findings (Health tab)
CREATE TABLE IF NOT EXISTS guardian_log (
  id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), level text NOT NULL, check_name text NOT NULL, detail text,
  league text, fixture_id bigint, model text);
CREATE INDEX IF NOT EXISTS guardian_log_at_idx ON guardian_log (at);

-- Idea 29 (30 Sep): when to bet. Bets (and rests) by how long before kick-off they were made: the closing-line value
-- says whether the model's edge is best taken early (before the market sharpens) or late (when the market knows more).
DROP VIEW IF EXISTS v_research_timing;
CREATE VIEW v_research_timing AS
WITH s AS (SELECT s.model, s.order_type, s.ev, s.clv, s.paper_pnl, s.status, extract(epoch FROM f.kickoff - s.made_at) / 3600 AS h
           FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id WHERE s.clv IS NOT NULL)
SELECT model, order_type,
       CASE WHEN h >= 36 THEN 1 WHEN h >= 18 THEN 2 WHEN h >= 9 THEN 3 WHEN h >= 4 THEN 4 WHEN h >= 1.5 THEN 5 ELSE 6 END AS ord,
       CASE WHEN h >= 36 THEN '36 h or more' WHEN h >= 18 THEN '18-36 h' WHEN h >= 9 THEN '9-18 h' WHEN h >= 4 THEN '4-9 h'
            WHEN h >= 1.5 THEN '1.5-4 h' ELSE 'under 1.5 h' END AS before_ko,
       count(*) AS n, avg(ev) AS ev, avg(clv) AS clv, avg((clv > 0)::int) AS beat_close,
       sum(paper_pnl) FILTER (WHERE status = 'settled') AS pnl, count(*) FILTER (WHERE status = 'settled') AS settled
FROM s GROUP BY 1, 2, 3, 4;

-- Idea 30 (30 Sep): does pressure show before a goal? The two minutes of prices before each suspension: how far the
-- side the market then moved towards had already shortened. Checks that came to nothing are the baseline.
DROP VIEW IF EXISTS v_research_pregoal;
CREATE VIEW v_research_pregoal AS
WITH x AS (SELECT e.kind, e.suspended_s, e.minute,
                  (((e.pre -> -1 -> 1) -> e.up_key) ->> 'mid_novig')::float - (((e.pre -> 0 -> 1) -> e.up_key) ->> 'mid_novig')::float AS drift
           FROM inplay_events e WHERE e.pre IS NOT NULL AND jsonb_array_length(e.pre) >= 2 AND e.up_key IS NOT NULL)
SELECT kind, count(*) AS n, avg(drift) AS drift, avg((drift > 0.005)::int) AS shortened, avg((drift < -0.005)::int) AS drifted,
       avg(suspended_s) AS suspended_s, percentile_cont(0.5) WITHIN GROUP (ORDER BY suspended_s) AS suspended_median
FROM x WHERE drift IS NOT NULL GROUP BY kind;

-- Idea 31 (30 Sep): do bets the variants disagree about do worse?
DROP VIEW IF EXISTS v_research_disagree;
CREATE VIEW v_research_disagree AS
SELECT model, order_type,
       CASE WHEN disagreement < 0.03 THEN 1 WHEN disagreement < 0.06 THEN 2 WHEN disagreement < 0.10 THEN 3 ELSE 4 END AS ord,
       CASE WHEN disagreement < 0.03 THEN 'under 3 points' WHEN disagreement < 0.06 THEN '3-6 points'
            WHEN disagreement < 0.10 THEN '6-10 points' ELSE '10 points or more' END AS spread,
       count(*) AS n, avg(ev) AS ev, avg(clv) AS clv, avg((clv > 0)::int) AS beat_close,
       sum(paper_pnl) FILTER (WHERE status = 'settled') AS pnl, count(*) FILTER (WHERE status = 'settled') AS settled
FROM suggestions WHERE disagreement IS NOT NULL AND clv IS NOT NULL GROUP BY 1, 2, 3, 4;

-- Idea 34 (30 Sep): nothing to play for. From the season simulations (idea 8): a side is 'nothing at stake' when no
-- zone's chance moves 2 points between winning and losing, 'a lot' when one moves 10+. Does the closing price allow
-- for it? Implied win chance at the close v how often the side won.
DROP VIEW IF EXISTS v_research_stakes;
CREATE VIEW v_research_stakes AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
sw AS (SELECT st.fixture_id,
         coalesce((SELECT max(abs((v ->> 'swing')::float)) FROM jsonb_each(st.data -> 'home') z(k, v) WHERE jsonb_typeof(v) = 'object' AND v ->> 'swing' IS NOT NULL), 0) AS home_sw,
         coalesce((SELECT max(abs((v ->> 'swing')::float)) FROM jsonb_each(st.data -> 'away') z(k, v) WHERE jsonb_typeof(v) = 'object' AND v ->> 'swing' IS NOT NULL), 0) AS away_sw
       FROM stakes st WHERE jsonb_typeof(st.data -> 'home') = 'object'),
sides AS (SELECT f.id, sw.home_sw AS own, sw.away_sw AS opp, ((lc.rows -> 'H') ->> 'mid_novig')::float AS implied, (f.outcome_1x2 = 'H')::int AS won
          FROM fixtures f JOIN sw ON sw.fixture_id = f.id JOIN lc ON lc.fixture_id = f.id
          UNION ALL
          SELECT f.id, sw.away_sw, sw.home_sw, ((lc.rows -> 'A') ->> 'mid_novig')::float, (f.outcome_1x2 = 'A')::int
          FROM fixtures f JOIN sw ON sw.fixture_id = f.id JOIN lc ON lc.fixture_id = f.id)
SELECT CASE WHEN own < 0.02 THEN 'nothing at stake' WHEN own >= 0.10 THEN 'a lot at stake' ELSE 'some' END AS side,
       CASE WHEN opp < 0.02 THEN 'nothing at stake' WHEN opp >= 0.10 THEN 'a lot at stake' ELSE 'some' END AS opponent,
       count(*) AS n, avg(implied) AS implied, avg(won) AS won
FROM sides WHERE implied IS NOT NULL GROUP BY 1, 2;

-- API-Football's daily allowance, shared by the pricing job and the in-play worker (free plan: 100 requests a day)
CREATE TABLE IF NOT EXISTS api_budget (day date NOT NULL, kind text NOT NULL, n int NOT NULL DEFAULT 0, PRIMARY KEY (day, kind));

-- Ideas 15 and 2 / 20 (30 Sep): each suggestion's predicted chance of beating the close, and its selection's predicted
-- move to the close (probability points), recorded so the Research tab can check both models on bets they never saw
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS meta_p double precision;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS pred_move double precision;
DROP VIEW IF EXISTS v_research_meta;
CREATE VIEW v_research_meta AS
SELECT CASE WHEN meta_p < 0.40 THEN 1 WHEN meta_p < 0.50 THEN 2 WHEN meta_p < 0.60 THEN 3 ELSE 4 END AS ord,
       CASE WHEN meta_p < 0.40 THEN 'under 40%' WHEN meta_p < 0.50 THEN '40-50%' WHEN meta_p < 0.60 THEN '50-60%' ELSE '60% or more' END AS predicted,
       count(*) AS n, avg(meta_p) AS meta_p, avg((clv > 0)::int) AS beat_close, avg(clv) AS clv
FROM suggestions WHERE order_type = 'take' AND meta_p IS NOT NULL AND clv IS NOT NULL GROUP BY 1, 2;
DROP VIEW IF EXISTS v_research_closepred;
CREATE VIEW v_research_closepred AS
SELECT CASE WHEN pred_move <= -0.01 THEN 1 WHEN pred_move < 0.01 THEN 2 ELSE 3 END AS ord,
       CASE WHEN pred_move <= -0.01 THEN 'predicted to drift' WHEN pred_move < 0.01 THEN 'predicted to hold' ELSE 'predicted to shorten' END AS predicted,
       order_type, count(*) AS n, avg(pred_move) AS pred_move, avg(close_novig - p_market) AS actual_move, avg(clv) AS clv
FROM suggestions WHERE pred_move IS NOT NULL AND close_novig IS NOT NULL GROUP BY 1, 2, 3;

-- Ideas 4 / 21 (30 Sep): starting line-ups (API-Football, about an hour before kick-off) and how many starters changed
-- from each side's previous recorded line-up
CREATE TABLE IF NOT EXISTS lineups (
  fixture_id bigint NOT NULL REFERENCES fixtures(id), side text NOT NULL, team text, af_team_id int, formation text,
  players jsonb, names jsonb, changes int, prev_fixture bigint, fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (fixture_id, side));
CREATE INDEX IF NOT EXISTS lineups_team_idx ON lineups (af_team_id, fetched_at);

-- Ideas 4 / 21: does the market fully price rotation? Each side's changes against its price three hours before kick-off
-- (before line-ups), its closing price (after) and how often it won.
DROP VIEW IF EXISTS v_research_lineups;
CREATE VIEW v_research_lineups AS
WITH s AS (SELECT l.fixture_id, l.changes, CASE WHEN l.side = 'home' THEN 'H' ELSE 'A' END AS key, f.outcome_1x2
           FROM lineups l JOIN fixtures f ON f.id = l.fixture_id WHERE f.outcome_1x2 IS NOT NULL)
SELECT CASE WHEN s.changes IS NULL THEN 0 WHEN s.changes <= 1 THEN 1 WHEN s.changes <= 3 THEN 2 ELSE 3 END AS ord,
       CASE WHEN s.changes IS NULL THEN 'first line-up seen' WHEN s.changes <= 1 THEN '0-1 changes' WHEN s.changes <= 3 THEN '2-3 changes'
            ELSE '4 or more changes' END AS changes,
       count(*) AS n, avg(p3.p) AS p_before, avg(pc.p) AS p_close, avg((s.outcome_1x2 = s.key)::int) AS won
FROM s LEFT JOIN price_path p3 ON p3.fixture_id = s.fixture_id AND p3.key = s.key AND p3.hours = 3
       LEFT JOIN price_path pc ON pc.fixture_id = s.fixture_id AND pc.key = s.key AND pc.hours = 0
GROUP BY 1, 2;

-- Idea 9 (30 Sep): travel. Distance between the two grounds (Wikidata, venues) against the away side's closing price
-- and results. A long trip the market underrates shows as away sides winning less often than priced.
DROP VIEW IF EXISTS v_research_travel;
CREATE VIEW v_research_travel AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
d AS (SELECT f.id, f.outcome_1x2, ((lc.rows -> 'A') ->> 'mid_novig')::float AS p_away, ((lc.rows -> f.outcome_1x2) ->> 'mid_novig')::float AS p_out,
             (SELECT (p.probs ->> f.outcome_1x2)::float FROM predictions p WHERE p.fixture_id = f.id AND p.model = 'dixon_coles') AS m_out,
             2 * 6371 * asin(sqrt(power(sin(radians(va.lat - vh.lat) / 2), 2) + cos(radians(vh.lat)) * cos(radians(va.lat)) * power(sin(radians(va.lon - vh.lon) / 2), 2))) AS km
      FROM fixtures f JOIN lc ON lc.fixture_id = f.id
      JOIN venues vh ON vh.league = f.league AND vh.team = f.home_model AND vh.lat IS NOT NULL
      JOIN venues va ON va.league = f.league AND va.team = f.away_model AND va.lat IS NOT NULL)
SELECT CASE WHEN km < 50 THEN 1 WHEN km < 200 THEN 2 WHEN km < 400 THEN 3 ELSE 4 END AS ord,
       CASE WHEN km < 50 THEN 'under 50 km (derby)' WHEN km < 200 THEN '50-200 km' WHEN km < 400 THEN '200-400 km' ELSE '400 km or more' END AS trip,
       count(*) AS n, avg(km) AS km, avg(p_away) AS away_priced, avg((outcome_1x2 = 'A')::int) AS away_won,
       avg(-ln(m_out)) AS ll_model, avg(-ln(p_out)) AS ll_market
FROM d WHERE p_away IS NOT NULL GROUP BY 1, 2;

-- Idea 16 (30 Sep): a sample of each unpriced market type's contracts, so extra markets are wired to their real names
ALTER TABLE market_types_seen ADD COLUMN IF NOT EXISTS sample jsonb;

-- Idea 16 (1 Oct): the correct score. The winning correct-score selection (CS_i-j, or CS_oh / CS_od / CS_oa) and how
-- the live model's scoreline grid ('dixon_coles:cs') does against the closing correct-score market.
ALTER TABLE fixtures ADD COLUMN IF NOT EXISTS outcome_cs text;
DROP VIEW IF EXISTS v_research_cs;
CREATE VIEW v_research_cs AS
WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
            WHERE f.outcome_cs IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC),
x AS (SELECT f.league, (p.probs ->> f.outcome_cs)::float AS pm, ((lc.rows -> f.outcome_cs) ->> 'mid_novig')::float AS pk
      FROM fixtures f JOIN lc ON lc.fixture_id = f.id JOIN predictions p ON p.fixture_id = f.id AND p.model = 'dixon_coles:cs')
SELECT coalesce(league, 'all') AS league, count(*) AS n, avg(-ln(greatest(pm, 1e-6))) AS ll_model, avg(-ln(greatest(pk, 1e-6))) AS ll_market
FROM x WHERE pm IS NOT NULL AND pk IS NOT NULL GROUP BY ROLLUP (league);

-- The daily card (Mitch, 16 Oct 2026: "rest these 5, 5 real bets, 5 forced bets"). card = 'bet' | 'forced' | 'rest',
-- card_day = the day it was carded for. Forced picks are suggestions with order_type 'lean': priced at the back price on
-- offer when the card was made, settled like bets, never mixed into the bets' totals.
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS card text;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS card_day date;
CREATE TABLE IF NOT EXISTS daily_cards (day date PRIMARY KEY, made_at timestamptz NOT NULL DEFAULT now(), bets int, forced int, rests int);
DROP VIEW IF EXISTS v_card;
CREATE VIEW v_card AS
SELECT card, count(*) AS n, count(*) FILTER (WHERE status = 'settled') AS settled, count(*) FILTER (WHERE status = 'unfilled') AS unfilled,
       count(*) FILTER (WHERE status = 'open') AS open, sum(paper_pnl) FILTER (WHERE status = 'settled') AS pnl,
       sum(paper_pnl) FILTER (WHERE status = 'unfilled') AS pnl_unfilled_as_if, avg(clv) FILTER (WHERE status = 'settled') AS clv,
       avg((clv > 0)::int) FILTER (WHERE status = 'settled' AND clv IS NOT NULL) AS beat_close, avg(ev) AS ev, avg(price) AS price,
       count(*) FILTER (WHERE status = 'settled' AND outcome = 'winner') AS won
FROM suggestions WHERE card IS NOT NULL GROUP BY card;

-- Does the model add anything to the market? (16 Oct) The live champion blended with the Smarkets price at each point
-- before kick-off (log-linear, weight w on the model), scored on the result. If no w above 0 beats w = 0, the model holds
-- no information the market does not already have at that time.
DROP VIEW IF EXISTS v_research_blend;
CREATE VIEW v_research_blend AS
WITH lp AS (SELECT DISTINCT ON (p.fixture_id) p.fixture_id, p.probs FROM predictions p JOIN fixtures f ON f.id = p.fixture_id
            WHERE p.model = 'dixon_coles' AND p.made_at <= f.kickoff ORDER BY p.fixture_id, p.made_at DESC),
pp AS (SELECT fixture_id, hours, max(p) FILTER (WHERE key = 'H') AS kh, max(p) FILTER (WHERE key = 'D') AS kd, max(p) FILTER (WHERE key = 'A') AS ka
       FROM price_path WHERE key IN ('H', 'D', 'A') GROUP BY 1, 2),
x AS (SELECT pp.hours, (lp.probs ->> f.outcome_1x2)::float AS pm, (lp.probs ->> 'H')::float AS mh, (lp.probs ->> 'D')::float AS md, (lp.probs ->> 'A')::float AS ma,
             (CASE f.outcome_1x2 WHEN 'H' THEN kh WHEN 'D' THEN kd ELSE ka END) / (kh + kd + ka) AS pk,
             kh / (kh + kd + ka) AS nh, kd / (kh + kd + ka) AS nd, ka / (kh + kd + ka) AS na
      FROM fixtures f JOIN lp ON lp.fixture_id = f.id JOIN pp ON pp.fixture_id = f.id
      WHERE f.outcome_1x2 IN ('H', 'D', 'A') AND kh > 0 AND kd > 0 AND ka > 0)
SELECT hours, w, count(*) AS n,
       avg(-ln(exp(w * ln(pm) + (1 - w) * ln(pk)) / (exp(w * ln(mh) + (1 - w) * ln(nh)) + exp(w * ln(md) + (1 - w) * ln(nd)) + exp(w * ln(ma) + (1 - w) * ln(na))))) AS ll
FROM x CROSS JOIN (VALUES (0.0::float), (0.1), (0.2), (0.3), (1.0)) g(w)
WHERE pm > 0 AND mh > 0 AND md > 0 AND ma > 0 GROUP BY 1, 2;

-- Real bets (Mitch, 16 Oct: "an 'I took this bet' thing, confirming the odds, EV and stake, for a real P&L"). Logged from
-- the page with BETS_KEY; settled automatically from the exchange's own result for that selection, like the paper book.
CREATE TABLE IF NOT EXISTS real_bets (
  id bigserial PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now(), fixture_id bigint NOT NULL REFERENCES fixtures(id),
  key text NOT NULL, contract_id text, suggestion_id bigint, model text, tier text NOT NULL, odds double precision NOT NULL,
  stake double precision NOT NULL, p_work double precision, p_model double precision, p_market double precision, ev double precision,
  suggested_price double precision, back_at_log double precision, late boolean NOT NULL DEFAULT false, note text,
  status text NOT NULL DEFAULT 'open', outcome text, pnl double precision, close_novig double precision, clv double precision,
  settled_at timestamptz, deleted boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS real_bets_fixture_idx ON real_bets (fixture_id);
