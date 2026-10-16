// OPTIONAL. The live page is served by its own Render service (sbms-page, sbms/web.py). This file is only for adding the
// same page and feeds to totalfooty-api instead. To do that, copy this file and web/page.html (renamed model-page.html)
// into the API repo, same folder, and mount it:
//   const modelRoutes = require('./model-routes'); app.use('/model', modelRoutes(pool));
// `pool` is your existing pg Pool on totalfooty-db. Nothing here writes to the database or talks to Smarkets.
//   GET /model             the live page (Ultimate HTML layout, reads /model/page-data, refreshes itself every 5 minutes)
//   GET /model/page-data   everything the page shows, in one JSON
//   GET /model/suggestions, /results, /scoreboard, /health   the raw feeds
// Optional: set MODEL_PAGE_KEY in totalfooty-api's environment to require ?key=<value> on every /model address.
const express = require('express');
const path = require('path');

module.exports = function modelRoutes(pool) {
  const r = express.Router();
  const KEY = process.env.MODEL_PAGE_KEY;
  if (KEY) r.use((req, res, next) => (req.query.key === KEY ? next() : res.status(401).send('key required')));
  const rows = async (sql, params = [], optional = false) => {
    try { return (await pool.query(sql, params)).rows; }
    catch (e) { if (optional) return []; throw e; }
  };

  // The live page.
  r.get('/', (req, res) => res.sendFile(path.join(__dirname, 'model-page.html')));

  // Everything the page shows: yesterday to three days ahead, the paper book, the scoreboard, the back-test, health.
  r.get('/page-data', async (req, res) => {
    try {
      const fixtures = await rows(`
        SELECT id, league, slug, home, away, kickoff, outcome_1x2, settled_at, match_note, flags
        FROM sbms.fixtures
        WHERE kickoff >= date_trunc('day', now()) - interval '1 day' AND kickoff < date_trunc('day', now()) + interval '3 days'
        ORDER BY kickoff, league, home`);
      const ids = fixtures.map(f => f.id);
      const preds = ids.length ? await rows(`
        SELECT DISTINCT ON (p.fixture_id, p.model) p.fixture_id, p.model, p.made_at, p.lam_h, p.lam_a, p.rho, p.probs, p.band, p.layer_notes
        FROM sbms.predictions p JOIN sbms.fixtures f ON f.id = p.fixture_id
        WHERE p.fixture_id = ANY($1) AND p.made_at <= f.kickoff
        ORDER BY p.fixture_id, p.model, p.made_at DESC`, [ids]) : [];
      const quotes = ids.length ? await rows(`
        SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.read_at, q.is_close, q.rows
        FROM sbms.quotes q JOIN sbms.fixtures f ON f.id = q.fixture_id
        WHERE q.fixture_id = ANY($1) AND q.read_at <= f.kickoff
        ORDER BY q.fixture_id, q.read_at DESC`, [ids]) : [];
      const working = ids.length ? await rows(`SELECT fixture_id, model, made_at, band, rows, pick FROM sbms.working WHERE fixture_id = ANY($1)`, [ids], true) : [];
      const suggestions = ids.length ? await rows(`SELECT * FROM sbms.suggestions WHERE fixture_id = ANY($1) ORDER BY featured DESC, ev DESC`, [ids]) : [];
      const book = await rows(`
        SELECT s.*, f.kickoff, f.league, f.home, f.away, f.outcome_1x2
        FROM sbms.suggestions s JOIN sbms.fixtures f ON f.id = s.fixture_id
        WHERE s.status IN ('settled', 'unfilled') ORDER BY f.kickoff DESC LIMIT 1000`);
      const paper = await rows('SELECT * FROM sbms.v_paper ORDER BY model');
      const board = await rows('SELECT * FROM sbms.v_scoreboard ORDER BY model, league NULLS FIRST');
      const backtest = await rows(`SELECT DISTINCT ON (league, season) * FROM sbms.backtest_results ORDER BY league, season, run_at DESC`);
      const runs = await rows('SELECT id, kind, started_at, finished_at, n_events, n_priced, n_suggestions, n_settled, notes, error FROM sbms.runs ORDER BY id DESC LIMIT 24');
      const lastFull = await rows(`SELECT id, started_at, finished_at, notes, error FROM sbms.runs WHERE kind = 'full' AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1`);
      const unmapped = await rows('SELECT slug, n_events, last_seen, how FROM sbms.competitions_seen WHERE mapped_to IS NULL ORDER BY n_events DESC LIMIT 100');
      const inferred = await rows(`SELECT slug, mapped_to, n_events FROM sbms.competitions_seen WHERE how = 'inferred' ORDER BY n_events DESC`);
      const names = await rows('SELECT league, name, detail, seen_at FROM sbms.name_misses ORDER BY seen_at DESC LIMIT 100');
      const managers = await rows('SELECT league, team, manager, changed_on, source FROM sbms.manager_changes ORDER BY changed_on DESC LIMIT 100');
      const tuning = await rows('SELECT id, league, kind, decided_at, adopted, value, evidence, source FROM sbms.league_tuning ORDER BY decided_at DESC, id DESC LIMIT 400', [], true);
      const stakes = ids.length ? await rows('SELECT fixture_id, computed_at, data, headline_team, headline_zone, swing FROM sbms.stakes WHERE fixture_id = ANY($1)', [ids], true) : [];
      const inplay = { live: await rows(`SELECT DISTINCT ON (s.fixture_id) s.fixture_id, s.at, s.minute, s.sh, s.sa, s.probs, s.rows, f.home, f.away, f.league, f.kickoff
                                          FROM sbms.inplay_snapshots s JOIN sbms.fixtures f ON f.id = s.fixture_id WHERE s.at > now() - interval '15 minutes'
                                          ORDER BY s.fixture_id, s.at DESC`, [], true),
                       bets: await rows(`SELECT b.*, f.home, f.away, f.league, f.kickoff FROM sbms.inplay_bets b JOIN sbms.fixtures f ON f.id = b.fixture_id
                                          ORDER BY b.at DESC LIMIT 300`, [], true),
                       events: await rows(`SELECT e.id, e.fixture_id, e.at, e.minute, e.key, e.before, e.after, e.move, e.up_key, e.trades, e.kind, e.suspended_s, e.plan, f.home, f.away,
                                                  f.league, f.outcome_1x2 FROM sbms.inplay_events e JOIN sbms.fixtures f ON f.id = e.fixture_id
                                           WHERE e.complete ORDER BY e.at DESC LIMIT 1000`, [], true) };
      const marketTypes = await rows('SELECT name, param, n, last_seen, sample FROM sbms.market_types_seen ORDER BY n DESC LIMIT 200', [], true);
      const research = { fills: await rows('SELECT * FROM sbms.v_research_fills ORDER BY model, order_type, filled', [], true),
                         close: await rows('SELECT * FROM sbms.v_research_close ORDER BY dimension, bucket', [], true),
                         slots: await rows('SELECT * FROM sbms.v_research_slots ORDER BY slot', [], true),
                         moves: await rows('SELECT * FROM sbms.v_research_moves ORDER BY direction, timing', [], true),
                         drift: await rows('SELECT * FROM sbms.v_research_drift ORDER BY hours DESC', [], true),
                         rest: await rows('SELECT * FROM sbms.v_research_rest ORDER BY rest', [], true),
                         timing: await rows('SELECT * FROM sbms.v_research_timing ORDER BY model, order_type, ord', [], true),
                         pregoal: await rows('SELECT * FROM sbms.v_research_pregoal ORDER BY kind', [], true),
                         disagree: await rows('SELECT * FROM sbms.v_research_disagree ORDER BY model, order_type, ord', [], true),
                         stakes: await rows('SELECT * FROM sbms.v_research_stakes ORDER BY side, opponent', [], true),
                         meta: await rows('SELECT * FROM sbms.v_research_meta ORDER BY ord', [], true),
                         closepred: await rows('SELECT * FROM sbms.v_research_closepred ORDER BY order_type, ord', [], true),
                         travel: await rows('SELECT * FROM sbms.v_research_travel ORDER BY ord', [], true),
                         lineups: await rows('SELECT * FROM sbms.v_research_lineups ORDER BY ord', [], true),
                         cs: await rows(`SELECT * FROM sbms.v_research_cs ORDER BY league = 'all' DESC, n DESC`, [], true),
                         blend: await rows('SELECT * FROM sbms.v_research_blend ORDER BY hours DESC, w', [], true) };
      const card = await rows('SELECT * FROM sbms.v_card', [], true);
      const realBets = await rows(`SELECT b.*, f.home, f.away, f.league, f.kickoff, f.outcome_1x2 FROM sbms.real_bets b JOIN sbms.fixtures f ON f.id = b.fixture_id
                                   WHERE NOT b.deleted ORDER BY f.kickoff DESC, b.id DESC LIMIT 3000`, [], true);
      const betsEnabled = false;   // logging real bets goes through sbms-page (sbms/web.py), not this mirror
      const learned = {};
      (await rows(`SELECT DISTINCT ON (league) league, fitted_at, params FROM sbms.model_params WHERE league IN ('META', 'CLOSE')
                   ORDER BY league, fitted_at DESC`, [], true)).forEach(r => { learned[r.league.toLowerCase()] = { fitted_at: r.fitted_at, n: r.params.n, fixtures: r.params.fixtures, test: r.params.test }; });
      const guardian = await rows(`SELECT at, level, check_name, detail, league, fixture_id, model FROM sbms.guardian_log
                                   WHERE at > now() - interval '7 days' ORDER BY at DESC LIMIT 300`, [], true);
      const rm = await rows(`SELECT fitted_at, params FROM sbms.model_params WHERE league = 'REACTION' ORDER BY fitted_at DESC LIMIT 1`, [], true);
      const reaction = rm.length ? { fitted_at: rm[0].fitted_at, n: rm[0].params.n, oos: rm[0].params.oos, edge: rm[0].params.edge } : null;
      res.set('Cache-Control', 'no-store');
      res.json({ now: new Date().toISOString(), fixtures, preds, quotes, working, suggestions, book, paper, board, backtest,
                 runs, lastFull: lastFull[0] || null, unmapped, inferred, names, managers, tuning, research, marketTypes, stakes, inplay, guardian, reaction, learned, card, realBets, betsEnabled });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  const q = async (res, sql, params = []) => {
    try { const { rows } = await pool.query(sql, params); res.json(rows); }
    catch (e) { res.status(500).json({ error: e.message }); }
  };

  // Paper suggestions for the next N days (default 2): featured first, then by EV.
  r.get('/suggestions', (req, res) => q(res, `
    SELECT f.kickoff, f.league, f.home, f.away, s.model, s.key, s.order_type, s.price, s.filled, round((s.ev * 100)::numeric, 1) AS ev_pct,
           round((s.p_model * 100)::numeric, 1) AS model_pct, round((s.p_market * 100)::numeric, 1) AS market_pct,
           s.featured, s.status, s.made_at
    FROM sbms.suggestions s JOIN sbms.fixtures f ON f.id = s.fixture_id
    WHERE f.kickoff > now() - interval '3 hours' AND f.kickoff < now() + make_interval(days => $1)
    ORDER BY s.featured DESC, f.kickoff, s.ev DESC`, [Number(req.query.days || 2)]));

  // Settled paper record.
  r.get('/results', (req, res) => q(res, `
    SELECT f.kickoff, f.league, f.home, f.away, s.model, s.key, s.order_type, s.price, s.filled, s.status, s.close_novig, round((s.clv * 100)::numeric, 1) AS clv_pct,
           s.outcome, s.paper_pnl, s.featured
    FROM sbms.suggestions s JOIN sbms.fixtures f ON f.id = s.fixture_id WHERE s.status IN ('settled', 'unfilled') ORDER BY f.kickoff DESC LIMIT 200`));

  // Does the model beat the market? Log loss per league (lower is better) and the paper totals.
  r.get('/scoreboard', async (req, res) => {
    try {
      const board = (await pool.query('SELECT * FROM sbms.v_scoreboard ORDER BY league NULLS FIRST')).rows;
      const paper = (await pool.query('SELECT * FROM sbms.v_paper')).rows;
      const backtest = (await pool.query(`SELECT DISTINCT ON (league, season) * FROM sbms.backtest_results ORDER BY league, season, run_at DESC`)).rows;
      res.json({ board, paper, backtest });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Health: last runs, competitions seen but not priced, team names that did not match.
  r.get('/health', async (req, res) => {
    try {
      const runs = (await pool.query('SELECT * FROM sbms.runs ORDER BY id DESC LIMIT 12')).rows;
      const unmapped = (await pool.query('SELECT slug, n_events, last_seen, how FROM sbms.competitions_seen WHERE mapped_to IS NULL ORDER BY n_events DESC LIMIT 100')).rows;
      const inferred = (await pool.query(`SELECT slug, mapped_to, n_events FROM sbms.competitions_seen WHERE how = 'inferred' ORDER BY n_events DESC`)).rows;
      const names = (await pool.query('SELECT league, name, detail, seen_at FROM sbms.name_misses ORDER BY seen_at DESC LIMIT 100')).rows;
      res.json({ runs, unmapped, inferred, names });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  return r;
};
