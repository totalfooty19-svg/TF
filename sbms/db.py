"""Thin PostgreSQL layer (psycopg 3). All SQL lives here."""
import json
import os
import psycopg
from psycopg.types.json import Jsonb
from . import config as C


def connect():
    if not C.DATABASE_URL:
        raise SystemExit('DATABASE_URL is not set (Render: link the totalfooty-db internal connection string)')
    # totalfooty-db is shared with the TotalFooty app, which may already have tables called fixtures, runs,
    # predictions ... Everything the bot owns lives in its own Postgres schema, `sbms`, so nothing can collide.
    conn = psycopg.connect(C.DATABASE_URL, autocommit=True)
    with conn.cursor() as cur:
        cur.execute('CREATE SCHEMA IF NOT EXISTS sbms')
        cur.execute('SET search_path TO sbms')
    return conn


def ensure_schema(conn):
    sql = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'schema.sql')).read()
    with conn.cursor() as cur:
        cur.execute(sql)


def start_run(conn, kind):
    with conn.cursor() as cur:
        cur.execute('INSERT INTO runs (kind) VALUES (%s) RETURNING id', (kind,)); return cur.fetchone()[0]


def finish_run(conn, run_id, **kw):
    with conn.cursor() as cur:
        cur.execute('UPDATE runs SET finished_at = now(), n_events=%s, n_priced=%s, n_suggestions=%s, n_settled=%s, notes=%s, error=%s WHERE id=%s',
                    (kw.get('n_events'), kw.get('n_priced'), kw.get('n_suggestions'), kw.get('n_settled'), Jsonb(kw.get('notes') or {}), kw.get('error'), run_id))


def seen_competition(conn, slug, mapped_to, how):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO competitions_seen (slug, n_events, mapped_to, how) VALUES (%s, 1, %s, %s)
                       ON CONFLICT (slug) DO UPDATE SET last_seen = now(), n_events = competitions_seen.n_events + 1,
                       mapped_to = EXCLUDED.mapped_to, how = EXCLUDED.how""", (slug, mapped_to, how))


def latest_params(conn, league):
    with conn.cursor() as cur:
        cur.execute('SELECT fitted_at, params FROM model_params WHERE league=%s ORDER BY fitted_at DESC LIMIT 1', (league,))
        return cur.fetchone()


def save_params(conn, league, params, source):
    with conn.cursor() as cur:
        cur.execute('INSERT INTO model_params (league, engine, n_matches, source, params) VALUES (%s,%s,%s,%s,%s)',
                    (league, params.get('engine'), params.get('n'), source, Jsonb(params)))


def name_miss(conn, league, name, detail):
    with conn.cursor() as cur:
        cur.execute('INSERT INTO name_misses (league, name, detail) VALUES (%s,%s,%s) ON CONFLICT (league, name) DO UPDATE SET seen_at = now(), detail = EXCLUDED.detail',
                    (league, name, detail))


def upsert_fixture(conn, ev_id, slug, league, home, away, kickoff, hm, am, note, markets):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO fixtures (event_id, slug, league, home, away, kickoff, home_model, away_model, match_note, markets)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (event_id) DO UPDATE SET kickoff = EXCLUDED.kickoff, markets = EXCLUDED.markets,
                       home_model = EXCLUDED.home_model, away_model = EXCLUDED.away_model, match_note = EXCLUDED.match_note
                       RETURNING id""", (ev_id, slug, league, home, away, kickoff, hm, am, note, Jsonb(markets)))
        return cur.fetchone()[0]


def add_prediction(conn, fid, model, lh, la, rho, probs, band, notes=None):
    """The latest prediction per fixture and variant, overwritten each run until kick-off."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO predictions (fixture_id, model, lam_h, lam_a, rho, probs, band, layer_notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (fixture_id, model) DO UPDATE SET made_at = now(), lam_h = EXCLUDED.lam_h, lam_a = EXCLUDED.lam_a,
                       rho = EXCLUDED.rho, probs = EXCLUDED.probs, band = EXCLUDED.band, layer_notes = EXCLUDED.layer_notes""",
                    (fid, model, lh, la, rho, Jsonb(probs), band, Jsonb(notes or {})))


def committee_scores(conn, days=None):
    """Idea 27: each variant's log loss on the result over each league's recently settled fixtures -> {league: {model: (n, ll)}}."""
    days = C.COMMITTEE_DAYS if days is None else days
    with conn.cursor() as cur:
        cur.execute("""SELECT f.league, p.model, count(*), avg(-ln(greatest((p.probs ->> f.outcome_1x2)::float, 1e-6)))
                       FROM predictions p JOIN fixtures f ON f.id = p.fixture_id
                       WHERE f.outcome_1x2 IN ('H', 'D', 'A') AND f.settled_at > now() - make_interval(days => %s)
                         AND p.made_at <= f.kickoff AND p.probs ? f.outcome_1x2
                       GROUP BY f.league, p.model""", (days,))
        out = {}
        for lg, m, n, ll in cur.fetchall(): out.setdefault(lg, {})[m] = (int(n), float(ll))
        return out


def guard(conn, level, check, detail, league=None, fid=None, model=None):
    """Idea 33: a data problem, written once per fixture, check and model every 12 hours (Health tab)."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO guardian_log (level, check_name, detail, league, fixture_id, model)
                       SELECT %s,%s,%s,%s,%s,%s WHERE NOT EXISTS (SELECT 1 FROM guardian_log WHERE check_name = %s
                         AND fixture_id IS NOT DISTINCT FROM %s AND league IS NOT DISTINCT FROM %s AND model IS NOT DISTINCT FROM %s
                         AND at > now() - interval '12 hours')""",
                    (level, check, detail, league, fid, model, check, fid, league, model))


def breaker_leagues(conn, live_models, n=None, trip=None, resume=None):
    """Idea 32: {league: (state, mean clv, bets)} from the live model's last n settled bets per league. A league trips
    below `trip` and stays tripped until it recovers above `resume` (its bets keep being recorded, just not featured)."""
    n = C.BREAKER_N if n is None else n; trip = C.BREAKER_CLV if trip is None else trip; resume = C.BREAKER_RESUME if resume is None else resume
    with conn.cursor() as cur:
        cur.execute("""SELECT league, avg(clv), count(*) FROM (
                         SELECT f.league, s.clv, row_number() OVER (PARTITION BY f.league ORDER BY f.kickoff DESC) AS rn
                         FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
                         WHERE s.order_type = 'take' AND s.model = ANY(%s) AND s.clv IS NOT NULL) x
                       WHERE rn <= %s GROUP BY league""", (list(live_models), n))
        rows = cur.fetchall()
        cur.execute("SELECT DISTINCT ON (league) league, adopted FROM league_tuning WHERE kind = 'breaker' ORDER BY league, decided_at DESC, id DESC")
        was = {lg: a for lg, a in cur.fetchall()}
    out = {}
    for lg, clv, k in rows:
        if k < n: continue
        tripped = was.get(lg, False)
        now_tripped = (clv < resume) if tripped else (clv < trip)
        out[lg] = (now_tripped, float(clv), int(k), tripped)
    return out


def af_allow(conn, kind):
    """API-Football's daily allowance (free plan: 100 requests), shared by every job: True and counted if one more
    request of this kind may be made today (UTC)."""
    with conn.cursor() as cur:
        cur.execute("SELECT coalesce(sum(n), 0) AS total, coalesce(sum(n) FILTER (WHERE kind = %s), 0) AS mine FROM api_budget WHERE day = (now() AT TIME ZONE 'UTC')::date", (kind,))
        total, mine = cur.fetchone()
        cap = {'results': C.AF_RESULTS_BUDGET, 'lineups': C.AF_LINEUPS_BUDGET}.get(kind)
        if total >= C.AF_DAILY_BUDGET or (cap is not None and mine >= cap): return False
        cur.execute("""INSERT INTO api_budget (day, kind, n) VALUES ((now() AT TIME ZONE 'UTC')::date, %s, 1)
                       ON CONFLICT (day, kind) DO UPDATE SET n = api_budget.n + 1""", (kind,))
        return True


def meta_rows(conn):
    """Idea 15: one row per fixture and selection (the first bet found on it), settled against the close, oldest first."""
    with conn.cursor() as cur:
        cur.execute("""SELECT DISTINCT ON (s.fixture_id, s.key) s.fixture_id, s.key, s.ev, s.price, s.spread_pts, s.volume, s.disagreement, s.clv,
                              extract(epoch FROM f.kickoff - s.made_at) / 3600 AS hours, p.band, f.kickoff
                       FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
                       LEFT JOIN predictions p ON p.fixture_id = s.fixture_id AND p.model = s.model
                       WHERE s.order_type = 'take' AND s.clv IS NOT NULL ORDER BY s.fixture_id, s.key, s.made_at""")
        rows = cur.fetchall()
    rows.sort(key=lambda r: r[10])
    return [dict(fid=r[0], key=r[1], ev=r[2], price=r[3], spread_pts=r[4], volume=r[5], disagreement=r[6], clv=r[7], hours=r[8], band=r[9]) for r in rows]


def close_rows(conn, champion='dixon_coles'):
    """Ideas 2 / 20: every settled fixture's price path with its closing price and the champion's probability, by kick-off."""
    with conn.cursor() as cur:
        cur.execute("""SELECT pp.fixture_id, pp.key, pp.hours, pp.p, pp.back_depth3, pp.lay_depth3, pp.volume, c.p AS p_close,
                              (pr.probs ->> pp.key)::float AS p_model, f.kickoff
                       FROM price_path pp JOIN price_path c ON c.fixture_id = pp.fixture_id AND c.key = pp.key AND c.hours = 0
                       JOIN fixtures f ON f.id = pp.fixture_id
                       LEFT JOIN predictions pr ON pr.fixture_id = pp.fixture_id AND pr.model = %s
                       WHERE pp.hours > 0 AND pp.p IS NOT NULL AND c.p IS NOT NULL ORDER BY f.kickoff, pp.fixture_id, pp.key, pp.hours DESC""", (champion,))
        return [dict(fid=a, key=b, hours=h, p=p, back_depth3=bd, lay_depth3=ld, volume=v, p_close=pc, p_model=pm)
                for a, b, h, p, bd, ld, v, pc, pm, _ in cur.fetchall()]


def lineups_due(conn, live_models):
    """Ideas 4 / 21: fixtures kicking off within the line-up window with no line-ups yet, those the live model has a
    suggestion on first. -> [(id, home, away, kickoff, flags)]"""
    lo, hi = C.LINEUP_WINDOW_MIN
    with conn.cursor() as cur:
        cur.execute("""SELECT f.id, f.home, f.away, f.kickoff, f.flags FROM fixtures f
                       WHERE f.kickoff BETWEEN now() + make_interval(mins => %s) AND now() + make_interval(mins => %s)
                         AND NOT EXISTS (SELECT 1 FROM lineups l WHERE l.fixture_id = f.id)
                       ORDER BY EXISTS (SELECT 1 FROM suggestions s WHERE s.fixture_id = f.id AND s.model = ANY(%s)) DESC, f.kickoff""",
                    (lo, hi, list(live_models)))
        return cur.fetchall()


def save_lineups(conn, fid, sides):
    """sides: [(side 'home'/'away', dict(team, team_id, formation, players, names))]. Changes = starters not in the
    team's previous recorded line-up (None when this is the first one seen)."""
    with conn.cursor() as cur:
        for side, t in sides:
            cur.execute("""SELECT fixture_id, players FROM lineups WHERE af_team_id = %s AND fixture_id <> %s ORDER BY fetched_at DESC LIMIT 1""",
                        (t['team_id'], fid))
            prev = cur.fetchone()
            changes = len(set(t['players']) - set(prev[1] or [])) if prev else None
            cur.execute("""INSERT INTO lineups (fixture_id, side, team, af_team_id, formation, players, names, changes, prev_fixture)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (fixture_id, side) DO NOTHING""",
                        (fid, side, t['team'], t['team_id'], t['formation'], Jsonb(t['players']), Jsonb(t['names']), changes, prev[0] if prev else None))


# ---------------------------------------------------------------- self-tuning (tuning.py)
def tuning_rows(conn):
    with conn.cursor() as cur:
        cur.execute('SELECT league, kind, decided_at, adopted, value FROM league_tuning ORDER BY decided_at DESC, id DESC')
        return [dict(league=a, kind=b, decided_at=c, adopted=d, value=e) for a, b, c, d, e in cur.fetchall()]


def add_tuning(conn, league, kind, adopted, value, evidence, source):
    with conn.cursor() as cur:
        cur.execute('INSERT INTO league_tuning (league, kind, adopted, value, evidence, source) VALUES (%s,%s,%s,%s,%s,%s)',
                    (league, kind, adopted, Jsonb(value or {}), Jsonb(evidence or {}), source))


def live_pairs(conn, league, since, champion='dixon_coles'):
    """For each live challenger ('dixon_coles~...'), the probability it and the champion gave the result, on the
    league's settled fixtures that kicked off after `since` (the last recipe change)."""
    with conn.cursor() as cur:
        cur.execute("""SELECT f.id, p.model, (p.probs ->> f.outcome_1x2)::float AS p FROM fixtures f JOIN predictions p ON p.fixture_id = f.id
                       WHERE f.league = %s AND f.outcome_1x2 IS NOT NULL AND f.kickoff > %s AND p.made_at <= f.kickoff
                         AND (p.model = %s OR p.model LIKE %s)""", (league, since, champion, champion + '~%'))
        by = {}
        for fid, model, p in cur.fetchall(): by.setdefault(fid, {})[model] = p
    pairs = {}
    for fid, ms in by.items():
        if champion not in ms or ms[champion] is None: continue
        for m, p in ms.items():
            if m != champion and p is not None: pairs.setdefault(m.split('~', 1)[1], []).append((ms[champion], p))
    return pairs


def anchor_rows(conn, champion='dixon_coles'):
    """Per league, newest first: (kickoff, the probability the champion gave the result, the closing market's)."""
    with conn.cursor() as cur:
        cur.execute("""WITH lc AS (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
                                    WHERE f.outcome_1x2 IS NOT NULL AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC)
                       SELECT f.league, f.kickoff, (p.probs ->> f.outcome_1x2)::float AS p_model, ((lc.rows -> f.outcome_1x2) ->> 'mid_novig')::float AS p_market
                       FROM fixtures f JOIN predictions p ON p.fixture_id = f.id AND p.model = %s JOIN lc ON lc.fixture_id = f.id
                       WHERE f.outcome_1x2 IS NOT NULL AND (lc.rows -> f.outcome_1x2) ->> 'mid_novig' IS NOT NULL
                       ORDER BY f.league, f.kickoff DESC""", (champion,))
        out = {}
        for lg, ko, pm, pk in cur.fetchall(): out.setdefault(lg, []).append((ko, pm, pk))
        return out


def stakes_age_hours(conn, fid):
    with conn.cursor() as cur:
        cur.execute('SELECT extract(epoch FROM now() - computed_at) / 3600 FROM stakes WHERE fixture_id = %s', (fid,))
        r = cur.fetchone(); return float(r[0]) if r else None


def save_stakes(conn, fid, data, head):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO stakes (fixture_id, data, headline_team, headline_zone, swing) VALUES (%s,%s,%s,%s,%s)
                       ON CONFLICT (fixture_id) DO UPDATE SET computed_at = now(), data = EXCLUDED.data, headline_team = EXCLUDED.headline_team,
                       headline_zone = EXCLUDED.headline_zone, swing = EXCLUDED.swing""",
                    (fid, Jsonb(data), head[0] if head else None, head[1] if head else None, head[2] if head else None))


def events_seen(conn, evs):
    """Idea 9: every football event the job saw (any competition), for rest days."""
    with conn.cursor() as cur:
        for ev in evs:
            name = ev.get('name') or ''
            h, a = (x.strip() for x in name.split(' vs ', 1)) if ' vs ' in name else (None, None)
            cur.execute("""INSERT INTO events_seen (event_id, name, home, away, slug, kickoff) VALUES (%s,%s,%s,%s,%s,%s)
                           ON CONFLICT (event_id) DO UPDATE SET kickoff = EXCLUDED.kickoff, seen_at = now()""",
                        (str(ev.get('id')), name, h, a, ev.get('full_slug'), ev.get('start_datetime')))


def venues_for(conn, league):
    with conn.cursor() as cur:
        cur.execute('SELECT team, lat, lon, venue, source FROM venues WHERE league = %s', (league,))
        return {t: dict(lat=a, lon=b, venue=v, source=s) for t, a, b, v, s in cur.fetchall()}


def upsert_venues(conn, league, got):
    """got: {team: dict(venue, lat, lon)} from Wikidata. Rows marked 'manual' are never overwritten."""
    with conn.cursor() as cur:
        for t, v in got.items():
            cur.execute("""INSERT INTO venues (league, team, venue, lat, lon, source) VALUES (%s,%s,%s,%s,%s,'wikidata')
                           ON CONFLICT (league, team) DO UPDATE SET venue = EXCLUDED.venue, lat = EXCLUDED.lat, lon = EXCLUDED.lon,
                           updated_at = now() WHERE venues.source <> 'manual'""", (league, t, v.get('venue'), v['lat'], v['lon']))


def set_flag(conn, fid, name, value):
    with conn.cursor() as cur:
        cur.execute('UPDATE fixtures SET flags = jsonb_set(flags, %s, %s) WHERE id = %s', ([name], Jsonb(value), fid))


def get_flag(conn, fid, name):
    with conn.cursor() as cur:
        cur.execute('SELECT flags -> %s FROM fixtures WHERE id = %s', (name, fid))
        r = cur.fetchone(); return r[0] if r else None


def live_fixtures(conn):
    """Fixtures that kicked off in the last 2h15 and are not settled, with the live model's last pre-match prediction."""
    with conn.cursor() as cur:
        cur.execute("""SELECT f.id, f.home, f.away, f.kickoff, f.markets, f.league, p.lam_h, p.lam_a
                       FROM fixtures f JOIN predictions p ON p.fixture_id = f.id AND p.model = 'dixon_coles'
                       WHERE f.kickoff < now() AND f.kickoff > now() - interval '135 minutes' AND f.settled_at IS NULL""")
        return [dict(id=a, home=b, away=c, kickoff=d, markets=e, league=f_, lh=g, la=h) for a, b, c, d, e, f_, g, h in cur.fetchall()]


def add_inplay_snapshot(conn, fid, minute, sh, sa, probs, rows):
    keep = ('H', 'D', 'A', 'O2.5', 'U2.5')
    compact = {k: {x: (rows[k] or {}).get(x) for x in ('back', 'lay', 'mid_novig', 'back_depth3', 'lay_depth3')} for k in keep if k in rows}
    with conn.cursor() as cur:
        cur.execute('INSERT INTO inplay_snapshots (fixture_id, minute, sh, sa, probs, rows) VALUES (%s,%s,%s,%s,%s,%s)',
                    (fid, minute, sh, sa, Jsonb(probs), Jsonb(compact)))


def open_event(conn, fid, minute, j, rows, kind='jump, no suspension', suspended_s=None, pre=None, at=None, plan=None):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO inplay_events (fixture_id, minute, key, before, after, move, up_key, path, kind, suspended_s, pre, at, plan)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, coalesce(%s, now()), %s) RETURNING id""",
                    (fid, minute, j['key'], j['before'], j['after'], j['move'], j['up_key'], Jsonb([[0, _compact(rows)]]), kind, suspended_s,
                     Jsonb([[round(t), _compact(r)] for t, r in (pre or [])]), at, Jsonb(plan) if plan else None))
        return cur.fetchone()[0]


def open_events(conn):
    """Events still collecting their price path: -> [(id, fixture_id, at, up_key)]"""
    with conn.cursor() as cur:
        cur.execute("SELECT id, fixture_id, at, up_key FROM inplay_events WHERE NOT complete AND at > now() - interval '30 minutes'")
        return cur.fetchall()


def extend_event(conn, eid, seconds, rows):
    with conn.cursor() as cur:
        cur.execute("UPDATE inplay_events SET path = path || %s::jsonb WHERE id = %s", (Jsonb([[round(seconds), _compact(rows)]]), eid))


def close_event(conn, eid, trades):
    with conn.cursor() as cur:
        cur.execute("UPDATE inplay_events SET complete = true, trades = %s WHERE id = %s", (Jsonb(trades), eid))
        # idea 35: the reaction model's planned trade, if any, gets its realised locked profit
        cur.execute("""UPDATE inplay_events SET plan = plan || jsonb_build_object('realised',
                         (((trades -> (plan ->> 'key')) -> 'green') ->> (plan ->> 'exit'))::float) WHERE id = %s AND plan IS NOT NULL""", (eid,))


def reaction_events(conn, limit=3000):
    """Idea 35: completed events, oldest first, for the reaction model."""
    with conn.cursor() as cur:
        cur.execute("""SELECT at, minute, move, up_key, kind, trades, pre FROM inplay_events
                       WHERE complete AND trades IS NOT NULL ORDER BY at DESC LIMIT %s""", (limit,))
        rows = [dict(at=a, minute=m, move=mv, up_key=u, kind=k, trades=t, pre=p) for a, m, mv, u, k, t, p in cur.fetchall()]
    return rows[::-1]


def event_path(conn, eid):
    with conn.cursor() as cur:
        cur.execute('SELECT path FROM inplay_events WHERE id = %s', (eid,))
        r = cur.fetchone(); return r[0] if r else []


def _compact(rows):
    return {k: {x: (rows.get(k) or {}).get(x) for x in ('back', 'lay', 'mid_novig', 'back_depth3', 'lay_depth3')} for k in ('H', 'D', 'A', 'O2.5', 'U2.5') if k in rows}


def last_inplay_rows(conn, fid):
    with conn.cursor() as cur:
        cur.execute('SELECT rows FROM inplay_snapshots WHERE fixture_id = %s ORDER BY at DESC LIMIT 1', (fid,))
        r = cur.fetchone(); return r[0] if r else None


def add_inplay_bet(conn, fid, minute, sh, sa, b):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO inplay_bets (fixture_id, minute, sh, sa, key, contract_id, price, p_model, p_market, p_work, ev)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (fixture_id, key, sh, sa) DO NOTHING RETURNING id""",
                    (fid, minute, sh, sa, b['key'], b['cid'], b['price'], b['p_model'], b['p_market'], b['p_work'], b['ev']))
        r = cur.fetchone(); return r[0] if r else None


def news_adjustments(conn):
    """Idea 5: adjustments still in force."""
    with conn.cursor() as cur:
        cur.execute('SELECT fixture_id, side, attack, defence, reason FROM news_adjustments WHERE expires_at > now()')
        return [dict(fixture_id=a, side=b, attack=c, defence=d, reason=e) for a, b, c, d, e in cur.fetchall()]


def last_quote(conn, fid):
    with conn.cursor() as cur:
        cur.execute('SELECT read_at, rows FROM quotes WHERE fixture_id = %s ORDER BY read_at DESC LIMIT 1', (fid,))
        return cur.fetchone()


def is_flagged(conn, fid, name='sharp_move'):
    with conn.cursor() as cur:
        cur.execute('SELECT flags ? %s FROM fixtures WHERE id = %s', (name, fid))
        r = cur.fetchone(); return bool(r and r[0])


def flag_fixture(conn, fid, name, value):
    """Keeps the largest move seen for the fixture under flags[name] (and every one in flags[name + '_all'])."""
    with conn.cursor() as cur:
        cur.execute("""UPDATE fixtures SET flags = jsonb_set(jsonb_set(flags, %s, coalesce(flags -> %s, '[]'::jsonb) || %s::jsonb),
                                                            %s, CASE WHEN abs(coalesce((flags -> %s ->> 'move')::float, 0)) >= abs(%s)
                                                                     THEN flags -> %s ELSE %s::jsonb END)
                       WHERE id = %s""",
                    ([name + '_all'], name + '_all', Jsonb([value]), [name], name, value['move'], name, Jsonb(value), fid))


def record_paths(conn, hours=C.PATH_HOURS):
    """Ideas 2 and 20: for fixtures settled in the last three days without a path yet, keep the price and depth at each
    of `hours` before kick-off (the last read at or before that time). Runs before the weekly prune removes the reads."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO price_path (fixture_id, hours, read_at, key, p, back, lay, back_depth3, lay_depth3, volume)
                       SELECT f.id, b.h, q.read_at, k.key, ((q.rows -> k.key) ->> 'mid_novig')::float, ((q.rows -> k.key) ->> 'back')::float,
                              ((q.rows -> k.key) ->> 'lay')::float, ((q.rows -> k.key) ->> 'back_depth3')::float,
                              ((q.rows -> k.key) ->> 'lay_depth3')::float, ((q.rows -> k.key) ->> 'volume')::float
                       FROM fixtures f CROSS JOIN unnest(%s::int[]) AS b(h)
                       JOIN LATERAL (SELECT read_at, rows FROM quotes WHERE fixture_id = f.id AND read_at <= f.kickoff - make_interval(hours => b.h)
                                     ORDER BY read_at DESC LIMIT 1) q ON true
                       CROSS JOIN (VALUES ('H'), ('D'), ('A'), ('O2.5'), ('U2.5')) AS k(key)
                       WHERE f.settled_at IS NOT NULL AND f.settled_at > now() - interval '3 days'
                         AND NOT EXISTS (SELECT 1 FROM price_path pp WHERE pp.fixture_id = f.id)
                         AND (q.rows -> k.key) ->> 'mid_novig' IS NOT NULL
                       ON CONFLICT DO NOTHING""", (list(hours),))
        return cur.rowcount


def market_types(conn, seen):
    """seen: {(type, param): count} -> upserted into market_types_seen."""
    with conn.cursor() as cur:
        for (name, param), n in seen.items():
            cur.execute("""INSERT INTO market_types_seen (name, param, n) VALUES (%s, %s, %s)
                           ON CONFLICT (name, param) DO UPDATE SET n = market_types_seen.n + EXCLUDED.n, last_seen = now()""",
                        (name, param or '', n))


def unsampled_types(conn, names):
    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT name FROM market_types_seen WHERE name = ANY(%s) AND sample IS NOT NULL", (list(names),))
        done = {r[0] for r in cur.fetchall()}
    return [n for n in names if n not in done]


def save_sample(conn, name, sample):
    """Idea 16: a sample of a market type's contracts (names, types, params), kept on every row of that type."""
    with conn.cursor() as cur:
        cur.execute("UPDATE market_types_seen SET sample = %s WHERE name = %s", (Jsonb(sample[:40]), name))


def prune(conn):
    """Keep the disk small: old quotes (all but each fixture's last one before kick-off), old fits and old working."""
    with conn.cursor() as cur:
        cur.execute("""DELETE FROM quotes q USING fixtures f WHERE f.id = q.fixture_id AND f.kickoff < now() - make_interval(days => %s)
                       AND q.id <> (SELECT q2.id FROM quotes q2 WHERE q2.fixture_id = q.fixture_id AND q2.read_at <= f.kickoff
                                    ORDER BY q2.read_at DESC LIMIT 1)""", (C.KEEP_QUOTES_DAYS,))
        nq = cur.rowcount
        cur.execute("""DELETE FROM model_params m WHERE fitted_at < now() - make_interval(days => %s)
                       AND fitted_at < (SELECT max(fitted_at) FROM model_params m2 WHERE m2.league = m.league)""", (C.KEEP_PARAMS_DAYS,))
        np_ = cur.rowcount
        cur.execute("""DELETE FROM working w USING fixtures f WHERE f.id = w.fixture_id AND f.kickoff < now() - interval '14 days'""")
        nw = cur.rowcount
        cur.execute("DELETE FROM inplay_snapshots WHERE at < now() - make_interval(days => %s)", (C.KEEP_SNAPSHOTS_DAYS,))
        cur.execute("DELETE FROM events_seen WHERE kickoff < now() - interval '120 days'")
        ne = cur.rowcount
        cur.execute("DELETE FROM guardian_log WHERE at < now() - interval '60 days'")
        return dict(quotes=nq, params=np_, working=nw, events=ne, guardian=cur.rowcount)


def save_working(conn, fid, model, band, rows, pick_key):
    """The latest working for a fixture and variant (every market row, with its gate or order). Overwritten each run."""
    keep = ('key', 'p_model', 'p_capped', 'p_market', 'p_work', 'back', 'lay', 'spread_pts', 'volume', 'take_ev', 'gate',
            'order_type', 'price', 'ev')
    compact = [{k: r.get(k) for k in keep} for r in rows]
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO working (fixture_id, model, band, rows, pick) VALUES (%s,%s,%s,%s,%s)
                       ON CONFLICT (fixture_id, model) DO UPDATE SET made_at = now(), band = EXCLUDED.band, rows = EXCLUDED.rows,
                       pick = EXCLUDED.pick""", (fid, model, band, Jsonb(compact), pick_key))


def manager_changes(conn):
    with conn.cursor() as cur:
        cur.execute('SELECT league, team, manager, changed_on FROM manager_changes')
        return [dict(league=a, team=b, manager=c, changed_on=d) for a, b, c, d in cur.fetchall()]


def add_quotes(conn, fid, rows, is_close=False):
    with conn.cursor() as cur:
        cur.execute('INSERT INTO quotes (fixture_id, rows, is_close) VALUES (%s,%s,%s)', (fid, Jsonb(rows), is_close))


def add_suggestion(conn, fid, model, s, notes=None):
    """A paper suggestion is fixed once made (like a bet taken at that price): later runs never overwrite it.
    order_type 'take' = a BET at the back price on offer; 'rest' = an order resting at s['price'], which is not a bet and
    is recorded apart (29 Sep). One of each per fixture and model: an earlier rest never blocks a later take."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO suggestions (fixture_id, model, key, contract_id, market_id, price, resting_price, p_model, p_market, p_work, ev,
                                                resting_ev, order_type, filled, spread_pts, volume, layer_notes, disagreement, meta_p, pred_move)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (fixture_id, model, order_type) DO NOTHING RETURNING id""",
                    (fid, model, s['key'], s['cid'], s['mid'], s['price'], s['resting_price'], s['p_model'], s['p_market'], s['p_work'], s['ev'],
                     s['resting_ev'], s['order_type'], True if s['order_type'] == 'take' else None, s['spread_pts'], s['volume'], Jsonb(notes or {}),
                     s.get('disagreement'), s.get('meta_p'), s.get('pred_move')))
        r = cur.fetchone(); return r[0] if r else None


def card_made(conn, day):
    with conn.cursor() as cur:
        cur.execute('SELECT 1 FROM daily_cards WHERE day = %s', (day,))
        return cur.fetchone() is not None


def card_candidates(conn, day, live_model, minutes_ahead=30):
    """The live model's latest working for the day's fixtures not yet started: -> [(fid, kickoff, markets, rows, has_take, rests)]
    rests = [(suggestion id, key, resting price)] of the live model's open resting orders on that fixture."""
    with conn.cursor() as cur:
        cur.execute("""SELECT f.id, f.kickoff, f.markets, w.rows,
                              EXISTS (SELECT 1 FROM suggestions s WHERE s.fixture_id = f.id AND s.model = %s AND s.order_type = 'take') AS has_take
                       FROM fixtures f JOIN working w ON w.fixture_id = f.id AND w.model = %s
                       WHERE (f.kickoff AT TIME ZONE 'UTC')::date = %s AND f.kickoff > now() + make_interval(mins => %s)""",
                    (live_model, live_model, day, minutes_ahead))
        fx = cur.fetchall()
        cur.execute("""SELECT s.fixture_id, s.id, s.key, s.price FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
                       WHERE s.model = %s AND s.order_type = 'rest' AND s.status = 'open' AND s.card IS NULL
                         AND (f.kickoff AT TIME ZONE 'UTC')::date = %s""", (live_model, day))
        rests = {}
        for fid, sid, key, price in cur.fetchall(): rests.setdefault(fid, []).append((sid, key, price))
    return [(fid, ko, mk or {}, rows or [], has_take, rests.get(fid, [])) for fid, ko, mk, rows, has_take in fx]


def add_forced(conn, fid, model, r, day):
    """A forced pick: the back price on offer now, whether or not it clears the floor (order_type 'lean')."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO suggestions (fixture_id, model, key, contract_id, market_id, price, p_model, p_market, p_work, ev,
                                                order_type, spread_pts, volume, card, card_day, layer_notes)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'lean',%s,%s,'forced',%s,%s) ON CONFLICT (fixture_id, model, order_type) DO NOTHING RETURNING id""",
                    (fid, model, r['key'], r['cid'], r['mid'], r['back'], r.get('p_model'), r.get('p_market'), r.get('p_work'), r['ev'],
                     r.get('spread_pts'), r.get('volume'), day, Jsonb(dict(card='forced pick: the best price on offer by the model, not a value bet'))))
        x = cur.fetchone(); return x[0] if x else None


def card_rests(conn, ids, day):
    with conn.cursor() as cur:
        cur.execute("UPDATE suggestions SET card = 'rest', card_day = %s WHERE id = ANY(%s)", (day, list(ids)))
        return cur.rowcount


def save_card(conn, day, bets, forced, rests):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO daily_cards (day, bets, forced, rests) VALUES (%s,%s,%s,%s) ON CONFLICT (day) DO NOTHING", (day, bets, forced, rests))


def feature_today(conn, day, n_max, live_models=('dixon_coles', 'elo_cross'), skip_leagues=()):
    """Feature the day's best BETS, up to n_max per kick-off date: takes only, the highest EV at the price that was on
    offer (Mitch, 29 Sep: "the 4 picks should be the best 4 bets available to take there and then"). Resting orders are
    never featured. A featured bet is fixed once made, so the four are the first four found; fewer is correct. Only the
    live variants are featured; testing variants are scored, never featured (register rule)."""
    with conn.cursor() as cur:
        cur.execute("""SELECT count(*) FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
                       WHERE s.featured AND s.order_type = 'take' AND f.kickoff::date = %s""", (day,))
        have = cur.fetchone()[0]
        if have >= n_max: return 0
        cur.execute("""UPDATE suggestions SET featured = true, card = 'bet', card_day = %s WHERE id IN (
                         SELECT s.id FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
                         WHERE NOT s.featured AND s.status = 'open' AND s.order_type = 'take' AND f.kickoff::date = %s
                           AND f.kickoff > now() AND s.model = ANY(%s) AND NOT (f.league = ANY(%s))
                         ORDER BY s.ev DESC LIMIT %s)""", (day, day, list(live_models), list(skip_leagues), n_max - have))
        return cur.rowcount


def fixtures_kicking_off(conn, minutes):
    with conn.cursor() as cur:
        cur.execute("SELECT id, markets, kickoff FROM fixtures WHERE kickoff > now() AND kickoff <= now() + make_interval(mins => %s)", (minutes,))
        return cur.fetchall()


def set_close(conn, fid):
    """Write the closing no-vig price and CLV onto that fixture's open suggestions from its latest close quotes, and
    decide each resting order: filled if any quote read between the suggestion and kick-off showed a back price at or
    above its price (the paper-order fill rule of 29 Sep)."""
    with conn.cursor() as cur:
        cur.execute("""UPDATE suggestions s SET close_novig = ((q.rows -> s.key) ->> 'mid_novig')::float,
                          clv = s.price * ((q.rows -> s.key) ->> 'mid_novig')::float - 1
                       FROM (SELECT DISTINCT ON (fixture_id) fixture_id, rows FROM quotes WHERE fixture_id = %s ORDER BY fixture_id, read_at DESC) q
                       WHERE s.fixture_id = q.fixture_id AND (q.rows -> s.key) ->> 'mid_novig' IS NOT NULL""", (fid,))
        cur.execute("""UPDATE real_bets b SET close_novig = ((q.rows -> b.key) ->> 'mid_novig')::float,
                          clv = b.odds * ((q.rows -> b.key) ->> 'mid_novig')::float - 1
                       FROM (SELECT DISTINCT ON (fixture_id) fixture_id, rows FROM quotes WHERE fixture_id = %s ORDER BY fixture_id, read_at DESC) q
                       WHERE b.fixture_id = q.fixture_id AND NOT b.late AND (q.rows -> b.key) ->> 'mid_novig' IS NOT NULL""", (fid,))
        cur.execute("""UPDATE suggestions s SET filled = EXISTS (
                          SELECT 1 FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
                          WHERE q.fixture_id = s.fixture_id AND q.read_at >= s.made_at AND q.read_at <= f.kickoff
                            AND ((q.rows -> s.key) ->> 'back')::float >= s.price - 1e-9)
                       WHERE s.fixture_id = %s AND s.order_type = 'rest' AND s.status = 'open'""", (fid,))


def to_settle(conn, hours):
    with conn.cursor() as cur:
        # Also fixtures already settled whose other selections are still open: markets settle at different times
        # (on 29 Sep a draw-no-bet selection stayed open after its result market settled). Looked at for 7 days.
        cur.execute("""SELECT f.id, f.markets FROM fixtures f WHERE f.kickoff < now() - make_interval(hours => %s)
                       AND (f.settled_at IS NULL OR (f.kickoff > now() - interval '7 days'
                            AND EXISTS (SELECT 1 FROM suggestions s WHERE s.fixture_id = f.id AND s.status = 'open')))""", (hours,))
        return cur.fetchall()


def settle(conn, fid, outcome_1x2, contract_outcomes, stake=C.PAPER_STAKE, comm=C.COMMISSION, outcome_cs=None):
    with conn.cursor() as cur:
        cur.execute('UPDATE fixtures SET outcome_1x2 = coalesce(%s, outcome_1x2), outcome_cs = coalesce(%s, outcome_cs), settled_at = coalesce(settled_at, now()) WHERE id = %s',
                    (outcome_1x2, outcome_cs, fid))
        cur.execute("SELECT id, contract_id, price, order_type, filled FROM suggestions WHERE fixture_id=%s AND status='open'", (fid,))
        n = 0
        for sid, cid, price, otype, filled in cur.fetchall():
            o = contract_outcomes.get(cid)
            if isinstance(o, str) and o.lower() in ('void', 'voided', 'cancelled', 'canceled', 'refunded'): o = 'void'
            if o not in ('winner', 'loser', 'void'): continue
            pnl = stake * (price - 1) * (1 - comm) if o == 'winner' else (-stake if o == 'loser' else 0.0)
            # the paper-order fill rule (RUN-UPDATE counting rules, 29 Sep): an unfilled resting order is settled as if
            # taken, in its own column ('unfilled'), and reported apart from filled ones
            status = 'unfilled' if (otype == 'rest' and not filled) else 'settled'
            with conn.cursor() as c2:
                c2.execute("UPDATE suggestions SET status=%s, outcome=%s, paper_pnl=%s, settled_at=now() WHERE id=%s", (status, o, pnl, sid))
            n += 1
        # real bets (16 Oct): the same rule, on the stake actually placed
        try:
            cur.execute("""UPDATE real_bets b SET close_novig = ((q.rows -> b.key) ->> 'mid_novig')::float,
                              clv = b.odds * ((q.rows -> b.key) ->> 'mid_novig')::float - 1
                           FROM (SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.rows FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
                                 WHERE q.fixture_id = %s AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC) q
                           WHERE b.fixture_id = q.fixture_id AND b.clv IS NULL AND NOT b.late AND (q.rows -> b.key) ->> 'mid_novig' IS NOT NULL""", (fid,))
            cur.execute("SELECT id, contract_id, odds, stake FROM real_bets WHERE fixture_id = %s AND status = 'open' AND NOT deleted", (fid,))
            for bid, cid, odds, st in cur.fetchall():
                o = contract_outcomes.get(cid)
                if isinstance(o, str) and o.lower() in ('void', 'voided', 'cancelled', 'canceled', 'refunded'): o = 'void'
                if o not in ('winner', 'loser', 'void'): continue
                pnl = st * (odds - 1) * (1 - comm) if o == 'winner' else (-st if o == 'loser' else 0.0)
                with conn.cursor() as c2:
                    c2.execute("UPDATE real_bets SET status = 'settled', outcome = %s, pnl = %s, settled_at = now() WHERE id = %s", (o, round(pnl, 2), bid))
        except Exception:
            pass
        # idea 11: in-play paper bets on the same contracts
        try:
            cur.execute("SELECT id, contract_id, price FROM inplay_bets WHERE fixture_id = %s AND status = 'open'", (fid,))
            for bid, cid, price in cur.fetchall():
                o = contract_outcomes.get(cid)
                if isinstance(o, str) and o.lower() in ('void', 'voided', 'cancelled', 'canceled', 'refunded'): o = 'void'
                if o not in ('winner', 'loser', 'void'): continue
                pnl = stake * (price - 1) * (1 - comm) if o == 'winner' else (-stake if o == 'loser' else 0.0)
                with conn.cursor() as c2:
                    c2.execute("UPDATE inplay_bets SET status = 'settled', outcome = %s, paper_pnl = %s, settled_at = now() WHERE id = %s", (o, pnl, bid))
        except Exception:
            pass
        return n
