"""The live page: a small read-only web server (Render web service 'sbms-page').

    GET /            the page (web/page.html, Ultimate HTML layout; it reads /page-data and refreshes every 5 minutes)
    GET /page-data   everything the page shows, in one JSON
    GET /healthz     'ok' (Render's health check)

Standard library only, plus psycopg (already a dependency). Every connection is read-only and uses the `sbms` schema,
so nothing here can change the database or touch the TotalFooty app's tables.
Optional: set MODEL_PAGE_KEY to require ?key=<value> on / and /page-data.
Run: python -m sbms.web   (listens on $PORT, default 10000)"""
import datetime as dt
import decimal
import hmac
import json
import os
import pathlib
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import psycopg
from psycopg.rows import dict_row

from . import config as C

PAGE = pathlib.Path(__file__).resolve().parents[1] / 'web' / 'page.html'
KEY = os.environ.get('MODEL_PAGE_KEY', '')
NEWS_KEY = os.environ.get('NEWS_KEY', '')          # ideas 5 / 26: the only key that can write (news adjustments); unset = no writes
BETS_KEY = os.environ.get('BETS_KEY', '')          # 16 Oct: logging real bets from the page ("I took this bet"); unset = off

# The same queries as node/model-routes.js (/page-data). Yesterday to three days ahead, the book, the scoreboard, health.
Q_FIXTURES = """
    SELECT id, league, slug, home, away, kickoff, outcome_1x2, settled_at, match_note, flags FROM fixtures
    WHERE kickoff >= date_trunc('day', now()) - interval '1 day' AND kickoff < date_trunc('day', now()) + interval '3 days'
    ORDER BY kickoff, league, home"""
Q_PREDS = """
    SELECT DISTINCT ON (p.fixture_id, p.model) p.fixture_id, p.model, p.made_at, p.lam_h, p.lam_a, p.rho, p.probs, p.band, p.layer_notes
    FROM predictions p JOIN fixtures f ON f.id = p.fixture_id
    WHERE p.fixture_id = ANY(%s) AND p.made_at <= f.kickoff ORDER BY p.fixture_id, p.model, p.made_at DESC"""
Q_QUOTES = """
    SELECT DISTINCT ON (q.fixture_id) q.fixture_id, q.read_at, q.is_close, q.rows
    FROM quotes q JOIN fixtures f ON f.id = q.fixture_id
    WHERE q.fixture_id = ANY(%s) AND q.read_at <= f.kickoff ORDER BY q.fixture_id, q.read_at DESC"""
Q_WORKING = "SELECT fixture_id, model, made_at, band, rows, pick FROM working WHERE fixture_id = ANY(%s)"
Q_SUGS = "SELECT * FROM suggestions WHERE fixture_id = ANY(%s) ORDER BY featured DESC, ev DESC"
Q_BOOK = """
    SELECT s.*, f.kickoff, f.league, f.home, f.away, f.outcome_1x2 FROM suggestions s JOIN fixtures f ON f.id = s.fixture_id
    WHERE s.status IN ('settled', 'unfilled') ORDER BY f.kickoff DESC LIMIT 1000"""
Q_REST = dict(
    paper='SELECT * FROM v_paper ORDER BY model',
    board='SELECT * FROM v_scoreboard ORDER BY model, league NULLS FIRST',
    backtest='SELECT DISTINCT ON (league, season) * FROM backtest_results ORDER BY league, season, run_at DESC',
    runs='SELECT id, kind, started_at, finished_at, n_events, n_priced, n_suggestions, n_settled, notes, error FROM runs ORDER BY id DESC LIMIT 24',
    unmapped='SELECT slug, n_events, last_seen, how FROM competitions_seen WHERE mapped_to IS NULL ORDER BY n_events DESC LIMIT 100',
    inferred="SELECT slug, mapped_to, n_events FROM competitions_seen WHERE how = 'inferred' ORDER BY n_events DESC",
    names='SELECT league, name, detail, seen_at FROM name_misses ORDER BY seen_at DESC LIMIT 100',
    managers='SELECT league, team, manager, changed_on, source FROM manager_changes ORDER BY changed_on DESC LIMIT 100',
)
Q_TUNING = 'SELECT id, league, kind, decided_at, adopted, value, evidence, source FROM league_tuning ORDER BY decided_at DESC, id DESC LIMIT 400'
Q_LASTFULL = "SELECT id, started_at, finished_at, notes, error FROM runs WHERE kind = 'full' AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1"


def connect():
    conn = psycopg.connect(C.DATABASE_URL, autocommit=True, row_factory=dict_row, connect_timeout=10)
    with conn.cursor() as cur:
        cur.execute('SET search_path TO sbms')
        cur.execute('SET default_transaction_read_only = on')
        cur.execute("SET statement_timeout = '20s'")
    return conn


def page_data():
    with connect() as conn, conn.cursor() as cur:
        def rows(sql, params=None, optional=False):
            try:
                cur.execute(sql, params); return cur.fetchall()
            except psycopg.Error:
                if optional: return []
                raise
        fixtures = rows(Q_FIXTURES)
        ids = [f['id'] for f in fixtures]
        out = dict(now=dt.datetime.now(dt.timezone.utc), fixtures=fixtures,
                   preds=rows(Q_PREDS, (ids,)) if ids else [], quotes=rows(Q_QUOTES, (ids,)) if ids else [],
                   working=rows(Q_WORKING, (ids,), optional=True) if ids else [],
                   suggestions=rows(Q_SUGS, (ids,)) if ids else [], book=rows(Q_BOOK))
        for k, sql in Q_REST.items():
            out[k] = rows(sql)
        out['tuning'] = rows(Q_TUNING, optional=True)
        out['news'] = rows('SELECT * FROM news_adjustments ORDER BY created_at DESC LIMIT 100', optional=True)
        out['inplay'] = dict(
            live=rows("""SELECT DISTINCT ON (s.fixture_id) s.fixture_id, s.at, s.minute, s.sh, s.sa, s.probs, s.rows, f.home, f.away, f.league, f.kickoff
                        FROM inplay_snapshots s JOIN fixtures f ON f.id = s.fixture_id WHERE s.at > now() - interval '15 minutes'
                        ORDER BY s.fixture_id, s.at DESC""", optional=True),
            bets=rows("""SELECT b.*, f.home, f.away, f.league, f.kickoff FROM inplay_bets b JOIN fixtures f ON f.id = b.fixture_id
                        ORDER BY b.at DESC LIMIT 300""", optional=True),
            events=rows("""SELECT e.id, e.fixture_id, e.at, e.minute, e.key, e.before, e.after, e.move, e.up_key, e.trades, e.kind, e.suspended_s, e.plan, f.home, f.away,
                                 f.league, f.outcome_1x2 FROM inplay_events e JOIN fixtures f ON f.id = e.fixture_id
                          WHERE e.complete ORDER BY e.at DESC LIMIT 1000""", optional=True))
        out['stakes'] = rows('SELECT fixture_id, computed_at, data, headline_team, headline_zone, swing FROM stakes WHERE fixture_id = ANY(%s)', (ids,), optional=True) if ids else []
        out['marketTypes'] = rows('SELECT name, param, n, last_seen, sample FROM market_types_seen ORDER BY n DESC LIMIT 200', optional=True)
        out['research'] = dict(fills=rows('SELECT * FROM v_research_fills ORDER BY model, order_type, filled', optional=True),
                               close=rows('SELECT * FROM v_research_close ORDER BY dimension, bucket', optional=True),
                               slots=rows('SELECT * FROM v_research_slots ORDER BY slot', optional=True),
                               moves=rows('SELECT * FROM v_research_moves ORDER BY direction, timing', optional=True),
                               drift=rows('SELECT * FROM v_research_drift ORDER BY hours DESC', optional=True),
                               rest=rows('SELECT * FROM v_research_rest ORDER BY rest', optional=True),
                               timing=rows('SELECT * FROM v_research_timing ORDER BY model, order_type, ord', optional=True),
                               pregoal=rows('SELECT * FROM v_research_pregoal ORDER BY kind', optional=True),
                               disagree=rows('SELECT * FROM v_research_disagree ORDER BY model, order_type, ord', optional=True),
                               stakes=rows('SELECT * FROM v_research_stakes ORDER BY side, opponent', optional=True),
                               meta=rows('SELECT * FROM v_research_meta ORDER BY ord', optional=True),
                               closepred=rows('SELECT * FROM v_research_closepred ORDER BY order_type, ord', optional=True),
                               travel=rows('SELECT * FROM v_research_travel ORDER BY ord', optional=True),
                               lineups=rows('SELECT * FROM v_research_lineups ORDER BY ord', optional=True),
                               cs=rows("SELECT * FROM v_research_cs ORDER BY league = 'all' DESC, n DESC", optional=True),
                               blend=rows('SELECT * FROM v_research_blend ORDER BY hours DESC, w', optional=True))
        out['card'] = rows('SELECT * FROM v_card', optional=True)
        out['learned'] = {r['league'].lower(): dict(fitted_at=r['fitted_at'], n=r['params'].get('n'), fixtures=r['params'].get('fixtures'), test=r['params'].get('test'))
                          for r in rows("""SELECT DISTINCT ON (league) league, fitted_at, params FROM model_params WHERE league IN ('META', 'CLOSE')
                                          ORDER BY league, fitted_at DESC""", optional=True)}
        out['guardian'] = rows("""SELECT at, level, check_name, detail, league, fixture_id, model FROM guardian_log
                                  WHERE at > now() - interval '7 days' ORDER BY at DESC LIMIT 300""", optional=True)
        rm = rows("SELECT fitted_at, params FROM model_params WHERE league = 'REACTION' ORDER BY fitted_at DESC LIMIT 1", optional=True)
        out['reaction'] = dict(fitted_at=rm[0]['fitted_at'], n=rm[0]['params'].get('n'), oos=rm[0]['params'].get('oos'),
                               edge=rm[0]['params'].get('edge')) if rm else None
        out['realBets'] = rows("""SELECT b.*, f.home, f.away, f.league, f.kickoff, f.outcome_1x2 FROM real_bets b JOIN fixtures f ON f.id = b.fixture_id
                                  WHERE NOT b.deleted ORDER BY f.kickoff DESC, b.id DESC LIMIT 3000""", optional=True)
        out['betsEnabled'] = bool(BETS_KEY)
        lf = rows(Q_LASTFULL)
        out['lastFull'] = lf[0] if lf else None
        return out


def upcoming():
    """Ideas 5 and 26: the fixtures of the next 48 hours with the champion's probabilities (small, for scheduled tasks)."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""SELECT f.id, f.league, f.home, f.away, f.kickoff, p.lam_h, p.lam_a, p.probs, p.layer_notes
                       FROM fixtures f LEFT JOIN predictions p ON p.fixture_id = f.id AND p.model = 'dixon_coles'
                       WHERE f.kickoff > now() AND f.kickoff < now() + interval '48 hours' ORDER BY f.kickoff""")
        fx = cur.fetchall()
        cur.execute("SELECT * FROM news_adjustments WHERE expires_at > now() ORDER BY created_at DESC")
        return dict(now=dt.datetime.now(dt.timezone.utc), fixtures=fx, active_adjustments=cur.fetchall())


ADJ_LIMITS = (0.85, 1.15)


def add_adjustment(q):
    """Idea 5: record one news adjustment. Query fields: fixture (id from /upcoming), side ('home' | 'away'),
    attack and defence (multipliers on that side's goals scored / conceded, 0.85-1.15), reason (required, <= 500
    characters), source (a link), hours (how long it applies, default 72, at most 168). -> (status, message)"""
    one = lambda k, d=None: (q.get(k) or [d])[0]
    try:
        fid = int(one('fixture')); side = one('side')
        att, dfn = float(one('attack', 1.0)), float(one('defence', 1.0)); hours = min(float(one('hours', 72)), 168.0)
    except (TypeError, ValueError):
        return 400, 'fixture must be an id; attack, defence and hours must be numbers'
    reason, source = (one('reason') or '').strip()[:500], (one('source') or '').strip()[:500]
    if side not in ('home', 'away'): return 400, "side must be 'home' or 'away'"
    if not reason: return 400, 'a reason is required'
    if not (ADJ_LIMITS[0] <= att <= ADJ_LIMITS[1] and ADJ_LIMITS[0] <= dfn <= ADJ_LIMITS[1]):
        return 400, f'attack and defence must be between {ADJ_LIMITS[0]} and {ADJ_LIMITS[1]}'
    conn = psycopg.connect(C.DATABASE_URL, autocommit=True, connect_timeout=10)      # the one writing connection
    try:
        with conn.cursor() as cur:
            cur.execute('SET search_path TO sbms')
            cur.execute("""INSERT INTO news_adjustments (fixture_id, league, team, side, attack, defence, reason, source, expires_at, author)
                           SELECT f.id, f.league, CASE WHEN %s = 'home' THEN f.home_model ELSE f.away_model END, %s, %s, %s, %s, %s,
                                  now() + make_interval(hours => %s::int), %s
                           FROM fixtures f WHERE f.id = %s AND f.kickoff > now() RETURNING id""",
                        (side, side, att, dfn, reason, source, int(hours), (one('author') or 'claude-news')[:60], fid))
            r = cur.fetchone()
    finally:
        conn.close()
    return (200, f'recorded adjustment {r[0]}') if r else (404, 'no upcoming fixture with that id')


def _writer(dict_rows=False):
    conn = psycopg.connect(C.DATABASE_URL, autocommit=True, connect_timeout=10, **(dict(row_factory=dict_row) if dict_rows else {}))
    with conn.cursor() as cur: cur.execute('SET search_path TO sbms')
    return conn


def record_bet(body):
    """'I took this bet' (Mitch, 16 Oct). body: fixture_id, key, odds, stake, optional suggestion_id and note. The model's
    view is taken from the suggestion (or the live model's latest working for that selection), so the EV is the model's
    at the odds actually taken, after commission. -> (status, dict)"""
    try:
        fid = int(body.get('fixture_id')); key = str(body.get('key') or '')[:20]
        odds = float(body.get('odds')); stake = float(body.get('stake'))
        sid = int(body['suggestion_id']) if body.get('suggestion_id') not in (None, '') else None
    except (TypeError, ValueError, KeyError):
        return 400, dict(error='fixture_id, key, odds and stake are required numbers')
    note = str(body.get('note') or '').strip()[:300]
    if not 1.01 <= odds <= 1000: return 400, dict(error='odds must be between 1.01 and 1000')
    if not 0 < stake <= 100000: return 400, dict(error='stake must be above 0 and at most 100,000')
    conn = _writer(True)
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT id, markets, kickoff, now() > kickoff AS late FROM fixtures WHERE id = %s', (fid,))
            f = cur.fetchone()
            if not f: return 404, dict(error='no such fixture')
            cid = next((c for m in (f['markets'] or {}).values() for c, k in ((m or {}).get('contracts') or {}).items() if k == key), None)
            if not cid: return 400, dict(error=f'no exchange selection {key!r} on this fixture')
            sug = None
            if sid:
                cur.execute('SELECT id, model, order_type, card, price, p_work, p_model, p_market FROM suggestions WHERE id = %s AND fixture_id = %s AND key = %s', (sid, fid, key))
                sug = cur.fetchone()
            view = sug
            if not view:
                cur.execute("""SELECT w.model, x->>'p_work' AS p_work, x->>'p_model' AS p_model, x->>'p_market' AS p_market
                               FROM working w, jsonb_array_elements(w.rows) x WHERE w.fixture_id = %s AND x->>'key' = %s
                               ORDER BY (w.model = 'dixon_coles') DESC, w.made_at DESC LIMIT 1""", (fid, key))
                view = cur.fetchone()
            cur.execute('SELECT rows FROM quotes WHERE fixture_id = %s ORDER BY read_at DESC LIMIT 1', (fid,))
            q = cur.fetchone(); qr = ((q or {}).get('rows') or {}).get(key) or {}
            fl = lambda v: float(v) if v not in (None, '') else None
            pw = fl((view or {}).get('p_work'))
            ev = pw * (odds - 1) * (1 - C.COMMISSION) - (1 - pw) if pw is not None else None
            tier = (sug or {}).get('card') or {'take': 'bet', 'rest': 'rest', 'lean': 'forced'}.get((sug or {}).get('order_type'), 'own pick')
            cur.execute("""INSERT INTO real_bets (fixture_id, key, contract_id, suggestion_id, model, tier, odds, stake, p_work, p_model, p_market, ev,
                                                  suggested_price, back_at_log, late, note)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                        (fid, key, cid, sid if sug else None, (view or {}).get('model'), tier, odds, stake, pw, fl((view or {}).get('p_model')),
                         fl((view or {}).get('p_market')), ev, (sug or {}).get('price'), fl(qr.get('back')), bool(f['late']), note or None))
            r = cur.fetchone(); bid = r['id'] if isinstance(r, dict) else r[0]
    finally:
        conn.close()
    return 200, dict(id=bid, ev=ev, tier=tier, late=bool(f['late']))


def undo_bet(body):
    try: bid = int(body.get('id'))
    except (TypeError, ValueError): return 400, dict(error='id required')
    conn = _writer()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE real_bets SET deleted = true WHERE id = %s AND status = 'open' AND NOT deleted RETURNING id", (bid,))
            r = cur.fetchone()
    finally:
        conn.close()
    return (200, dict(id=bid)) if r else (404, dict(error='no open bet with that id (settled bets stay on the record)'))


def _json_default(x):
    if isinstance(x, (dt.datetime, dt.date)): return x.isoformat()
    if isinstance(x, decimal.Decimal): return float(x)
    return str(x)


class Handler(BaseHTTPRequestHandler):
    server_version = 'sbms-page'

    def _send(self, code, body, ctype):
        b = body if isinstance(body, bytes) else body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(b)

    def _authorised(self, q):
        return not KEY or hmac.compare_digest((q.get('key') or [''])[0], KEY)

    def do_HEAD(self): self.do_GET()

    def do_POST(self):
        """Real bets (16 Oct): POST /bets/take and /bets/undo, JSON body, header X-Bets-Key = BETS_KEY."""
        u = urlparse(self.path); q = parse_qs(u.query); path = u.path.rstrip('/')
        if path not in ('/bets/take', '/bets/undo'): return self._send(404, 'not found', 'text/plain; charset=utf-8')
        if not self._authorised(q): return self._send(401, json.dumps(dict(error='page key required')), 'application/json')
        if not BETS_KEY: return self._send(403, json.dumps(dict(error='bet logging is off: set BETS_KEY on sbms-page')), 'application/json')
        if not hmac.compare_digest(self.headers.get('X-Bets-Key', ''), BETS_KEY):
            return self._send(401, json.dumps(dict(error='wrong bets key')), 'application/json')
        try:
            n = min(int(self.headers.get('Content-Length') or 0), 10000)
            body = json.loads(self.rfile.read(n) or b'{}')
            code, out = (record_bet if path == '/bets/take' else undo_bet)(body if isinstance(body, dict) else {})
        except Exception as e:
            traceback.print_exc(); code, out = 500, dict(error=type(e).__name__)
        return self._send(code, json.dumps(out, default=_json_default), 'application/json')

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); path = u.path.rstrip('/') or '/'
        if path == '/healthz':
            return self._send(200, 'ok', 'text/plain; charset=utf-8')
        if path == '/adjust':   # ideas 5 / 26: the one write path, and only with NEWS_KEY
            if not NEWS_KEY or not hmac.compare_digest((q.get('key') or [''])[0], NEWS_KEY):
                return self._send(401, 'news key required', 'text/plain; charset=utf-8')
            try:
                code, msg = add_adjustment(q)
            except Exception as e:
                traceback.print_exc(); code, msg = 500, f'{type(e).__name__}'
            return self._send(code, msg, 'text/plain; charset=utf-8')
        if path == '/upcoming':
            ok = (KEY and hmac.compare_digest((q.get('key') or [''])[0], KEY)) or (NEWS_KEY and hmac.compare_digest((q.get('key') or [''])[0], NEWS_KEY)) or not KEY
            if not ok: return self._send(401, 'key required', 'text/plain; charset=utf-8')
            try:
                return self._send(200, json.dumps(upcoming(), default=_json_default), 'application/json')
            except Exception as e:
                traceback.print_exc(); return self._send(500, json.dumps({'error': type(e).__name__}), 'application/json')
        if path not in ('/', '/page-data'):
            return self._send(404, 'not found', 'text/plain; charset=utf-8')
        if not self._authorised(q):
            return self._send(401, 'key required: add ?key=... to the address', 'text/plain; charset=utf-8')
        if path == '/':
            return self._send(200, PAGE.read_bytes(), 'text/html; charset=utf-8')
        try:
            body = json.dumps(page_data(), default=_json_default)
            return self._send(200, body, 'application/json')
        except Exception as e:
            traceback.print_exc()
            return self._send(500, json.dumps({'error': f'{type(e).__name__}: {e}'[:500]}), 'application/json')

    def log_message(self, fmt, *args):   # one line per request, without the key
        print(f'{self.command} {urlparse(self.path).path} {args[1] if len(args) > 1 else ""}', flush=True)


def main():
    if not C.DATABASE_URL:
        raise SystemExit('DATABASE_URL is not set')
    port = int(os.environ.get('PORT', '10000'))
    print(f'sbms-page listening on {port}', flush=True)
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()


if __name__ == '__main__':
    main()
