"""Idea 11: the in-play worker (Render background worker 'sbms-inplay', off until switched on in render.yaml).
Every INPLAY_EVERY_S seconds (15), for each fixture in play, it reads the Smarkets book and:
  - goal reaction (Mitch, 30 Sep; trading.py): a jump of the result market opens an event; the book is recorded for
    the next five minutes and the paper trades (back then lay at 1 / 2 / 3 / 5 minutes; back and hold) are worked out.
    Needs no score feed;
  - the model (with API_FOOTBALL_KEY): the score and minute from the live feed, the in-play probabilities from the
    live model's pre-match goal expectations, a snapshot, and, only on a fresh score and a calm book, an in-play
    PAPER bet where a price on offer clears INPLAY_FLOOR_EV under the usual cap and anchor.
Settled by the main job with the fixture. Nothing is placed.
Usage: python -m sbms.jobs.inplay [--once]"""
import datetime as dt
import sys
import time
import traceback
from .. import config as C
from .. import db, pricing, inplay, trading
from ..sources import apifootball as af
from .run import read_book_fast, UTC


def _minute(kickoff, now):
    """A rough match minute from the clock alone (15 minutes of half-time taken out after the 60th minute of clock time)."""
    m = (now - kickoff).total_seconds() / 60
    return m - 15 if m > 60 else min(m, 45 + 2)


def reaction_model(conn, state, now):
    """Idea 35: the reaction model, refitted hourly from the completed events; None until REACTION_MIN events exist.
    The fit and its walk-forward record are saved (model_params 'REACTION') for the page."""
    got = state.get('reaction')
    if got and (now - got[0]).total_seconds() < C.REACTION_REFIT_S: return got[1]
    model = None
    try:
        evs = db.reaction_events(conn)
        usable = [e for e in evs if e.get('kind') != 'check, no change']
        if len(usable) >= C.REACTION_MIN:
            model = trading.fit_reaction(trading.samples(usable)) or None
            db.save_params(conn, 'REACTION', dict(engine='ridge', n=len(usable), model=model, features=list(trading.FEATURES),
                                                  oos=trading.walk_forward(usable), edge=C.REACTION_EDGE), 'inplay_events')
    except Exception:
        traceback.print_exc()
    state['reaction'] = (now, model)
    return model


def step(conn, state, now=None):
    """One pass over the fixtures in play: read each book; extend and close the goal-reaction events; open a new event
    on a jump; and, when a fresh score is known, the model's in-play paper bets."""
    now = now or dt.datetime.now(UTC)
    fx = db.live_fixtures(conn)
    if not fx: return dict(live=0)
    if C.API_FOOTBALL_KEY and (state.get('polled') is None or (now - state['polled']).total_seconds() >= C.INPLAY_SCORE_EVERY_S):
        state['scores'] = [af.simple(x) for x in af.live(C.API_FOOTBALL_KEY)]; state['polled'] = now
    scores = state.get('scores') or []
    evs = {}
    for eid, fid, at, up_key in db.open_events(conn): evs.setdefault(fid, []).append((eid, at, up_key))
    prev_all = state.setdefault('prev', {})
    model = reaction_model(conn, state, now)                                     # idea 35 (None until enough events)
    n_bets = n_events = 0
    for f in fx:
        try:
            rows = read_book_fast(f['markets'] or {})
        except Exception:
            traceback.print_exc(); continue
        prev = prev_all.get(f['id']); prev_all[f['id']] = (now, rows)
        is_open = trading.book_open(rows)
        hist = state.setdefault('recent', {}).setdefault(f['id'], [])      # the last two minutes of open books
        susp = state.setdefault('susp', {})
        # goal reaction: extend open events, close the ones whose window has passed
        for eid, at, up_key in evs.get(f['id'], []):
            secs = (now - at).total_seconds()
            if is_open: db.extend_event(conn, eid, secs, rows)
            if secs >= C.EVENT_WINDOW_S:
                db.close_event(conn, eid, trading.trades([(t, r) for t, r in db.event_path(conn, eid)], up_key))
        if not is_open:
            # suspended (goal, red card, VAR check...): remember when, and the last open book before it
            if f['id'] not in susp and hist: susp[f['id']] = dict(since=now, before=hist[-1][1], pre=list(hist))
            continue
        if f['id'] in susp:
            # reopened: an event whatever the prices did, classified by the move (goal / red card v a check that changed nothing)
            s0 = susp.pop(f['id'])
            j = trading.jump(s0['before'], rows, min_move=0.0)
            if j and not evs.get(f['id']) and (now - s0['since']).total_seconds() <= C.SUSP_MAX_S:
                secs_susp = (now - s0['since']).total_seconds()
                kind = trading.classify(j['move'], True)
                pre = [((t - s0['since']).total_seconds(), r) for t, r in s0['pre']]
                mnt = round(_minute(f['kickoff'], now), 1)
                pl = trading.plan(model, dict(move=j['move'], up_key=j['up_key'], minute=mnt, kind=kind), rows, pre) if model and kind != 'check, no change' else None
                db.open_event(conn, f['id'], mnt, j, rows, kind, secs_susp, pre, plan=pl); n_events += 1
        elif prev and not evs.get(f['id']) and (now - prev[0]).total_seconds() <= 3 * C.INPLAY_EVERY_S + 30:
            # a jump with no suspension seen between two reads
            j = trading.jump(prev[1], rows)
            if j:
                mnt = round(_minute(f['kickoff'], now), 1); pre = [((t - now).total_seconds(), r) for t, r in hist]
                pl = trading.plan(model, dict(move=j['move'], up_key=j['up_key'], minute=mnt, kind='jump, no suspension'), rows, pre) if model else None
                db.open_event(conn, f['id'], mnt, j, rows, pre=pre, plan=pl); n_events += 1
        hist.append((now, rows)); del hist[:-max(2, int(120 / C.INPLAY_EVERY_S))]
        # the model's in-play bets need the score
        s = af.find(scores, f['home'], f['away'], f['kickoff'], hours=3) if scores else None
        if not s or s.get('hg') is None or s.get('status') in ('FT', 'AET', 'PEN'): continue
        minute = inplay.minute_now(s.get('elapsed'), state['polled'], now, s.get('status'))
        p = inplay.probs(f['lh'], f['la'], minute, s['hg'], s['ag'])
        last = db.last_inplay_rows(conn, f['id']) or {}
        jumps = [(rows.get(k) or {}).get('mid_novig', 0) - (last.get(k) or {}).get('mid_novig', (rows.get(k) or {}).get('mid_novig', 0))
                 for k in ('H', 'D', 'A') if (rows.get(k) or {}).get('mid_novig') is not None]
        db.add_inplay_snapshot(conn, f['id'], minute, s['hg'], s['ag'], p, rows)
        if not inplay.safe_to_bet((now - state['polled']).total_seconds(), jumps): continue
        for key, r in rows.items():
            if key not in p or r.get('mid_novig') is None or not r.get('back'): continue
            e = pricing.evaluate_row(key, p[key], r['mid_novig'], r, r.get('volume'), C.BAND_CAP['full'])
            if e.get('order_type') == 'take' and e['ev'] >= C.INPLAY_FLOOR_EV:
                e.update(cid=r['cid'])
                if db.add_inplay_bet(conn, f['id'], minute, s['hg'], s['ag'], e): n_bets += 1
    return dict(live=len(fx), events=n_events, bets=n_bets)


def main(once=False):
    conn = db.connect(); db.ensure_schema(conn)
    state = {'conn': conn}
    af.set_budget(lambda k: db.af_allow(state['conn'], k))
    print('sbms-inplay started (paper only)', flush=True)
    while True:
        try:
            r = step(conn, state)
            if r.get('live'): print(dt.datetime.now(UTC).strftime('%H:%M:%S'), r, flush=True)
        except Exception:
            traceback.print_exc()
            try: conn.close()
            except Exception: pass
            time.sleep(5); conn = db.connect(); state['conn'] = conn
        if once: break
        time.sleep(C.INPLAY_EVERY_S)


if __name__ == '__main__':
    main('--once' in sys.argv)
