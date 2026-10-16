"""In-play goal reaction (Mitch, 30 Sep 2026): "look at a goal, see what odds were available after, then see where it
settles two or three minutes later, and look for a model that takes odds that are later going to be offsettable for
a profit. Some we lock in profit by reversing the bet; some we hold to completion."

A goal shows up in the exchange's own prices as a sudden jump in the result market, so no score feed is needed. For
every jump the worker records the book for the next few minutes. Then, for each selection, two paper trades are
worked out from the prices that were really on offer:
  - trade out: back at the first back price after the jump, lay at the lay price EXIT_SECONDS later, sized so the
    profit is the same whatever happens (the usual "green up"): profit = stake x (back / lay - 1), less commission;
  - hold: the same back bet kept to the final whistle (settled with the fixture).
Both "fade the overreaction" (back the side the jump moved against) and "follow the move" (back the side it moved
towards) are recorded for every jump, so the evidence says which, if either, pays and when to get out.
Suspensions (Mitch, 30 Sep: "you'll see the market suspended as well"): around a goal, a red card or a VAR check the
exchange suspends its markets (the book goes empty) and reopens them at new prices. A suspension is recorded as an
event from the moment the book empties; the entry price is the first price after it reopens (the earliest a bet
could really be made); and what the prices did on reopening says what happened: a big jump (goal / red card) or
nothing much (a check that came to nothing: VAR, a penalty review, a disallowed goal). The reads just before the
suspension are kept too: prices often drift as pressure builds before a goal.
Pure functions; the worker (jobs/inplay.py) records, the page's In-play tab summarises."""
from . import config as C

KEYS = ('H', 'D', 'A')


def book_open(rows):
    """Is the result market quoting at all? (A suspended market has an empty book.)"""
    return any((rows.get(k) or {}).get('back') or (rows.get(k) or {}).get('lay') for k in KEYS)


def classify(move, suspended):
    if suspended:
        return 'goal or red card' if abs(move) >= C.JUMP_MIN else 'check, no change'
    return 'jump, no suspension'


def jump(prev, rows, min_move=None):
    """The largest move of the result market's no-vig probabilities between two reads. -> dict or None."""
    best, up = None, None
    for k in KEYS:
        a = (prev.get(k) or {}).get('mid_novig'); b = (rows.get(k) or {}).get('mid_novig')
        if a is None or b is None: continue
        if best is None or abs(b - a) > abs(best['move']): best = dict(key=k, before=round(a, 4), after=round(b, 4), move=round(b - a, 4))
        if up is None or b - a > up[1]: up = (k, b - a)
    if not best or abs(best['move']) < (C.JUMP_MIN if min_move is None else min_move): return None
    best['up_key'] = up[0]            # the selection the jump moved towards ('follow'); the other two are 'fade'
    return best


def green(back, lay, stake=None, comm=None):
    """Profit locked in by backing at `back` then laying at `lay` with the lay stake that equalises both outcomes.
    Commission is charged on the net winnings of the market, which here is the locked profit when positive."""
    stake = C.PAPER_STAKE if stake is None else stake; comm = C.COMMISSION if comm is None else comm
    if not back or not lay: return None
    p = stake * (back / lay - 1)
    return round(p * (1 - comm) if p > 0 else p, 2)


def hold(back, won, stake=None, comm=None):
    stake = C.PAPER_STAKE if stake is None else stake; comm = C.COMMISSION if comm is None else comm
    return round(stake * (back - 1) * (1 - comm), 2) if won else -stake


def trades(path, direction_key):
    """path: [(seconds after the jump, rows)] in time order, rows = {key: {back, lay, back_depth3, lay_depth3}}.
    direction_key: the selection whose probability jumped UP. -> {key: dict(side, entry, exits{s: lay}, green{s: pnl})}."""
    if not path: return {}
    t0, first = path[0]
    out = {}
    for k in KEYS:
        entry = (first.get(k) or {}).get('back')
        if not entry: continue
        ex, gr = {}, {}
        for s in C.EXIT_SECONDS:
            later = next((r for t, r in path if t >= s), None)
            lay = (later or {}).get(k, {}).get('lay') if later else None
            if lay:
                ex[s] = lay; gr[s] = green(entry, lay)
        out[k] = dict(side='follow' if k == direction_key else 'fade', entry=entry, entry_depth=(first.get(k) or {}).get('back_depth3'),
                      exits=ex, green=gr)
    return out


# ---------------------------------------------------------------- idea 35: the reaction model
# Mitch, 30 Sep: "look for a model that takes odds that are later going to be offsettable for a profit". Once enough
# events are recorded, a small ridge regression per exit time predicts each trade's locked profit (per PAPER_STAKE)
# from what is known the moment the book reopens: the size of the jump, whether the trade follows or fades it, the
# minute, goal / red card v a jump with no suspension, the entry price, the depth at it, and how that selection's
# price had moved in the two minutes before. The worker then plans at most one paper trade per event: the selection
# and exit time with the best prediction, if it clears REACTION_EDGE. Honest scoring: walk-forward (each event
# predicted by a model fitted only on earlier events), so the page's figures are out of sample.
import math as _m

FEATURES = ('jump', 'follow', 'follow_x_jump', 'minute', 'goal', 'log_entry', 'pre_drift', 'depth')


def features(ev, key, entry, entry_depth, pre=None):
    """ev: dict(move, up_key, minute, kind). -> list of floats in FEATURES order."""
    jump_ = abs(ev.get('move') or 0); fol = 1.0 if key == ev.get('up_key') else 0.0
    drift = 0.0
    if pre and len(pre) >= 2:
        a = ((pre[0][1] or {}).get(key) or {}).get('mid_novig'); b = ((pre[-1][1] or {}).get(key) or {}).get('mid_novig')
        if a is not None and b is not None: drift = b - a
    return [jump_, fol, fol * jump_, (ev.get('minute') or 0) / 90, 1.0 if ev.get('kind') == 'goal or red card' else 0.0,
            _m.log(entry) if entry and entry > 1 else 0.0, drift, _m.log1p(entry_depth or 0) / 10]


def samples(events):
    """events: [dict(at, minute, move, up_key, kind, trades, pre)] (checks excluded) -> [(event index, key, x, {exit: green})]."""
    out = []
    for i, ev in enumerate(events):
        if ev.get('kind') == 'check, no change': continue
        for k, t in (ev.get('trades') or {}).items():
            if not t.get('entry'): continue
            g = {int(s): v for s, v in (t.get('green') or {}).items() if v is not None}
            if g: out.append((i, k, features(ev, k, t['entry'], t.get('entry_depth'), ev.get('pre')), g))
    return out


def fit_reaction(smp, ridge=None):
    """-> {exit: dict(w, mu, sd, n)} (ridge regression on standardised features, per exit time)."""
    import numpy as np
    ridge = C.REACTION_RIDGE if ridge is None else ridge
    model = {}
    for s in C.EXIT_SECONDS:
        rows = [(x, g[s]) for _, _, x, g in smp if s in g]
        if len(rows) < 10: continue
        X = np.array([r[0] for r in rows], float); y = np.array([r[1] for r in rows], float)
        mu = X.mean(0); sd = X.std(0); sd[sd < 1e-9] = 1.0
        Z = np.hstack([np.ones((len(X), 1)), (X - mu) / sd])
        P = ridge * np.eye(Z.shape[1]); P[0, 0] = 0.0
        w = np.linalg.solve(Z.T @ Z + P, Z.T @ y)
        model[s] = dict(w=w.tolist(), mu=mu.tolist(), sd=sd.tolist(), n=len(rows))
    return model


def predict(model, x):
    out = {}
    for s, m in (model or {}).items():
        z = [1.0] + [(xi - mi) / si for xi, mi, si in zip(x, m['mu'], m['sd'])]
        out[int(s)] = sum(a * b for a, b in zip(z, m['w']))
    return out


def plan(model, ev, rows, pre=None, edge=None):
    """The one trade to make on a new event, or None: -> dict(key, side, exit, pred, entry)."""
    edge = C.REACTION_EDGE if edge is None else edge
    best = None
    for k in KEYS:
        r = rows.get(k) or {}
        if not r.get('back'): continue
        for s, p in predict(model, features(ev, k, r['back'], r.get('back_depth3'), pre)).items():
            if p > edge and (best is None or p > best['pred']):
                best = dict(key=k, side='follow' if k == ev.get('up_key') else 'fade', exit=s, pred=round(p, 2), entry=r['back'])
    return best


def walk_forward(events, start=None, every=20, edge=None):
    """Out-of-sample record of the planning rule: each event from `start` on is planned with a model fitted on the events
    before it (refitted every `every` events). -> dict(n_events, planned, mean, hit, all_mean)."""
    start = C.REACTION_MIN if start is None else start
    smp = samples(events)
    model, fitted_at, realised, every_green = None, -1, [], []
    for i, ev in enumerate(events):
        if i < start or ev.get('kind') == 'check, no change': continue
        if model is None or i - fitted_at >= every:
            model = fit_reaction([r for r in smp if r[0] < i]); fitted_at = i
        tr = ev.get('trades') or {}
        rows = {k: dict(back=t.get('entry'), back_depth3=t.get('entry_depth')) for k, t in tr.items()}
        p = plan(model, ev, rows, ev.get('pre'), edge)
        for k, t in tr.items():
            every_green += [v for v in (t.get('green') or {}).values() if v is not None]
        if p:
            g = ((tr.get(p['key']) or {}).get('green') or {})
            v = g.get(p['exit'], g.get(str(p['exit'])))
            if v is not None: realised.append(v)
    mean = lambda a: round(sum(a) / len(a), 2) if a else None
    return dict(n_events=len(events), planned=len(realised), mean=mean(realised), total=round(sum(realised), 2),
                hit=round(sum(v > 0 for v in realised) / len(realised), 3) if realised else None, all_mean=mean(every_green))
