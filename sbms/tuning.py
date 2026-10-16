"""Self-tuning: the model competing with slight variations of itself (Mitch, 29 Sep 2026: "the model running the current
variant and slight variations at the same time - trying to outperform not only the market, but also itself").

Per league there is, in force:
  - a RECIPE: xi (how fast old results fade) and fit_years (how many years of results the fit uses);
  - a CALIBRATION or none: multipliers on the home and away goal expectations that correct a consistent lean;
  - an ANCHOR weight: the model's share against the market in the anchored probability (0.30 until earned).
The recipe in force is the "champion". Every hour the live job also prices "challengers": the champion with the fade
halved, the fade doubled, and (when a calibration is in force) without it. Each is its own model variant with its own
predictions and paper bets, so the scoreboard compares them with the champion and with the market.

The weekly job (jobs/backtest.py) decides, league by league, and writes every decision to league_tuning:
  1. back-test grid: walk-forward over the last year for every xi x fit_years variation; a variation replaces the
     champion if it beats it by TUNE_MARGIN over at least TUNE_MIN_MATCHES matches;
  2. live challengers: a challenger replaces the champion if it beats it by LIVE_CHALLENGE_MARGIN over at least
     LIVE_CHALLENGE_MIN settled fixtures since the last recipe change;
  3. calibration: fitted on the earlier two thirds of the champion's walk-forward predictions, adopted only if it
     improves the latest third (1X2 + over/under 2.5 log loss); shrunk towards none and clipped to +-10%;
  4. anchor (16 Oct): the model's say v the market is the blend weight that predicts results best, live (the latest
     ANCHOR_WINDOW settled fixtures v the Smarkets close) or from the weekly back-test (v Pinnacle's close); it may be 0.
A recipe changes at most once per RECIPE_COOLDOWN_DAYS in a league. Nothing is deleted; each decision is dated."""
import datetime as dt
import math
from collections import defaultdict
from . import config as C
from . import pricing
from .models import dc, fastdc, shots, prices

METHODS = ('goals', 'shots', 'pyramid', 'xg', 'prices')
METHOD_LABEL = dict(goals='goals', shots='goals + shots on target', pyramid='whole-pyramid fit', xg='goals + xG (Understat)',
                    prices='ratings from closing prices')
DEFAULT_RECIPE = dict(xi=C.DC_XI, fit_years=C.DC_SEASONS, method='goals')


def recipe_key(r):
    xi = min(max(float(r['xi']), C.XI_BOUNDS[0]), C.XI_BOUNDS[1])
    return dict(xi=round(xi, 7), fit_years=int(r['fit_years']), method=r.get('method') or 'goals', shrink=int(r.get('shrink') or 0))


def describe(r):
    """'old results fade by half in 385 days; 3 years of results'"""
    return (f"{METHOD_LABEL.get(r.get('method') or 'goals')}; half-life {math.log(2) / r['xi']:.0f} days, {r['fit_years']} years"
            + (f"; thin-data ratings pulled to average (k={r['shrink']})" if r.get('shrink') else ''))


def methods_for(lg):
    """Which methods a league can use: shots need football-data's main files; the pyramid needs a listed pyramid."""
    src = (lg or {}).get('source', ('', ''))
    out = ['goals']
    if src[0] == 'fd': out.append('shots')
    if src[0] == 'fd' and any(src[1] in codes for codes in C.PYRAMIDS.values()): out.append('pyramid')
    from .sources import understat
    if src[0] == 'fd' and src[1] in understat.LEAGUES: out.append('xg')
    if src[0] == 'fd': out.append('prices')
    return tuple(out)


def pyramid_of(code):
    return next(((c, codes) for c, codes in C.PYRAMIDS.items() if code in codes), (None, None))


def challengers(recipe, calibration, methods=('goals',)):
    """Slight variations of the champion priced live beside it: the fade halved and doubled, each other method the
    league can use, and (with a bias correction in force) the champion without it. -> [(name, recipe, calibrated)]"""
    out = [('fade_slower', recipe_key(dict(recipe, xi=recipe['xi'] * 0.5)), True),
           ('fade_faster', recipe_key(dict(recipe, xi=recipe['xi'] * 2.0)), True)]
    for m in methods:
        if m != (recipe.get('method') or 'goals'):
            out.append((m, recipe_key(dict(recipe, method=m)), True))
    if recipe.get('shrink'): out.append(('unshrunk', recipe_key(dict(recipe, shrink=0)), True))
    else: out.append(('shrunk', recipe_key(dict(recipe, shrink=C.SHRINK_K)), True))
    if calibration:
        out.append(('uncalibrated', recipe_key(recipe), False))
    return out


def apply_calibration(lh, la, cal):
    if not cal: return lh, la
    return lh * cal['home'], la * cal['away']


def draw_factor(cal):
    return float(cal.get('draw', 1.0)) if cal else 1.0


def in_force(rows):
    """rows: league_tuning rows (dicts, newest first). -> {league: {'recipe', 'calibration', 'anchor', 'changed'}}"""
    out = defaultdict(lambda: dict(recipe=recipe_key(DEFAULT_RECIPE), calibration=None, anchor=C.ANCHOR_DEFAULT, trust=None, weather=None,
                                   referee=None, changed={}))
    seen = set()
    for r in rows:
        if not r['adopted'] or (r['league'], r['kind']) in seen: continue
        seen.add((r['league'], r['kind'])); t = out[r['league']]; v = r['value']
        if r['kind'] == 'recipe': t['recipe'] = recipe_key(v)
        elif r['kind'] == 'calibration': t['calibration'] = None if v.get('off') else dict(home=float(v['home']), away=float(v['away']), draw=float(v.get('draw', 1.0)))
        elif r['kind'] == 'anchor': t['anchor'] = float(v['weight'])
        elif r['kind'] == 'trust': t['trust'] = {k: float(x) for k, x in v.items() if k in ('early', 'mid', 'late')}
        elif r['kind'] in ('weather', 'referee'): t[r['kind']] = None if v.get('off') else {k: float(x) for k, x in (v.get('factors') or {}).items()}
        t['changed'][r['kind']] = r['decided_at']
    return out


# ---------------------------------------------------------------- back-test grid and calibration (pure functions)
def fit_method(recipe, train, day, pyramid_train=None):
    """Fit a recipe's method on results before `day`. goals: Dixon-Coles (penaltyblog where installed); shots: goals
    blended with shots on target; pyramid: one fit over every division of the country. -> params or None"""
    m = recipe.get('method') or 'goals'
    if m == 'goals':
        p = dc.fit(train, day, xi=recipe['xi'])
    elif m == 'shots':
        p = shots.fit(train, day, recipe['xi'], dc.fit(train, day, xi=recipe['xi']))
    elif m == 'pyramid':
        p = fastdc.fit(pyramid_train, day, recipe['xi']) if pyramid_train else None
    elif m == 'prices':
        p = prices.fit(train, day, recipe['xi'])
    elif m == 'xg':
        p = shots.fit(train, day, recipe['xi'], dc.fit(train, day, xi=recipe['xi']), keys=('hxg', 'axg'))
    else:
        p = None
    if p is not None and recipe.get('shrink'):
        p = shrink(p, pyramid_train if m == 'pyramid' else train, day, recipe['xi'], recipe['shrink'])
    return p


def shrink(params, matches, day, xi, k):
    """Idea 13, a margin of error on every rating: each team's attack and defence are pulled towards the average by
    k / (n + k), where n is the team's time-weighted number of matches. Well-known teams barely move; a team the fit
    knows from a handful of games moves a long way. -> new params (the same shape)."""
    n = defaultdict(float)
    for mt in matches:
        w = math.exp(-xi * max((day - mt['date']).days, 0)); n[mt['home']] += w; n[mt['away']] += w
    teams = [t for t in params['attack'] if n.get(t)]
    tot = sum(n[t] for t in teams) or 1.0
    abar = sum(params['attack'][t] * n[t] for t in teams) / tot; dbar = sum(params['defence'][t] * n[t] for t in teams) / tot
    out = dict(params, attack=dict(params['attack']), defence=dict(params['defence']), shrink_k=k)
    for t in params['attack']:
        w = n.get(t, 0.0) / (n.get(t, 0.0) + k)
        out['attack'][t] = abar + (params['attack'][t] - abar) * w
        out['defence'][t] = dbar + (params['defence'][t] - dbar) * w
    return out


def walk_forward(hist, start, end, step_days, recipe, min_train=150, pyramid_hist=None):
    """Out-of-sample predictions: every step, refit on the recipe's window of results before that day only (no
    look-ahead), then predict the matches of the next step. -> [dict(key, date, lh, la, rho, hg, ag, close_1x2)]
    pyramid_hist: every division's results, for the 'pyramid' method (it trains on them, predicts this league)."""
    out, day = [], start
    span = dt.timedelta(days=365 * recipe['fit_years'])
    while day < end:
        nxt = day + dt.timedelta(days=step_days)
        week = [m for m in hist if day <= m['date'] < nxt]
        if week:
            train = [m for m in hist if day - span <= m['date'] < day]
            if len(train) >= min_train:
                ptrain = [m for m in pyramid_hist if day - span <= m['date'] < day] if pyramid_hist else None
                params = fit_method(recipe, train, day, ptrain)
                if params is None: day = nxt; continue
                cnt = defaultdict(int)
                for m in train: cnt[m['home']] += 1; cnt[m['away']] += 1
                for m in week:
                    if cnt[m['home']] < 5 or cnt[m['away']] < 5: continue
                    if m['home'] not in params['attack'] or m['away'] not in params['attack']: continue
                    lh, la = dc.lambdas(params, m['home'], m['away'])
                    out.append(dict(key=(m['date'], m['home'], m['away']), date=m['date'], lh=lh, la=la, rho=params['rho'],
                                    hg=m['hg'], ag=m['ag'], close_1x2=m.get('close_1x2'), home=m['home'], time=m.get('time'),
                                    referee=m.get('referee')))
        day = nxt
    return out


def _outcome(r):
    return 'H' if r['hg'] > r['ag'] else ('A' if r['ag'] > r['hg'] else 'D')


def score(recs, cal=None, markets=('1x2',), factors=None, field=None):
    """Mean log loss over records. markets: '1x2' and/or 'ou25' (summed per match). factors / field: a goal factor per
    record group (weather bucket, referee), applied to both sides, e.g. factors={'wet': 0.95}, field='wx'."""
    if not recs: return None
    tot = 0.0
    for r in recs:
        lh, la = apply_calibration(r['lh'], r['la'], cal)
        if factors and field:
            f = factors.get(r.get(field), 1.0); lh, la = lh * f, la * f
        p = pricing.market_probs(pricing.score_grid(lh, la, r['rho'], draw=draw_factor(cal)))
        if '1x2' in markets: tot += -math.log(max(p[_outcome(r)], 1e-9))
        if 'ou25' in markets: tot += -math.log(max(p['O2.5'] if r['hg'] + r['ag'] > 2.5 else p['U2.5'], 1e-9))
    return tot / len(recs)


def fit_calibration(recs):
    """Home and away multipliers = actual goals / expected goals, shrunk towards 1 and clipped."""
    n = len(recs)
    if not n: return None
    sh, sa = sum(r['lh'] for r in recs), sum(r['la'] for r in recs)
    gh, ga = sum(r['hg'] for r in recs), sum(r['ag'] for r in recs)
    w = n / (n + C.CAL_SHRINK)
    f = lambda raw: min(max(1 + (raw - 1) * w, C.CAL_CLIP[0]), C.CAL_CLIP[1])
    home, away = round(f(gh / sh), 4), round(f(ga / sa), 4)
    # Idea 18, the draw specialist: with the goal corrections in place, the multiplier on drawn scores that best explains
    # the results, shrunk towards 1 the same way.
    from scipy.optimize import minimize_scalar
    raw_d = float(minimize_scalar(lambda d: score(recs, dict(home=home, away=away, draw=d)), bounds=(0.6, 1.6), method='bounded',
                                  options=dict(xatol=1e-3)).x)
    draw = round(min(max(1 + (raw_d - 1) * w, C.CAL_DRAW_CLIP[0]), C.CAL_DRAW_CLIP[1]), 4)
    return dict(home=home, away=away, draw=draw, n=n, raw_home=round(gh / sh, 4), raw_away=round(ga / sa, 4), raw_draw=round(raw_d, 4))


def fit_group_factors(recs, field, shrink, clip=C.CAL_CLIP):
    """Per group (e.g. weather bucket, referee): actual goals / expected goals over both sides, shrunk towards 1 by
    n / (n + shrink) and clipped. -> {group: factor}, {group: n}"""
    g, e, n = defaultdict(float), defaultdict(float), defaultdict(int)
    for r in recs:
        k = r.get(field)
        if k is None: continue
        g[k] += r['hg'] + r['ag']; e[k] += r['lh'] + r['la']; n[k] += 1
    out = {}
    for k in g:
        w = n[k] / (n[k] + shrink)
        out[k] = round(min(max(1 + (g[k] / e[k] - 1) * w, clip[0]), clip[1]), 4)
    return out, dict(n)


def review_group_factors(recs, field, shrink, min_n=None):
    """Ideas 10 and 22: fit group factors on the earlier two thirds, keep them only if they improve the latest third
    (1X2 + over/under 2.5 log loss). -> (adopt, value, evidence)"""
    recs = sorted([r for r in recs if r.get(field) is not None], key=lambda r: r['date'])
    need = min_n or C.TUNE_MIN_MATCHES
    if len(recs) < need: return False, None, dict(reason=f'{len(recs)} matches with {field}, need {need}')
    cut = int(len(recs) * (1 - C.CAL_HOLDOUT)); fit_part, test = recs[:cut], recs[cut:]
    trial, n_fit = fit_group_factors(fit_part, field, shrink)
    base = score(test, None, ('1x2', 'ou25')); withf = score(test, None, ('1x2', 'ou25'), trial, field)
    ev = dict(fitted_on=len(fit_part), tested_on=len(test), ll_without=round(base, 5), ll_with=round(withf, 5),
              trial={k: v for k, v in sorted(trial.items(), key=lambda x: -n_fit.get(x[0], 0))[:30]})
    if withf < base:
        full, n_full = fit_group_factors(recs, field, shrink)
        return True, dict(factors=full, n=n_full), ev
    return False, dict(off=True), dict(ev, reason='did not improve the matches it was not fitted on')


def review_calibration(recs):
    """Fit on the earlier part, test on the latest CAL_HOLDOUT. -> (adopt, value, evidence)"""
    recs = sorted(recs, key=lambda r: r['date'])
    if len(recs) < C.TUNE_MIN_MATCHES: return False, None, dict(reason=f'{len(recs)} matches, need {C.TUNE_MIN_MATCHES}')
    cut = int(len(recs) * (1 - C.CAL_HOLDOUT))
    fit_part, test = recs[:cut], recs[cut:]
    cal = fit_calibration(fit_part)
    base = score(test, None, ('1x2', 'ou25')); withc = score(test, cal, ('1x2', 'ou25'))
    ev = dict(fitted_on=len(fit_part), tested_on=len(test), ll_without=round(base, 5), ll_with=round(withc, 5), trial=cal)
    if withc < base:
        full = fit_calibration(recs)
        return True, dict(home=full['home'], away=full['away'], draw=full['draw']), dict(ev, adopted_from=len(recs), raw_home=full['raw_home'],
                                                                                           raw_away=full['raw_away'], raw_draw=full['raw_draw'])
    return False, dict(off=True), dict(ev, reason='did not improve the matches it was not fitted on')


def grid(hist, today, champion, methods=('goals',), pyramid_hist=None):
    """Walk-forward every xi x fit_years variation of the champion's method over the last TUNE_WINDOW_DAYS, plus each
    other method the league can use at the champion's fade and window. Scored on the matches every variation priced
    (paired). -> (results {name: dict}, name of the champion, records by name)"""
    start = today - dt.timedelta(days=C.TUNE_WINDOW_DAYS)
    base_xi = champion['xi']; cm = champion.get('method') or 'goals'
    combos = {}
    for m in C.TUNE_XI_MULTS:
        for fy in C.TUNE_FIT_YEARS:
            r = recipe_key(dict(xi=base_xi * m, fit_years=fy, method=cm))
            name = f"{cm}: xi x{m:g}, {fy} yrs"
            if r not in combos.values(): combos[name] = r   # at a bound two multipliers can give the same recipe
    for meth in methods:
        if meth != cm and (meth != 'pyramid' or pyramid_hist) and (meth != 'shots' or shots.usable(hist)) \
                and (meth != 'xg' or shots.usable(hist, need=0.5, keys=('hxg', 'axg'))) and (meth != 'prices' or prices.usable(hist, need=0.5)):
            combos[f"{meth}: xi x1, {champion['fit_years']} yrs"] = recipe_key(dict(champion, method=meth))
    sk = 0 if champion.get('shrink') else C.SHRINK_K
    combos[f"{cm}: xi x1, {champion['fit_years']} yrs, {'shrunk' if sk else 'unshrunk'}"] = recipe_key(dict(champion, shrink=sk))
    champ_name = next((n for n, r in combos.items() if r == recipe_key(champion)), None)
    if champ_name is None:
        combos['champion'] = recipe_key(champion); champ_name = 'champion'
    recs = {n: walk_forward(hist, start, today, C.TUNE_STEP_DAYS, r, pyramid_hist=pyramid_hist) for n, r in combos.items()}
    recs = {n: v for n, v in recs.items() if v}
    common = set.intersection(*[set(x['key'] for x in v) for v in recs.values()]) if recs else set()
    results = {}
    for n, v in recs.items():
        vv = [x for x in v if x['key'] in common]
        results[n] = dict(recipe=combos[n], n=len(vv), ll=score(vv))
    return results, champ_name, recs


def decide_grid(results, champ_name):
    """-> (adopt, winner_name, evidence)"""
    if champ_name not in results:
        return False, champ_name, dict(reason='the champion could not be replayed (its data is missing)')
    ch = results[champ_name]
    if not ch['n'] or ch['n'] < C.TUNE_MIN_MATCHES:
        return False, champ_name, dict(reason=f"{ch['n']} matches, need {C.TUNE_MIN_MATCHES}")
    best = min(results, key=lambda n: results[n]['ll'] if results[n]['ll'] is not None else 9)
    gain = ch['ll'] - results[best]['ll']
    ev = dict(champion=champ_name, champion_ll=round(ch['ll'], 5), best=best, best_ll=round(results[best]['ll'], 5),
              gain=round(gain, 5), n=ch['n'], all={n: dict(ll=round(r['ll'], 5) if r['ll'] is not None else None, recipe=r['recipe']) for n, r in results.items()})
    if best != champ_name and gain >= C.TUNE_MARGIN:
        return True, best, ev
    return False, champ_name, dict(ev, reason=f'no variation beat the champion by {C.TUNE_MARGIN}')


def decide_live(pairs):
    """pairs: {challenger: [(p_champion, p_challenger), ...]} on settled fixtures (probability each gave the result).
    -> list of (challenger, n, ll_champion, ll_challenger, beats)"""
    out = []
    for name, ps in pairs.items():
        n = len(ps)
        if not n: continue
        lc = sum(-math.log(max(a, 1e-9)) for a, _ in ps) / n; lx = sum(-math.log(max(b, 1e-9)) for _, b in ps) / n
        out.append((name, n, lc, lx, n >= C.LIVE_CHALLENGE_MIN and lc - lx >= C.LIVE_CHALLENGE_MARGIN))
    return out


def season_starts(dates, gap_days=35):
    """Season boundaries from the calendar itself: a season starts after a break of at least gap_days."""
    ds = sorted(set(dates))
    if not ds: return []
    starts = [ds[0]]
    for a, b in zip(ds, ds[1:]):
        if (b - a).days >= gap_days: starts.append(b)
    return starts


def phase_of(day, starts):
    """-> 'early' | 'mid' | 'late' from the weeks since the latest season start on or before `day`."""
    s = max((x for x in starts if x <= day), default=None)
    if s is None: return 'late'
    weeks = (day - s).days // 7
    return [name for w, name in C.TRUST_PHASES if weeks >= w][-1]


def decide_trust(recs, starts):
    """Idea 19, trust by the week of the season. recs: [(date, model log loss, market log loss)] from the walk-forward
    back-test. Each phase's gap to the market is compared with the best phase; a phase that is clearly worse gets less
    say (a factor on the anchor). -> (factors {phase: f}, evidence)"""
    by = defaultdict(list)
    for d, lm, lk in recs: by[phase_of(d, starts)].append(lm - lk)
    gaps = {p: sum(v) / len(v) for p, v in by.items() if len(v) >= C.TRUST_MIN}
    ev = dict(n={p: len(v) for p, v in by.items()}, gap={p: round(g, 5) for p, g in gaps.items()})
    if len(gaps) < 2: return {p: 1.0 for _, p in C.TRUST_PHASES}, dict(ev, reason=f'fewer than two phases with {C.TRUST_MIN}+ matches')
    best = min(gaps.values())
    f = {p: round(max(C.TRUST_FLOOR, 1 - (gaps[p] - best) / C.TRUST_SCALE), 3) if p in gaps else 1.0 for _, p in C.TRUST_PHASES}
    return f, ev


def blend_ll(rows, w):
    """Mean log loss of w x model + (1 - w) x market on the probabilities each gave the result."""
    return sum(-math.log(max(w * a + (1 - w) * b, 1e-9)) for a, b in rows) / len(rows)


def decide_anchor(weight, rows, min_n=None):
    """The model's say v the market (16 Oct): the weight in ANCHOR_GRID whose blend of model and market predicts the
    results best. rows: [(p_model, p_market)] for the result that happened, newest first. Moves straight to the best
    weight, which may be zero (the model adds nothing), when it beats the weight in force by ANCHOR_BLEND_MARGIN.
    -> (new_weight, evidence) or (None, evidence)"""
    min_n = C.ANCHOR_WINDOW if min_n is None else min_n
    rows = [(a, b) for a, b in rows if a and b]
    if min_n == C.ANCHOR_WINDOW: rows = rows[:C.ANCHOR_WINDOW]
    n = len(rows)
    if n < min_n: return None, dict(n=n, reason=f'{n} settled fixtures, need {min_n}')
    grid = {w: blend_ll(rows, w) for w in C.ANCHOR_GRID}
    best = min(grid, key=grid.get)
    now_ll = blend_ll(rows, weight)
    ev = dict(n=n, weight_before=weight, best=best, ll_best=round(grid[best], 5), ll_in_force=round(now_ll, 5),
              ll_model=round(blend_ll(rows, 1.0), 5), ll_market=round(grid[0.0], 5), grid={str(w): round(v, 5) for w, v in grid.items()})
    if abs(best - weight) > 1e-9 and now_ll - grid[best] >= C.ANCHOR_BLEND_MARGIN:
        why = 'the model adds nothing to the market here: no say' if best == 0 else f'the blend predicts best with the model at {best:.0%}'
        return best, dict(ev, reason=why)
    return None, dict(ev, reason='no change: the weight in force is best, or within the margin')