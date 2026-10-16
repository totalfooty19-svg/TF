"""Idea 17 (29 Sep 2026): rate teams on shots on target as well as goals.

A goal is rare and noisy; shots on target happen about three to five times as often and show who is creating chances,
so they settle a team's rating faster. This is the stand-in for xG in leagues with no public xG (football-data.co.uk
records shots on target for most of its leagues).

Two fits on the same matches and the same fade: goals (Dixon-Coles) and shots on target (Poisson). Shots are turned
into goals with each side's conversion rate (goals per shot on target, home and away, over the same window), and the
two are blended on the log scale with weight SHOTS_WEIGHT. Because every piece is linear in log-lambda, the blend is
again an attack / defence / home-advantage set, returned in the dc.py shape so dc.lambdas() prices from it."""
import math
from .. import config as C
from . import fastdc


def usable(matches, need=0.8, keys=('hst', 'ast')):
    have = sum(1 for m in matches if m.get(keys[0]) is not None and m.get(keys[1]) is not None)
    return bool(matches) and have >= need * len(matches)


def fit(matches, base_date, xi, goals_params, w=None, keys=('hst', 'ast')):
    """matches: dicts with hg, ag and the two count fields (shots on target 'hst'/'ast', or xG 'hxg'/'axg').
    goals_params: the Dixon-Coles goals fit of the same recipe (supplies rho and the goals half of the blend).
    -> dc-format params, or None when the data is missing."""
    w = C.SHOTS_WEIGHT if w is None else w
    kh, ka = keys
    ms = [m for m in matches if m.get(kh) is not None and m.get(ka) is not None]
    if not usable(matches, keys=keys) or len(ms) < 60: return None
    s = fastdc.fit(ms, base_date, xi, hg_key=kh, ag_key=ka, fit_rho=False)
    dw = [math.exp(-xi * max((base_date - m['date']).days, 0)) for m in ms]
    conv_h = sum(d * m['hg'] for d, m in zip(dw, ms)) / max(sum(d * m[kh] for d, m in zip(dw, ms)), 1e-9)
    conv_a = sum(d * m['ag'] for d, m in zip(dw, ms)) / max(sum(d * m[ka] for d, m in zip(dw, ms)), 1e-9)
    g = goals_params
    teams = [t for t in g['attack'] if t in s['attack']]
    # log lh = (1-w)(hfa_g + a_g[h] + d_g[a]) + w(log conv_h + hfa_s + a_s[h] + d_s[a])
    # log la = (1-w)(a_g[a] + d_g[h])        + w(log conv_a + a_s[a] + d_s[h])
    # Put the away constant c = w log conv_a into every defence, and take it back out of the home advantage.
    c = w * math.log(conv_a)
    att = {t: (1 - w) * g['attack'][t] + w * s['attack'][t] for t in teams}
    dfn = {t: (1 - w) * g['defence'][t] + w * s['defence'][t] + c for t in teams}
    hfa = (1 - w) * g['home_advantage'] + w * (math.log(conv_h) + s['home_advantage']) - c
    return dict(engine='xg-blend' if kh == 'hxg' else 'shots-blend', attack=att, defence=dfn, home_advantage=hfa, rho=g['rho'], n=len(ms),
                shots_weight=w, conversion=dict(home=round(conv_h, 4), away=round(conv_a, 4)))
