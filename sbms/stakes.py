"""Idea 8 (30 Sep 2026): what is at stake in each match.

The rest of the season is simulated SIMS times from the current table and the champion model's ratings. For an upcoming
match, splitting the simulations by that match's result gives each side's chance of finishing in each zone (title,
promotion, play-offs, relegation) if it wins, draws or loses. The difference between winning and losing is how much the
match matters to that side. Late in a season, sides with nothing to play for are a known weakness in the market; this
measures it instead of guessing. For now it is shown on the page and stored for research; whether stakes change results
beyond the price is tested before anything uses it for pricing.

Zones only for leagues whose rules are certain (England's five divisions; round robin, home and away). Other leagues
are left out rather than guessed."""
import numpy as np
from .models import dc

SIMS = 10000
# zone -> (first position, last position), 1-based. England, 2025/26 rules.
ZONES = {
    'E0': dict(title=(1, 1), top_four=(1, 4), relegation=(18, 20)),
    'E1': dict(title=(1, 1), promotion=(1, 2), play_offs=(3, 6), relegation=(22, 24)),
    'E2': dict(title=(1, 1), promotion=(1, 2), play_offs=(3, 6), relegation=(21, 24)),
    'E3': dict(title=(1, 1), promotion=(1, 3), play_offs=(4, 7), relegation=(23, 24)),
    'EC': dict(title=(1, 1), promotion=(1, 1), play_offs=(2, 7), relegation=(21, 24)),
}


def current_season(matches, starts):
    """Matches since the latest season start (tuning.season_starts)."""
    if not starts: return []
    s = starts[-1]
    return [m for m in matches if m['date'] >= s]


def simulate(league, played, params, sims=SIMS, seed=0):
    """played: this season's matches (home, away, hg, ag). params: dc-format ratings. -> dict with the sims, or None."""
    zones = ZONES.get(league)
    if not zones or not played: return None
    teams = sorted({m['home'] for m in played} | {m['away'] for m in played})
    if any(t not in params['attack'] for t in teams): return None
    ix = {t: i for i, t in enumerate(teams)}; n = len(teams)
    pts = np.zeros(n); gd = np.zeros(n); gf = np.zeros(n); done = set()
    for m in played:
        h, a = ix[m['home']], ix[m['away']]; done.add((h, a))
        gd[h] += m['hg'] - m['ag']; gd[a] += m['ag'] - m['hg']; gf[h] += m['hg']; gf[a] += m['ag']
        if m['hg'] > m['ag']: pts[h] += 3
        elif m['hg'] < m['ag']: pts[a] += 3
        else: pts[h] += 1; pts[a] += 1
    rem = [(h, a) for h in range(n) for a in range(n) if h != a and (h, a) not in done]
    if not rem: return None
    lam = np.array([dc.lambdas(params, teams[h], teams[a]) for h, a in rem])
    rng = np.random.default_rng(seed)
    hg = rng.poisson(lam[:, 0], size=(sims, len(rem))); ag = rng.poisson(lam[:, 1], size=(sims, len(rem)))
    P = np.tile(pts, (sims, 1)); G = np.tile(gd, (sims, 1)); F = np.tile(gf, (sims, 1))
    hi = np.array([h for h, _ in rem]); ai = np.array([a for _, a in rem])
    win, draw = hg > ag, hg == ag
    for k in range(len(rem)):
        P[:, hi[k]] += 3 * win[:, k] + draw[:, k]; P[:, ai[k]] += 3 * (hg[:, k] < ag[:, k]) + draw[:, k]
        G[:, hi[k]] += hg[:, k] - ag[:, k]; G[:, ai[k]] -= hg[:, k] - ag[:, k]
        F[:, hi[k]] += hg[:, k]; F[:, ai[k]] += ag[:, k]
    score = P * 1e6 + G * 1e3 + F + rng.random(P.shape) * 1e-3          # points, then goal difference, then goals scored
    pos = np.empty_like(P, dtype=int)
    order = np.argsort(-score, axis=1)
    pos[np.arange(sims)[:, None], order] = np.arange(1, n + 1)
    return dict(league=league, teams=teams, ix=ix, rem={p: k for k, p in enumerate(rem)}, pos=pos, hg=hg, ag=ag, zones=zones)


def for_match(sim, home, away):
    """-> {team: {zone: dict(now, if_win, if_draw, if_lose, swing)}} for both sides, or None if not a remaining fixture."""
    if not sim or home not in sim['ix'] or away not in sim['ix']: return None
    k = sim['rem'].get((sim['ix'][home], sim['ix'][away]))
    if k is None: return None
    hw = sim['hg'][:, k] > sim['ag'][:, k]; dr = sim['hg'][:, k] == sim['ag'][:, k]; aw = ~hw & ~dr
    out = {}
    for team, w, l in ((home, hw, aw), (away, aw, hw)):
        p = sim['pos'][:, sim['ix'][team]]; z = {}
        for zone, (lo, hi) in sim['zones'].items():
            inz = (p >= lo) & (p <= hi)
            f = lambda mask: float(inz[mask].mean()) if mask.any() else None
            now, iw, idr, il = float(inz.mean()), f(w), f(dr), f(l)
            if now < 0.005 and (iw or 0) < 0.005: continue                      # not in play for this side
            if now > 0.995 and (il or 1) > 0.995: continue
            z[zone] = dict(now=round(now, 4), if_win=None if iw is None else round(iw, 4), if_draw=None if idr is None else round(idr, 4),
                           if_lose=None if il is None else round(il, 4), swing=round((iw or 0) - (il or 0), 4) if iw is not None and il is not None else None)
        out[team] = z
    return out


def headline(st):
    """The biggest swing on either side: (team, zone, swing) or None."""
    best = None
    for team, zs in (st or {}).items():
        for zone, v in zs.items():
            if v.get('swing') is not None and (best is None or abs(v['swing']) > abs(best[2])): best = (team, zone, v['swing'])
    return best
