"""Idea 6 (30 Sep 2026): team ratings learned from closing prices instead of results.

A result is one noisy draw; a closing price summarises everything the market knew. For every past match with closing
result and over/under 2.5 odds (football-data.co.uk), the goal expectations the market implied are recovered with the
market-consensus fitter (models/consensus.py). Team ratings are then fitted to those implied expectations by weighted
least squares on the log scale, with the recipe's fade:
    log lh_implied = hfa + attack[home] + defence[away];   log la_implied = attack[away] + defence[home]
Returned in the dc.py shape, so dc.lambdas() prices from it. A method in its own right ('prices'), competing with goals,
shots, xG and the pyramid; the market's view averaged over time, which the model then has to beat."""
import math
import numpy as np
from . import consensus, fastdc


def implied(m):
    """The goal expectations a match's closing prices implied (cached on the match). None without both markets."""
    if 'imp' in m: return m['imp']
    c1, c2 = m.get('close_1x2'), m.get('close_ou25')
    out = None
    if c1 and c2 and all(x and x > 1 for x in c1 + c2):
        inv = [1 / x for x in c1]; s = sum(inv); iv2 = [1 / x for x in c2]; s2 = sum(iv2)
        rows = {'H': dict(mid_novig=inv[0] / s), 'D': dict(mid_novig=inv[1] / s), 'A': dict(mid_novig=inv[2] / s),
                'O2.5': dict(mid_novig=iv2[0] / s2), 'U2.5': dict(mid_novig=iv2[1] / s2)}
        f = consensus.fit(rows, -0.05)
        if f: out = (f['lh'], f['la'])
    m['imp'] = out
    return out


def usable(matches, need=0.8):
    return bool(matches) and sum(1 for m in matches if m.get('close_1x2') and m.get('close_ou25')) >= need * len(matches)


def fit(matches, base_date, xi, ridge=1e-3):
    ms = [m for m in matches if implied(m)]
    if len(ms) < 60: return None
    teams = sorted({m['home'] for m in ms} | {m['away'] for m in ms}); ix = {t: i for i, t in enumerate(teams)}; n = len(teams)
    rows, y, w = [], [], []
    for m in ms:
        lh, la = m['imp']; wt = math.exp(-xi * max((base_date - m['date']).days, 0))
        r1 = np.zeros(2 * n + 1); r1[ix[m['home']]] = 1; r1[n + ix[m['away']]] = 1; r1[2 * n] = 1
        r2 = np.zeros(2 * n + 1); r2[ix[m['away']]] = 1; r2[n + ix[m['home']]] = 1
        rows += [r1, r2]; y += [math.log(lh), math.log(la)]; w += [wt, wt]
    X, Y, W = np.array(rows), np.array(y), np.sqrt(np.array(w))
    A = np.vstack([X * W[:, None], math.sqrt(ridge) * np.eye(2 * n + 1)[:2 * n]])
    b = np.concatenate([Y * W, np.zeros(2 * n)])
    x = np.linalg.lstsq(A, b, rcond=None)[0]
    rho = fastdc.fit(ms, base_date, xi)['rho']          # the low-score correction from the results themselves
    return dict(engine='prices', attack={t: float(x[ix[t]]) for t in teams}, defence={t: float(x[n + ix[t]]) for t in teams},
                home_advantage=float(x[2 * n]), rho=rho, n=len(ms))
