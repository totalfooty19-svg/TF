"""Idea 1 (29 Sep 2026): Smarkets checked against itself.

Each market on a fixture (1X2, draw no bet, both teams to score, over/under 1.5 / 2.5 / 3.5) is priced by a different
crowd. Together they imply one set of scoreline odds; in thin leagues the markets often disagree with each other.
This fits the goal expectations (home, away) that best explain ALL of a fixture's no-vig prices at once, the market's
own consensus, with no football model involved. Priced as the variant 'market_consensus': a row whose price disagrees
with what the other markets jointly say shows up as value under the usual rules (cap, anchor, +4% floor).

Needs the result market and at least one goals market; otherwise the consensus would only echo one market."""
import math
import numpy as np
from .. import pricing

GROUPS = [('H', 'D', 'A'), ('DNB_H', 'DNB_A'), ('BTTS_Y', 'BTTS_N'), ('O1.5', 'U1.5'), ('O2.5', 'U2.5'), ('O3.5', 'U3.5')]
RESULT = {('H', 'D', 'A'), ('DNB_H', 'DNB_A')}


def _groups(rows):
    return [g for g in GROUPS if all(k in rows and rows[k].get('mid_novig') is not None for k in g)]


_N = 11
_I = np.arange(_N)[:, None]; _J = np.arange(_N)[None, :]
_LF = np.array([math.lgamma(k + 1) for k in range(_N)])
_MASKS = {'H': _I > _J, 'D': _I == _J, 'A': _I < _J, 'BTTS_Y': (_I > 0) & (_J > 0), 'BTTS_N': (_I == 0) | (_J == 0)}
for _line in (1.5, 2.5, 3.5):
    _MASKS[f'O{_line}'] = (_I + _J) > _line; _MASKS[f'U{_line}'] = (_I + _J) < _line


def _probs(lh, la, rho):
    """Vectorised Dixon-Coles grid -> the market probabilities the consensus needs (same maths as pricing.py)."""
    k = np.arange(_N)
    ph = np.exp(-lh + k * math.log(lh) - _LF); pa = np.exp(-la + k * math.log(la) - _LF)
    g = np.outer(ph, pa)
    g[0, 0] *= 1 - lh * la * rho; g[0, 1] *= 1 + lh * rho; g[1, 0] *= 1 + la * rho; g[1, 1] *= 1 - rho
    g /= g.sum()
    p = {k_: float(g[m].sum()) for k_, m in _MASKS.items()}
    p['DNB_H'] = p['H'] / (p['H'] + p['A']); p['DNB_A'] = p['A'] / (p['H'] + p['A'])
    return p


def fit(rows, rho=-0.05):
    """rows: {key: {mid_novig, ...}} for one fixture. -> dict(lh, la, rho, loss, groups) or None.
    Minimises the cross-entropy between each market group's no-vig prices and the grid's probabilities, each group
    weighted equally."""
    gs = _groups(rows)
    if not any(g in RESULT for g in gs) or not any(g not in RESULT for g in gs):
        return None
    target = [(g, [rows[k]['mid_novig'] for k in g]) for g in gs]

    def loss(x):
        p = _probs(math.exp(x[0]), math.exp(x[1]), rho)
        tot = 0.0
        for g, q in target:
            tot -= sum(qi * math.log(max(p[k], 1e-12)) for k, qi in zip(g, q))
        return tot / len(target)

    from scipy.optimize import minimize
    # start from a total of 2.6 goals split by the result market
    ph, pa = rows['H']['mid_novig'] if 'H' in rows else 0.45, rows['A']['mid_novig'] if 'A' in rows else 0.3
    share = min(max(0.5 + (ph - pa) * 0.6, 0.2), 0.8)
    r = minimize(loss, (math.log(2.6 * share), math.log(2.6 * (1 - share))), method='L-BFGS-B',
                 bounds=[(math.log(0.1), math.log(6))] * 2)
    lh, la = math.exp(r.x[0]), math.exp(r.x[1])
    return dict(lh=lh, la=la, rho=rho, loss=float(r.fun), groups=['/'.join(g) for g in gs])


def disagreement(rows, probs):
    """Per market row: consensus probability minus the row's own no-vig price (for the page and the research tab)."""
    return {k: probs[k] - r['mid_novig'] for k, r in rows.items() if k in probs and r.get('mid_novig') is not None}
