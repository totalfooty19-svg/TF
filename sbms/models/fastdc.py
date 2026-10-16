"""A fast Dixon-Coles fitter for large fits (a whole country's pyramid; shots models), with exact gradients.

Two stages, the standard way: (1) time-weighted Poisson maximum likelihood for attack, defence and home advantage,
by L-BFGS with an analytic gradient; (2) rho, the Dixon-Coles low-score correction, by a one-dimensional fit with the
strengths held. A tiny ridge penalty only fixes the scale (attack and defence can trade a constant otherwise).
Returns the same plain-JSON shape as models/dc.py, so dc.lambdas() prices from it."""
import math
import numpy as np


def fit(matches, base_date, xi, hg_key='hg', ag_key='ag', fit_rho=True, ridge=1e-4):
    """matches: dicts with date, home, away and the two count fields. -> params dict (dc format)."""
    teams = sorted({m['home'] for m in matches} | {m['away'] for m in matches})
    ix = {t: i for i, t in enumerate(teams)}; n = len(teams)
    hi = np.array([ix[m['home']] for m in matches]); ai = np.array([ix[m['away']] for m in matches])
    hg = np.array([float(m[hg_key]) for m in matches]); ag = np.array([float(m[ag_key]) for m in matches])
    w = np.array([math.exp(-xi * max((base_date - m['date']).days, 0)) for m in matches])

    def nll(x):
        att, dfn, hfa = x[:n], x[n:2 * n], x[2 * n]
        eh = hfa + att[hi] + dfn[ai]; ea = att[ai] + dfn[hi]
        lh, la = np.exp(eh), np.exp(ea)
        f = np.sum(w * (lh - hg * eh + la - ag * ea)) + ridge * (att @ att + dfn @ dfn)
        rh, ra = w * (lh - hg), w * (la - ag)          # d nll / d log-lambda
        g_att = np.bincount(hi, rh, n) + np.bincount(ai, ra, n) + 2 * ridge * att
        g_dfn = np.bincount(ai, rh, n) + np.bincount(hi, ra, n) + 2 * ridge * dfn
        return f, np.concatenate([g_att, g_dfn, [rh.sum()]])

    from scipy.optimize import minimize, minimize_scalar
    x0 = np.zeros(2 * n + 1); x0[2 * n] = 0.2
    r = minimize(nll, x0, jac=True, method='L-BFGS-B', options=dict(maxiter=2000))
    att, dfn, hfa = r.x[:n], r.x[n:2 * n], r.x[2 * n]
    rho = 0.0
    if fit_rho:
        lh = np.exp(hfa + att[hi] + dfn[ai]); la = np.exp(att[ai] + dfn[hi])
        m00 = (hg == 0) & (ag == 0); m01 = (hg == 0) & (ag == 1); m10 = (hg == 1) & (ag == 0); m11 = (hg == 1) & (ag == 1)

        def nll_rho(rho):
            tau = np.ones_like(lh)
            tau[m00] = 1 - lh[m00] * la[m00] * rho; tau[m01] = 1 + lh[m01] * rho
            tau[m10] = 1 + la[m10] * rho; tau[m11] = 1 - rho
            return -np.sum(w * np.log(np.clip(tau, 1e-10, None)))
        rho = float(minimize_scalar(nll_rho, bounds=(-0.3, 0.3), method='bounded').x)
    return dict(engine='fastdc', attack={t: float(att[ix[t]]) for t in teams}, defence={t: float(dfn[ix[t]]) for t in teams},
                home_advantage=float(hfa), rho=rho, n=len(matches), converged=bool(r.success))
