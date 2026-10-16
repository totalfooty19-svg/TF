"""Dixon-Coles per league. On Render penaltyblog does the fitting (pip install penaltyblog); where it is not installed
(e.g. a test machine) an equivalent scipy implementation is used. Either way the fitted parameters are stored as plain
JSON {attack, defence, home_advantage, rho} and predictions are computed from them by the same formula penaltyblog uses:
  lambda_home = exp(home_advantage + attack[home] + defence[away]); lambda_away = exp(attack[away] + defence[home])."""
import math
import numpy as np
from .. import config as C

try:
    import penaltyblog as pb   # noqa
    HAVE_PB = True
except Exception:   # pragma: no cover - depends on the machine
    HAVE_PB = False


def decay_weights(dates, base_date, xi=C.DC_XI):
    return np.array([math.exp(-xi * max((base_date - d).days, 0)) for d in dates])


def fit(matches, base_date, engine='auto', xi=C.DC_XI):
    """matches: list of dicts with date (datetime.date), home, away, hg, ag. xi: how fast old results fade (the league's
    recipe; tuning.py). Returns params dict."""
    dates = [m['date'] for m in matches]
    w = decay_weights(dates, base_date, xi)
    hg = np.array([m['hg'] for m in matches], dtype=float); ag = np.array([m['ag'] for m in matches], dtype=float)
    th = [m['home'] for m in matches]; ta = [m['away'] for m in matches]
    if engine in ('auto', 'penaltyblog') and HAVE_PB:
        model = pb.models.DixonColesGoalModel(hg, ag, th, ta, w)
        model.fit()
        p = model.get_params()
        teams = sorted(set(th) | set(ta))
        return dict(engine='penaltyblog', attack={t: float(p[f'attack_{t}']) for t in teams}, defence={t: float(p[f'defence_{t}']) for t in teams},
                    home_advantage=float(p['home_advantage']), rho=float(p['rho']), n=len(matches))
    return _fit_local(hg, ag, th, ta, w)


def _fit_local(hg, ag, th, ta, w):
    from scipy.optimize import minimize
    teams = sorted(set(th) | set(ta)); ix = {t: i for i, t in enumerate(teams)}; n = len(teams)
    hi = np.array([ix[t] for t in th]); ai = np.array([ix[t] for t in ta])
    from scipy.special import gammaln
    lgh, lga = gammaln(hg + 1), gammaln(ag + 1)

    def nll(x):
        att, dfn, hfa, rho = x[:n], x[n:2 * n], x[2 * n], x[2 * n + 1]
        lh = np.exp(hfa + att[hi] + dfn[ai]); la = np.exp(att[ai] + dfn[hi])
        ll = hg * np.log(lh) - lh - lgh + ag * np.log(la) - la - lga
        tau = np.ones_like(lh)
        m00 = (hg == 0) & (ag == 0); m01 = (hg == 0) & (ag == 1); m10 = (hg == 1) & (ag == 0); m11 = (hg == 1) & (ag == 1)
        tau[m00] = 1 - lh[m00] * la[m00] * rho; tau[m01] = 1 + lh[m01] * rho; tau[m10] = 1 + la[m10] * rho; tau[m11] = 1 - rho
        tau = np.clip(tau, 1e-10, None)
        return -np.sum(w * (ll + np.log(tau)))
    x0 = np.concatenate([np.zeros(n), np.zeros(n), [0.25], [-0.05]])
    cons = [{'type': 'eq', 'fun': lambda x: np.sum(x[:n])}]   # identifiability: attack strengths sum to zero
    bounds = [(-3, 3)] * (2 * n) + [(-1, 1), (-0.3, 0.3)]
    res = minimize(nll, x0, method='SLSQP', constraints=cons, bounds=bounds, options=dict(maxiter=500))
    x = res.x
    return dict(engine='local-scipy', attack={t: float(x[ix[t]]) for t in teams}, defence={t: float(x[n + ix[t]]) for t in teams},
                home_advantage=float(x[2 * n]), rho=float(x[2 * n + 1]), n=int(len(hg)), converged=bool(res.success))


def lambdas(params, home, away, neutral=False):
    hfa = 0.0 if neutral else params['home_advantage']
    lh = math.exp(hfa + params['attack'][home] + params['defence'][away])
    la = math.exp(params['attack'][away] + params['defence'][home])
    return lh, la
