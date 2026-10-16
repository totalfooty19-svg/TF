"""Two models that learn from the bot's own records (30 Sep 2026). Both are fitted once a day by the pricing job from
the database, scored out of sample (fitted on the older 70%, tested on the newer 30%), saved in model_params with
their scores, and used only for recording until the Research tab shows they work; each has a switch in config.py.

Idea 15, a model of its own mistakes ('META'): will this bet beat the closing price? A logistic regression on what is
known when the bet is found: the edge, the price, the market (result / goals / both score / draw no bet), thin data,
hours before kick-off, the spread and volume, and how much the variants disagreed. Every new suggestion records its
prediction (suggestions.meta_p). META_SKIP, when set, skips bets predicted below it.

Ideas 2 and 20, the closing price ('CLOSE'): where will this price be at kick-off? A ridge regression on each settled
fixture's price path (price_path, 48 / 24 / 12 / 6 / 3 / 1 hours before): the price, the weight of money waiting on
each side (back v lay depth in the best three levels), the volume, hours left, and the model's disagreement with the
price. Every new suggestion records the predicted move of its selection (suggestions.pred_move)."""
import math
from . import config as C

MARKETS = ('result', 'goals', 'btts', 'dnb')


def market_of(key):
    k = str(key)
    if k in ('H', 'D', 'A'): return 'result'
    if k.startswith('DNB'): return 'dnb'
    if k.startswith('BTTS'): return 'btts'
    return 'goals'


# ---------------------------------------------------------------- idea 15
META_FEATURES = ('ev', 'log_price', 'result', 'goals', 'btts', 'thin', 'log_hours', 'spread', 'log_volume', 'disagreement')


def meta_x(ev, price, key, band, hours, spread_pts, volume, disagreement):
    m = market_of(key)
    return [ev or 0.0, math.log(price) if price and price > 1 else 0.0, float(m == 'result'), float(m == 'goals'), float(m == 'btts'),
            float(band == 'thin'), math.log1p(max(0.0, hours or 0.0)), (spread_pts or 0.0) / 10, math.log1p(volume or 0.0) / 10, disagreement or 0.0]


def _standardise(X):
    import numpy as np
    mu = X.mean(0); sd = X.std(0); sd[sd < 1e-9] = 1.0
    return mu, sd


def fit_logistic(X, y, ridge=1.0, iters=50):
    """L2-penalised logistic regression by Newton's method on standardised features. -> dict(w, mu, sd)."""
    import numpy as np
    X = np.asarray(X, float); y = np.asarray(y, float)
    mu, sd = _standardise(X)
    Z = np.hstack([np.ones((len(X), 1)), (X - mu) / sd])
    w = np.zeros(Z.shape[1]); P = ridge * np.eye(Z.shape[1]); P[0, 0] = 0.0
    for _ in range(iters):
        p = 1 / (1 + np.exp(-np.clip(Z @ w, -30, 30)))
        g = Z.T @ (p - y) + P @ w
        H = Z.T @ (Z * (p * (1 - p))[:, None]) + P
        step = np.linalg.solve(H, g); w -= step
        if np.abs(step).max() < 1e-8: break
    return dict(w=w.tolist(), mu=mu.tolist(), sd=sd.tolist())


def predict_logistic(m, x):
    z = m['w'][0] + sum(wi * (xi - mi) / si for wi, xi, mi, si in zip(m['w'][1:], x, m['mu'], m['sd']))
    return 1 / (1 + math.exp(-max(-30, min(30, z))))


def meta_fit(rows, min_n=None, split=0.7):
    """rows: [dict(x, beat, clv)] oldest first. -> dict(model, n, test) or None when too few."""
    min_n = C.META_MIN if min_n is None else min_n
    if len(rows) < min_n: return None
    cut = int(len(rows) * split)
    train, test = rows[:cut], rows[cut:]
    if len(train) < 10 or len(test) < 5 or len({r['beat'] for r in train}) < 2: return None
    m = fit_logistic([r['x'] for r in train], [r['beat'] for r in train])
    preds = [predict_logistic(m, r['x']) for r in test]
    ll = -sum(math.log(p if r['beat'] else 1 - p) for p, r in zip(preds, test)) / len(test)
    base = sum(r['beat'] for r in train) / len(train)
    ll0 = -sum(math.log(base if r['beat'] else 1 - base) for r in test) / len(test)
    kept = [r['clv'] for p, r in zip(preds, test) if p >= C.META_SKIP_TEST]
    skipped = [r['clv'] for p, r in zip(preds, test) if p < C.META_SKIP_TEST]
    avg = lambda a: round(sum(a) / len(a), 4) if a else None
    full = fit_logistic([r['x'] for r in rows], [r['beat'] for r in rows])      # the model in use: all the data
    return dict(model=full, features=list(META_FEATURES), n=len(rows),
                test=dict(n=len(test), logloss=round(ll, 4), logloss_base_rate=round(ll0, 4), threshold=C.META_SKIP_TEST,
                          kept=len(kept), kept_clv=avg(kept), skipped=len(skipped), skipped_clv=avg(skipped)))


# ---------------------------------------------------------------- ideas 2 and 20
CLOSE_FEATURES = ('p', 'imbalance', 'log_volume', 'log_hours', 'model_gap')


def close_x(p, back_depth, lay_depth, volume, hours, p_model):
    bd, ld = back_depth or 0.0, lay_depth or 0.0
    imb = (bd - ld) / (bd + ld) if bd + ld > 0 else 0.0
    return [p, imb, math.log1p(volume or 0.0) / 10, math.log1p(max(0.0, hours or 0.0)), (p_model - p) if p_model is not None else 0.0]


def fit_ridge(X, y, ridge=None):
    import numpy as np
    ridge = C.CLOSE_RIDGE if ridge is None else ridge
    X = np.asarray(X, float); y = np.asarray(y, float)
    mu, sd = _standardise(X)
    Z = np.hstack([np.ones((len(X), 1)), (X - mu) / sd])
    P = ridge * np.eye(Z.shape[1]); P[0, 0] = 0.0
    w = np.linalg.solve(Z.T @ Z + P, Z.T @ y)
    return dict(w=w.tolist(), mu=mu.tolist(), sd=sd.tolist())


def predict_ridge(m, x):
    return m['w'][0] + sum(wi * (xi - mi) / si for wi, xi, mi, si in zip(m['w'][1:], x, m['mu'], m['sd']))


def close_fit(rows, min_fixtures=None, split=0.7):
    """rows: [dict(fid, x, move)] ordered by kick-off (move = closing price - price then, as probabilities).
    Split by fixture so no fixture is in both halves. -> dict(model, n, test) or None."""
    min_fixtures = C.CLOSE_MIN if min_fixtures is None else min_fixtures
    fids = list(dict.fromkeys(r['fid'] for r in rows))
    if len(fids) < min_fixtures: return None
    cut = set(fids[:int(len(fids) * split)])
    train = [r for r in rows if r['fid'] in cut]; test = [r for r in rows if r['fid'] not in cut]
    if len(train) < 10 or len(test) < 5: return None
    m = fit_ridge([r['x'] for r in train], [r['move'] for r in train])
    pred = [predict_ridge(m, r['x']) for r in test]
    act = [r['move'] for r in test]
    mean_a = sum(act) / len(act)
    ss_res = sum((a - p) ** 2 for a, p in zip(act, pred)); ss_tot = sum((a - mean_a) ** 2 for a in act) or 1e-12
    big = [(a, p) for a, p in zip(act, pred) if abs(p) >= 0.01]
    return dict(model=fit_ridge([r['x'] for r in rows], [r['move'] for r in rows]), features=list(CLOSE_FEATURES),
                n=len(rows), fixtures=len(fids),
                test=dict(n=len(test), r2=round(1 - ss_res / ss_tot, 4), mae=round(sum(abs(a - p) for a, p in zip(act, pred)) / len(act), 4),
                          mae_no_move=round(sum(abs(a) for a in act) / len(act), 4),
                          called=len(big), direction_right=round(sum((a > 0) == (p > 0) for a, p in big) / len(big), 3) if big else None))
