"""Idea 27 (30 Sep 2026): the committee. Every variant priced for a fixture (the champion, its layers, the challengers,
the market consensus and, with a key, Pinnacle) votes, weighted by how well it has predicted this league's recent
results. It is priced as its own variant, 'committee', and scored like every other: it earns a say only by beating the
champion on unseen matches.

Weights: exponential in each member's recent log loss on the result (the 'Hedge' rule): w = exp(-ETA x n x (loss -
best loss)), so a member 0.01 worse per match over 100 matches keeps exp(-1) = 37% of the best member's weight. A member
with too little history gets the smallest weight any proven member has (no free say). Until two members have history
the vote is equal. Pooling is linear (an average of probabilities), which keeps every market's probabilities summing to
one and is hard to break.

Idea 31 (30 Sep): the same votes say how much the variants disagree about a selection (highest minus lowest
probability). Stored with each suggestion so the Research tab can test whether bets the variants disagree on do worse.
Pure functions."""
import math
from . import config as C


def weights(scores, members, eta=None, min_n=None):
    """scores: {model: (n, logloss)} for this league; members: the variants priced for this fixture -> {model: weight}."""
    eta = C.COMMITTEE_ETA if eta is None else eta; min_n = C.COMMITTEE_MIN_N if min_n is None else min_n
    members = list(members)
    if not members: return {}
    known = {m: scores[m] for m in members if m in (scores or {}) and scores[m][0] >= min_n}
    if len(known) < 2: return {m: 1 / len(members) for m in members}
    best = min(ll for _, ll in known.values())
    raw = {m: math.exp(-eta * n * (ll - best)) for m, (n, ll) in known.items()}
    floor = min(raw.values())
    raw.update({m: floor for m in members if m not in raw})
    s = sum(raw.values())
    return {m: w / s for m, w in raw.items()}


def pool(member_probs, w):
    """member_probs: {model: {key: p}} -> {key: p}, each key averaged over the members that price it."""
    out = {}
    keys = {k for p in member_probs.values() for k in p}
    for k in keys:
        num = den = 0.0
        for m, p in member_probs.items():
            v = p.get(k)
            if v is None or not math.isfinite(v): continue
            num += w.get(m, 0) * v; den += w.get(m, 0)
        if den > 0: out[k] = num / den
    return out


def disagreement(member_probs, key):
    vals = [p[key] for p in member_probs.values() if p.get(key) is not None and math.isfinite(p[key])]
    return round(max(vals) - min(vals), 4) if len(vals) >= 2 else None
