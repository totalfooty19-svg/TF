"""European club competitions: cross-league pricing from ClubElo ratings (a Dixon-Coles fit cannot compare clubs from
different leagues). Expected score from the Elo difference, then a ratio split of an assumed total (which rises a little
with the mismatch), with a floor on the weaker lambda — the I-1.0 additive split drove it to ~0 (register, 25 Sep)."""
import math
from .. import config as C


def expected_score(elo_h, elo_a, hfa=C.ELO_HFA, neutral=False):
    dr = elo_h - elo_a + (0 if neutral else hfa)
    return 1 / (1 + 10 ** (-dr / 400))


def _exp_score(lh, la, maxg=12):
    ph = [math.exp(-lh) * lh ** k / math.factorial(k) for k in range(maxg + 1)]
    pa = [math.exp(-la) * la ** k / math.factorial(k) for k in range(maxg + 1)]
    w = sum(ph[i] * pa[j] for i in range(maxg + 1) for j in range(maxg + 1) if i > j)
    d = sum(ph[i] * pa[i] for i in range(maxg + 1))
    return w + 0.5 * d


def lambdas(elo_h, elo_a, total=C.ELO_TOTAL_GOALS, neutral=False, floor=0.20):
    """Total goals rise modestly with the mismatch (+0.6 per 400 Elo), the split is by ratio, and neither lambda may fall
    under `floor` (the G-1 lesson: a lambda near zero is a model artefact, not a forecast)."""
    we = expected_score(elo_h, elo_a, neutral=neutral)
    dr = abs(elo_h - elo_a + (0 if neutral else C.ELO_HFA))
    t = total + 0.6 * dr / 400
    lo, hi = -6.0, 6.0
    for _ in range(90):
        x = (lo + hi) / 2; r = math.exp(x)
        if _exp_score(t * r / (1 + r), t / (1 + r)) < we: lo = x
        else: hi = x
    r = math.exp((lo + hi) / 2)
    lh, la = t * r / (1 + r), t / (1 + r)
    return max(lh, floor), max(la, floor)
