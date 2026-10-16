"""Idea 11 (30 Sep 2026): in-play. The chance of each final result from the score and the minute.

From kick-off the rest of the match is scored as two Poisson processes whose rates are the pre-match goal
expectations (the live model's last prediction before kick-off, with its bias correction, weather and referee
factors), scaled by the share of the match's goal-time still to come. Goals come a little more often in the second
half (about 55% of goals), so a second-half minute weighs SECOND_HALF_WEIGHT times a first-half one; each half
carries its usual stoppage time. Red cards are not modelled (no card feed), which is one reason in-play paper bets
are held to a higher floor.

Pure functions only; the worker is jobs/inplay.py."""
import math
from . import config as C

FIRST, SECOND = 45 + 2, 45 + 4          # minutes including typical stoppage time
SECOND_HALF_WEIGHT = 1.22               # ~55% of goals come after half-time
_TOTAL = FIRST + SECOND * SECOND_HALF_WEIGHT


def remaining_share(minute):
    """Share of the match's goal-time still to come at `minute` (0 at the start, 90+ near the end)."""
    m = max(0.0, float(minute))
    if m <= FIRST:
        left = (FIRST - m) + SECOND * SECOND_HALF_WEIGHT
    else:
        left = max(0.0, (FIRST + SECOND) - m) * SECOND_HALF_WEIGHT
    return max(0.0, left / _TOTAL)


def probs(lh, la, minute, sh, sa, max_goals=10):
    """-> probabilities of the final result and goals markets given the score (sh, sa) at `minute`."""
    r = remaining_share(minute)
    mh, ma = lh * r, la * r
    ph = [math.exp(-mh) * mh ** k / math.factorial(k) for k in range(max_goals + 1)]
    pa = [math.exp(-ma) * ma ** k / math.factorial(k) for k in range(max_goals + 1)]
    out = dict(H=0.0, D=0.0, A=0.0, BTTS_Y=0.0)
    over = {1.5: 0.0, 2.5: 0.0, 3.5: 0.0}
    for i in range(max_goals + 1):
        for j in range(max_goals + 1):
            p = ph[i] * pa[j]
            fh, fa = sh + i, sa + j
            out['H' if fh > fa else ('A' if fa > fh else 'D')] += p
            if fh > 0 and fa > 0: out['BTTS_Y'] += p
            for line in over:
                if fh + fa > line: over[line] += p
    s = out['H'] + out['D'] + out['A']
    for k in ('H', 'D', 'A', 'BTTS_Y'): out[k] /= s
    out['BTTS_N'] = 1 - out['BTTS_Y']
    for line, v in over.items():
        out[f'O{line}'] = v / s; out[f'U{line}'] = 1 - v / s
    if out['H'] + out['A'] > 0:
        out['DNB_H'] = out['H'] / (out['H'] + out['A']); out['DNB_A'] = out['A'] / (out['H'] + out['A'])
    return out


def minute_now(elapsed, polled_at, now, status):
    """The match minute now from the last score poll (API-Football 'elapsed' and status)."""
    if status == 'HT': return 45.0
    base = float(elapsed or 0)
    return base + max(0.0, (now - polled_at).total_seconds() / 60)


def safe_to_bet(score_age_s, jumps):
    """Only bet on a fresh score and a calm book: a goal between polls would otherwise look like value."""
    return score_age_s <= C.INPLAY_MAX_SCORE_AGE_S and all(abs(j) < C.INPLAY_JUMP for j in jumps)
