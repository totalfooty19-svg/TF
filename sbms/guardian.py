"""Idea 33 (30 Sep 2026): the data guardian. Cheap checks on every run that stop bad data becoming a bet.

  - a broken book: the result market's mid prices imply less than 95% or more than 110% (a half-loaded or stale book;
    mids rather than back prices, since a thin book's wide spread is not a broken one),
    or a selection whose best lay is below its best back (a crossed book) -> no bet on the fixture this run;
  - a broken prediction: a goal expectation outside 0.15-4.5, or result probabilities that are not numbers or do not
    sum to one -> no bet from that variant;
  - a model and market 25+ points apart on a result. The model's cap means it would never bet the whole gap, but a gap
    that size is far more often a wrong team match (two clubs with similar names) or a stale results file than an edge
    -> no bet from that variant, and the fixture is listed for a look;
  - stale results: a league still being priced whose latest result is 28+ days old (a warning only).
Every problem is written to guardian_log (Health tab). Pure checks here; the job decides what to skip."""
import datetime as dt
import math
from . import config as C

KEYS = ('H', 'D', 'A')


def book_problem(rows):
    two_sided = all((rows.get(k) or {}).get('back') and (rows.get(k) or {}).get('lay') for k in KEYS)
    mids = [(rows.get(k) or {}).get('mid') for k in KEYS]
    if two_sided and all(mids):
        s = sum(mids)                                    # mids are stored as probabilities
        lo, hi = C.GUARD_OVERROUND
        if not lo <= s <= hi: return f'result book mid-prices imply {s:.0%} (outside {lo:.0%}-{hi:.0%})'
    for k, r in rows.items():
        b, l = (r or {}).get('back'), (r or {}).get('lay')
        if b and l and l < b - 1e-9: return f'{k}: lay {l} below back {b} (crossed book)'
    return None


def prediction_problem(lh, la, probs):
    lo, hi = C.GUARD_LAMBDA
    for x in (lh, la):
        if x is not None and (not math.isfinite(x) or not lo <= x <= hi): return f'goal expectation {x} outside {lo}-{hi}'
    vals = [probs.get(k) for k in KEYS]
    if any(v is None for v in vals): return None          # a variant that does not price the result (none today)
    if any(not math.isfinite(v) or v < 0 for v in vals): return 'result probabilities are not numbers'
    if abs(sum(vals) - 1) > 0.02: return f'result probabilities sum to {sum(vals):.3f}'
    return None


def gap_problem(probs, rows):
    for k in KEYS:
        p, m = probs.get(k), (rows.get(k) or {}).get('mid_novig')
        if p is not None and m is not None and abs(p - m) >= C.GUARD_GAP:
            return f'{k}: model {p:.0%} v market {m:.0%}'
    return None


def stale_problem(latest_match, today):
    if not latest_match: return None
    d = latest_match if isinstance(latest_match, dt.date) else dt.date.fromisoformat(str(latest_match)[:10])
    age = (today - d).days
    return f'latest result {d.isoformat()} ({age} days old)' if age >= C.GUARD_STALE_DAYS else None
