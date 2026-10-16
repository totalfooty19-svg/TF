"""Smarkets price ladder (derived 25 Sep 2026 from 4,227 quoted levels) and basis-point helpers."""
import math

LADDER = [(2.0, 0.01), (3.0, 0.02), (4.0, 0.05), (6.0, 0.10), (10.0, 0.20), (20.0, 0.50), (30.0, 1.0),
          (50.0, 2.0), (100.0, 5.0), (100000.0, 10.0)]


def step_at(o: float) -> float:
    for top, step in LADDER:
        if o < top - 1e-9:
            return step
    return LADDER[-1][1]


def ladder_down(o: float) -> float:
    """Largest ladder price <= o."""
    base = 1.01
    for top, step in LADDER:
        if o <= top + 1e-9:
            n = math.floor((o - base) / step + 1e-9)
            return round(base + n * step, 2)
        base = top
    return round(o, 2)


def ladder_up(o: float) -> float:
    """Smallest ladder price >= o."""
    d = ladder_down(o)
    return d if abs(d - o) < 1e-9 else round(d + step_at(d + 1e-9), 2)


def ticks_down(o: float, n: int) -> float:
    v = o
    for _ in range(n):
        v = round(v - step_at(v - 1e-6), 2)
    return v


def bp_to_odds(bp: int) -> float:
    """Smarkets quotes are in basis points of probability (10000 = certainty)."""
    return 10000.0 / bp


def odds_to_bp(o: float) -> int:
    return int(round(10000.0 / o))
