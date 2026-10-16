"""Idea 25, the integrity filter (29 Sep 2026): flag a sharp, fast move in a fixture's prices.

Very unusual money in a thin market can mean someone knows something (a team-news leak or worse). For now a move is
only RECORDED on the fixture (fixtures.flags) and shown on the page; the Research tab then tests whether flagged moves
were informed (the side the money moved to won more often than even its new price said). Blocking bets on flagged
fixtures is switched on only if that evidence appears (INTEGRITY_BLOCK in config.py)."""
from . import config as C

KEYS = ('H', 'D', 'A', 'O2.5', 'U2.5')


def check(prev, rows, now, kickoff):
    """prev: (read_at, rows) of the fixture's last quote read, or None. -> flag dict or None."""
    if not prev: return None
    read_at, before = prev
    minutes = (now - read_at).total_seconds() / 60
    if minutes <= 0 or minutes > C.INTEGRITY_WINDOW_MIN: return None
    best = None
    for k in KEYS:
        a = (before.get(k) or {}).get('mid_novig'); b = (rows.get(k) or {}).get('mid_novig')
        if a is None or b is None: continue
        if best is None or abs(b - a) > abs(best[3]): best = (k, a, b, b - a)
    if not best or abs(best[3]) < C.INTEGRITY_MOVE: return None
    k, a, b, mv = best
    r = rows.get(k) or {}
    return dict(key=k, before=round(a, 4), after=round(b, 4), move=round(mv, 4), minutes=round(minutes),
                hours_to_kickoff=round((kickoff - now).total_seconds() / 3600, 1), at=now.isoformat(),
                back_depth3=r.get('back_depth3'), lay_depth3=r.get('lay_depth3'), volume=r.get('volume'))
