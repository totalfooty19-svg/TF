"""Turning a score grid and an exchange book into suggestions. Pure functions — no I/O — so every rule is unit-tested."""
import math
from . import config as C
from .ladder import bp_to_odds, ticks_down, ladder_down, ladder_up

# ---------------------------------------------------------------- score grid -> market probabilities
def dc_tau(i, j, lh, la, rho):
    if i == 0 and j == 0: return 1 - lh * la * rho
    if i == 0 and j == 1: return 1 + lh * rho
    if i == 1 and j == 0: return 1 + la * rho
    if i == 1 and j == 1: return 1 - rho
    return 1.0


def score_grid(lh, la, rho=0.0, max_goals=C.MAX_GOALS, draw=1.0):
    """Dixon-Coles grid (rho = 0 gives independent Poisson). Normalised. draw: a multiplier on every drawn score (the
    draw correction of idea 18; 1.0 = none)."""
    ph = [math.exp(-lh) * lh ** k / math.factorial(k) for k in range(max_goals + 1)]
    pa = [math.exp(-la) * la ** k / math.factorial(k) for k in range(max_goals + 1)]
    g = [[ph[i] * pa[j] * dc_tau(i, j, lh, la, rho) * (draw if i == j else 1.0) for j in range(max_goals + 1)] for i in range(max_goals + 1)]
    s = sum(map(sum, g))
    return [[v / s for v in row] for row in g]


def market_probs(grid):
    n = len(grid)
    cell = lambda f: sum(grid[i][j] for i in range(n) for j in range(n) if f(i, j))
    h, d, a = cell(lambda i, j: i > j), cell(lambda i, j: i == j), cell(lambda i, j: i < j)
    out = {'H': h, 'D': d, 'A': a,
           'DNB_H': h / (h + a), 'DNB_A': a / (h + a),
           'BTTS_Y': cell(lambda i, j: i > 0 and j > 0), 'BTTS_N': cell(lambda i, j: i == 0 or j == 0)}
    for line in (1.5, 2.5, 3.5):
        o = cell(lambda i, j: i + j > line)
        out[f'O{line}'], out[f'U{line}'] = o, 1 - o
    return out


def cs_probs(grid):
    """Idea 16 (1 Oct): the correct-score market as Smarkets lists it: CS_i-j for 0-0 ... 3-3 and the three 'any other'
    results (CS_oh home win, CS_od draw, CS_oa away win, each beyond 3 goals a side)."""
    n = len(grid); out = {}
    for i in range(n):
        for j in range(n):
            k = f'CS_{i}-{j}' if i <= 3 and j <= 3 else ('CS_oh' if i > j else ('CS_oa' if j > i else 'CS_od'))
            out[k] = out.get(k, 0.0) + grid[i][j]
    s = sum(out.values())
    return {k: v / s for k, v in out.items()}


def extra_markets(grid):
    """Idea 16: markets beyond the six the bot prices today, from the same scoreline grid, ready for when their Smarkets
    names are confirmed (market_types_seen).
      CS_i-j       correct score i-j (and CS_other: any score beyond 3-3)
      AH_H_<line>  Asian handicap, home side with <line> goals (e.g. AH_H_-1.5, AH_H_+0.5), and AH_A_<line> for the away side:
                   {win, push} for half and whole lines; for quarter lines, where half the stake goes on each neighbouring
                   line, {w_lo, p_lo, w_hi, p_hi}. ah_ev() turns either into EV at a price."""
    n = len(grid); out = {}
    tot = 0.0
    for i in range(4):
        for j in range(4):
            out[f'CS_{i}-{j}'] = grid[i][j]; tot += grid[i][j]
    out['CS_other'] = 1 - tot
    diff = {}
    for i in range(n):
        for j in range(n):
            diff[i - j] = diff.get(i - j, 0.0) + grid[i][j]

    def ah(side, line):
        """(p_win, p_push, p_half_win, p_half_loss) for a bet on `side` with handicap `line` (quarter lines split)."""
        sgn = 1 if side == 'H' else -1
        def single(l):
            w = sum(p for d, p in diff.items() if sgn * d + l > 0); pu = sum(p for d, p in diff.items() if sgn * d + l == 0)
            return w, pu
        if abs(line * 4 - round(line * 4)) < 1e-9 and abs(line * 2 - round(line * 2)) > 1e-9:   # quarter line: two halves
            (w1, p1), (w2, p2) = single(line - 0.25), single(line + 0.25)
            return dict(w_lo=w1, p_lo=p1, w_hi=w2, p_hi=p2)
        w, pu = single(line)
        return dict(win=w, push=pu)
    for line in (-2.5, -2, -1.5, -1, -0.75, -0.5, -0.25, 0, 0.25, 0.5, 0.75, 1, 1.5):
        out[f'AH_H_{line:+g}'] = ah('H', line); out[f'AH_A_{-line:+g}'] = ah('A', -line)
    return out


def ah_ev(d, odds, comm=C.COMMISSION):
    """EV per unit stake of an Asian handicap bet at decimal odds from extra_markets()'s dict."""
    net = (odds - 1) * (1 - comm)
    if 'win' in d:
        lose = 1 - d['win'] - d['push']
        return d['win'] * net - lose
    # quarter line: half the stake on each neighbouring line
    lo_lose = 1 - d['w_lo'] - d['p_lo']; hi_lose = 1 - d['w_hi'] - d['p_hi']
    return 0.5 * (d['w_lo'] * net - lo_lose) + 0.5 * (d['w_hi'] * net - hi_lose)


# ---------------------------------------------------------------- exchange book
def devig(mids: dict) -> dict:
    """Exchange no-vig: normalise mid-point probabilities (the exchange margin is small, so proportional is adequate)."""
    s = sum(mids.values())
    return {k: v / s for k, v in mids.items()}


def contract_view(bids, offers):
    """bids/offers: lists of (bp, quantity) as returned. On Smarkets, 'offers' are what a backer can take:
    best back odds = 10000 / lowest offer bp. 'bids' are the backers' queue: best lay odds = 10000 / highest bid bp."""
    best_offer = min((bp for bp, q in offers), default=None)
    best_bid = max((bp for bp, q in bids), default=None)
    back = bp_to_odds(best_offer) if best_offer else None
    lay = bp_to_odds(best_bid) if best_bid else None
    if best_offer and best_bid: mid = (best_offer + best_bid) / 2 / 10000
    elif best_offer: mid = best_offer / 10000
    elif best_bid: mid = best_bid / 10000
    else: mid = None
    spread_pts = (best_offer - best_bid) / 100 if best_offer and best_bid else None
    # Order-book depth (29 Sep, for predicting price moves, weight of money and the integrity filter): the quantity at the
    # best price and within the best three price levels on each side, in Smarkets' own quantity units (stored raw).
    top = lambda lv, rev: sorted(lv, key=lambda x: x[0], reverse=rev)[:3]
    offs, bids_ = top(offers, False), top(bids, True)
    depth = dict(back_qty=offs[0][1] if offs else None, lay_qty=bids_[0][1] if bids_ else None,
                 back_depth3=sum(q for _, q in offs) if offs else None, lay_depth3=sum(q for _, q in bids_) if bids_ else None)
    return dict(back=back, lay=lay, mid=mid, spread_pts=spread_pts, back_bp=best_offer, lay_bp=best_bid, **depth)


# ---------------------------------------------------------------- the rules
def ev_back(p, odds, comm=C.COMMISSION):
    return p * (odds - 1) * (1 - comm) - (1 - p)


def capped(p_model, p_mkt, band):
    lo, hi = p_mkt * (1 - band), p_mkt * (1 + band)
    return min(max(p_model, lo), hi)


def threshold_for(key):
    if str(key).startswith('CS_'): return C.THRESH_CS
    return C.THRESH_RESULT if key in ('H', 'D', 'A', 'DNB_H', 'DNB_A') else C.THRESH_GOALS


def floor_price(p_work, floor=C.FLOOR_EV, comm=C.COMMISSION):
    """The lowest ladder price at which backing p_work clears the floor after commission."""
    if p_work <= 0: return None
    return ladder_up(1 + (floor + 1 - p_work) / (p_work * (1 - comm)))


def evaluate_row(key, p_model, p_mkt, view, volume, band, anchor=None):
    """Returns a dict with the numbers and the first gate the row fails (gate=None means it qualifies).

    L-1 (Mitch, 29 Sep 2026): "if a bet is there and we think it's value we can take it; if we have capital we aren't
    using, we can place it where we want it." So:
      - TAKE: the best back price on offer clears the floor -> order_type 'take' at that price (no spread or volume test);
      - REST: otherwise an order resting at the lowest ladder price that clears the floor -> order_type 'rest'. It counts
        only if the book reaches that price before kick-off (db.set_close marks `filled`); unfilled rests are kept in their own column.
    The old liquidity line (spread > 6 pts) and S-1a (untraded) no longer block; spread and volume are still recorded.
    Set C.LIQUIDITY_GATES = True to restore them."""
    pc = capped(p_model, p_mkt, band)
    a = C.ANCHOR_MODEL_WEIGHT if anchor is None else anchor     # the league's earned weight (tuning.py)
    pw = a * pc + (1 - a) * p_mkt
    r = dict(key=key, p_model=p_model, p_capped=pc, p_market=p_mkt, p_work=pw, back=view['back'], lay=view['lay'],
             spread_pts=view['spread_pts'], volume=volume, ev=None, gate=None, order_type=None, price=None,
             take_ev=None, resting_price=None, resting_ev=None)
    if pc < threshold_for(key): r['gate'] = 'threshold'; return r
    if C.LIQUIDITY_GATES:
        if volume is None or volume < C.MIN_VOLUME: r['gate'] = 'untraded'; return r
        if view['spread_pts'] is None or view['spread_pts'] > C.MAX_SPREAD_PTS: r['gate'] = 'thin'; return r
    if view['back']:
        r['take_ev'] = ev_back(pw, view['back'])
        if r['take_ev'] >= C.FLOOR_EV - 1e-12:
            r.update(order_type='take', price=view['back'], ev=r['take_ev']); return r
    fp = floor_price(pw)
    if fp is None: r['gate'] = 'floor'; return r
    r.update(order_type='rest', price=fp, ev=ev_back(pw, fp), resting_price=fp, resting_ev=ev_back(pw, fp))
    return r


def pick_for_fixture(rows):
    """One per fixture. A price we can take now beats a resting order: the 'take' row with the highest EV; if none, the
    'rest' row whose resting price is closest to the current back price (most likely to fill)."""
    ok = [r for r in rows if r['gate'] is None]
    takes = [r for r in ok if r['order_type'] == 'take']
    if takes: return max(takes, key=lambda r: r['ev'])
    rests = [r for r in ok if r['order_type'] == 'rest']
    if not rests: return None
    return min(rests, key=lambda r: (r['price'] / r['back']) if r['back'] else 99.0)
