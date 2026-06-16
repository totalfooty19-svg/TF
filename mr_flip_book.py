"""
mr_flip_book.py — portfolio engine for the validated MR flip (build 2026-06-15a)

Turns the per-trade +0.45R edge into a BOOK: equity curve, drawdown, annual
returns, and tests the HEDGE thesis directly.

The flip fires BOTH ways:
  LONG  at upper + N*CW   (up-side breakout continuation)
  SHORT at lower - N*CW   (down-side breakout continuation)
So on any given day the book holds a mix of longs and shorts. The key question
(TF's): when we're heavy long and a short signal fires, the short REDUCES net
book exposure — it's a hedge, not extra risk. So the right risk measure is NET
directional exposure (long risk - short risk), not gross position count.

WHAT THIS ANSWERS:
  1. LONG vs SHORT standalone: does each side make money alone? (hedge viability)
  2. NET-EXPOSURE timeline: how directional is the book day to day? Are shorts
     naturally offsetting the longs?
  3. EQUITY / DRAWDOWN / ANNUAL RETURN at risk = 0.5/1/1.5/2/2.5% per trade,
     compounded chronologically, with realistic concurrent-position accounting.
  4. PER-TICKER edge so the basket can later be trimmed to best performers.

METHOD (honest):
  - Each trade has entry_date, exit_date, direction, R (stop-first, net cost).
  - Risk model: each trade risks `risk_pct` of CURRENT equity (1R = risk_pct).
    PnL on close = R * risk_pct * equity_at_entry. Compounded on exit date order.
  - Concurrency is REAL: capital is committed entry->exit. We do NOT assume
    infinite simultaneous capital. If gross concurrent risk would exceed 100% of
    equity, new entries that day are SKIPPED (documented) — this is the honest
    brake the per-trade mean ignores.
  - Net-exposure series = sum(long risk open) - sum(short risk open) each day.

ENV: MRB_NAMES, MRB_SHARD, MRB_N (default 3), MRB_STOP (default 1.0),
     MRB_COST (0.084), MRB_RISK_GRID ("0.5,1,1.5,2,2.5")
"""
import os
import sys
import datetime as dt
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner as sc
from intraday_resolve import fetch_bars, compute_atr

try:
    from capital_markets import TICKER_TO_EPIC
except Exception:
    TICKER_TO_EPIC = {}

BUILD = "mr_flip_book build 2026-06-15f (deep-dive battery: DD attribution / sub-annual corr / crash-grind / breadth)"

N_FOCUS = float(os.environ.get("MRB_N", "3"))
STOP_MULT = float(os.environ.get("MRB_STOP", "1.0"))
COST = float(os.environ.get("MRB_COST", "0.084"))
RISK_GRID = [float(x) for x in os.environ.get("MRB_RISK_GRID", "0.5,1,1.5,2,2.5").split(",")]
ATR_MULT_SL = sc.ATR_MULT_SL
CHANNEL_MAX_AGE = sc.CHANNEL_MAX_AGE
DAILY_START = dt.datetime(2000, 1, 1)


def _ext_levels(upper, lower, cw_d2, n_cw):
    return upper + n_cw * cw_d2, lower - n_cw * cw_d2


def _build_flip(side, ext_level, line, cw_d2, atr_val, stop_mult):
    if not np.isfinite(atr_val) or atr_val <= 0 or cw_d2 <= 0:
        return None
    reward = abs(ext_level - line)
    if reward <= 0:
        return None
    if side == "up":
        entry = ext_level
        stop = entry - stop_mult * atr_val
        target = entry + reward
        if entry > stop and target > entry:
            return dict(direction="long", entry=entry, stop=stop, target=target)
    else:
        entry = ext_level
        stop = entry + stop_mult * atr_val
        target = entry - reward
        if entry < stop and target < entry and target > 0:
            return dict(direction="short", entry=entry, stop=stop, target=target)
    return None


def _reaches(side, ext_level, H, L, i_from, i_to):
    for j in range(i_from, i_to + 1):
        if side == "up" and H[j] >= ext_level:
            return j
        if side == "down" and L[j] <= ext_level:
            return j
    return None


def _resolve(t, H, L, C, i0, n_bars):
    """Returns (R_stopfirst, exit_idx). Stop-first on ambiguous bars (conservative)."""
    entry, stop, target, direction = t["entry"], t["stop"], t["target"], t["direction"]
    Dd = abs(entry - stop)
    if Dd <= 0:
        return None
    end = min(i0 + n_bars, len(H) - 1)
    for j in range(i0, end + 1):
        hi, lo = H[j], L[j]
        if direction == "long":
            if lo <= stop:
                return ((stop - entry) / Dd, j)
            if hi >= target:
                return ((target - entry) / Dd, j)
        else:
            if hi >= stop:
                return ((entry - stop) / Dd, j)
            if lo <= target:
                return ((entry - target) / Dd, j)
    sign = 1.0 if direction == "long" else -1.0
    return (sign * (C[end] - entry) / Dd, end)


def run_name(client, tk, n_cw, stop_mult):
    """Returns list of trades: dict(tk, entry_date, exit_date, direction, R)."""
    epic = TICKER_TO_EPIC.get(tk, tk)
    out = []
    try:
        ddf = fetch_bars(client, epic, "DAY", DAILY_START)
    except Exception:
        return out
    if ddf is None or ddf.empty or len(ddf) < 150:
        return out
    ddf = ddf.copy()
    ddf["atr"] = compute_atr(ddf)
    H = ddf["high"].values
    L = ddf["low"].values
    C = ddf["close"].values
    A = ddf["atr"].values
    dates = list(ddf.index)
    N = len(ddf)
    seen = set()
    for si in list(range(120, N, 90)) + [N - 1]:
        try:
            chans, dfa = sc.find_active_channels(tk, ddf.iloc[:si + 1], ddf.index[si])
        except Exception:
            continue
        for ch in chans:
            d2 = ch.d2_idx
            cw_d2 = ch.d2_width
            if cw_d2 <= 0:
                continue
            for i in range(d2 + 1, si + 1):
                up, lo = ch.project(i - d2)
                if up - lo <= 0:
                    continue
                atr_val = A[i]
                up_ext, lo_ext = _ext_levels(up, lo, cw_d2, n_cw)
                for side, ext_level, line in (("up", up_ext, up), ("down", lo_ext, lo)):
                    j_ext = _reaches(side, ext_level, H, L, i, min(i + CHANNEL_MAX_AGE, N - 1))
                    if j_ext is None:
                        continue
                    key = (d2, round(cw_d2, 4), dates[i], side, n_cw)
                    if key in seen:
                        continue
                    seen.add(key)
                    fl = _build_flip(side, ext_level, line, cw_d2, atr_val, stop_mult)
                    if fl is None:
                        continue
                    res = _resolve(fl, H, L, C, j_ext, CHANNEL_MAX_AGE)
                    if res is None:
                        continue
                    Rnet = res[0] - COST
                    out.append(dict(tk=tk, entry_date=dates[j_ext], exit_date=dates[res[1]],
                                    direction=fl["direction"], R=float(Rnet)))
    return out


def simulate(trades, risk_pct, cap_net=0.30, cap_gross=2.0):
    """
    Chronological compounding equity sim with a NET-EXPOSURE cap (the hedge model).
    risk_pct as fraction (0.01 = 1%). Each trade risks risk_pct of CURRENT equity.

    The cap is on NET directional exposure, NOT gross:
      net_risk  = (sum long risk) - (sum short risk)   [signed]
      gross_risk = (sum long risk) + (sum short risk)   [for margin sanity only]
    A new trade is ALLOWED if it keeps |net_risk| <= cap_net. So an offsetting
    trade (a short when net is long) ALWAYS reduces |net| and is welcomed.
    A wide gross ceiling (cap_gross) still guards against absurd margin.

    SAME-BAR FIX (15c): a trade with entry_date == exit_date resolves on its entry
    bar (the ~0.8% same-bar residue). In 15a/15b such a trade emitted open+close on
    the same date, the sort put CLOSE before OPEN, so its close was a no-op (not yet
    in open_map) and its open then locked net/gross budget that was NEVER released.
    That leak ratcheted monotonically and pinned whichever cap was binding -> the
    book choked to a few hundred taken trades (the broken B.4 table, both 15a gross
    and 15b net). Fix: same-bar trades are handled as zero-duration roundtrips that
    realise PnL but never occupy budget (financially correct -- they tie up no
    overnight capital -- and they cannot leak it).
    Returns dict(eq, taken, skipped, max_dd, cagr, ann, final, peak_gross).
    """
    if not trades:
        return None
    ev = []
    for t in trades:
        if t["entry_date"] == t["exit_date"]:
            ev.append((t["exit_date"], "roundtrip", t))   # zero-duration, holds nothing
        else:
            ev.append((t["entry_date"], "open", t))
            ev.append((t["exit_date"], "close", t))
    # close frees capital first, then same-bar roundtrips realise, then new opens compete
    _order = {"close": 0, "roundtrip": 1, "open": 2}
    ev.sort(key=lambda x: (x[0], _order[x[1]]))

    equity = 1.0
    net_risk = 0.0            # signed: +long -short, in risk fractions
    gross_risk = 0.0
    open_map = {}             # id(t) -> (signed risk, abs risk)
    taken = skipped = 0
    peak_gross = 0.0
    eq_dates, eq_vals = [], []
    for date, kind, t in ev:
        if kind == "open":
            sgn = 1.0 if t["direction"] == "long" else -1.0
            new_net = net_risk + sgn * risk_pct
            new_gross = gross_risk + risk_pct
            # allow if it keeps |net| within cap (offsetting trades always pass),
            # subject to a loose gross margin ceiling
            if abs(new_net) > cap_net + 1e-9 or new_gross > cap_gross + 1e-9:
                skipped += 1
                continue
            open_map[id(t)] = (sgn * risk_pct, risk_pct)
            net_risk = new_net
            gross_risk = new_gross
            peak_gross = max(peak_gross, gross_risk)
            taken += 1
        elif kind == "roundtrip":
            # same-bar: realise PnL, occupy no net/gross (no overnight hold)
            equity += t["R"] * risk_pct * equity
            eq_dates.append(date)
            eq_vals.append(equity)
            taken += 1
        else:
            rec = open_map.pop(id(t), None)
            if rec is None:
                continue
            signed_r, abs_r = rec
            net_risk -= signed_r
            gross_risk -= abs_r
            equity += t["R"] * risk_pct * equity   # realise PnL on close, compounded
            eq_dates.append(date)
            eq_vals.append(equity)
    if not eq_vals:
        return None
    eq = pd.Series(eq_vals, index=pd.to_datetime(eq_dates)).sort_index()
    eq = eq.groupby(eq.index).last()
    peak = eq.cummax()
    dd = (eq / peak - 1.0)
    max_dd = dd.min()
    years = (eq.index[-1] - eq.index[0]).days / 365.25
    cagr = (eq.iloc[-1]) ** (1 / years) - 1 if years > 0 and eq.iloc[-1] > 0 else float("nan")
    ann = eq.resample("YE").last().pct_change().dropna()
    return dict(eq=eq, taken=taken, skipped=skipped, max_dd=max_dd, cagr=cagr,
                ann=ann, final=eq.iloc[-1], peak_gross=peak_gross)


def additive_r_curve(trs):
    """Leverage-free book equity in R: each trade contributes its R at a FIXED 1-unit
    stake, summed in EXIT-date order (PnL realises at close). No compounding, so it
    cannot overflow or hit ruin the way the %-of-equity model does at book concurrency.
    Gives the honest accumulation shape and the R-drawdown.
    Returns dict(total_R, max_dd_R, longest_dd_days, ann, n) or None."""
    if not trs:
        return None
    s = sorted(trs, key=lambda t: t["exit_date"])
    idx = pd.to_datetime([t["exit_date"] for t in s])
    r = np.asarray([t["R"] for t in s], dtype=float)
    cum = np.cumsum(r)
    dd = np.maximum.accumulate(cum) - cum          # drawdown in R (>= 0)
    max_dd_R = float(dd.max()) if len(dd) else 0.0
    cs = pd.Series(cum, index=idx)
    underwater = (cs < cs.cummax()).values
    longest_days = 0
    start = None
    for d, uw in zip(cs.index, underwater):
        if uw and start is None:
            start = d
        elif not uw and start is not None:
            longest_days = max(longest_days, (d - start).days)
            start = None
    if start is not None:
        longest_days = max(longest_days, (cs.index[-1] - start).days)
    ann = pd.Series(r, index=idx).resample("YE").sum()
    return dict(total_R=float(cum[-1]), max_dd_R=max_dd_R,
                longest_dd_days=int(longest_days), ann=ann, n=len(s))


def admission_stats(trades, risk_pct, cap_net, cap_gross):
    """Net-cap admission ONLY -- taken / skipped / peak gross. No equity is computed,
    so nothing can overflow. Same gate and same-bar roundtrip handling as simulate();
    this is the trustworthy half of the old Section 3 (the throttle behaviour)."""
    ev = []
    for t in trades:
        if t["entry_date"] == t["exit_date"]:
            ev.append((t["exit_date"], "roundtrip", t))
        else:
            ev.append((t["entry_date"], "open", t))
            ev.append((t["exit_date"], "close", t))
    _order = {"close": 0, "roundtrip": 1, "open": 2}
    ev.sort(key=lambda x: (x[0], _order[x[1]]))
    net = gross = 0.0
    open_map = {}
    taken = skipped = 0
    peak_gross = 0.0
    for date, kind, t in ev:
        if kind == "open":
            sgn = 1.0 if t["direction"] == "long" else -1.0
            nn = net + sgn * risk_pct
            ng = gross + risk_pct
            if abs(nn) > cap_net + 1e-9 or ng > cap_gross + 1e-9:
                skipped += 1
                continue
            open_map[id(t)] = (sgn * risk_pct, risk_pct)
            net = nn
            gross = ng
            peak_gross = max(peak_gross, gross)
            taken += 1
        elif kind == "roundtrip":
            taken += 1
        else:
            rec = open_map.pop(id(t), None)
            if rec is None:
                continue
            sr, ar = rec
            net -= sr
            gross -= ar
    return dict(taken=taken, skipped=skipped, peak_gross=peak_gross)


def direction_year_split(tdf, down_years):
    """N.1: per-year LONG vs SHORT R. Tests whether shorts carry the equity down-years
    (regime-complementary hedge) or are just a smaller, coincident long. Prints the
    table; returns dict(years, long_R, short_R, corr, down_long, down_short, short_led)."""
    t = tdf.copy()
    t["year"] = pd.to_datetime(t["exit_date"]).dt.year
    g = t.groupby(["year", "direction"])["R"].agg(s="sum", m="mean", c="size").reset_index()
    def cell(yr, d, col):
        row = g[(g["year"] == yr) & (g["direction"] == d)]
        return float(row[col].iloc[0]) if len(row) else 0.0
    years = sorted(int(y) for y in t["year"].unique())
    print(f"  {'year':>6} | {'LONG_R':>9} {'L_mean':>7} {'L_n':>6} | "
          f"{'SHORT_R':>9} {'S_mean':>7} {'S_n':>6} | lead")
    la, sa = [], []
    for yr in years:
        lr, lm, ln = cell(yr, "long", "s"), cell(yr, "long", "m"), cell(yr, "long", "c")
        sr, sm, sn = cell(yr, "short", "s"), cell(yr, "short", "m"), cell(yr, "short", "c")
        la.append(lr); sa.append(sr)
        lead = "SHORT" if sr > lr else "long"
        flag = " <DOWN" if yr in down_years else ""
        print(f"  {yr:>6} | {lr:>+9.1f} {lm:>+7.3f} {int(ln):>6} | "
              f"{sr:>+9.1f} {sm:>+7.3f} {int(sn):>6} | {lead}{flag}")
    la, sa = np.asarray(la), np.asarray(sa)
    corr = float("nan")
    if len(la) > 1 and la.std() > 0 and sa.std() > 0:
        corr = float(np.corrcoef(la, sa)[0, 1])
    dmask = np.array([yr in down_years for yr in years])
    dl = float(la[dmask].sum()) if dmask.any() else 0.0
    ds = float(sa[dmask].sum()) if dmask.any() else 0.0
    return dict(years=years, long_R=la, short_R=sa, corr=corr,
                down_long=dl, down_short=ds, short_led=int((sa > la).sum()))


def deep_dive(tdf):
    """Section 6 battery (off existing trade data, no account params): answers the
    questions N.1 raised -- drawdown attribution, sub-annual correlation, crash-vs-grind,
    book breadth/concurrency. All run on the trades already in memory (one scan)."""
    t = tdf.copy()
    t["exit_date"] = pd.to_datetime(t["exit_date"])
    t = t.sort_values("exit_date").reset_index(drop=True)
    t["year"] = t["exit_date"].dt.year
    t["m"] = t["exit_date"].dt.to_period("M")
    cum = t["R"].cumsum().values
    run_peak = np.maximum.accumulate(cum)
    ddv = run_peak - cum
    trough_i = int(np.argmax(ddv)) if len(ddv) else 0
    peak_i = int(np.argmax(cum[:trough_i + 1])) if trough_i > 0 else 0
    win = t.iloc[peak_i:trough_i + 1]
    pk, tr = t["exit_date"].iloc[peak_i], t["exit_date"].iloc[trough_i]

    print("\n  --- 6a DRAWDOWN ATTRIBUTION (is the worst combined DD a joint long+short bleed?) ---")
    lwin = win[win["direction"] == "long"]["R"].sum()
    swin = win[win["direction"] == "short"]["R"].sum()
    joint = "BOTH bled together (coincident)" if (lwin < 0 and swin < 0) else "one side offset the other"
    print(f"  worst combined R-DD {ddv[trough_i]:.0f}R over {pk.date()} -> {tr.date()} ({(tr - pk).days}d)")
    print(f"    in-window: long {lwin:+.0f}R, short {swin:+.0f}R  ->  {joint}")
    print(f"  underwater {100*(ddv > 1e-9).mean():.0f}% of trade-time")

    print("\n  --- 6b SUB-ANNUAL CORRELATION (does the +0.42 annual coincidence hold monthly?) ---")
    lm = t[t["direction"] == "long"].groupby("m")["R"].sum()
    sm = t[t["direction"] == "short"].groupby("m")["R"].sum()
    mm = pd.concat([lm, sm], axis=1).fillna(0.0); mm.columns = ["L", "S"]
    mcorr = float(mm["L"].corr(mm["S"])) if len(mm) > 1 else float("nan")
    opp = float((((mm["L"] > 0) & (mm["S"] < 0)) | ((mm["L"] < 0) & (mm["S"] > 0))).mean())
    print(f"  monthly corr(long, short) = {mcorr:+.2f}   (annual was +0.42)")
    print(f"  opposite-sign months = {100*opp:.0f}%  (genuine intra-year offset, even if annual is +ve)")

    print("\n  --- 6c CRASH vs GRIND down-years (do shorts carry crashes but not grinds?) ---")
    for label, yrs in (("CRASH [2000,2002,2008]", {2000, 2002, 2008}),
                       ("GRIND [2018,2022]    ", {2018, 2022})):
        sub = t[t["year"].isin(yrs)]
        lr = sub[sub["direction"] == "long"]["R"].sum()
        sr = sub[sub["direction"] == "short"]["R"].sum()
        print(f"  {label}: long {lr:+.0f}R vs short {sr:+.0f}R  ->  "
              f"{'SHORTS carry' if sr > lr else 'longs lead'}")

    print("\n  --- 6d BOOK BREADTH / CONCURRENCY (is the worst drawdown broad or concentrated?) ---")
    wtk = win.groupby("tk")["R"].sum().sort_values()
    ntk = int(t["tk"].nunique())
    nneg = int((wtk < 0).sum())
    print(f"  worst-DD window: {nneg}/{ntk} tickers net-negative "
          f"({'broad' if nneg > ntk / 2 else 'concentrated'})")
    print("  biggest losers in window: " + ", ".join(f"{k} {v:+.0f}R" for k, v in wtk.head(3).items()))
    piv = t.pivot_table(index="m", columns="tk", values="R", aggfunc="sum").fillna(0.0)
    if piv.shape[1] > 1:
        cm = piv.corr().values
        iu = np.triu_indices_from(cm, k=1)
        ac = float(np.nanmean(cm[iu]))
        print(f"  avg pairwise monthly corr across {piv.shape[1]} tickers = {ac:+.2f} "
              f"({'correlated book' if ac > 0.2 else 'largely idiosyncratic'})")


def main():
    print(BUILD)
    mode = sys.argv[1] if len(sys.argv) > 1 else "live"
    names_env = os.environ.get("MRB_NAMES", "").strip()
    if names_env:
        names = [x.strip().upper() for x in names_env.split(",") if x.strip()]
    else:
        names = list(getattr(sc, "SP100", []))[:79] or list(getattr(sc, "UNIVERSE", []))
    shard = os.environ.get("MRB_SHARD", "").strip()
    if shard and ":" in shard:
        a, b = shard.split(":")
        names = names[int(a):int(b)]
    print(f"mode={mode} names={len(names)} N={N_FOCUS} stop={STOP_MULT} cost={COST} "
          f"risk_grid={RISK_GRID}")

    client = None
    if mode == "live":
        from capital_client import CapitalClient
        try:
            client = CapitalClient.from_env()
        except Exception as e1:
            try:
                from accounts import load_accounts
                acc = load_accounts()[0]
                client = CapitalClient(api_key=acc.capital_api_key, login=acc.capital_login,
                                       password=acc.capital_password, demo=acc.demo)
            except Exception as e2:
                raise SystemExit(f"[book] no creds: {e1}; {e2}")
        client.login_session()
        print("[capital] logged in")

    trades = []
    for k, tk in enumerate(names, 1):
        print(f"  [{k}/{len(names)}] {tk} ...", flush=True)
        trades.extend(run_name(client, tk, N_FOCUS, STOP_MULT))
    if not trades:
        print("no trades — abort")
        return
    tdf = pd.DataFrame(trades)
    n = len(tdf)

    # ===== 1. LONG vs SHORT standalone =====
    print("\n" + "=" * 70)
    print("1. LONG vs SHORT STANDALONE  (does each side make money alone? hedge viability)")
    print("=" * 70)
    for d in ("long", "short"):
        g = tdf[tdf["direction"] == d]
        if len(g):
            print(f"  {d.upper():<6} n={len(g):<6} meanR={g['R'].mean():+.4f}  "
                  f"win={100*(g['R']>0).mean():4.1f}%  totalR={g['R'].sum():+.1f}")
    nl, ns = (tdf["direction"] == "long").sum(), (tdf["direction"] == "short").sum()
    print(f"  mix: {nl} long ({100*nl/n:.0f}%) / {ns} short ({100*ns/n:.0f}%)")
    print("  >>> if BOTH sides are clearly positive, shorts hedge longs AND make money —")
    print("      a heavy-long day with shorts firing is naturally de-risked, not extra risk.")

    # ===== 2. NET-EXPOSURE timeline =====
    print("\n" + "=" * 70)
    print("2. NET DIRECTIONAL EXPOSURE  (is the book naturally hedged day to day?)")
    print("=" * 70)
    # build daily open long-count and short-count using entry/exit spans, unit risk
    ev = []
    for t in trades:
        sgn = 1 if t["direction"] == "long" else -1
        ev.append((t["entry_date"], sgn))
        ev.append((t["exit_date"], -sgn))
    edf = pd.DataFrame(ev, columns=["date", "delta"]).groupby("date")["delta"].sum().sort_index()
    net = edf.cumsum()  # net (#long - #short) open over time, unit weights
    # also gross
    evg = []
    for t in trades:
        evg.append((t["entry_date"], 1))
        evg.append((t["exit_date"], -1))
    gdf = pd.DataFrame(evg, columns=["date", "delta"]).groupby("date")["delta"].sum().sort_index()
    gross = gdf.cumsum()
    netfrac = (net / gross.replace(0, np.nan)).abs()
    print(f"  avg gross open positions : {gross.mean():.1f}")
    print(f"  avg |net| open positions : {net.abs().mean():.1f}")
    print(f"  avg net/gross ratio      : {netfrac.mean():.2f}  "
          f"(0 = perfectly hedged, 1 = fully one-directional)")
    print(f"  max one-sided net long   : {net.max():.0f}")
    print(f"  max one-sided net short  : {net.min():.0f}")
    print("  >>> low net/gross means longs & shorts substantially offset — the book")
    print("      is self-hedging, so you can run MORE gross risk for the same net exposure.")

    # ===== 3. ADDITIVE-R BOOK (leverage-free) + net-cap admission =====
    print("\n" + "=" * 70)
    print("3. ADDITIVE-R BOOK  (leverage-free: 1R/trade, summed at close, NO compounding)")
    print("=" * 70)
    print("  The compounded %-of-equity model is retired here: at book concurrency")
    print("  (100-200% gross, 100s of open positions) it explodes/ruins (1e200x / nan) -")
    print("  a leverage artefact, NOT the edge. Additive R shows the true accumulation")
    print("  shape and the R-drawdown. (Deployable % sizing/DD = C.2/F.1, needs account params.)")
    print(f"  {'book':>9} | {'n':>7} | {'totalR':>11} | {'maxDD_R':>9} | {'R-MAR':>7} | {'longestDD':>10}")
    for label, sub in (("COMBINED", trades),
                       ("LONG", [t for t in trades if t["direction"] == "long"]),
                       ("SHORT", [t for t in trades if t["direction"] == "short"])):
        c = additive_r_curve(sub)
        if c is None:
            continue
        rmar = c["total_R"] / c["max_dd_R"] if c["max_dd_R"] > 0 else float("nan")
        print(f"  {label:>9} | {c['n']:>7} | {c['total_R']:>+11.1f} | {c['max_dd_R']:>9.1f} | "
              f"{rmar:>7.2f} | {c['longest_dd_days']:>8}d")
    print("  >>> R-MAR = totalR / max R-drawdown (leverage-free robustness). If COMBINED")
    print("      maxDD_R is below BOTH long and short alone, shorts smooth the curve (hedge in R).")

    cc = additive_r_curve(trades)
    print("\n  COMBINED additive-R by year (cross-check vs the banked 27/27 positive):")
    for dtix, v in cc["ann"].items():
        print(f"    {dtix.year}: {v:>+8.1f}R")

    # net-cap admission (taken/skipped/peak-gross only -- leverage-free, feeds C.2)
    print("\n" + "-" * 70)
    print("  NET-CAP ADMISSION  (how much the net cap throttles the book -- no equity):")
    NET_CAPS = [float(x) for x in os.environ.get("MRB_NET_CAPS", "0.10,0.20,0.30").split(",")]
    print(f"  {'netcap':>7} | {'risk%':>6} | {'taken':>8} | {'skip':>8} | {'taken%':>7} | {'pkGross':>8}")
    ntot = len(trades)
    for nc in NET_CAPS:
        for rp in RISK_GRID:
            a = admission_stats(trades, rp / 100.0, cap_net=nc, cap_gross=2.0)
            print(f"  {nc:>7.2f} | {rp:>6.1f} | {a['taken']:>8} | {a['skipped']:>8} | "
                  f"{100*a['taken']/ntot:>6.1f}% | {100*a['peak_gross']:>7.0f}%")

    # ===== 4. PER-TICKER (for basket trimming later) =====
    print("\n" + "=" * 70)
    print("4. PER-TICKER EDGE  (top/bottom — for trimming the basket to best performers)")
    print("=" * 70)
    pt = tdf.groupby("tk").agg(n=("R", "size"), meanR=("R", "mean"), totalR=("R", "sum"))
    pt = pt.sort_values("meanR", ascending=False)
    print("  TOP 10 by meanR:")
    print(pt.head(10).to_string())
    print("\n  BOTTOM 10 by meanR:")
    print(pt.tail(10).to_string())
    pos = (pt["meanR"] > 0).sum()
    print(f"\n  {pos}/{len(pt)} tickers positive. Trimming to top performers raises meanR but")
    print(f"  cuts trade count — the trade-count vs edge balance you flagged. Real selection")
    print(f"  should be done on TRAIN and validated on held-out (P5, full 449 universe).")

    # ===== 5. DIRECTION x YEAR (N.1: regime-complementary hedge test) =====
    print("\n" + "=" * 70)
    print("5. DIRECTION x YEAR  (N.1: do shorts carry the down-years longs can't?)")
    print("=" * 70)
    DOWN_YEARS = {2000, 2001, 2002, 2008, 2018, 2022}  # ~S&P total-return-negative yrs; edit as needed
    n1 = direction_year_split(tdf, DOWN_YEARS)
    print(f"\n  corr(LONG_R/yr, SHORT_R/yr) = {n1['corr']:+.2f}  "
          f"(negative = regime-complementary; positive = coincident)")
    _dy = sorted(y for y in DOWN_YEARS if y in n1["years"])
    print(f"  DOWN-YEARS {_dy}: long {n1['down_long']:+.0f}R vs short {n1['down_short']:+.0f}R -> "
          f"shorts {'CARRY' if n1['down_short'] > n1['down_long'] else 'do NOT carry'} them")
    print(f"  short-led years: {n1['short_led']}/{len(n1['years'])} | "
          f"long {n1['long_R'].sum():+.0f}R vs short {n1['short_R'].sum():+.0f}R total "
          f"(gap = equity-drift tailwind on longs if they win the bull years)")
    print("  >>> regime insurance (shorts carry down-years, anti-corr) vs a coincident")
    print("      return-stream (both positive throughout, shorts just a smaller long).")
    # ===== 6. DEEP-DIVE BATTERY (off existing trade data; answers N.1's questions) =====
    print("\n" + "=" * 70)
    print("6. DEEP-DIVE BATTERY  (DD attribution / sub-annual corr / crash-grind / breadth)")
    print("=" * 70)
    deep_dive(tdf)
    print("\n" + "=" * 70)
    print("BOOK SUMMARY")
    print("=" * 70)
    bk = additive_r_curve(trades)
    if bk is not None:
        rmar = bk["total_R"] / bk["max_dd_R"] if bk["max_dd_R"] > 0 else float("nan")
        print(f"  additive-R book (leverage-free): {bk['total_R']:+.0f}R total, "
              f"max R-DD {bk['max_dd_R']:.0f}R, R-MAR {rmar:.2f}, longest DD {bk['longest_dd_days']}d")
        print(f"  compounded %-equity retired (exploded at book concurrency); real % sizing = C.2/F.1")
    print(f"  long/short both positive? -> hedge is viable (see section 1)")
    print(f"  net/gross ratio -> how self-hedged the book is (see section 2)")
    print(f"  NEXT: cross-asset (mr_flip_assets) + full-449 basket selection are separate runs.")


if __name__ == "__main__":
    main()
