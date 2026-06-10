"""
fakeout_live.py — LIVE fakeout signal generator (PIECE 1 of the go-live build).

STATUS: DRY-RUN ONLY. This module DETECTS fade setups and emits *intended* orders. It does NOT
place anything on Capital. Order placement, the monitor loop, run_bot wiring, the V4 off-switch
and sizing reconciliation are later pieces. Do NOT flip DRY_RUN off until:
  (1) parity test passes — this module's signals over history match the backtest ledger, AND
  (2) the net-cost / entry-mechanic question is resolved (see ENTRY_MECHANIC below), AND
  (3) a floor-size micro-live fill check has run.

WHY THIS IS SAFE / CORRECT-BY-REUSE: every bit of setup logic is the SAME pure function the
backtest uses (fakeout_engine.detect_events / target_price + scanner.find_active_channels +
fakeout_engine.project_lines). We re-implement NOTHING — so a fresh-bar run produces the identical
signals the +0.176 OOS result was built on. fakeout_engine.py (pure, no deps) must be present in
bot/ alongside this file.

ENTRY MECHANIC (UNRESOLVED — this is the cost crux):
  The backtest enters at the snap-back CLOSE price with no spread modelled. Live you only know the
  snap-back AFTER the trigger bar closes, so the realistic fill is a MARKET order at/after that
  close (you PAY the spread) — NOT a passive limit that earns it. That difference is what moves net
  from ~+0.13 down toward ~+0.05 at a conservative cost. ENTRY_MODE below makes the choice explicit
  and the micro-live test measures which one is real. Default = 'market' (the honest/pessimistic one).
"""

import fakeout_engine as fe   # pure logic, shared with the backtest -> parity by construction

# ---- config -----------------------------------------------------------------------------------
DRY_RUN      = True            # NEVER set False until parity + cost + micro-fill gates pass
ENTRY_MODE   = "market"        # 'market' (pay spread, honest) | 'limit' (earn spread, fill-risk)
RISK_PCT     = 0.005           # 0.5% per trade (locked sizing; USE_2R OFF)
FRESH_BARS   = 1               # only act on a snap-back in the most recent FRESH_BARS trigger bars
import os                       # used immediately below
# Channel projection horizon. PINNED to 60 = EXACT parity with the backtest
# (fakeout_backtest.py MAX_HTF_AHEAD = 60). This is NOT a tunable — live trades the same horizon
# the backtest scored. The per-signal diagnostic log below records 'ahead' on every order, so any
# large-ahead / drifted-line fill is visible in the run output if you want to eyeball it.
MAX_HTF_AHEAD = 60
# TRADEABLE HORIZON CAP (2026-06-10): the audit's deploy plan (§5/§8) calls for setting a max
# tradeable 'ahead' from the pit harness — this is that lever, previously specified but never
# built. DETECTION still runs at the pinned 60 (parity with the backtest, untouched above); this
# cap only decides which detected signals are allowed to become ORDERS. Signals dropped by it are
# still DIAG-logged (marked DROPPED) so the data keeps flowing while you throttle the drift band.
# Default 60 = no behaviour change until explicitly set (e.g. FAKEOUT_MAX_HTF_AHEAD=20).
def _max_tradeable_ahead():
    try:
        return int(os.environ.get("FAKEOUT_MAX_HTF_AHEAD", "60"))
    except ValueError:
        return 60
FAKEOUT_DIAG  = os.environ.get("FAKEOUT_DIAG", "true").strip().lower() != "false"  # per-signal audit log
# PARALLEL FETCH (2026-06-10): per-name work (trigger fetch + detect, or daily fetch + channel
# build) is independent across names, and the run is IO-bound on Capital requests — so it is
# fanned out over FAKEOUT_FETCH_WORKERS threads (default 6). The shared CapitalClient is
# thread-safe (auth single-flight) and globally paced (CAPITAL_MIN_REQ_INTERVAL), so workers
# cannot burst past the broker rate limit. Results are gathered in SUBMISSION ORDER, so the
# signal list ordering is identical to the old sequential loop (matters: ordering decides which
# trades hit the concurrency cap first). FAKEOUT_FETCH_WORKERS=1 restores sequential behaviour.
def _fetch_workers():
    try:
        return max(1, int(os.environ.get("FAKEOUT_FETCH_WORKERS", "6")))
    except ValueError:
        return 6


def _parallel_gather(fn, items):
    """Map fn over items with the worker pool; concatenate list results in submission order.
    Sequential when workers==1 or a single item (zero behaviour change)."""
    workers = _fetch_workers()
    out = []
    if workers <= 1 or len(items) <= 1:
        for it in items:
            out += fn(it)
        return out
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fn, it) for it in items]
        for f in futs:
            out += f.result()
    return out
R_LO, R_HI   = 0.5, 5.0        # implied-R band gate (mirrors the backtest)

# SURVIVING_COMBOS are LOADED from the s9 fakeout-WF survivor table — never hardcoded, so the
# scanner only ever trades combos a walk-forward actually selected. If the file is missing it
# loads NOTHING and the scanner finds nothing (safe-by-default), rather than guessing.
# CSV columns: ctf,ttf,direction,A,B,C,D,E   (E: 'line' | 'mid' | 'R:1.5' | 'cw:1')
import csv, os
import datetime as _dt

# Fetch lookbacks — mirror fakeout_backtest exactly so live bars == backtest bars.
# (fetch_bars compares bar timestamps to start_dt, so start_dt must NOT be None.)
_DAILY_START = _dt.datetime(2004, 1, 1)
_TF_DAYS = {"MINUTE_15": 380, "MINUTE_30": 500, "HOUR": 1100, "HOUR_4": 1400, "MINUTE": 40}

def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)

def _tf_start(ttf):
    return _utcnow() - _dt.timedelta(days=_TF_DAYS.get(ttf, 1100))

# LIVE trigger fetch only needs enough RECENT bars to detect the run+snapback ending at the last
# bar (FRESH_BARS=1) — a run is <=B(<=3)+lag(1) bars, so a couple of weeks is ample. The backtest
# still uses full history separately; slimming this is the main latency win (drops ~7,700 hourly
# bars/name to ~100) and does NOT change last-bar detection.
_TRIGGER_SLIM_DAYS = {"MINUTE_15": 4, "MINUTE_30": 8, "HOUR": 12, "HOUR_4": 24}

def _trigger_start(ttf):
    return _utcnow() - _dt.timedelta(days=_TRIGGER_SLIM_DAYS.get(ttf, 12))

_TF_DUR = {"MINUTE_15": _dt.timedelta(minutes=15), "MINUTE_30": _dt.timedelta(minutes=30),
           "HOUR": _dt.timedelta(hours=1), "HOUR_4": _dt.timedelta(hours=4)}

def _drop_forming(tdf, ttf):
    """Drop a trailing still-forming bar so live detection acts ONLY on closed bars (the backtest
    only ever sees completed bars). Harmless if the feed already excludes the forming bar."""
    dur = _TF_DUR.get(ttf)
    if tdf is None or tdf.empty or dur is None:
        return tdf
    import pandas as pd  # noqa
    ts = pd.Timestamp(tdf.index[-1])
    ts = ts.tz_convert("UTC").tz_localize(None) if ts.tz is not None else ts
    if _utcnow() < ts.to_pydatetime() + dur:     # period not fully elapsed -> still forming
        return tdf.iloc[:-1]
    return tdf

_SURVIVORS_CSV = os.environ.get("FAKEOUT_SURVIVORS_CSV", "fakeout_survivors.csv")

def _parse_E(s):
    s = s.strip()
    if s in ("line", "mid"):
        return s
    if ":" in s:
        kind, val = s.split(":", 1)
        if kind.strip() in ("R", "cw"):
            return (kind.strip(), float(val))
    raise ValueError(f"bad E rule: {s!r}")

def load_survivors(path=None):
    """Load WF-selected survivor combos from CSV. Missing file -> [] + loud warning (scanner
    finds nothing). This is the ONLY source of combos; nothing is hardcoded.
    FAKEOUT_TRIGGERS (default 'HOUR,HOUR_4') restricts which trigger TFs are tradeable, so combos
    that don't fit the hourly cron cadence (e.g. MINUTE_30) are dropped automatically."""
    path = path or _SURVIVORS_CSV
    allowed = {t.strip() for t in os.environ.get("FAKEOUT_TRIGGERS", "HOUR,HOUR_4").split(",") if t.strip()}
    combos, skipped = [], 0
    if not os.path.exists(path):
        print(f"[fakeout_live] WARNING: survivor file '{path}' not found — 0 combos loaded, "
              f"scanner will find NOTHING. Export the s9 fakeout-WF survivors to this CSV "
              f"(cols: ctf,ttf,direction,A,B,C,D,E) before going live.")
        return combos
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                ttf = row["ttf"].strip()
                if allowed and ttf not in allowed:
                    skipped += 1
                    continue
                combos.append((row["ctf"].strip(), ttf, row["direction"].strip(),
                               float(row["A"]), int(row["B"]), float(row["C"]), float(row["D"]),
                               _parse_E(row["E"])))
            except (KeyError, ValueError) as ex:
                print(f"[fakeout_live] skipping bad survivor row {dict(row)}: {ex}")
    msg = f"[fakeout_live] loaded {len(combos)} survivor combos from {path}"
    if skipped:
        msg += f" (dropped {skipped} not in FAKEOUT_TRIGGERS={sorted(allowed)})"
    print(msg)
    return combos

SURVIVING_COMBOS = load_survivors()

# ---- small data helpers (replicated verbatim from fakeout_backtest so behaviour is identical) ---
def _resample_ohlc(daily, rule, compute_atr):
    import pandas as pd  # noqa
    o = daily["open"].resample(rule).first()
    h = daily["high"].resample(rule).max()
    l = daily["low"].resample(rule).min()
    c = daily["close"].resample(rule).last()
    df = pd.concat({"open": o, "high": h, "low": l, "close": c}, axis=1).dropna()
    df["atr"] = compute_atr(df)
    return df

def _resample_tf(df, rule):
    import pandas as pd  # noqa
    o = df["open"].resample(rule).first(); h = df["high"].resample(rule).max()
    l = df["low"].resample(rule).min(); c = df["close"].resample(rule).last()
    return pd.concat({"open": o, "high": h, "low": l, "close": c}, axis=1).dropna()

def _fetch_trigger(fetch_bars, client, epic, ttf):
    """Mirror fakeout_backtest.fetch_tf: real lookback start, native-then-resample fallback."""
    start = _trigger_start(ttf)
    try:
        df = fetch_bars(client, epic, ttf, start)
    except Exception:
        df = None
    if df is not None and not df.empty:
        return df
    if ttf == "HOUR_4":
        base = fetch_bars(client, epic, "HOUR", start)
        if base is not None and not base.empty:
            return _resample_tf(base, "4h")
    if ttf == "MINUTE_30":
        base = fetch_bars(client, epic, "MINUTE_15", start)
        if base is not None and not base.empty:
            return _resample_tf(base, "30min")
    return df

def _channel_for(ctf, daily, sc, compute_atr, tk):
    hdf = daily if ctf == "D" else _resample_ohlc(daily, "W" if ctf == "W" else "ME", compute_atr)
    if ctf == "D" and "atr" not in hdf:
        hdf = hdf.copy(); hdf["atr"] = compute_atr(hdf)
    chans, _ = sc.find_active_channels(tk, hdf, hdf.index[-1])
    return chans, hdf

# ---- the core: latest actionable fade setups, as pure signal geometry (no sizing, no placement) -
# Sizing + placement live in fakeout_exec.py (routed through tested capital_sizing/capital_orders).
# ----------------------------------------------------------------------------------------------
# DAILY BUILD-ONCE CHANNEL CACHE (speed fix, 2026-06-10)
# The heavy work — fetching daily history + building channels for the whole universe — only changes
# when a new daily bar closes (once a day). So we build channels ONCE (first run of the day, ideally
# pre-open) and persist them to Postgres; every later run that day LOADS the cached channels and only
# fetches the slim trigger bars for the CANDIDATES, then detects on the last closed bar. Detection and
# the engine are byte-identical to the build path (shared _detect_orders), so parity holds. Any cache
# miss or DB error falls back to a full inline build, so trading never breaks.
# ----------------------------------------------------------------------------------------------
_CACHE_TAIL = 400   # HTF bars kept per (ticker,ctf): covers every active channel + current triggers.
_CHAN_CACHE_DDL = """
CREATE TABLE IF NOT EXISTS fakeout_channel_cache (
    ticker     TEXT NOT NULL,
    ctf        TEXT NOT NULL,
    cache_date DATE NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (ticker, ctf)
);
"""
_cache_table_ready = False


class _CachedCh:
    """Lightweight stand-in for scanner.Channel — exposes exactly what detection needs, and its
    project() is identical to scanner.Channel.project()."""
    def __init__(self, u, l, sh, sl, d2_idx, d1_date, d2_date):
        self.d2_high = u; self.d2_low = l; self.slope_h = sh; self.slope_l = sl
        self.d2_idx = d2_idx; self.d1_date = d1_date; self.d2_date = d2_date

    def project(self, bars_from_d2):
        return (self.d2_high + self.slope_h * bars_from_d2,
                self.d2_low + self.slope_l * bars_from_d2)


def _ensure_cache_table():
    global _cache_table_ready
    if _cache_table_ready:
        return
    import capital_db
    with capital_db.db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(_CHAN_CACHE_DDL)
    _cache_table_ready = True


def _cache_is_fresh():
    """True iff a COMPLETE build was written today (manifest row '__BUILT__')."""
    import capital_db
    _ensure_cache_table()
    with capital_db.db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM fakeout_channel_cache WHERE ticker=%s AND cache_date=CURRENT_DATE",
                        ("__BUILT__",))
            return cur.fetchone() is not None


def _channel_payload(chans, hdf):
    """Serialize one (ticker,ctf)'s channels to a JSON payload (no DB)."""
    import json
    htf_tail = [str(ts) for ts in list(hdf.index)[-_CACHE_TAIL:]]
    ch_list = [{"u": float(c.d2_high), "l": float(c.d2_low), "sh": float(c.slope_h),
                "sl": float(c.slope_l), "d1": str(c.d1_date), "d2": str(c.d2_date)} for c in chans]
    return json.dumps({"htf": htf_tail, "ch": ch_list})


def _cache_write_batch(rows):
    """Write ALL (ticker,ctf,payload) rows + the '__BUILT__' manifest in ONE connection/transaction.
    Was per-row before (one connection each ~350x) which added minutes — this opens one."""
    import capital_db
    _ensure_cache_table()
    with capital_db.db_connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO fakeout_channel_cache (ticker, ctf, cache_date, payload)
                   VALUES (%s, %s, CURRENT_DATE, %s)
                   ON CONFLICT (ticker, ctf) DO UPDATE
                     SET cache_date=CURRENT_DATE, payload=EXCLUDED.payload""",
                [(tk, ctf, payload) for (tk, ctf, payload) in rows])
            cur.execute(
                """INSERT INTO fakeout_channel_cache (ticker, ctf, cache_date, payload)
                   VALUES ('__BUILT__','-',CURRENT_DATE,'{}')
                   ON CONFLICT (ticker, ctf) DO UPDATE SET cache_date=CURRENT_DATE""")


def _cache_load_all():
    """Return {ticker: {ctf: (chans, htf_idx)}} reconstructed from today's cached rows.
    d2_idx is re-based to the stored htf tail; since ahead = k - d2_idx is a difference of positions
    in the SAME list, it equals the full-history ahead, so detection is identical to the build path."""
    import capital_db, json, bisect
    import pandas as pd
    _ensure_cache_table()
    out = {}
    with capital_db.db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT ticker, ctf, payload FROM fakeout_channel_cache
                           WHERE cache_date=CURRENT_DATE AND ticker<>%s""", ("__BUILT__",))
            rows = cur.fetchall()
    for tk, ctf, payload in rows:
        try:
            d = json.loads(payload)
            htf = [pd.Timestamp(s) for s in d["htf"]]
            chans = []
            for c in d["ch"]:
                d2_ts = pd.Timestamp(c["d2"])
                pos = bisect.bisect_left(htf, d2_ts)
                if pos >= len(htf) or htf[pos] != d2_ts:
                    continue   # d2 older than the cached tail (can't be active) -> skip
                chans.append(_CachedCh(c["u"], c["l"], c["sh"], c["sl"], pos,
                                       pd.Timestamp(c["d1"]), d2_ts))
            if chans:
                out.setdefault(tk, {})[ctf] = (chans, htf)
        except Exception:
            continue
    return out


def _detect_orders(tk, ctf, ttf, direction, A, B, C, D, E, chans, htf_idx, tbars, tidx):
    """Shared detection — IDENTICAL math for the build path and the cached path (parity guarantee)."""
    import bisect as _bisect
    out = []
    for ch in chans:
        lines = fe.project_lines(ch.project, htf_idx, ch.d2_idx, tidx, MAX_HTF_AHEAD)
        def line_at(i, _l=lines):
            return _l[i] if _l[i] is not None else (float("nan"), float("nan"))
        evs = fe.detect_events(tbars, tidx, line_at, direction, max_snapback_lag=1)
        evs = [e for e in evs if lines[e["entry_i"]] is not None]
        for ev in evs:
            if ev["entry_i"] < len(tbars) - FRESH_BARS:
                continue
            if ev["breakout_depth"] < A or ev["n_closes"] < B or ev["snapback_depth"] < C:
                continue
            entry, cw = ev["entry"], ev["cw"]
            if direction == "short":
                stop = ev["extreme"] + D * cw; stop_dist = stop - entry
            else:
                stop = ev["extreme"] - D * cw; stop_dist = entry - stop
            if stop_dist <= 0:
                continue
            tgt = fe.target_price(direction, entry, ev["upper"], ev["lower"], cw, stop_dist, E)
            if tgt is None:
                continue
            impR = abs(tgt - entry) / stop_dist
            if not (R_LO <= impR <= R_HI):
                continue
            _k = _bisect.bisect_right(htf_idx, ev["entry_ts"]) - 1
            ahead = _k - ch.d2_idx
            _cap = _max_tradeable_ahead()
            _dropped = ahead > _cap
            if FAKEOUT_DIAG:
                print(f"  [fakeout DIAG] {tk} {ctf}|{ttf} {direction} "
                      f"anchor d1={getattr(ch,'d1_date',None)} d2={getattr(ch,'d2_date',None)} "
                      f"ahead={ahead}HTFbars  line(u/l)={ev['upper']:.4f}/{ev['lower']:.4f} "
                      f"entry={entry:.4f} stop={stop:.4f} tgt={tgt:.4f} R={impR:.2f} "
                      f"brk={ev['breakout_depth']:.2f}cw snb={ev['snapback_depth']:.2f}cw "
                      f"n_closes={ev['n_closes']}"
                      + (f"  DROPPED ahead>{_cap}" if _dropped else ""))
            if _dropped:
                continue
            out.append(dict(
                ticker=tk, ctf=ctf, ttf=ttf, direction=direction,
                entry_mode=ENTRY_MODE, entry=round(entry, 6),
                stop=round(stop, 6), target=round(tgt, 6),
                implied_R=round(impR, 3), ahead_htf_bars=int(ahead),
                line_upper=round(ev["upper"], 6), line_lower=round(ev["lower"], 6),
                d2_date=str(getattr(ch, "d2_date", "")),
                combo=dict(A=A, B=B, C=C, D=D, E=E), snapback_ts=str(ev["entry_ts"])))
    return out


def _signals_build_and_cache(client, names, fetch_bars, compute_atr, sc, TICKER_TO_EPIC):
    """SLOW path (first run of day / forced / no cache): fetch daily, build channels for the whole
    universe, PERSIST them, and detect inline. Pre-open this just warms the cache (market shut)."""
    ctfs = sorted({c[0] for c in SURVIVING_COMBOS})
    orders = []
    cache_rows = []
    import time as _t; _t0 = _t.perf_counter()
    print(f"  [fakeout] BUILDING channels for {len(names)} names (slow ~once/day; "
          f"caches to DB, then later runs are lean; {_fetch_workers()} fetch workers)")
    from threading import Lock as _Lock
    _rows_lock = _Lock()   # cache_rows is append-only from workers; guard it

    def _build_one(tk):
        _orders = []
        try:
            epic = TICKER_TO_EPIC.get(tk, tk)
            daily = fetch_bars(client, epic, "DAY", _DAILY_START)
            if daily is None or daily.empty:
                return _orders
            daily = daily.copy(); daily["atr"] = compute_atr(daily)
            chan_by_ctf = {}
            for ctf in ctfs:                              # build once per ctf (was once per combo)
                chans, hdf = _channel_for(ctf, daily, sc, compute_atr, tk)
                if chans:
                    chan_by_ctf[ctf] = (chans, hdf)
                    with _rows_lock:
                        cache_rows.append((tk, ctf, _channel_payload(chans, hdf)))
            if not chan_by_ctf:
                return _orders                            # no channels -> never touch triggers
            tf_cache = {}
            for (ctf, ttf, direction, A, B, C, D, E) in SURVIVING_COMBOS:
                if ctf not in chan_by_ctf:
                    continue
                chans, hdf = chan_by_ctf[ctf]
                if ttf not in tf_cache:
                    tf_cache[ttf] = _drop_forming(_fetch_trigger(fetch_bars, client, epic, ttf), ttf)
                tdf = tf_cache[ttf]
                if tdf is None or tdf.empty:
                    continue
                tbars = list(zip(tdf["open"], tdf["high"], tdf["low"], tdf["close"]))
                tidx = list(tdf.index)
                _orders += _detect_orders(tk, ctf, ttf, direction, A, B, C, D, E,
                                          chans, list(hdf.index), tbars, tidx)
        except Exception as ex:
            print(f"  [fakeout_live] {tk} ERR {ex}")
        return _orders

    orders += _parallel_gather(_build_one, list(names))
    try:
        _cache_write_batch(cache_rows)
        print(f"  [fakeout] BUILD complete in {_t.perf_counter()-_t0:.0f}s — cached "
              f"{len(cache_rows)} (ticker,ctf) channel sets; next run today is the lean cached path")
    except Exception as ex:
        print(f"  [fakeout cache] batch write failed: {ex} — NOT cached, next run will rebuild")
    return orders


def _signals_from_cache(client, names, fetch_bars):
    """FAST path: load today's cached channels, fetch slim triggers for CANDIDATES only, detect."""
    try:
        from capital_markets import TICKER_TO_EPIC
    except Exception:
        TICKER_TO_EPIC = {}
    cache = _cache_load_all()
    orders = []
    nameset = set(names)
    candidates = [tk for tk in cache if tk in nameset]
    print(f"  [fakeout] cached run — {len(candidates)} candidate names (of {len(names)}); "
          f"{_fetch_workers()} fetch workers")

    def _cached_one(tk):
        _orders = []
        ctf_map = cache[tk]
        try:
            epic = TICKER_TO_EPIC.get(tk, tk)
            tf_cache = {}
            for (ctf, ttf, direction, A, B, C, D, E) in SURVIVING_COMBOS:
                if ctf not in ctf_map:
                    continue
                chans, htf_idx = ctf_map[ctf]
                if ttf not in tf_cache:
                    tf_cache[ttf] = _drop_forming(_fetch_trigger(fetch_bars, client, epic, ttf), ttf)
                tdf = tf_cache[ttf]
                if tdf is None or tdf.empty:
                    continue
                tbars = list(zip(tdf["open"], tdf["high"], tdf["low"], tdf["close"]))
                tidx = list(tdf.index)
                _orders += _detect_orders(tk, ctf, ttf, direction, A, B, C, D, E,
                                          chans, htf_idx, tbars, tidx)
        except Exception as ex:
            print(f"  [fakeout_live] {tk} ERR {ex}")
        return _orders

    orders += _parallel_gather(_cached_one, candidates)
    return orders


def latest_signals(client, names, fetch_bars, compute_atr, sc):
    """Dispatch: if a COMPLETE build exists for today, take the FAST cached path (lean trigger-only
    runs); otherwise build + cache the whole universe once (SLOW, ideally the pre-open run). Force a
    rebuild with FAKEOUT_REBUILD=1. Detection is byte-identical on both paths."""
    try:
        from capital_markets import TICKER_TO_EPIC
    except Exception:
        TICKER_TO_EPIC = {}
    force = os.environ.get("FAKEOUT_REBUILD", "").strip().lower() in ("1", "true", "yes")
    try:
        fresh = (not force) and _cache_is_fresh()
    except Exception as ex:
        print(f"  [fakeout cache] unavailable ({ex}); building inline (no cache)")
        fresh = False
    if fresh:
        try:
            return _signals_from_cache(client, names, fetch_bars)
        except Exception as ex:
            print(f"  [fakeout cache] cached run failed ({ex}); rebuilding inline")
    return _signals_build_and_cache(client, names, fetch_bars, compute_atr, sc, TICKER_TO_EPIC)


if __name__ == "__main__":
    # Manual dry-run hook — wire client/scanner/fetchers the same way run_bot does, then:
    #   orders = latest_signals(client, names, fetch_bars, compute_atr, sc, account_equity)
    #   for o in orders: print(o)
    print("fakeout_live.py — DRY-RUN module. Import latest_signals(); it PLACES NOTHING.")
    print(f"  ENTRY_MODE={ENTRY_MODE}  RISK_PCT={RISK_PCT}  combos={len(SURVIVING_COMBOS)} (weekly only)")
    print("  Gate before going live: (1) parity vs backtest ledger (2) net-cost resolved (3) micro-fill test.")
