"""Walk-forward historical test — the fast way to learn whether the model beats the market (hundreds of matches in one run
instead of months of waiting). For each league on football-data.co.uk and each test season: every week, refit Dixon-Coles
on everything before that week only (no look-ahead), predict that week's matches, and compare with the closing 1X2 prices
(Pinnacle close where available, else the market average close).
Reports per league/season: 1X2 log loss model v market, and a paper betting simulation at the closing prices:
  'anchored' = the live rule (0.30 x band-capped model + 0.70 x market, +4% floor), 'raw' = the model alone (+4% floor).
Betting at the close is the hardest test (the close is the sharpest price); a real bet placed earlier gets a different price.
It is also the WEEKLY REVIEW of the self-tuning model (tuning.py), in this order: tidy the database; review each
league's anchor on live results; review the live challengers; then, per league, the back-test grid (a variation of the
recipe that beats the champion takes over) and the calibration (adopted only if it improves matches it was not fitted
on); and last the reporting back-test of the champion, as before. Every decision is written to league_tuning.
Usage: python -m sbms.jobs.backtest [LEAGUE_CODE ...] [--seasons 2] [--step 7] [--no-db] [--no-tune]"""
import argparse
import datetime as dt
import math
from collections import defaultdict
from .. import config as C
from .. import pricing, tuning
from ..models import dc
from ..sources import results as rs, understat, venues as vsrc, weather as wsrc, apifootball as af


def load_history(lg, today, n_seasons):
    src, code = lg['source']
    if src == 'fd':
        return sorted([m for s in rs.season_codes(today, n_seasons) for m in rs.footballdata_season(code, s)], key=lambda m: m['date'])
    if src == 'fdx':
        return sorted(rs.footballdata_extra(code, today - dt.timedelta(days=365 * n_seasons + 30)), key=lambda m: m['date'])
    return []


def run_league(lg, today, test_seasons=2, step_days=7, fit_years=3, hist=None, recipe=None, pyramid_hist=None, blend_out=None):
    recipe = recipe or tuning.DEFAULT_RECIPE; fit_years = recipe['fit_years']
    hist = hist if hist is not None else load_history(lg, today, test_seasons + fit_years)
    if len(hist) < 300: return None, f'{len(hist)} matches only', []
    start = today - dt.timedelta(days=365 * test_seasons)
    res = defaultdict(lambda: dict(n=0, ll_m=0.0, ll_k=0.0, bets_a=0, pnl_a=0.0, bets_r=0, pnl_r=0.0))
    trecs = []                     # (date, model log loss, market log loss) for idea 19
    day = max(start, hist[0]['date'] + dt.timedelta(days=300))
    while day < today:
        week = [m for m in hist if day <= m['date'] < day + dt.timedelta(days=step_days) and m['close_1x2']]
        if week:
            train = [m for m in hist if day - dt.timedelta(days=365 * fit_years) <= m['date'] < day]
            if len(train) >= 150:
                span = dt.timedelta(days=365 * fit_years)
                ptrain = [m for m in pyramid_hist if day - span <= m['date'] < day] if pyramid_hist else None
                params = tuning.fit_method(recipe, train, day, ptrain)   # the method in force (goals / shots / pyramid)
                if params is None: day += dt.timedelta(days=step_days); continue
                cnt = defaultdict(int)
                for m in train: cnt[m['home']] += 1; cnt[m['away']] += 1
                for m in week:
                    if cnt[m['home']] < 5 or cnt[m['away']] < 5: continue
                    if m['home'] not in params['attack'] or m['away'] not in params['attack']: continue
                    lh, la = dc.lambdas(params, m['home'], m['away'])
                    p = pricing.market_probs(pricing.score_grid(lh, la, params['rho']))
                    inv = [1 / o for o in m['close_1x2']]; s = sum(inv); mk = dict(zip('HDA', [x / s for x in inv]))
                    out = 'H' if m['hg'] > m['ag'] else ('A' if m['ag'] > m['hg'] else 'D')
                    season = f"{m['date'].year if m['date'].month >= 7 else m['date'].year - 1}"
                    r = res[season]; r['n'] += 1; r['ll_m'] += -math.log(max(p[out], 1e-9)); r['ll_k'] += -math.log(mk[out])
                    trecs.append((m['date'], -math.log(max(p[out], 1e-9)), -math.log(mk[out])))
                    if blend_out is not None: blend_out.append((m['date'], p[out], mk[out]))     # the model's say (16 Oct)
                    odds = dict(zip('HDA', m['close_1x2']))
                    # anchored rule (live): pick the best qualifying row of the three
                    best_a = best_r = None
                    for k in 'HDA':
                        if p[k] < C.THRESH_RESULT: continue
                        pw = C.ANCHOR_MODEL_WEIGHT * pricing.capped(p[k], mk[k], C.BAND_CAP['full']) + (1 - C.ANCHOR_MODEL_WEIGHT) * mk[k]
                        ea = pw * (odds[k] - 1) - (1 - pw); er = p[k] * (odds[k] - 1) - (1 - p[k])
                        if ea >= C.FLOOR_EV and (best_a is None or ea > best_a[1]): best_a = (k, ea)
                        if er >= C.FLOOR_EV and (best_r is None or er > best_r[1]): best_r = (k, er)
                    for best, bk, pk in ((best_a, 'bets_a', 'pnl_a'), (best_r, 'bets_r', 'pnl_r')):
                        if best:
                            r[bk] += 1; r[pk] += C.PAPER_STAKE * (odds[best[0]] - 1) if out == best[0] else -C.PAPER_STAKE
        day += dt.timedelta(days=step_days)
    out = {}
    for season, r in sorted(res.items()):
        if not r['n']: continue
        out[season] = dict(n=r['n'], ll_model=r['ll_m'] / r['n'], ll_market=r['ll_k'] / r['n'],
                           anchored=dict(bets=r['bets_a'], pnl=round(r['pnl_a'], 2), roi=(r['pnl_a'] / (C.PAPER_STAKE * r['bets_a']) if r['bets_a'] else None)),
                           raw=dict(bets=r['bets_r'], pnl=round(r['pnl_r'], 2), roi=(r['pnl_r'] / (C.PAPER_STAKE * r['bets_r']) if r['bets_r'] else None)))
    return out, f'{len(hist)} matches', trecs


def _cooling(changed_at, today):
    return changed_at is not None and (dt.datetime.now(dt.timezone.utc) - changed_at).days < C.RECIPE_COOLDOWN_DAYS


def review_anchor(conn, tune, log):
    """The model's say, live: per league, the blend of the champion and the Smarkets close that predicts results best.
    -> the leagues with enough live results to be judged live (the back-test judges the others)."""
    from .. import db
    rows = db.anchor_rows(conn); judged = set()
    for lg, rs_ in rows.items():
        if len(rs_) >= C.ANCHOR_WINDOW: judged.add(lg)
        t = tune[lg]; last = t['changed'].get('anchor')
        new_since = sum(1 for ko, _, _ in rs_ if last is None or ko > last)
        if last is not None and new_since < C.ANCHOR_MIN_NEW:
            continue
        new, ev = tuning.decide_anchor(t['anchor'], [(a, b) for _, a, b in rs_])
        if ev.get('n', 0) < C.ANCHOR_WINDOW: continue
        db.add_tuning(conn, lg, 'anchor', new is not None, dict(weight=new if new is not None else t['anchor']), dict(ev, new_since=new_since), 'live')
        log(f"{lg} anchor {'-> ' + str(new) if new is not None else 'kept ' + str(t['anchor'])}: {ev['reason']} (n={ev['n']}, model {ev['ll_model']} v market {ev['ll_market']})")
        if new is not None: t['anchor'] = new; t['changed']['anchor'] = dt.datetime.now(dt.timezone.utc)
    return judged


def review_live(conn, tune, today, log):
    """The model v itself, live: a challenger that beats the champion over enough settled fixtures takes over."""
    from .. import db
    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT league FROM fixtures WHERE outcome_1x2 IS NOT NULL AND league <> 'EUROPE'")
        leagues = [r[0] for r in cur.fetchall()]
    for lg in leagues:
        t = tune[lg]; since = t['changed'].get('recipe') or dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
        results = tuning.decide_live(db.live_pairs(conn, lg, since))
        winners = [r for r in results if r[4]]
        for name, n, lc, lx, beats in results:
            if n >= C.LIVE_CHALLENGE_MIN:
                log(f"{lg} live: {name} {lx:.4f} v champion {lc:.4f} over {n}{' -> BEATS' if beats else ''}")
        if not winners: continue
        name, n, lc, lx, _ = min(winners, key=lambda r: r[3])
        ev = dict(challenger=name, n=n, ll_champion=round(lc, 5), ll_challenger=round(lx, 5), gain=round(lc - lx, 5),
                  others={r[0]: dict(n=r[1], ll=round(r[3], 5)) for r in results})
        if _cooling(t['changed'].get('recipe'), today):
            db.add_tuning(conn, lg, 'recipe', False, t['recipe'], dict(ev, reason=f'cooling off: changed within {C.RECIPE_COOLDOWN_DAYS} days'), 'live'); continue
        if name == 'uncalibrated':
            db.add_tuning(conn, lg, 'calibration', True, dict(off=True), dict(ev, reason='the uncalibrated challenger beat the champion live'), 'live')
        elif name in ('no_weather', 'no_referee'):
            kind = name[3:]
            db.add_tuning(conn, lg, kind, True, dict(off=True), dict(ev, reason=f'the champion without the {kind} factor beat it live'), 'live')
        else:
            lgd = next((l for l in C.LEAGUES if l['code'] == lg), None)
            rc = next((r for n_, r, _ in tuning.challengers(t['recipe'], t['calibration'], tuning.methods_for(lgd)) if n_ == name), None)
            if rc is None:
                db.add_tuning(conn, lg, 'recipe', False, t['recipe'], dict(ev, reason=f'{name} is not a recipe variation'), 'live'); continue
            db.add_tuning(conn, lg, 'recipe', True, rc, dict(ev, reason=f'{name} beat the champion live', recipe=tuning.describe(rc)), 'live')
            t['recipe'] = rc; t['changed']['recipe'] = dt.datetime.now(dt.timezone.utc)
        log(f"{lg} live: {name} takes over ({lx:.4f} v {lc:.4f} over {n})")


_UK = None


def _kickoff_utc(r):
    """A football-data match's kick-off in UTC (its Time column is UK time; 15:00 when missing)."""
    global _UK
    if _UK is None:
        from zoneinfo import ZoneInfo
        _UK = ZoneInfo('Europe/London')
    hh, mm = (int(x) for x in (r.get('time') or '15:00').split(':'))
    return dt.datetime(r['date'].year, r['date'].month, r['date'].day, hh, mm, tzinfo=_UK).astimezone(dt.timezone.utc)


def attach_weather(conn, lg, recs, caches, log):
    """Idea 10: each replayed match's recorded weather at the home ground, as a bucket in r['wx']. Grounds come from the
    venues table, refreshed from Wikidata (one request per country) when teams are missing."""
    from .. import db
    teams = sorted({r['home'] for r in recs})
    ven = db.venues_for(conn, lg['code'])
    missing = [t for t in teams if t not in ven]
    if missing and lg.get('country') in vsrc.COUNTRY_QIDS:
        if lg['country'] not in caches['wd']:
            caches['wd'][lg['country']] = vsrc.clubs(lg['country'])
        got, miss = vsrc.match_teams(missing, caches['wd'][lg['country']])
        if got: db.upsert_venues(conn, lg['code'], got)
        if miss: log(f"{lg['code']} venues not found: {', '.join(miss[:12])}")
        ven = db.venues_for(conn, lg['code'])
    by = defaultdict(list)
    for r in recs:
        v = ven.get(r['home'])
        if v and v['lat'] is not None: by[(round(v['lat'], 3), round(v['lon'], 3))].append(r)
    n = 0
    for (lat, lon), rs_ in by.items():
        start, end = min(r['date'] for r in rs_), max(r['date'] for r in rs_)
        key = (lat, lon, start, end)
        if key not in caches['wx']:
            caches['wx'][key] = wsrc.history(lat, lon, start, end + dt.timedelta(days=1))
        for r in rs_:
            b = wsrc.bucket(wsrc.summarise(caches['wx'][key], _kickoff_utc(r)))
            if b: r['wx'] = b; n += 1
    return n


def review_factors(conn, lg, t, kind, recs, shrink, log, today, min_n=None):
    """Record a weather / referee factor review like the calibration: adopt when it improves unseen matches, switch an
    existing one off when it no longer does."""
    from .. import db
    field = 'wx' if kind == 'weather' else 'referee'
    ok, value, ev = tuning.review_group_factors(recs, field, shrink, min_n)
    if value is None:
        log(f"{lg['code']} {kind}: {ev.get('reason')}"); return
    had = t.get(kind)
    if ok or had:
        db.add_tuning(conn, lg['code'], kind, True, value, ev, 'backtest'); t[kind] = None if value.get('off') else value['factors']
    else:
        db.add_tuning(conn, lg['code'], kind, False, value, ev, 'backtest')
    log(f"{lg['code']} {kind}: {'ON' if ok else 'off'} ({ev.get('ll_without')} -> {ev.get('ll_with')}) {value.get('factors', '') if ok else ev.get('reason', '')}")


def review_grid(conn, lg, hist, today, tune, log, pyramid_hist=None, caches=None):
    """The model v its variations on the last year (walk-forward), then the calibration of whichever recipe is in force."""
    from .. import db
    t = tune[lg['code']]
    results, champ_name, recs = tuning.grid(hist, today, t['recipe'], tuning.methods_for(lg), pyramid_hist)
    adopt, best, ev = tuning.decide_grid(results, champ_name)
    if adopt and _cooling(t['changed'].get('recipe'), today):
        adopt, ev = False, dict(ev, reason=f'cooling off: changed within {C.RECIPE_COOLDOWN_DAYS} days')
    rc = results[best]['recipe'] if adopt else tuning.recipe_key(t['recipe'])
    db.add_tuning(conn, lg['code'], 'recipe', adopt, rc, dict(ev, recipe=tuning.describe(rc)), 'backtest')
    log(f"{lg['code']} grid: {'ADOPT ' + best if adopt else 'keep champion'} ({ev.get('reason', '')} champion {ev.get('champion_ll')} best {ev.get('best')} {ev.get('best_ll')} n={ev.get('n')})")
    if adopt:
        t['recipe'] = rc; t['changed']['recipe'] = dt.datetime.now(dt.timezone.utc)
    # calibration on the recipe now in force (its walk-forward records are in the grid)
    crecs = recs[best] if adopt else recs[champ_name]
    ok, value, cev = tuning.review_calibration(crecs)
    if value is not None:
        had = t['calibration']
        if ok and not had and _cooling(t['changed'].get('calibration'), today):
            ok, cev = False, dict(cev, reason=f'switched off within {C.RECIPE_COOLDOWN_DAYS} days: not switched back on yet')
            db.add_tuning(conn, lg['code'], 'calibration', False, value, cev, 'backtest')
        elif ok or had:   # record an adoption, or switching an existing one off; an unchanged 'none' is logged only
            db.add_tuning(conn, lg['code'], 'calibration', True, value, cev, 'backtest')
            t['calibration'] = None if value.get('off') else value
        else:
            db.add_tuning(conn, lg['code'], 'calibration', False, value, cev, 'backtest')
    log(f"{lg['code']} calibration: {'ON ' + str(value) if ok else 'off'} ({cev.get('reason', '')} {cev.get('ll_without')} -> {cev.get('ll_with')})")
    if caches is not None:
        try:
            n = attach_weather(conn, lg, crecs, caches, log)
            log(f"{lg['code']} weather attached to {n} of {len(crecs)} replayed matches")
            if n: review_factors(conn, lg, t, 'weather', crecs, C.WEATHER_SHRINK, log, today)
        except Exception as e:
            log(f"{lg['code']} weather ERROR {repr(e)[:200]}")
        try:
            if sum(1 for r in crecs if r.get('referee')) >= C.TUNE_MIN_MATCHES:
                review_factors(conn, lg, t, 'referee', crecs, C.REFEREE_SHRINK, log, today)
        except Exception as e:
            log(f"{lg['code']} referee ERROR {repr(e)[:200]}")
    return t['recipe']


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('leagues', nargs='*'); ap.add_argument('--seasons', type=int, default=2)
    ap.add_argument('--step', type=int, default=7); ap.add_argument('--no-db', action='store_true')
    ap.add_argument('--no-tune', action='store_true'); a = ap.parse_args()
    today = dt.date.today()
    lgs = [lg for lg in C.LEAGUES if lg['source'][0] in ('fd', 'fdx') and (not a.leagues or lg['code'] in a.leagues)]
    conn = None
    if not a.no_db:
        from .. import db
        conn = db.connect(); db.ensure_schema(conn)
        af.set_budget(lambda k: db.af_allow(conn, k))
    tune = tuning.in_force(db.tuning_rows(conn)) if conn else tuning.in_force([])
    tuning_on = conn is not None and not a.no_tune
    if conn:
        print('prune', db.prune(conn))
    live_anchor = set()
    if tuning_on:
        try: live_anchor = review_anchor(conn, tune, print) or set()
        except Exception as e: print('review ERROR', repr(e)[:300])
        try: review_live(conn, tune, today, print)
        except Exception as e: print('review ERROR', repr(e)[:300])
    tot = defaultdict(float); pyr_cache = {}; caches = dict(wd={}, wx={})
    for lg in lgs:
        try:
            hist = load_history(lg, today, a.seasons + C.TUNE_MAX_FIT_YEARS)
            if tuning_on and 'xg' in tuning.methods_for(lg):
                try:
                    miss = understat.attach(hist, lg['source'][1], today, a.seasons + C.TUNE_MAX_FIT_YEARS)
                    print(lg['code'], 'xG attached to', sum(1 for m in hist if 'hxg' in m), 'of', len(hist), 'matches', ('unmatched: ' + ', '.join(miss[:8])) if miss else '')
                except Exception as e:
                    print(lg['code'], 'xG ERROR', repr(e)[:200])
            recipe = tune[lg['code']]['recipe']
            if tuning_on:   # idea 22: referees on past matches (football-data's own column, else API-Football)
                try:
                    have = sum(1 for m in hist if m.get('referee'))
                    for m in hist:
                        if m.get('referee'): m['referee'] = af.norm_ref(m['referee'])
                    if have < 0.5 * len(hist) and C.API_FOOTBALL_KEY and lg['code'] in af.LEAGUE_IDS:
                        lid, lname = af.LEAGUE_IDS[lg['code']]; fx = []
                        y = today.year if today.month >= 7 else today.year - 1
                        for season in range(y - a.seasons, y + 1):
                            got = af.league_season(lid, season, C.API_FOOTBALL_KEY)
                            if got and lname.lower().split()[0] not in (got[0].get('league', {}).get('name') or '').lower():
                                print(lg['code'], 'API-Football league', lid, 'is', got[0].get('league', {}).get('name'), '- not used'); fx = []; break
                            fx += [af.simple(x) for x in got]
                        print(lg['code'], 'referees attached from API-Football:', af.attach_referees(hist, fx))
                    else:
                        print(lg['code'], 'referees on', have, 'of', len(hist), 'matches (football-data)')
                except Exception as e:
                    print(lg['code'], 'referee data ERROR', repr(e)[:200])
            pyr = None
            country, codes = tuning.pyramid_of(lg['source'][1])
            if tuning_on and country and 'pyramid' in tuning.methods_for(lg):
                if country not in pyr_cache:
                    try: pyr_cache[country] = rs.load_pyramid(codes, today, C.TUNE_MAX_FIT_YEARS + 1)
                    except Exception as e: print(country, 'pyramid data ERROR', repr(e)[:200]); pyr_cache[country] = None
                pyr = pyr_cache[country]
            if tuning_on and len(hist) >= 300:
                try: recipe = review_grid(conn, lg, hist, today, tune, print, pyr, caches)
                except Exception as e: print(lg['code'], 'tuning ERROR', repr(e)[:200])
            brecs = []
            out, info, trecs = run_league(lg, today, a.seasons, a.step, hist=hist, recipe=recipe, pyramid_hist=pyr, blend_out=brecs)
            if tuning_on and brecs and lg['code'] not in live_anchor:
                # the model's say from past matches v Pinnacle's close, for leagues without enough live results yet
                t = tune[lg['code']]
                new, ev = tuning.decide_anchor(t['anchor'], [(a_, b_) for _, a_, b_ in sorted(brecs, reverse=True)], min_n=C.ANCHOR_BT_MIN)
                if ev.get('n', 0) >= C.ANCHOR_BT_MIN:
                    db.add_tuning(conn, lg['code'], 'anchor', new is not None, dict(weight=new if new is not None else t['anchor']), ev, 'backtest')
                    print(lg['code'], 'model say', ('-> ' + str(new)) if new is not None else 'kept ' + str(t['anchor']), ev['reason'], 'grid', ev.get('grid'))
            if tuning_on and trecs:
                f, ev = tuning.decide_trust(trecs, tuning.season_starts([m['date'] for m in hist]))
                old = tune[lg['code']].get('trust') or {p: 1.0 for _, p in C.TRUST_PHASES}
                changed = any(abs(f[p] - old.get(p, 1.0)) >= 0.05 for p in f)
                db.add_tuning(conn, lg['code'], 'trust', changed, f, dict(ev, before=old), 'backtest')
                print(lg['code'], 'trust by phase', f, ev.get('gap'), 'changed' if changed else 'kept')
        except Exception as e:
            print(lg['code'], 'ERROR', repr(e)[:200]); continue
        if not out: print(lg['code'], 'skipped:', info); continue
        for season, r in out.items():
            print(f"{lg['code']:4s} {season} n={r['n']:4d} LL model {r['ll_model']:.4f} market {r['ll_market']:.4f} | anchored {r['anchored']} | raw {r['raw']}")
            tot['n'] += r['n']; tot['llm'] += r['ll_model'] * r['n']; tot['llk'] += r['ll_market'] * r['n']
            tot['ba'] += r['anchored']['bets']; tot['pa'] += r['anchored']['pnl']; tot['br'] += r['raw']['bets']; tot['pr'] += r['raw']['pnl']
            if conn:
                from psycopg.types.json import Jsonb
                with conn.cursor() as cur:
                    cur.execute('INSERT INTO backtest_results (league, season, n, ll_model, ll_market, n_bets, roi, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                                (lg['code'], season, r['n'], r['ll_model'], r['ll_market'], r['anchored']['bets'], r['anchored']['roi'], Jsonb(r)))
    if tot['n']:
        print(f"ALL n={int(tot['n'])} LL model {tot['llm']/tot['n']:.4f} market {tot['llk']/tot['n']:.4f} | anchored bets {int(tot['ba'])} pnl {tot['pa']:.2f} "
              f"roi {tot['pa']/(50*tot['ba']) if tot['ba'] else 0:.3%} | raw bets {int(tot['br'])} pnl {tot['pr']:.2f} roi {tot['pr']/(50*tot['br']) if tot['br'] else 0:.3%}")


if __name__ == '__main__':
    main()
