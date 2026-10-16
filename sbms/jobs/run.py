"""The scheduled job. Render cron: every 15 minutes.
  full run  (minute 0–14 of each hour): settle, read every football event in the next 48h, price the covered ones,
            store predictions / quotes / paper suggestions, feature up to four a day, capture closes.
  close run (the other quarters): settle, and capture closing quotes for events kicking off in the next 20 minutes.
PAPER ONLY — suggestions are recorded, never placed.
Usage: python -m sbms.jobs.run [full|close|auto]"""
import datetime as dt
import sys
import traceback
from .. import config as C
from .. import db, names, pricing, layers, tuning, integrity, stakes, committee, guardian, learn
from ..models import dc, elo, consensus
from ..sources import smarkets as sm, results as rs, understat, oddsapi, weather as wsrc, apifootball as af
from ..leagues import classify

UTC = dt.timezone.utc


def league_fits(conn, lg, today, notes, t, pyr_cache):
    """The champion fit for a league and a fit for each challenger that needs one (tuning.py): fade variations and the
    other methods (goals, shots, pyramid). Each cached for REFIT_HOURS and refitted at once when its recipe changes.
    -> {'': champion params, 'fade_slower': params, 'shots': params, ...}"""
    methods = tuning.methods_for(lg)
    specs = [('', tuning.recipe_key(t['recipe']))] + [(n, r) for n, r, _ in tuning.challengers(t['recipe'], t['calibration'], methods) if n != 'uncalibrated']
    out, data = {}, {}

    def league_matches():
        if 'm' not in data:
            try:
                data['m'], data['src'] = rs.load_league(lg, today, years=C.TUNE_MAX_FIT_YEARS)
            except Exception as e:
                notes.setdefault('data_errors', {})[lg['code']] = repr(e)[:300]; data['m'], data['src'] = [], None
            if 'xg' in methods and data['m']:
                try:
                    miss = understat.attach(data['m'], lg['source'][1], today, C.TUNE_MAX_FIT_YEARS)
                    if miss: notes.setdefault('xg_name_misses', {})[lg['code']] = miss[:20]
                except Exception as e:
                    notes.setdefault('xg_errors', {})[lg['code']] = repr(e)[:200]
        return data['m']

    def pyramid_matches():
        country, codes = tuning.pyramid_of(lg['source'][1])
        if not country: return []
        if country not in pyr_cache:
            try:
                pyr_cache[country] = rs.load_pyramid(codes, today, C.TUNE_MAX_FIT_YEARS)
            except Exception as e:
                notes.setdefault('data_errors', {})['PYR:' + country] = repr(e)[:300]; pyr_cache[country] = []
        return pyr_cache[country]

    for name, rc in specs:
        key = lg['code'] + ('~' + name if name else '')
        row = db.latest_params(conn, key)
        refit_h = C.AF_REFIT_HOURS if lg['source'][0] in ('af', 'afid') else C.REFIT_HOURS
        if row and (dt.datetime.now(UTC) - row[0]).total_seconds() < refit_h * 3600 and row[1].get('recipe') == rc:
            out[name] = row[1]; continue
        since = today - dt.timedelta(days=365 * rc['fit_years'])
        use = [m for m in league_matches() if m['date'] >= since]
        if len(use) < 60:
            if not name: notes.setdefault('thin_data', {})[lg['code']] = f"{len(use)} matches ({data.get('src')})"
            out[name] = row[1] if row else None; continue
        ptrain = [m for m in pyramid_matches() if m['date'] >= since] if rc['method'] == 'pyramid' else None
        try:
            params = tuning.fit_method(rc, use, today, ptrain)
        except Exception as e:
            notes.setdefault('fit_errors', {})[key] = repr(e)[:200]; params = None
        if params is None:
            out[name] = row[1] if row else None; continue
        per_team = {}
        for m in (ptrain if rc['method'] == 'pyramid' else use):
            for tm in (m['home'], m['away']): per_team[tm] = per_team.get(tm, 0) + 1
        params['matches_per_team'] = per_team
        params['league_teams'] = sorted({m['home'] for m in use} | {m['away'] for m in use})   # match names within the league only
        starts = tuning.season_starts([m['date'] for m in use])
        params['season_start'] = starts[-1].isoformat() if starts else None
        params['band'] = 'full' if len(use) >= C.DC_MIN_MATCHES else 'thin'
        params['recipe'] = rc
        params['latest_match'] = max(m['date'] for m in use).isoformat()                  # idea 33: stale data check
        db.save_params(conn, key, params, data.get('src'))
        out[name] = params
    return out


def elo_table(conn, today, notes):
    row = db.latest_params(conn, 'CLUBELO')
    if row and (dt.datetime.now(UTC) - row[0]).total_seconds() < C.REFIT_HOURS * 3600:
        return row[1]['elo']
    try:
        table = rs.clubelo(today)
        db.save_params(conn, 'CLUBELO', dict(engine='clubelo', n=len(table), elo=table), 'api.clubelo.com')
        return table
    except Exception as e:
        notes['clubelo_error'] = repr(e)[:300]
        return row[1]['elo'] if row else None


def cs_group(rows):
    """The correct-score market as one no-vig group, only when all 19 selections (0-0 ... 3-3 and the three 'any
    other' results) are present."""
    g = tuple(k for k in rows if k.startswith('CS_'))
    return g if len(g) == 19 else ()


def read_book(markets):
    """markets: {mid: {type, param, contracts:{cid:key}}} -> rows {key: {...}} with no-vig mids per market group."""
    contracts, quotes, vols = sm.book(list(markets.keys()))
    rows = {}
    for c in contracts:
        mid = c['market_id']; m = markets.get(mid)
        if not m: continue
        ct = c.get('contract_type') or {}
        key = sm.contract_key(m['type'], m['param'], ct.get('name'), ct.get('param'))
        if not key: continue
        q = quotes.get(c['id'], {})
        v = pricing.contract_view([(x['price'], x['quantity']) for x in q.get('bids', [])], [(x['price'], x['quantity']) for x in q.get('offers', [])])
        rows[key] = dict(v, cid=c['id'], market_id=mid, volume=vols.get(mid))
        m['contracts'][c['id']] = key
    groups = [('H', 'D', 'A'), ('DNB_H', 'DNB_A'), ('BTTS_Y', 'BTTS_N'), ('O1.5', 'U1.5'), ('O2.5', 'U2.5'), ('O3.5', 'U3.5'), cs_group(rows)]
    for g in groups:
        if all(k in rows and rows[k]['mid'] for k in g):
            nv = pricing.devig({k: rows[k]['mid'] for k in g})
            for k in g: rows[k]['mid_novig'] = nv[k]
    return rows


def read_book_fast(markets):
    """In-play: one quotes request, using the contract -> selection map stored with the fixture (no contracts or volumes
    calls), so a fixture can be read every 15 seconds."""
    q = sm.quotes(list(markets.keys()))
    rows = {}
    for mid, m in markets.items():
        for cid, key in (m.get('contracts') or {}).items():
            x = q.get(cid) or {}
            v = pricing.contract_view([(y['price'], y['quantity']) for y in x.get('bids', [])], [(y['price'], y['quantity']) for y in x.get('offers', [])])
            rows[key] = dict(v, cid=cid, market_id=mid)
    for g in [('H', 'D', 'A'), ('DNB_H', 'DNB_A'), ('BTTS_Y', 'BTTS_N'), ('O1.5', 'U1.5'), ('O2.5', 'U2.5'), ('O3.5', 'U3.5'), cs_group(rows)]:
        if all(k in rows and rows[k]['mid'] for k in g):
            nv = pricing.devig({k: rows[k]['mid'] for k in g})
            for k in g: rows[k]['mid_novig'] = nv[k]
    return rows


def price_event(conn, ev, lg, how, fits, elo_tab, notes, mgr=(), t=None, sim_cache=None, odds_cache=None, wx_cache=None, news_adj=None, comm=None, learned=None):
    home, away = sm.split_name(ev)
    if not home: return None
    kickoff = ev['start_datetime']
    if lg == 'EUROPE':
        if not elo_tab: return None
        hm, hmeth = names.match(home, elo_tab.keys(), cutoff=0.85); am, ameth = names.match(away, elo_tab.keys(), cutoff=0.85)
        league_code, band, model = 'EUROPE', 'thin', 'elo_cross'
    else:
        params = fits['']
        teams = params.get('league_teams') or params['attack'].keys()
        hm, hmeth = names.match(home, teams); am, ameth = names.match(away, teams)
        league_code, model = lg['code'], 'dixon_coles'
        band = params.get('band', 'thin')
        mpt = params.get('matches_per_team', {})
        if hm and am and min(mpt.get(hm, 0), mpt.get(am, 0)) < 5: band = 'thin'
    for nm, got, meth in ((home, hm, hmeth), (away, am, ameth)):
        if not got: db.name_miss(conn, league_code, nm, meth)
    if not (hm and am): return None
    markets = {m['id']: dict(type=m['type'], param=m['param'], contracts={}) for m in sm.event_markets(ev['id'])}
    if not markets: return None
    rows = read_book(markets)
    fid = db.upsert_fixture(conn, ev['id'], sm.competition_slug(ev), league_code, home, away, kickoff, hm, am, f'{how}; {hmeth} / {ameth}', markets)
    neutral = bool((ev.get('venue') or {}).get('neutral'))
    if model == 'elo_cross':
        lh, la = elo.lambdas(elo_tab[hm], elo_tab[am], neutral=neutral); rho = 0.0
        variants = [(model, lh, la, {}, True)]
    else:
        # The foundation (penaltyblog Dixon-Coles), then our improvement layers on top (layers.py): the live stack is
        # the model; each testing layer is priced in parallel as its own variant.
        # The champion: the league's recipe in force, with its calibration if one is in force (tuning.py).
        t = t or tuning.in_force([])['']
        lh0, la0 = dc.lambdas(params, hm, am, neutral=neutral); rho = params['rho']
        lh, la = tuning.apply_calibration(lh0, la0, t['calibration'])
        # idea 10: the forecast at the home ground; a learned goal factor when one is in force for the league
        wx = _forecast(conn, fid, league_code, hm, _ts(kickoff), wx_cache, notes) if (wx_cache is not None and not neutral) else None
        wf = (t.get('weather') or {}).get(wx['bucket'], 1.0) if wx else 1.0
        # idea 22: the appointed referee (API-Football), with a learned goal factor when one is in force
        ref = _referee(conn, fid, home, away, _ts(kickoff), notes) if C.API_FOOTBALL_KEY else None
        rff = (t.get('referee') or {}).get(ref, 1.0) if ref else 1.0
        wxf = wf * rff                                          # both factors, on both sides' goal expectations
        lh, la = lh * wxf, la * wxf
        ctx = dict(home=hm, away=am, league=league_code, kickoff=_ts(kickoff), elo=elo_tab, neutral=neutral,
                   manager_changes=mgr, news=[a for a in (news_adj or []) if a['fixture_id'] == fid])
        variants = layers.variants(ctx, lh, la)
        champ_note = dict(recipe=tuning.describe(t['recipe']),
                          calibration=(f"home x{t['calibration']['home']:.3f}, away x{t['calibration']['away']:.3f}, draws x{tuning.draw_factor(t['calibration']):.3f}" if t['calibration'] else 'none'),
                          anchor=f"{t['anchor']:.2f}", referee=(f"{ref}, goals x{rff:.3f}" if ref else 'not known'), weather=(f"{wx['bucket']} ({wx['rain']} mm, {wx['wind']} km/h), goals x{wf:.3f}" if wx else 'no forecast'))
        dfac = tuning.draw_factor(t['calibration'])
        variants = [(n, a, b, dict(v, **champ_note) if n == layers.live_name() else dict(v), live) for n, a, b, v, live in variants]
        for v in variants: v[3]['draw'] = dfac                  # the champion and its layers carry the draw correction
        # Challengers: slight variations of the champion, priced beside it (never featured).
        for cname, crc, calibrated in tuning.challengers(t['recipe'], t['calibration'], tuning.methods_for(lg)):
            cp = params if cname == 'uncalibrated' else fits.get(cname)
            if not cp or hm not in cp['attack'] or am not in cp['attack']: continue
            clh, cla = dc.lambdas(cp, hm, am, neutral=neutral)
            if calibrated: clh, cla = tuning.apply_calibration(clh, cla, t['calibration']); clh, cla = clh * wxf, cla * wxf
            variants.append(('dixon_coles~' + cname, clh, cla, dict(recipe=tuning.describe(crc), calibration='on' if calibrated and t['calibration'] else 'none', rho=cp['rho'],
                                                                   draw=dfac if calibrated else 1.0), False))
        if wf != 1.0:    # the champion without the weather factor, so the factor has to keep earning its place live
            variants.append(('dixon_coles~no_weather', lh / wf, la / wf, dict(weather='ignored', rho=rho, draw=dfac), False))
        if rff != 1.0:   # ...and without the referee factor
            variants.append(('dixon_coles~no_referee', lh / rff, la / rff, dict(referee='ignored', rho=rho, draw=dfac), False))
    # Idea 7: Pinnacle's view of this fixture (when ODDS_API_KEY is set), as its own challenger.
    if odds_cache is not None and league_code in oddsapi.SPORTS:
        try:
            pe = oddsapi.find(_odds_for(conn, league_code, _ts(kickoff), odds_cache, notes), home, away, _ts(kickoff))
            pp = oddsapi.pinnacle_probs(pe) if pe else None
            if pp: variants.append(('sharp_pinnacle', None, None, dict(probs=pp, source='Pinnacle via the-odds-api'), False))
        except Exception as e:
            notes.setdefault('odds_errors', {})[league_code] = repr(e)[:200]
    # Idea 1: what all of this fixture's markets jointly say (no football model), as its own challenger.
    try:
        kf = consensus.fit(rows, rho if model != 'elo_cross' else -0.05)
    except Exception as e:
        kf = None; notes.setdefault('consensus_errors', []).append(repr(e)[:120])
    if kf:
        variants.append(('market_consensus', kf['lh'], kf['la'], dict(rho=kf['rho'], markets_used=len(kf['groups']),
                         implied_goals=f"{kf['lh']:.2f} - {kf['la']:.2f}", fit_loss=round(kf['loss'], 4)), False))
    moved = _flag_moves(conn, fid, rows, _ts(kickoff), notes)
    if model != 'elo_cross' and league_code in stakes.ZONES and sim_cache is not None:
        _stakes(conn, fid, lg, hm, am, fits, sim_cache, notes)
    blocked = C.INTEGRITY_BLOCK and (moved is not None or db.is_flagged(conn, fid))   # idea 25, only when switched on
    db.add_quotes(conn, fid, rows)
    n_new = 0
    anchor = t['anchor'] if (t and model != 'elo_cross') else None
    if anchor is not None and t.get('trust') and params.get('season_start'):
        # idea 19: the model's say scaled by the part of the season (early / mid / late)
        ph = tuning.phase_of(_ts(kickoff).date(), [dt.date.fromisoformat(params['season_start'])])
        anchor = anchor * t['trust'].get(ph, 1.0)
        for v in variants:
            if v[0] == layers.live_name():
                v[3]['anchor'] = f"{anchor:.2f}"; v[3]['season_phase'] = f"{ph} season, say x{t['trust'].get(ph, 1.0):.2f}"
    book_bad = guardian.book_problem(rows)                                # idea 33: a broken book -> no bet on the fixture
    if book_bad: db.guard(conn, 'block', 'book', book_bad, league_code, fid)
    priced = []; cs_variant = None
    for vname, vlh, vla, vnotes, _live in variants:
        vrho = vnotes.pop('rho', rho) if isinstance(vnotes, dict) else rho
        vdraw = vnotes.pop('draw', 1.0) if isinstance(vnotes, dict) else 1.0
        given = vnotes.pop('probs', None) if isinstance(vnotes, dict) else None
        probs = given if given else pricing.market_probs(pricing.score_grid(vlh, vla, vrho, draw=vdraw))   # a variant may bring its own
        priced.append((vname, vlh, vla, vrho, probs, vnotes, _live))
        if vname == layers.live_name() and vlh is not None and any(k.startswith('CS_') and r.get('mid_novig') is not None for k, r in rows.items()):
            cs_variant = (vlh, vla, vrho, vdraw)                                  # idea 16: the correct score, below
    members = {n: pr for n, _, _, _, pr, _, _ in priced}
    if len(members) >= 2:
        # idea 27: every variant votes, weighted by its recent log loss in this league
        w = committee.weights((comm or {}).get(league_code, {}), members)
        priced.append(('committee', None, None, None, committee.pool(members, w),
                       dict(weights={m: round(x, 3) for m, x in sorted(w.items(), key=lambda z: -z[1])}), False))
    for vname, vlh, vla, vrho, probs, vnotes, _live in priced:
        db.add_prediction(conn, fid, vname, vlh, vla, vrho, probs, band, vnotes)
        evaluated = []
        for key, r in rows.items():
            if key not in probs or r.get('mid_novig') is None: continue
            e = pricing.evaluate_row(key, probs[key], r['mid_novig'], r, r.get('volume'), C.BAND_CAP[band], anchor)
            e.update(cid=r['cid'], mid=r['market_id']); evaluated.append(e)
        pick = pricing.pick_for_fixture(evaluated)
        db.save_working(conn, fid, vname, band, evaluated, pick['key'] if pick else None)
        if not pick: continue
        pick['disagreement'] = committee.disagreement(members, pick['key'])        # idea 31
        _learned_view(pick, rows.get(pick['key']) or {}, band, _ts(kickoff), probs.get(pick['key']), learned)   # ideas 15, 2 / 20
        if C.META_SKIP is not None and pick.get('meta_p') is not None and pick['meta_p'] < C.META_SKIP: continue
        bad = guardian.prediction_problem(vlh, vla, probs)
        if bad: db.guard(conn, 'block', 'prediction', bad, league_code, fid, vname)
        gap = guardian.gap_problem(probs, rows)
        if gap: db.guard(conn, 'block', 'model v market gap', gap, league_code, fid, vname)
        if C.DISAGREE_BLOCK is not None and (pick['disagreement'] or 0) > C.DISAGREE_BLOCK: continue
        if book_bad or bad or gap:
            notes.setdefault('guardian_blocked', []).append(f'{fid} {vname}'); continue
        if not blocked and db.add_suggestion(conn, fid, vname, pick, vnotes) and _live and pick['order_type'] == 'take': n_new += 1
    if cs_variant:
        # Idea 16 (1 Oct): the correct score from the live model's own scoreline grid, recorded as its own variant
        # 'dixon_coles:cs' (scored, never featured: a long-shot market with thin books).
        clh, cla, crho, cdraw = cs_variant
        cprobs = pricing.cs_probs(pricing.score_grid(clh, cla, crho, draw=cdraw))
        db.add_prediction(conn, fid, 'dixon_coles:cs', clh, cla, crho, cprobs, band, dict(market='correct score'))
        ev_cs = []
        for key, r in rows.items():
            if key not in cprobs or r.get('mid_novig') is None: continue
            e = pricing.evaluate_row(key, cprobs[key], r['mid_novig'], r, r.get('volume'), C.BAND_CAP[band], anchor)
            e.update(cid=r['cid'], mid=r['market_id']); ev_cs.append(e)
        pk = pricing.pick_for_fixture(ev_cs)
        db.save_working(conn, fid, 'dixon_coles:cs', band, ev_cs, pk['key'] if pk else None)
        if pk and not book_bad and not blocked: db.add_suggestion(conn, fid, 'dixon_coles:cs', pk, dict(market='correct score'))
    return dict(fid=fid, new_suggestion=n_new > 0)


def _ts(x):
    return x if isinstance(x, dt.datetime) else dt.datetime.fromisoformat(str(x).replace('Z', '+00:00'))


def _forecast(conn, fid, league, team, kickoff, cache, notes):
    """Idea 10: the weather forecast at `team`'s ground for this kick-off, kept on the fixture (flags.weather) and
    refetched at most every 6 hours (Open-Meteo's free limit is generous but not endless). -> dict or None"""
    try:
        old = db.get_flag(conn, fid, 'weather')
        if old and (dt.datetime.now(UTC) - dt.datetime.fromisoformat(old['fetched'])).total_seconds() < 6 * 3600:
            return old
        if league not in cache: cache[league] = db.venues_for(conn, league)
        v = cache[league].get(team)
        if not v or v.get('lat') is None: return None
        w = wsrc.forecast(v['lat'], v['lon'], kickoff)
        if not w: return None
        w = dict(w, bucket=wsrc.bucket(w), venue=v.get('venue'), fetched=dt.datetime.now(UTC).isoformat())
        db.set_flag(conn, fid, 'weather', w)
        return w
    except Exception as e:
        notes.setdefault('weather_errors', {})[league] = repr(e)[:200]
        return None


_REF_CACHE = {}


def _referee(conn, fid, home, away, kickoff, notes):
    """Idea 22: the referee appointed to this fixture, from API-Football's fixtures for that day (one request per day,
    cached in model_params for REFEREE_EVERY_H hours, so the free plan's 100 requests a day are not touched hourly).
    Kept on the fixture (flags.referee). -> normalised name or None"""
    try:
        x = _af_fixture(conn, kickoff, home, away)
        if x and x.get('referee'):
            db.set_flag(conn, fid, 'referee', dict(name=x['referee'], api_fixture=x['id']))
            return x['referee']
    except Exception as e:
        notes.setdefault('referee_errors', []).append(repr(e)[:160])
    return None


def _odds_for(conn, code, kickoff, cache, notes):
    """Idea 7: The Odds API events for a league, cached in model_params for ODDS_API_EVERY_H hours so credits are spent at
    most once per league per period, and only when the league has a fixture in the next ODDS_API_WINDOW_H hours."""
    if code in cache: return cache[code]
    sport = oddsapi.SPORTS[code]; key = 'ODDS:' + sport
    row = db.latest_params(conn, key)
    fresh = row and (dt.datetime.now(UTC) - row[0]).total_seconds() < C.ODDS_API_EVERY_H * 3600
    soon = (kickoff - dt.datetime.now(UTC)).total_seconds() < C.ODDS_API_WINDOW_H * 3600
    if fresh or not soon:
        cache[code] = row[1].get('events') if row else None; return cache[code]
    if '_sports' not in cache:
        cache['_sports'] = oddsapi.available(C.ODDS_API_KEY)
    if sport not in cache['_sports']:
        notes.setdefault('odds_errors', {})[code] = f'sport {sport} not offered'; cache[code] = None; return None
    got = oddsapi.fetch(sport, C.ODDS_API_KEY, C.ODDS_API_MARKETS)
    db.save_params(conn, key, dict(engine='odds-api', events=got['events'], remaining=got['remaining']), 'the-odds-api')
    notes['odds_api_remaining'] = got['remaining']
    cache[code] = got['events']; return cache[code]


def _stakes(conn, fid, lg, hm, am, fits, sim_cache, notes):
    """Idea 8: what is at stake for each side, from a season simulation run at most once per league per run, and only
    when one of its fixtures has no stakes from the last 20 hours."""
    try:
        age = db.stakes_age_hours(conn, fid)
        if age is not None and age < 20: return
        code = lg['code']
        if code not in sim_cache:
            today = dt.datetime.now(UTC).date()
            ms, _ = rs.load_league(lg, today, years=1)
            played = stakes.current_season(ms, tuning.season_starts([m['date'] for m in ms]))
            sim_cache[code] = stakes.simulate(code, played, fits[''])
        st = stakes.for_match(sim_cache[code], hm, am)
        if st:
            head = stakes.headline(st)
            if head: head = ('home' if head[0] == hm else 'away',) + head[1:]
            db.save_stakes(conn, fid, dict(home=st[hm], away=st[am], names=[hm, am]), head)   # stored by side: names differ by source
    except Exception as e:
        notes.setdefault('stakes_errors', {})[lg['code']] = repr(e)[:200]


def _flag_moves(conn, fid, rows, kickoff, notes=None):
    """Idea 25: record a sharp move since the fixture's last read (recording only unless INTEGRITY_BLOCK)."""
    try:
        f = integrity.check(db.last_quote(conn, fid), rows, dt.datetime.now(UTC), kickoff)
        if f:
            db.flag_fixture(conn, fid, 'sharp_move', f)
            if notes is not None: notes.setdefault('sharp_moves', []).append(dict(fixture=fid, **{k: f[k] for k in ('key', 'before', 'after', 'minutes')}))
        return f
    except Exception as e:
        if notes is not None: notes.setdefault('integrity_errors', []).append(repr(e)[:120])
        return None


def capture_closes(conn):
    n = 0
    for fid, markets, kickoff in db.fixtures_kicking_off(conn, C.CLOSE_WINDOW_MIN):
        try:
            rows = read_book({k: dict(v, contracts={}) for k, v in (markets or {}).items()})
            _flag_moves(conn, fid, rows, kickoff)
            db.add_quotes(conn, fid, rows, is_close=True); db.set_close(conn, fid); n += 1
        except Exception:
            traceback.print_exc()
    return n


def capture_lineups(conn, notes):
    """Ideas 4 / 21: starting line-ups for fixtures kicking off in the next 15-80 minutes (API-Football, budgeted).
    Recorded for research: does the market fully price a side resting half its team?"""
    n = 0
    for fid, home, away, kickoff, flags in db.lineups_due(conn, ('elo_cross', layers.live_name())):
        afid = ((flags or {}).get('referee') or {}).get('api_fixture')
        if not afid:
            x = _af_fixture(conn, kickoff, home, away)
            afid = x['id'] if x else None
        if not afid: continue
        try:
            got = af.lineups(afid, C.API_FOOTBALL_KEY)
        except RuntimeError as e:                        # the day's allowance is used: stop for this run
            notes['lineup_budget'] = str(e)[:120]; break
        if not got: continue                             # not published yet: tried again next run
        by = {}
        for t in got:
            if names.match(t['team'] or '', [home])[0]: by['home'] = t
            elif names.match(t['team'] or '', [away])[0]: by['away'] = t
        if len(by) < 2: by = dict(home=got[0], away=got[1])        # API-Football lists the home side first
        db.save_lineups(conn, fid, list(by.items())); n += 1
    return n


def _af_fixture(conn, kickoff, home, away):
    """The API-Football fixture for one of ours, from the same cached day list the referees use (one request a day)."""
    day = kickoff.date(); key = 'AFDAY:' + day.isoformat()
    if key not in _REF_CACHE:
        row = db.latest_params(conn, key)
        if row and (dt.datetime.now(UTC) - row[0]).total_seconds() < C.REFEREE_EVERY_H * 3600:
            fx = row[1]['fixtures']
        else:
            fx = []
            for x in af.fixtures_on(day, C.API_FOOTBALL_KEY):
                sx = af.simple(x); fx.append(dict(sx, date=None, kickoff=sx['date'].isoformat() if sx['date'] else None))
            db.save_params(conn, key, dict(engine='api-football', fixtures=fx), 'api-football fixtures by date')
        for x in fx: x['date'] = dt.datetime.fromisoformat(x['kickoff']) if x.get('kickoff') else None
        _REF_CACHE[key] = fx
    return af.find(_REF_CACHE[key], home, away, kickoff)


def settle_due(conn):
    n = 0
    for fid, markets in db.to_settle(conn, C.SETTLE_AFTER_HOURS):
        try:
            outs = sm.outcomes(list((markets or {}).keys()))
            if not outs or all(v in (None, 'open', 'halted') for v in outs.values()): continue
            one = cs = None
            for mid, m in (markets or {}).items():
                if m['type'] in ('WINNER_3_WAY', 'CORRECT_SCORE'):
                    for cid, key in m['contracts'].items():
                        if outs.get(cid) == 'winner':
                            if m['type'] == 'WINNER_3_WAY': one = key
                            else: cs = key
            n += db.settle(conn, fid, one, outs, outcome_cs=cs)
        except Exception:
            traceback.print_exc()
    return n


def _learned_view(pick, r, band, kickoff, p_model, learned):
    """Ideas 15 and 2 / 20: what the two learned models say about a pick (recorded with the suggestion)."""
    if not learned: return
    hours = (kickoff - dt.datetime.now(UTC)).total_seconds() / 3600
    try:
        if learned.get('meta'):
            pick['meta_p'] = round(learn.predict_logistic(learned['meta'], learn.meta_x(pick['ev'], pick['price'], pick['key'], band, hours,
                                                                                    pick.get('spread_pts'), pick.get('volume'), pick.get('disagreement'))), 4)
        if learned.get('close') and r.get('mid_novig') is not None:
            pick['pred_move'] = round(learn.predict_ridge(learned['close'], learn.close_x(r['mid_novig'], r.get('back_depth3'), r.get('lay_depth3'),
                                                                                         r.get('volume'), hours, p_model)), 4)
    except Exception:
        pass


def learn_models(conn, notes):
    """Ideas 15 and 2 / 20: the latest fits, refitted when a day old and there is enough data. -> {'meta': m, 'close': m}"""
    out = {}
    for name, rows_fn, build, fit in (('META', db.meta_rows, lambda r: dict(x=learn.meta_x(r['ev'], r['price'], r['key'], r['band'], r['hours'], r['spread_pts'],
                                                                                              r['volume'], r['disagreement']), beat=int(r['clv'] > 0), clv=r['clv']), learn.meta_fit),
                                      ('CLOSE', db.close_rows, lambda r: dict(fid=r['fid'], x=learn.close_x(r['p'], r['back_depth3'], r['lay_depth3'], r['volume'],
                                                                                                             r['hours'], r['p_model']), move=r['p_close'] - r['p']), learn.close_fit)):
        try:
            row = db.latest_params(conn, name)
            if not row or (dt.datetime.now(UTC) - row[0]).total_seconds() > C.LEARN_EVERY_H * 3600:
                got = fit([build(r) for r in rows_fn(conn)])
                if got:
                    db.save_params(conn, name, dict(got, engine='logistic' if name == 'META' else 'ridge'), 'own records')
                    row = (dt.datetime.now(UTC), got)
                    notes.setdefault('learned', {})[name] = got['test']
            if row: out[name.lower()] = row[1]['model']
        except Exception as e:
            notes.setdefault('learn_errors', {})[name] = repr(e)[:200]
    return out


def make_card(conn, now):
    """The daily card (Mitch, 16 Oct: "rest these 5, 5 real bets, 5 forced bets"), made once a day by the first full run
    after CARD_HOUR_UTC from the day's fixtures not yet started, then fixed:
      forced - the CARD_SIZE prices on offer the model rates best (EV at the anchored probability), one per fixture,
               not already a bet, no long shots and only from a two-sided book. Most will not clear the floor: they test
               whether the model's ranking means anything, much faster than waiting for real bets;
      rests  - the CARD_SIZE open resting orders whose price is closest to the price on offer now (likeliest to fill).
    Bets are the featured ones (feature_today), up to MAX_FEATURED_PER_DAY, found at any time of day."""
    if now.hour < C.CARD_HOUR_UTC: return None
    day = now.date()
    if db.card_made(conn, day): return None
    live = layers.live_name()
    forced, rest_rank = [], []
    for fid, kickoff, markets, rows, has_take, rests in db.card_candidates(conn, day, live):
        cmap = {key: (cid, mid) for mid, m in markets.items() for cid, key in (m.get('contracts') or {}).items()}
        byk = {r.get('key'): r for r in rows}
        for sid, key, price in rests:
            back = (byk.get(key) or {}).get('back')
            if back and price: rest_rank.append((price / back, sid))
        if has_take: continue
        best = None
        for r in rows:
            k, back = r.get('key'), r.get('back')
            pc, pmk = r.get('p_capped'), r.get('p_market')
            # the model's own view at a fixed weight, whatever the tuned weight (which may be zero): forced picks test
            # whether the model's ranking means anything
            pw = C.FORCED_WEIGHT * pc + (1 - C.FORCED_WEIGHT) * pmk if pc is not None and pmk is not None else r.get('p_work')
            if k not in cmap or not back or pw is None or str(k).startswith('CS_'): continue
            if pw < C.LEAN_MIN_P or back > C.LEAN_MAX_PRICE: continue
            if r.get('spread_pts') is None or r['spread_pts'] > C.LEAN_MAX_SPREAD: continue
            ev = pricing.ev_back(pw, back)
            if best is None or ev > best['ev']:
                best = dict(r, ev=ev, cid=cmap[k][0], mid=cmap[k][1])
        if best: forced.append((fid, best))
    forced.sort(key=lambda x: -x[1]['ev'])
    n_forced = sum(1 for fid, b in forced[:C.CARD_SIZE] if db.add_forced(conn, fid, live, b, day))
    rest_rank.sort()
    n_rests = db.card_rests(conn, [sid for _, sid in rest_rank[:C.CARD_SIZE]], day) if rest_rank else 0
    db.save_card(conn, day, None, n_forced, n_rests)
    return dict(day=day.isoformat(), forced=n_forced, rests=n_rests)


def breaker(conn, notes):
    """Idea 32: the circuit breaker. A league whose live bets have averaged a closing-line value below BREAKER_CLV over
    the last BREAKER_N stops being featured; its bets are still recorded (not featured), so it can recover, and it is
    featured again once the same average is back above BREAKER_RESUME. Every trip and reset is logged in league_tuning."""
    try:
        state = db.breaker_leagues(conn, ('elo_cross', layers.live_name()))
    except Exception as e:
        notes['breaker_error'] = repr(e)[:200]; return []
    for lg, (now_t, clv, n, was_t) in state.items():
        if now_t != was_t:
            db.add_tuning(conn, lg, 'breaker', now_t, dict(tripped=now_t), dict(mean_clv=round(clv, 4), bets=n,
                          rule=f'trip below {C.BREAKER_CLV:+.0%}, reset above {C.BREAKER_RESUME:+.0%}, last {C.BREAKER_N} bets'), 'circuit breaker')
    out = sorted(lg for lg, v in state.items() if v[0])
    if out: notes['breaker_tripped'] = out
    return out


def settings_snapshot():
    """The rules this run priced under, saved with the run so the live page shows them from data, not from memory."""
    return dict(mode=C.MODE, commission=C.COMMISSION, floor_ev=C.FLOOR_EV, preferred_ev=C.PREFERRED_EV,
                thresh_result=C.THRESH_RESULT, thresh_goals=C.THRESH_GOALS, liquidity_gates=C.LIQUIDITY_GATES,
                anchor_model_weight=C.ANCHOR_MODEL_WEIGHT, band_cap=C.BAND_CAP, max_featured_per_day=C.MAX_FEATURED_PER_DAY, card_size=C.CARD_SIZE,
                paper_stake=C.PAPER_STAKE, dc_xi=C.DC_XI, dc_seasons=C.DC_SEASONS, dc_min_matches=C.DC_MIN_MATCHES,
                elo_hfa=C.ELO_HFA, elo_total_goals=C.ELO_TOTAL_GOALS, price_window_hours=C.PRICE_WINDOW_HOURS,
                promote_min=layers.PROMOTE_MIN, live_model=layers.live_name(),
                tuning=dict(xi_mults=C.TUNE_XI_MULTS, fit_years=C.TUNE_FIT_YEARS, window_days=C.TUNE_WINDOW_DAYS,
                            min_matches=C.TUNE_MIN_MATCHES, margin=C.TUNE_MARGIN, live_min=C.LIVE_CHALLENGE_MIN,
                            live_margin=C.LIVE_CHALLENGE_MARGIN, cooldown_days=C.RECIPE_COOLDOWN_DAYS, cal_shrink=C.CAL_SHRINK,
                            cal_clip=C.CAL_CLIP, anchor_default=C.ANCHOR_DEFAULT, anchor_max=C.ANCHOR_MAX, anchor_step=C.ANCHOR_STEP,
                            anchor_window=C.ANCHOR_WINDOW, anchor_margin=C.ANCHOR_MARGIN, anchor_min_new=C.ANCHOR_MIN_NEW),
                layers={n: s for n, (_, s) in layers.LAYERS.items()})


def main(kind='auto'):
    now = dt.datetime.now(UTC)
    if kind == 'auto': kind = 'full' if now.minute < 15 else 'close'
    conn = db.connect(); db.ensure_schema(conn)
    run_id = db.start_run(conn, kind); notes = {}
    af.set_budget(lambda k: db.af_allow(conn, k))       # API-Football's daily allowance, shared with the in-play worker
    if kind == 'full':
        notes['settings'] = settings_snapshot()
    n_events = n_priced = n_new = 0
    try:
        n_settled = settle_due(conn)
        try: notes['paths_recorded'] = db.record_paths(conn)
        except Exception as e: notes['path_error'] = repr(e)[:200]
        if kind == 'full':
            evs = sm.upcoming_events(now.strftime('%Y-%m-%dT%H:%M:%SZ'), (now + dt.timedelta(hours=C.PRICE_WINDOW_HOURS)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            n_events = len(evs)
            try: db.events_seen(conn, evs)
            except Exception as e: notes['events_seen_error'] = repr(e)[:200]
            by_league, params_cache = {}, {}
            elo_tab = elo_table(conn, now.date(), notes)      # European ties, and the elo_blend layer on domestic games
            mgr = db.manager_changes(conn)
            tune = tuning.in_force(db.tuning_rows(conn))      # each league's recipe, calibration and anchor
            pyr_cache = {}                                     # each country's pyramid results, loaded once a run
            sim_cache = {}                                     # each English league's season simulation, at most once a run
            odds_cache = {} if C.ODDS_API_KEY else None        # idea 7: Pinnacle prices, only with ODDS_API_KEY
            wx_cache = {}                                      # idea 10: grounds per league
            try: news_adj = db.news_adjustments(conn)          # idea 5: team news in force
            except Exception as e: news_adj = []; notes['news_error'] = repr(e)[:200]
            learned = learn_models(conn, notes)                # ideas 15, 2 / 20: fitted once a day once there is enough data
            try: comm = db.committee_scores(conn)             # idea 27: each variant's recent record per league
            except Exception as e: comm = {}; notes['committee_error'] = repr(e)[:200]
            for ev in evs:
                slug = sm.competition_slug(ev); lg, how = classify(slug)
                db.seen_competition(conn, slug or '?', (lg if lg == 'EUROPE' else lg['code']) if lg else None, how)
                # A league matched by country only is recorded for review (Health tab) but never priced: on 29 Sep
                # 'serbia-prva-liga' (the second tier) was inferred as the Serbian SuperLiga. Confirm by adding the slug.
                if lg and how != 'inferred': by_league.setdefault(lg if lg == 'EUROPE' else lg['code'], []).append((ev, lg, how))
            for code, items in by_league.items():
                if code == 'EUROPE':
                    fits = None
                else:
                    fits = league_fits(conn, items[0][1], now.date(), notes, tune[code], pyr_cache)
                    if not fits.get(''): continue
                    stale = guardian.stale_problem(fits[''].get('latest_match'), now.date())      # idea 33
                    if stale: db.guard(conn, 'warn', 'stale results', stale, code)
                for ev, lg, how in items:
                    try:
                        r = price_event(conn, ev, lg, how, fits, elo_tab, notes, mgr, tune[code], sim_cache, odds_cache, wx_cache, news_adj, comm, learned)
                        if r: n_priced += 1; n_new += int(r['new_suggestion'])
                    except Exception as e:
                        notes.setdefault('event_errors', []).append(f"{ev.get('id')} {repr(e)[:200]}")
            try: notes['card'] = make_card(conn, now)          # the daily card (16 Oct): bets / forced / rests
            except Exception as e: notes['card_error'] = repr(e)[:200]
            skip = breaker(conn, notes)                        # idea 32: leagues whose recent bets lost to the close
            for d in sorted({(now + dt.timedelta(days=k)).date() for k in range(3)}):
                db.feature_today(conn, d, C.MAX_FEATURED_PER_DAY, live_models=('elo_cross', layers.live_name()), skip_leagues=skip)
        if sm.SEEN_TYPES:
            try: db.market_types(conn, sm.SEEN_TYPES)
            except Exception as e: notes['market_types_error'] = repr(e)[:200]
        if sm.UNKNOWN:
            try:                                          # idea 16: sample the contracts of up to 5 new market types a run
                for name in db.unsampled_types(conn, list(sm.UNKNOWN))[:5]:
                    db.save_sample(conn, name, sm.sample_contracts(sm.UNKNOWN[name][:3]))
            except Exception as e: notes['market_sample_error'] = repr(e)[:200]
        n_close = capture_closes(conn); notes['closes'] = n_close
        if C.API_FOOTBALL_KEY:
            try: notes['lineups'] = capture_lineups(conn, notes)          # ideas 4 / 21
            except Exception as e: notes['lineup_error'] = repr(e)[:200]
        db.finish_run(conn, run_id, n_events=n_events, n_priced=n_priced, n_suggestions=n_new, n_settled=n_settled, notes=notes)
        print(f'{kind} run {run_id}: events {n_events}, priced {n_priced}, new bets {n_new}, settled {n_settled}, closes {n_close}')
    except Exception as e:
        db.finish_run(conn, run_id, notes=notes, error=traceback.format_exc()[-2000:])
        raise


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'auto')
