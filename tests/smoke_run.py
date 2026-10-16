"""Offline smoke test of the job's pricing path with a fake exchange and a fake database (no network, no Postgres)."""
import sys, types, pathlib, datetime as dt, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
# fake psycopg so sbms.db imports
fake = types.ModuleType('psycopg'); fake.connect = lambda *a, **k: None
tj = types.ModuleType('psycopg.types.json'); tj.Jsonb = lambda x: x
sys.modules['psycopg'] = fake; sys.modules['psycopg.types'] = types.ModuleType('psycopg.types'); sys.modules['psycopg.types.json'] = tj
from sbms.jobs import run
from sbms import db
calls = []
for fn in ('name_miss', 'add_prediction', 'add_quotes', 'save_working'):
    setattr(db, fn, (lambda n: lambda *a, **k: calls.append((n, a[1:3] if len(a) > 2 else a)))(fn))
db.upsert_fixture = lambda *a, **k: 1
GUARD = []
db.reaction_events = lambda conn: []
db.guard = lambda conn, level, check, detail, league=None, fid=None, model=None: GUARD.append((check, model, detail))
_gap = run.C.GUARD_GAP; run.C.GUARD_GAP = 1.0      # the fake book below is deliberately far from the model; the guardian is tested further down
db.add_suggestion = lambda conn, fid, model, s, notes=None: calls.append(('SUGGEST', model, s['key'], s['order_type'], round(s['price'], 2), round(s['ev'], 4), s['back'] and round(s['back'], 2))) or 1
# fake exchange: Arsenal v Leeds, market underrates Arsenal
run.sm.event_markets = lambda eid: [dict(id='m1', type='WINNER_3_WAY', param=None), dict(id='m2', type='OVER_UNDER', param='2.5')]
def book(ids):
    cs = [dict(id='c1', market_id='m1', contract_type=dict(name='HOME')), dict(id='c2', market_id='m1', contract_type=dict(name='DRAW')),
          dict(id='c3', market_id='m1', contract_type=dict(name='AWAY')), dict(id='c4', market_id='m2', contract_type=dict(name='OVER')),
          dict(id='c5', market_id='m2', contract_type=dict(name='UNDER'))]
    q = {'c1': dict(bids=[dict(price=5000, quantity=1)], offers=[dict(price=5051, quantity=1)]),
         'c2': dict(bids=[dict(price=2700, quantity=1)], offers=[dict(price=2740, quantity=1)]),
         'c3': dict(bids=[dict(price=2250, quantity=1)], offers=[dict(price=2300, quantity=1)]),
         'c4': dict(bids=[dict(price=5400, quantity=1)], offers=[dict(price=5450, quantity=1)]),
         'c5': dict(bids=[dict(price=4550, quantity=1)], offers=[dict(price=4600, quantity=1)])}
    return cs, q, {'m1': 90000, 'm2': 5000}
run.sm.book = book
params = dict(attack={'Arsenal': 0.45, 'Leeds': -0.2, 'Burnley': -0.3}, defence={'Arsenal': -0.5, 'Leeds': 0.1, 'Burnley': 0.2}, home_advantage=0.25, rho=-0.08,
              band='full', matches_per_team={'Arsenal': 60, 'Leeds': 40, 'Burnley': 40})
ev = dict(id='e1', name='Arsenal vs Leeds United', start_datetime='2026-10-10T14:00:00Z', full_slug='/sport/football/england-premier-league/2026/10/10/15-00/arsenal-vs-leeds', venue=dict(neutral=False))
lg = [l for l in run.C.LEAGUES if l['code'] == 'E0'][0]
r = run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [])
print(r); [print(c) for c in calls]
assert r and any(c[0] == 'add_quotes' for c in calls) and any(c[0] == 'add_prediction' for c in calls)
# with anchor 0.30 and a 15% band the largest possible edge on a 50% shot is ~ +2.7% after commission: nothing can be
# TAKEN at 1.98. Under L-1 (29 Sep) a resting order is recorded instead, at the lowest price that clears +4%; it counts
# only if the book reaches it before kick-off.
sug = [c for c in calls if c[0] == 'SUGGEST']
assert sug and all(c[3] == 'rest' and c[5] >= 0.04 and c[4] > c[6] for c in sug)
# the foundation and each testing layer are priced as separate variants
assert {c[1] for c in sug} >= {'dixon_coles'}
preds = [c for c in calls if c[0] == 'add_prediction']; assert len(preds) == 6 and {'market_consensus', 'committee'} <= {c[1][1] for c in preds}, preds
assert len([c for c in calls if c[0] == 'save_working']) == 6
# self-tuning: with a calibration in force and challenger fits, the champion is priced beside its variations
from sbms import tuning
calls.clear()
t = tuning.in_force([dict(league='E0', kind='calibration', decided_at=None, adopted=True, value=dict(home=1.05, away=0.97)),
                     dict(league='E0', kind='anchor', decided_at=None, adopted=True, value=dict(weight=0.36))])['E0']
slower = dict(params, attack={k: v * 0.9 for k, v in params['attack'].items()})
r2 = run.price_event(None, ev, lg, 'exact', {'': params, 'fade_slower': slower, 'fade_faster': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [], t)
models2 = [c[1][1] for c in calls if c[0] == 'add_prediction']
assert set(models2) == {'dixon_coles', 'dixon_coles+elo_blend', 'dixon_coles+manager_change', 'dixon_coles+news', 'dixon_coles~fade_slower', 'dixon_coles~fade_faster', 'dixon_coles~uncalibrated', 'market_consensus', 'committee'}, models2
print('variants:', models2)
# idea 7: Pinnacle's prices as a challenger (odds cache pre-filled, so no network or key needed)
calls.clear()
pin_event = dict(id='x', commence_time='2026-10-10T14:00:00Z', home_team='Arsenal', away_team='Leeds United',
                 bookmakers=[dict(key='pinnacle', markets=[dict(key='h2h', outcomes=[dict(name='Arsenal', price=1.80), dict(name='Draw', price=3.9),
                                                                                     dict(name='Leeds United', price=4.8)])])])
r3 = run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [], None, None, {'E0': [pin_event]})
pin = [c for c in calls if c[0] == 'add_prediction' and c[1][1] == 'sharp_pinnacle']
assert pin, [c[1][1] for c in calls if c[0] == 'add_prediction']
print('sharp_pinnacle priced')
# idea 10: a wet forecast with a weather factor in force: the champion is scaled and a no-weather challenger appears
calls.clear()
db.get_flag = lambda conn, fid, name: None; db.set_flag = lambda conn, fid, name, value: calls.append(('FLAG', name, value.get('bucket') or value.get('name')))
db.venues_for = lambda conn, league: {'Arsenal': dict(lat=51.55, lon=-0.108, venue='Emirates Stadium')}
run.wsrc.forecast = lambda lat, lon, ko: dict(rain=3.0, wind=20.0, temp=9.0)
tw = tuning.in_force([dict(league='E0', kind='weather', decided_at=None, adopted=True, value=dict(factors=dict(wet=0.92)))])['E0']
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [], tw, None, None, {})
names_w = [c[1][1] for c in calls if c[0] == 'add_prediction']
assert ('FLAG', 'weather', 'wet') in calls and 'dixon_coles~no_weather' in names_w, names_w
print('weather: wet forecast, factor applied, no_weather challenger')
# idea 22: an appointed referee with a factor in force (API-Football stubbed)
calls.clear(); run.C.API_FOOTBALL_KEY = 'test'
db.latest_params = lambda conn, key: None; db.save_params = lambda *a, **k: None
run.af.fixtures_on = lambda day, key: [dict(fixture=dict(id=1, referee='Michael Oliver, England', date='2026-10-10T14:00:00+00:00', status=dict(short='NS')),
                                            league=dict(id=39), teams=dict(home=dict(name='Arsenal'), away=dict(name='Leeds United')), goals=dict(home=None, away=None))]
tr = tuning.in_force([dict(league='E0', kind='referee', decided_at=None, adopted=True, value=dict(factors={'m oliver': 1.06}))])['E0']
nr = {}
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, nr, [], tr, None, None, {})
names_r = [c[1][1] for c in calls if c[0] == 'add_prediction']
assert 'dixon_coles~no_referee' in names_r and ('FLAG', 'referee', 'm oliver') in calls and not nr.get('referee_errors'), (names_r, nr)
run.C.API_FOOTBALL_KEY = ''
print('referee: appointment found, factor applied, no_referee challenger')
# idea 11: one in-play worker step: Arsenal 0-0 Leeds at 70 minutes, the book still priced as at kick-off
import datetime as _dtt
from sbms.jobs import inplay as IP
ko_ = _dtt.datetime.now(_dtt.timezone.utc) - _dtt.timedelta(minutes=85)
db.live_fixtures = lambda conn: [dict(id=5, home='Arsenal', away='Leeds United', kickoff=ko_, league='E0', lh=1.7, la=1.1,
                                      markets={'m1': dict(type='WINNER_3_WAY', param=None, contracts={}), 'm2': dict(type='OVER_UNDER', param='2.5', contracts={})})]
db.last_inplay_rows = lambda conn, fid: None
snaps, ibets = [], []
db.add_inplay_snapshot = lambda conn, fid, minute, sh, sa, probs, rows: snaps.append((minute, sh, sa, probs))
db.add_inplay_bet = lambda conn, fid, minute, sh, sa, b: ibets.append((b['key'], round(b['price'], 2), round(b['ev'], 3))) or 1
IP.C.API_FOOTBALL_KEY = 'test'
db.open_events = lambda conn: []
IP.read_book_fast = lambda markets: run.read_book({k: dict(v, contracts={}) for k, v in markets.items()})
IP.af.live = lambda key: [dict(fixture=dict(id=9, date=ko_.isoformat(), status=dict(short='2H', elapsed=70)), league=dict(id=39),
                               teams=dict(home=dict(name='Arsenal'), away=dict(name='Leeds United')), goals=dict(home=0, away=0))]
r_ip = IP.step(None, {})
assert r_ip['live'] == 1 and snaps and snaps[0][1:3] == (0, 0) and 69 < snaps[0][0] < 71 and snaps[0][3]['U2.5'] > 0.9
assert not ibets        # the 15% cap and the +6% in-play floor hold the model back against this (stale) book: no bet
_f = (IP.C.FLOOR_EV, IP.C.INPLAY_FLOOR_EV, IP.C.THRESH_GOALS); IP.C.FLOOR_EV, IP.C.INPLAY_FLOOR_EV, IP.C.THRESH_GOALS = 0.0, 0.0, 0.0
IP.step(None, {})       # with the floors at zero the betting path runs: under 2.5 at 0-0 late on
IP.C.FLOOR_EV, IP.C.INPLAY_FLOOR_EV, IP.C.THRESH_GOALS = _f; IP.C.API_FOOTBALL_KEY = ''
assert any(k == 'U2.5' for k, _, _ in ibets), ibets
print('in-play step:', r_ip, ibets[:3])
# goal reaction: a quiet book, a goal (the home price jumps), then the book settling; the event is recorded and closed
import datetime as _dg
from sbms.jobs import inplay as IP2
EV = {}
db.live_fixtures = lambda conn: [dict(id=7, home='A', away='B', kickoff=_t0 - _dg.timedelta(minutes=50), league='E0', lh=1.4, la=1.1, markets={'m': {}})]
db.open_events = lambda conn: [(eid, e['fid'], e['at'], e['up']) for eid, e in EV.items() if not e['done']]
def _oe(conn, fid, minute, j, rows, kind='jump, no suspension', suspended_s=None, pre=None, at=None, plan=None):
    EV[len(EV) + 1] = dict(fid=fid, at=_now[0], up=j['up_key'], path=[[0, rows]], done=False, trades=None, kind=kind, susp=suspended_s, pre=pre, move=j['move'], plan=plan)
    return len(EV)
db.open_event = _oe
db.extend_event = lambda conn, eid, secs, rows: EV[eid]['path'].append([round(secs), rows])
db.event_path = lambda conn, eid: EV[eid]['path']
def _ce(conn, eid, trades): EV[eid]['done'] = True; EV[eid]['trades'] = trades
db.close_event = _ce
def _bk(h, d, a): return {'H': dict(back=h, lay=round(h * 1.02, 2), mid_novig=1 / h), 'D': dict(back=d, lay=round(d * 1.02, 2), mid_novig=1 / d), 'A': dict(back=a, lay=round(a * 1.02, 2), mid_novig=1 / a)}
_t0 = _dg.datetime(2026, 10, 3, 15, 0, tzinfo=_dg.timezone.utc)
books = [_bk(2.2, 3.4, 3.6), _bk(2.2, 3.4, 3.6), _bk(1.45, 4.6, 7.5)] + [_bk(1.45 + 0.01 * i, 4.5, 7.2) for i in range(1, 25)]
IP2.C.API_FOOTBALL_KEY = ''
st = {}; _now = [None]
for i, bk in enumerate(books):
    _now[0] = _t0 + _dg.timedelta(seconds=15 * i)
    IP2.read_book_fast = lambda markets, bk=bk: bk
    IP2.step(None, st, now=_now[0])
assert len(EV) == 1 and EV[1]['done'] and EV[1]['up'] == 'H', EV
tr = EV[1]['trades']
assert tr['H']['side'] == 'follow' and 300 in tr['H']['green'] and tr['H']['entry'] == 1.45, tr['H']
print('goal reaction: event recorded, follow-home green at 5 min', tr['H']['green'][300], '| fade-away', tr['A']['green'][300])
assert EV[1]['kind'] == 'jump, no suspension' and EV[1]['susp'] is None
# suspensions: the book goes empty (a goal), reopens at new prices -> 'goal or red card', with the suspension's length
# and the reads before it; then a VAR check: empty, reopens at the same prices -> 'check, no change'
EV.clear(); st = {}
E = {}
books = ([_bk(2.2, 3.4, 3.6)] * 4 + [E] * 5 + [_bk(1.5, 4.4, 7.0)] + [_bk(1.5 + 0.01 * i, 4.4, 7.0) for i in range(1, 24)]
         + [_bk(1.75, 4.0, 5.5)] * 3 + [E] * 3 + [_bk(1.76, 4.0, 5.45)] + [_bk(1.76, 4.0, 5.45)] * 23)
for i, bk in enumerate(books):
    _now[0] = _t0 + _dg.timedelta(seconds=15 * i)
    IP2.read_book_fast = lambda markets, bk=bk: bk
    IP2.step(None, st, now=_now[0])
kinds = [e['kind'] for e in EV.values()]
assert kinds == ['goal or red card', 'jump, no suspension', 'check, no change'] or kinds == ['goal or red card', 'check, no change'], kinds
g = EV[1]; c = [e for e in EV.values() if e['kind'] == 'check, no change'][0]
assert g['susp'] == 75 and len(g['pre']) >= 2 and all(t < 0 for t, _ in g['pre']) and g['up'] == 'H' and g['done'], g
assert g['trades']['H']['entry'] == 1.5 and c['susp'] == 45 and abs(c['move']) < 0.08
print('suspensions: goal after', g['susp'], 's suspended; VAR-like check after', c['susp'], 's; kinds', kinds)
# idea 35: with a reaction model in force, a goal gets a planned paper trade (here: fade the big jump)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent)); import test_core as TC0
from sbms import trading as _tr
EV.clear(); st = {'reaction': (_t0 + _dg.timedelta(days=1), _tr.fit_reaction(_tr.samples(TC0._reaction_events(200))))}
for i, bk in enumerate([_bk(2.2, 3.4, 3.6)] * 4 + [E] * 4 + [_bk(1.35, 5.0, 10.0)] * 24):
    _now[0] = _t0 + _dg.timedelta(seconds=15 * i)
    IP2.read_book_fast = lambda markets, bk=bk: bk
    IP2.step(None, st, now=_now[0])
assert EV[1]['kind'] == 'goal or red card' and EV[1]['plan'] and EV[1]['plan']['side'] == 'fade', EV[1]['plan']
print('reaction model plan:', EV[1]['plan'])
# a very long empty book (the market closed, full time) is not an event
EV.clear(); st = {}
for i, bk in enumerate([_bk(2.2, 3.4, 3.6)] * 3 + [E] * 80 + [_bk(1.3, 5.0, 9.0)]):
    _now[0] = _t0 + _dg.timedelta(seconds=15 * i)
    IP2.read_book_fast = lambda markets, bk=bk: bk
    IP2.step(None, st, now=_now[0])
assert not EV, EV
# league_fits: champion + fade variations + the other methods (shots, pyramid) for a National League recipe
import random as _r
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent)); import test_core as TC
hist_ec, today_ec = TC._synthetic_league(drift=0.2, n_teams=12)
_rnd = _r.Random(3)
for m in hist_ec: m['hst'] = m['hg'] + _rnd.randint(1, 5); m['ast'] = m['ag'] + _rnd.randint(0, 4)
other_div = [dict(m, home='X' + m['home'], away='X' + m['away']) for m in hist_ec]      # a second division
run.rs.load_league = lambda lg, today, years=3: (hist_ec, 'synthetic EC')
run.rs.load_pyramid = lambda codes, today, years: hist_ec + other_div
saved = []
db.latest_params = lambda conn, key: None
db.save_params = lambda conn, key, params, source: saved.append(key)
lg_ec = [l for l in run.C.LEAGUES if l['code'] == 'EC'][0]
notes = {}
fits = run.league_fits(None, lg_ec, today_ec, notes, tuning.in_force([])['EC'], {})
assert set(fits) == {'', 'fade_slower', 'fade_faster', 'shots', 'pyramid', 'shrunk', 'prices'}, (set(fits), notes)
assert fits['prices'] is None and all(v for k, v in fits.items() if k != 'prices')   # no closing odds in this data: no prices model
assert fits['shots']['engine'] == 'shots-blend' and fits['pyramid']['engine'] == 'fastdc' and len(fits['pyramid']['attack']) == 24
assert len(fits['pyramid']['league_teams']) == 12 and not any(t.startswith('X') for t in fits['pyramid']['league_teams'])
assert saved == ['EC', 'EC~fade_slower', 'EC~fade_faster', 'EC~shots', 'EC~pyramid', 'EC~shrunk'], saved
assert fits['shrunk'].get('shrink_k') == 8
print('league_fits:', {k: v['engine'] if v else None for k, v in fits.items()})
# idea 8: the stakes step (season simulation) for an English fixture, with stand-in data and database
import datetime as _dt
season = []
_teams = sorted(fits['']['attack'])[:12]; _d = _dt.date(2026, 8, 8)
for rd in range(5):
    for i in range(0, 12, 2):
        season.append(dict(date=_d + _dt.timedelta(days=7 * rd), home=_teams[(i + rd) % 12], away=_teams[(i + 1 + 3 * rd) % 12], hg=1, ag=1))
season = [m for m in season if m['home'] != m['away']]
run.rs.load_league = lambda lg, today, years=3: ([dict(m, date=m['date'] - _dt.timedelta(days=400)) for m in season] + season, 'synthetic')
saved_st = []
db.stakes_age_hours = lambda conn, fid: None
db.save_stakes = lambda conn, fid, data, head: saved_st.append((fid, head, data))
lg_e2 = dict(lg_ec, code='E2')                               # 12 synthetic sides in League One's zones
sc = {}; n2 = {}
pair = next((h, a) for h in _teams for a in _teams if h != a and not any(m['home'] == h and m['away'] == a for m in season))
run._stakes(None, 99, lg_e2, pair[0], pair[1], fits, sc, n2)
assert not n2 and saved_st and saved_st[0][0] == 99 and sc['E2'] is not None, (n2, saved_st)
assert set(saved_st[0][2]) == {'home', 'away', 'names'} and saved_st[0][1][0] in ('home', 'away') and saved_st[0][2]['names'] == list(pair)
print('stakes headline:', saved_st[0][1])
snap = run.settings_snapshot(); assert snap['anchor_model_weight'] == 0.30 and snap['layers']['elo_blend'] == 'testing'
# idea 33: the guardian. With the gap check on, this deliberately distant fake book is blocked and logged
run.C.GUARD_GAP = _gap; calls.clear(); GUARD.clear()
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [])
assert not [c for c in calls if c[0] == 'SUGGEST' and c[1].startswith('dixon_coles')] and any(g[0] == 'model v market gap' and g[1] == 'dixon_coles' for g in GUARD), GUARD
assert any(c[0] == 'add_prediction' for c in calls)          # still predicted and scored, just no bet
# a broken book (home back 1.2 with the others unchanged) blocks every variant
_book = run.sm.book
def bad_book(ids):
    cs, q, v = _book(ids); q = dict(q); q['c1'] = dict(bids=[dict(price=8300, quantity=1)], offers=[dict(price=8400, quantity=1)]); return cs, q, v
run.sm.book = bad_book; run.C.GUARD_GAP = 1.0; calls.clear(); GUARD.clear()
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [])
run.sm.book = _book
assert GUARD and GUARD[0][0] == 'book' and not [c for c in calls if c[0] == 'SUGGEST'], GUARD
print('guardian:', GUARD[0][2])
# idea 27: the committee's weights follow each variant's record; idea 31: disagreement is attached to each suggestion
got = []
db.add_suggestion = lambda conn, fid, model, s, notes=None: got.append((model, s.get('disagreement'))) or 1
calls.clear()
comm = {'E0': {'dixon_coles': (100, 0.98), 'market_consensus': (100, 0.96), 'dixon_coles+elo_blend': (100, 1.02)}}
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [], None, None, None, None, None, comm)
cw = [c for c in calls if c[0] == 'add_prediction' and c[1][1] == 'committee']
assert cw and got and all(d is not None and 0 <= d < 1 for _, d in got), got
print('committee priced; disagreement on suggestions:', sorted({round(d, 3) for _, d in got})[:4])
# ideas 15 and 2 / 20: with both learned models in force, each suggestion records their predictions
from sbms import learn as _ln
_meta = _ln.fit_logistic([[0.05, 0.7, 1, 0, 0, 0, 2, 0.2, 0.5, 0.03], [0.1, 1.0, 0, 1, 0, 0, 3, 0.1, 0.6, 0.01], [0.06, 0.9, 1, 0, 0, 1, 1, 0.3, 0.4, 0.05]], [1, 0, 1])
_close = _ln.fit_ridge([[0.4, 0.2, 0.5, 2, 0.01], [0.3, -0.3, 0.6, 1, -0.02], [0.5, 0.0, 0.4, 3, 0.0]], [0.01, -0.01, 0.0])
got2 = []
db.add_suggestion = lambda conn, fid, model, s, notes=None: got2.append((model, s.get('meta_p'), s.get('pred_move'))) or 1
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [], None, None, None, None, None, None, dict(meta=_meta, close=_close))
assert got2 and all(0 < m < 1 and pm is not None for _, m, pm in got2), got2
print('learned models on suggestions:', got2[0])
# idea 16 (1 Oct): the correct score, with the contract names seen on the live API
_em, _bk0 = run.sm.event_markets, run.sm.book
run.sm.event_markets = lambda eid: _em(eid) + [dict(id='m3', type='CORRECT_SCORE', param=None)]
_scores = [f'{i}-{j}' for i in range(4) for j in range(4)]
def cs_book(ids):
    cs, q, v = _bk0(ids); cs = list(cs); q = dict(q)
    from sbms import pricing as _pr
    fair = _pr.cs_probs(_pr.score_grid(1.4, 1.2, -0.05))
    for k, typ, par in [('CS_' + sc, 'SCORE', sc) for sc in _scores] + [('CS_oh', 'ANY_OTHER_HOME_WIN', None), ('CS_od', 'ANY_OTHER_DRAW', None), ('CS_oa', 'ANY_OTHER_AWAY_WIN', None)]:
        cid = 'cs' + k
        cs.append(dict(id=cid, market_id='m3', contract_type=dict(name=typ, param=par)))
        bp = max(1, int(fair[k] * 10000)); q[cid] = dict(bids=[dict(price=max(1, bp - 30), quantity=1)], offers=[dict(price=bp + 30, quantity=1)])
    return cs, q, dict(v, m3=100)
run.sm.book = cs_book
calls.clear(); got3 = []
db.add_suggestion = lambda conn, fid, model, s, notes=None: got3.append((model, s['key'])) or 1
run.price_event(None, ev, lg, 'exact', {'': params}, {'Arsenal': 1990.0, 'Leeds': 1690.0}, {}, [])
run.sm.event_markets, run.sm.book = _em, _bk0
csp = [c for c in calls if c[0] == 'add_prediction' and c[1][1] == 'dixon_coles:cs']
assert csp, [c[1] for c in calls if c[0] == 'add_prediction']
assert not any(m == 'dixon_coles' and k.startswith('CS_') for m, k in got3)          # the champion's own pick never uses CS
print('correct score priced:', [x for x in got3 if x[0] == 'dixon_coles:cs'][:1] or 'no CS pick (fine)')
# the daily card (16 Oct): 5 forced picks (no long shots, two-sided books, not already a bet) and the 5 rests closest to filling
import datetime as _dc
_mk = lambda i: {f'm{i}': dict(type='WINNER_3_WAY', param=None, contracts={f'c{i}H': 'H', f'c{i}D': 'D', f'c{i}A': 'A'})}
_rows = lambda i, sp=2.0: [dict(key='H', back=2.2, p_work=0.45 + i * 0.005, spread_pts=sp), dict(key='D', back=3.4, p_work=0.28, spread_pts=sp),
                           dict(key='A', back=9.0, p_work=0.14, spread_pts=sp)]
CANDS = [(i, None, _mk(i), _rows(i, 20.0 if i == 2 else 2.0), i == 7, [(100 + i, 'H', 2.2 * (1.02 + 0.01 * i))]) for i in range(9)]
FORCED, RESTED, SAVED = [], [], []
db.card_made = lambda conn, day: bool(SAVED)
db.card_candidates = lambda conn, day, live: CANDS
db.add_forced = lambda conn, fid, model, r, day: FORCED.append((fid, r['key'], round(r['ev'], 3), r['cid'])) or 1
db.card_rests = lambda conn, ids, day: RESTED.extend(ids) or len(ids)
db.save_card = lambda conn, day, b, f, r: SAVED.append((f, r))
_n = _dc.datetime(2026, 10, 17, 7, 30, tzinfo=_dc.timezone.utc)
assert run.make_card(None, _n) is None and not FORCED                     # before 09:00 UK: nothing
got = run.make_card(None, _n.replace(hour=9))
assert got['forced'] == 5 and got['rests'] == 5 and SAVED == [(5, 5)], got
assert all(k == 'H' for _, k, _, _ in FORCED) and 2 not in [f for f, *_ in FORCED] and 7 not in [f for f, *_ in FORCED], FORCED   # no long shot, no wide book, no fixture already a bet
assert [f for f, *_ in FORCED] == [8, 6, 5, 4, 3] and RESTED == [100, 101, 102, 103, 104], (FORCED, RESTED)
assert run.make_card(None, _n.replace(hour=10)) is None                   # once a day
print('daily card:', got)
run.C.GUARD_GAP = _gap
print('smoke ok')
