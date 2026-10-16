import datetime as dt
import math
import random
from sbms import ladder, pricing, names, config as C
from sbms.models import dc, elo
from sbms.leagues import classify


def test_ladder():
    assert ladder.ladder_down(2.79) == 2.78 and ladder.ladder_up(2.79) == 2.80
    assert ladder.ticks_down(3.0, 2) == 2.96 and ladder.ticks_down(2.32, 2) == 2.28
    assert ladder.ladder_down(4.37) == 4.3 and round(ladder.bp_to_odds(4386), 2) == 2.28


def test_grid_sums_and_markets():
    g = pricing.score_grid(1.5, 1.1, -0.08)
    assert abs(sum(map(sum, g)) - 1) < 1e-9
    p = pricing.market_probs(g)
    assert abs(p['H'] + p['D'] + p['A'] - 1) < 1e-9 and abs(p['BTTS_Y'] + p['BTTS_N'] - 1) < 1e-9
    # Dixon-Coles with negative rho puts more mass on 0-0 / 1-1 than plain Poisson
    assert pricing.market_probs(pricing.score_grid(1.2, 1.2, -0.1))['D'] > pricing.market_probs(pricing.score_grid(1.2, 1.2, 0))['D']


def test_contract_view_and_ev():
    v = pricing.contract_view(bids=[(4132, 1), (4000, 1)], offers=[(4167, 1), (4200, 1)])
    assert round(v['back'], 2) == 2.40 and round(v['lay'], 2) == 2.42 and abs(v['spread_pts'] - 0.35) < 1e-9
    assert abs(pricing.ev_back(0.5, 2.1) - (0.5 * 1.1 * 0.98 - 0.5)) < 1e-12


def test_rules_gates():
    """L-1 (Mitch, 29 Sep): value on offer is taken whatever the spread or volume; otherwise rest at the floor price."""
    view = dict(back=2.5, lay=2.54, spread_pts=0.6)
    r = pricing.evaluate_row('H', 0.30, 0.38, view, 1000, 0.15)
    assert r['gate'] == 'threshold'
    # untraded and wide spread no longer block: capped 0.46, working 0.418; at 2.6 EV = 0.418*1.6*0.98 - 0.582 = +7.3%
    r = pricing.evaluate_row('H', 0.60, 0.40, dict(back=2.6, lay=3.1, spread_pts=6.2), 0, 0.15)
    assert r['gate'] is None and r['order_type'] == 'take' and r['price'] == 2.6 and r['ev'] > C.FLOOR_EV
    # EV at 2.5 is +3.6% (below floor) -> a resting order at the lowest ladder price that clears 4%
    r = pricing.evaluate_row('H', 0.60, 0.40, view, 1000, 0.15)
    assert abs(r['p_work'] - 0.418) < 1e-9 and r['order_type'] == 'rest' and r['gate'] is None
    fp = r['price']; assert pricing.ev_back(0.418, fp) >= C.FLOOR_EV and pricing.ev_back(0.418, fp - 0.01) < C.FLOOR_EV
    assert fp == 2.52
    # no back price at all: still rest where we want it
    r = pricing.evaluate_row('H', 0.60, 0.40, dict(back=None, lay=None, spread_pts=None), None, 0.15)
    assert r['order_type'] == 'rest' and r['price'] == 2.52
    # a take beats a rest in the fixture choice, even with a lower EV
    t = dict(gate=None, order_type='take', ev=0.041, price=2.0, back=2.0); q = dict(gate=None, order_type='rest', ev=0.04, price=3.0, back=2.9)
    assert pricing.pick_for_fixture([q, t]) is t
    # the old gates come back with one switch
    C.LIQUIDITY_GATES = True
    try:
        assert pricing.evaluate_row('H', 0.60, 0.40, view, 0, 0.15)['gate'] == 'untraded'
        assert pricing.evaluate_row('H', 0.60, 0.40, dict(back=2.5, lay=2.9, spread_pts=6.1), 1000, 0.15)['gate'] == 'thin'
    finally:
        C.LIQUIDITY_GATES = False


def test_layers_on_foundation():
    """The foundation is Dixon-Coles; layers multiply its lambdas; testing layers are separate variants."""
    from sbms import layers
    k = dt.datetime(2026, 10, 17, 14, 0, tzinfo=dt.timezone.utc)
    ctx = dict(home='Arsenal', away='Wolves', league='E0', kickoff=k, neutral=False,
               elo={'Arsenal': 1950.0, 'Wolves': 1700.0},
               manager_changes=[dict(league='E0', team='Wolves', manager='X', changed_on=dt.date(2026, 10, 1))])
    v = layers.variants(ctx, 1.6, 1.0)
    names_ = [x[0] for x in v]
    assert names_[0] == 'dixon_coles' and v[0][4] is True and (v[0][1], v[0][2]) == (1.6, 1.0)
    assert 'dixon_coles+elo_blend' in names_ and 'dixon_coles+manager_change' in names_
    mc = dict((x[0], x) for x in v)['dixon_coles+manager_change']
    assert abs(mc[2] - 0.95) < 1e-12 and mc[1] == 1.6          # only the side with the new manager, x0.95
    eb = dict((x[0], x) for x in v)['dixon_coles+elo_blend']
    assert eb[1] > 1.6 * 0.9 and eb[2] < 1.0 * 1.1 and eb[1] != 1.6
    # a change older than 42 days does nothing
    ctx['manager_changes'][0]['changed_on'] = dt.date(2026, 8, 1)
    assert dict((x[0], x) for x in layers.variants(ctx, 1.6, 1.0))['dixon_coles+manager_change'][2] == 1.0
    # promoting a layer makes it part of the live stack and keeps the bare foundation as a comparison
    layers.LAYERS['manager_change'] = (layers.manager_change, 'live')
    try:
        v = layers.variants(ctx, 1.6, 1.0)
        assert v[0][0] == 'dixon_coles+manager_change' and 'dixon_coles' in [x[0] for x in v]
        assert 'dixon_coles+manager_change+elo_blend' in [x[0] for x in v] and layers.live_name() == 'dixon_coles+manager_change'
    finally:
        layers.LAYERS['manager_change'] = (layers.manager_change, 'testing')


def test_names():
    teams = ['Man United', 'Man City', 'Wolves', "Nott'm Forest", 'Brighton', 'Tottenham', 'West Ham', 'Newcastle']
    assert names.match('Manchester United', teams)[0] == 'Man United'
    assert names.match('Manchester City', teams)[0] == 'Man City'
    assert names.match('Wolverhampton Wanderers', teams)[0] == 'Wolves'
    assert names.match('Nottingham Forest', teams)[0] == "Nott'm Forest"
    assert names.match('Brighton & Hove Albion', teams)[0] == 'Brighton'
    assert names.match('Tottenham Hotspur', teams)[0] == 'Tottenham'
    assert names.match('Arsenal', teams)[0] is None


def test_classify():
    assert classify('england-premier-league')[0]['code'] == 'E0'
    assert classify('bulgaria-second-division')[0] is None
    assert classify('germany-2-bundesliga')[0]['code'] == 'D2'          # second tiers priced since idea 24 (30 Sep)
    assert classify('france-ligue-2')[0]['code'] == 'F2'
    assert classify('germany-3-liga')[0] is None
    assert classify('us-usl-league-one')[1] == 'inferred'               # matched by country only: recorded, never priced
    assert classify('romania-liga-1')[0]['code'] == 'ROU'
    assert classify('uefa-champions-league')[0] == 'EUROPE'
    assert classify('africa-cup-of-nations-qualification')[0] is None
    assert classify('peru-liga-1')[0]['code'] == 'PER'


def test_dc_local_recovers_strengths():
    random.seed(1)
    teams = [f'T{i}' for i in range(10)]; att = {t: 0.3 - 0.06 * i for i, t in enumerate(teams)}; dfn = {t: -0.25 + 0.05 * i for i, t in enumerate(teams)}
    ms = []; d0 = dt.date(2025, 8, 1)
    def rpois(l):
        k, p, s = 0, math.exp(-l), math.exp(-l); u = random.random()
        while u > s: k += 1; p *= l / k; s += p
        return k
    for rnd in range(6):
        for h in teams:
            for a in teams:
                if h == a: continue
                lh = math.exp(0.25 + att[h] + dfn[a]); la = math.exp(att[a] + dfn[h])
                ms.append(dict(date=d0 + dt.timedelta(days=rnd * 30), home=h, away=a, hg=rpois(lh), ag=rpois(la)))
    p = dc._fit_local(*[__import__('numpy').array([m[k] for m in ms], dtype=float) for k in ('hg', 'ag')], [m['home'] for m in ms], [m['away'] for m in ms],
                      dc.decay_weights([m['date'] for m in ms], d0 + dt.timedelta(days=200)))
    assert abs(p['home_advantage'] - 0.25) < 0.08
    assert p['attack']['T0'] > p['attack']['T9'] and p['defence']['T0'] < p['defence']['T9']


def test_elo_split_never_degenerate():
    lh, la = elo.lambdas(2000, 1400)
    assert la >= 0.2 and lh > la and lh + la >= C.ELO_TOTAL_GOALS - 1e-9 and lh < 6
    lh2, la2 = elo.lambdas(1700, 1700, neutral=True)
    assert abs(lh2 - la2) < 1e-6


def test_paper_only():
    assert C.MODE == 'paper'
    import pathlib
    src = ' '.join(p.read_text() for p in pathlib.Path('sbms').rglob('*.py'))
    for banned in ('place_order', '/orders', '.post(', 'session_token', 'login(', 'Authorization'):
        assert banned not in src, banned


def test_smarkets_next_page_decoded():
    import sys, types
    from sbms.sources import smarkets as sm
    nxt = '?state=upcoming&type_domain=football&start_datetime_min=2026-09-29T15%3A01%3A00Z&sort=start_datetime%2Cid&limit=50&pagination_last_id=45347649&pagination_last_start_datetime=2026-09-29T21%3A00%3A00Z'
    p = sm.next_params(nxt)
    assert p['start_datetime_min'] == '2026-09-29T15:01:00Z' and p['sort'] == 'start_datetime,id' and p['pagination_last_id'] == '45347649'
    import requests
    url = requests.Request('GET', sm.BASE + '/events/', params=p).prepare().url
    assert '%253A' not in url and '%3A' in url


# ---------------------------------------------------------------- self-tuning (tuning.py)
def _synthetic_league(seed=3, n_teams=12, years=3.6, drift=1.2, goal_boost=1.0):
    """Weekly rounds; team strengths drift a lot over time, so results should fade fast."""
    import random, math, datetime as dt
    rnd = random.Random(seed); teams = [f'T{i}' for i in range(n_teams)]
    a0 = {t: rnd.gauss(0, 0.25) for t in teams}; slope = {t: rnd.gauss(0, drift) for t in teams}
    start = dt.date(2023, 3, 1); days = int(365 * years); out = []
    npr = __import__('numpy').random.default_rng(seed)
    for d in range(0, days, 7):
        day = start + dt.timedelta(days=d); f = d / 365
        order = teams[:]; rnd.shuffle(order)
        for i in range(0, n_teams, 2):
            h, a = order[i], order[i + 1]
            sh = a0[h] + slope[h] * f / years; sa = a0[a] + slope[a] * f / years
            lh = math.exp(0.25 + sh - sa * 0.8) * goal_boost; la = math.exp(sa - sh * 0.8) * goal_boost
            out.append(dict(date=day, home=h, away=a, hg=int(npr.poisson(lh)), ag=int(npr.poisson(la)), close_1x2=None))
    return out, start + dt.timedelta(days=days)


def test_tuning_grid_prefers_faster_fade_when_teams_drift():
    from sbms import tuning, config as C
    hist, today = _synthetic_league()
    old = (C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES); C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES = 42, 100
    try:
        results, champ, recs = tuning.grid(hist, today, tuning.DEFAULT_RECIPE)
        adopt, best, ev = tuning.decide_grid(results, champ)
    finally:
        C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES = old
    assert champ == 'goals: xi x1, 3 yrs' and len(results) == 7 and 'goals: xi x1, 3 yrs, shrunk' in results
    assert results['goals: xi x2, 2 yrs']['ll'] < results['goals: xi x0.5, 3 yrs']['ll'], {k: v['ll'] for k, v in results.items()}
    assert ev['n'] == results[champ]['n'] and all(r['n'] == ev['n'] for r in results.values())   # paired on the same matches
    if adopt: assert best != champ and ev['gain'] >= C.TUNE_MARGIN


def test_calibration_corrects_a_consistent_lean_and_only_when_it_helps():
    from sbms import tuning
    import random, math, datetime as dt
    rnd = random.Random(5); npr = __import__('numpy').random.default_rng(5)
    def recs(boost):
        out = []
        for i in range(900):
            lh, la = rnd.uniform(0.9, 2.0), rnd.uniform(0.6, 1.5)
            out.append(dict(key=i, date=dt.date(2025, 1, 1) + dt.timedelta(days=i // 3), lh=lh, la=la, rho=-0.05,
                            hg=int(npr.poisson(lh * boost)), ag=int(npr.poisson(la * boost))))
        return out
    ok, val, ev = tuning.review_calibration(recs(1.15))        # the model expects 15% too few goals
    assert ok and val['home'] > 1.03 and val['away'] > 1.03 and val['home'] <= 1.10, (val, ev)
    ok2, val2, ev2 = tuning.review_calibration(recs(1.0))      # no lean: adopted only if it helps unseen matches, and then tiny
    assert (not ok2 and val2 == {'off': True}) or (abs(val2['home'] - 1) < 0.03 and abs(val2['away'] - 1) < 0.03), (val2, ev2)
    ok3, _, ev3 = tuning.review_calibration(recs(1.15)[:100])  # too few matches: no decision
    assert not ok3 and 'need' in ev3['reason']


def test_anchor_is_earned_and_given_back():
    from sbms import tuning, config as C
    good = [(0.55, 0.50)] * 200; bad = [(0.45, 0.50)] * 200
    # 16 Oct: the weight that blends model and market best, straight away, and down to zero where the model adds nothing
    new, ev = tuning.decide_anchor(0.30, bad)
    assert new == 0.0 and ev['best'] == 0.0 and 'nothing' in ev['reason'], ev
    new, ev = tuning.decide_anchor(0.30, good)
    assert new is not None and new > 0.30 and ev['ll_best'] <= ev['ll_in_force'], ev
    assert tuning.decide_anchor(0.30, good[:150])[0] is None    # not enough fixtures
    assert tuning.decide_anchor(0.0, bad)[0] is None            # already at the best weight
    assert tuning.decide_anchor(0.30, bad[:120], min_n=100)[0] == 0.0   # the back-test's own minimum


def test_live_challenger_needs_enough_fixtures_and_margin():
    from sbms import tuning
    r = dict((x[0], x) for x in tuning.decide_live({'fade_slower': [(0.40, 0.46)] * 120, 'fade_faster': [(0.40, 0.46)] * 50,
                                                    'uncalibrated': [(0.40, 0.401)] * 150}))
    assert r['fade_slower'][4] and not r['fade_faster'][4] and not r['uncalibrated'][4]


def test_in_force_newest_adopted_wins_and_defaults():
    from sbms import tuning, config as C
    import datetime as dt
    t0 = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
    rows = [dict(league='E0', kind='recipe', decided_at=t0 + dt.timedelta(days=9), adopted=False, value=dict(xi=0.009, fit_years=2)),
            dict(league='E0', kind='recipe', decided_at=t0 + dt.timedelta(days=5), adopted=True, value=dict(xi=0.0036, fit_years=2)),
            dict(league='E0', kind='recipe', decided_at=t0, adopted=True, value=dict(xi=0.0009, fit_years=3)),
            dict(league='E0', kind='calibration', decided_at=t0, adopted=True, value=dict(off=True))]
    t = tuning.in_force(rows)
    assert t['E0']['recipe'] == dict(xi=0.0036, fit_years=2, method='goals', shrink=0) and t['E0']['calibration'] is None
    assert t['SP1']['recipe'] == tuning.recipe_key(tuning.DEFAULT_RECIPE) and t['SP1']['anchor'] == C.ANCHOR_DEFAULT
    names = [c[0] for c in tuning.challengers(t['E0']['recipe'], dict(home=1.02, away=1.0))]
    assert names == ['fade_slower', 'fade_faster', 'shrunk', 'uncalibrated']
    names = [c[0] for c in tuning.challengers(t['E0']['recipe'], None, ('goals', 'shots', 'pyramid'))]
    assert names == ['fade_slower', 'fade_faster', 'shots', 'pyramid', 'shrunk']
    lg = [l for l in C.LEAGUES if l['code'] == 'EC'][0]
    assert tuning.methods_for(lg) == ('goals', 'shots', 'pyramid', 'prices') and tuning.pyramid_of('EC')[0] == 'england'
    assert 'xg' in tuning.methods_for([l for l in C.LEAGUES if l['code'] == 'E0'][0])


def test_anchor_weight_changes_the_working_probability():
    from sbms import pricing
    view = dict(back=2.2, lay=2.24, spread_pts=1.0)
    a = pricing.evaluate_row('H', 0.55, 0.48, view, 100, 0.15)
    b = pricing.evaluate_row('H', 0.55, 0.48, view, 100, 0.15, anchor=0.45)
    assert abs(a['p_work'] - (0.3 * 0.55 + 0.7 * 0.48)) < 1e-9 and b['p_work'] > a['p_work']


def test_fastdc_matches_reference_fit():
    import numpy as np
    from sbms.models import dc, fastdc
    hist, today = _synthetic_league(drift=0.2, n_teams=16)
    a = dc._fit_local(np.array([m['hg'] for m in hist], float), np.array([m['ag'] for m in hist], float),
                      [m['home'] for m in hist], [m['away'] for m in hist], dc.decay_weights([m['date'] for m in hist], today))
    b = fastdc.fit(hist, today, 0.0018)
    worst = max(abs(math.log(dc.lambdas(a, h, x)[i]) - math.log(dc.lambdas(b, h, x)[i]))
                for h in a['attack'] for x in a['attack'] if h != x for i in (0, 1))
    assert worst < 0.01 and abs(a['rho'] - b['rho']) < 0.01, worst


def test_shots_blend_is_the_log_blend_of_the_two_fits():
    import random
    from sbms.models import dc, fastdc, shots
    hist, today = _synthetic_league(drift=0.2, n_teams=12)
    rnd = random.Random(1)
    for m in hist: m['hst'] = m['hg'] + rnd.randint(1, 5); m['ast'] = m['ag'] + rnd.randint(0, 4)
    g = fastdc.fit(hist, today, 0.0018); b = shots.fit(hist, today, 0.0018, g, w=0.5)
    s = fastdc.fit(hist, today, 0.0018, hg_key='hst', ag_key='ast', fit_rho=False)
    ch, ca = b['conversion']['home'], b['conversion']['away']
    for h, a in (('T1', 'T2'), ('T5', 'T0')):
        gh, ga = dc.lambdas(g, h, a); sh, sa = dc.lambdas(s, h, a); bh, ba = dc.lambdas(b, h, a)
        assert abs(bh / math.sqrt(gh * sh * ch) - 1) < 1e-3 and abs(ba / math.sqrt(ga * sa * ca) - 1) < 1e-3
    for m in hist[: len(hist) // 2]: m['hst'] = None
    assert shots.fit(hist, today, 0.0018, g) is None                     # too little shots data: no model


def test_pyramid_carries_a_promoted_teams_strength():
    """A strong team relegated from division 1 keeps its rating in division 2 in a pyramid fit, where a division-2-only
    fit knows it from a few games."""
    import random, datetime as dt
    from sbms.models import fastdc, dc
    rnd = random.Random(7); npr = __import__('numpy').random.default_rng(7)
    d1 = [f'A{i}' for i in range(10)]; d2 = [f'B{i}' for i in range(10)]
    strength = {t: 0.4 + rnd.gauss(0, 0.15) for t in d1}; strength.update({t: -0.1 + rnd.gauss(0, 0.15) for t in d2})
    strength['A0'] = 0.9                                                 # the best side in the country
    start = dt.date(2023, 8, 1); ms = []
    for wk in range(120):
        day = start + dt.timedelta(days=7 * wk)
        for div, teams in (('D1', d1), ('D2', d2)):
            if wk >= 100:                                                # A0 relegated for the last 20 weeks
                teams = [t for t in teams if t != 'A0'] + (['A0'] if div == 'D2' else []) + (['B9'] if div == 'D1' else [])
                teams = [t for t in teams if not (div == 'D2' and t == 'B9')]
            o = teams[:]; rnd.shuffle(o)
            for i in range(0, len(o) - 1, 2):
                h, a = o[i], o[i + 1]
                lh = math.exp(0.25 + strength[h] - strength[a]); la = math.exp(strength[a] - strength[h])
                ms.append(dict(date=day, home=h, away=a, hg=int(npr.poisson(lh)), ag=int(npr.poisson(la)), div=div))
    today = start + dt.timedelta(days=7 * 120)
    pyr = fastdc.fit(ms, today, 0.0018)
    only2 = fastdc.fit([m for m in ms if m['div'] == 'D2' and m['date'] >= start + dt.timedelta(days=7 * 100)], today, 0.0018)
    truth = math.exp(0.25 + strength['A0'] - strength['B1'])
    p_err = abs(dc.lambdas(pyr, 'A0', 'B1')[0] - truth); o_err = abs(dc.lambdas(only2, 'A0', 'B1')[0] - truth)
    assert p_err < o_err, (p_err, o_err)


def test_grid_compares_methods_on_the_same_matches():
    import random
    from sbms import tuning, config as C
    hist, today = _synthetic_league(drift=0.3, n_teams=12)
    rnd = random.Random(2)
    for m in hist: m['hst'] = m['hg'] + rnd.randint(1, 5); m['ast'] = m['ag'] + rnd.randint(0, 4)
    old = (C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES); C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES = 56, 100
    try:
        results, champ, recs = tuning.grid(hist, today, tuning.DEFAULT_RECIPE, methods=('goals', 'shots', 'pyramid'),
                                           pyramid_hist=hist)
    finally:
        C.TUNE_STEP_DAYS, C.TUNE_MIN_MATCHES = old
    assert 'shots: xi x1, 3 yrs' in results and 'pyramid: xi x1, 3 yrs' in results
    assert len({r['n'] for r in results.values()}) == 1 and results[champ]['n'] > 50


def test_shrink_pulls_thin_data_teams_to_average():
    import datetime as dt
    from sbms import tuning
    from sbms.models import fastdc
    hist, today = _synthetic_league(drift=0.1, n_teams=12)
    new = [dict(date=today - dt.timedelta(days=7 * i + 1), home='NEW' if i % 2 else 'T1', away='T1' if i % 2 else 'NEW',
                hg=4 if i % 2 else 0, ag=0 if i % 2 else 4) for i in range(4)]         # a newcomer with 4 thumping wins
    p = fastdc.fit(hist + new, today, 0.0018)
    q = tuning.shrink(p, hist + new, today, 0.0018, 8)
    mean_a = sum(p['attack'].values()) / len(p['attack'])
    assert abs(q['attack']['NEW'] - mean_a) < 0.6 * abs(p['attack']['NEW'] - mean_a)    # pulled most of the way in
    assert abs(q['attack']['T5'] - p['attack']['T5']) < 0.05                             # an established side barely moves
    assert tuning.recipe_key(dict(xi=0.0018, fit_years=3))['shrink'] == 0


def test_draw_specialist_finds_a_draw_excess():
    """Results with 25% more draws than the grid says: the calibration's draw correction finds it and it is adopted
    because it improves matches it was not fitted on; with no excess it stays near 1."""
    from sbms import tuning, pricing
    import random, datetime as dt
    def recs(boost, seed):
        rnd = random.Random(seed); out = []
        for i in range(1200):
            lh, la = rnd.uniform(0.9, 1.8), rnd.uniform(0.7, 1.4)
            g = pricing.score_grid(lh, la, -0.05, max_goals=8, draw=boost)
            cells = [(a, b, g[a][b]) for a in range(9) for b in range(9)]
            x = rnd.random(); acc = 0.0
            for a, b, pr in cells:
                acc += pr
                if acc >= x: break
            out.append(dict(key=i, date=dt.date(2025, 1, 1) + dt.timedelta(days=i // 4), lh=lh, la=la, rho=-0.05, hg=a, ag=b))
        return out
    ok, val, ev = tuning.review_calibration(recs(1.25, 11))
    assert ok and val['draw'] > 1.08, (val, ev)
    cal = tuning.fit_calibration(recs(1.0, 12))
    assert abs(cal['draw'] - 1) < 0.07, cal
    g = pricing.market_probs(pricing.score_grid(1.3, 1.1, -0.05, draw=1.2)); g0 = pricing.market_probs(pricing.score_grid(1.3, 1.1, -0.05))
    assert g['D'] > g0['D'] and abs(g['H'] + g['D'] + g['A'] - 1) < 1e-9


def test_trust_by_season_phase():
    import datetime as dt
    from sbms import tuning
    days = [dt.date(2024, 8, 10) + dt.timedelta(days=d) for d in range(0, 280, 3)] + [dt.date(2025, 8, 9) + dt.timedelta(days=d) for d in range(0, 280, 3)]
    starts = tuning.season_starts(days)
    assert starts == [dt.date(2024, 8, 10), dt.date(2025, 8, 9)]
    assert tuning.phase_of(dt.date(2025, 8, 20), starts) == 'early' and tuning.phase_of(dt.date(2025, 10, 10), starts) == 'mid' \
        and tuning.phase_of(dt.date(2026, 1, 10), starts) == 'late'
    recs = []
    for d in days:
        ph = tuning.phase_of(d, starts)
        for _ in range(6): recs.append((d, 1.00 + (0.03 if ph == 'early' else 0.0), 0.99))   # early season 0.03 worse
    f, ev = tuning.decide_trust(recs, starts)
    assert f['mid'] == 1.0 and f['late'] == 1.0 and f['early'] == tuning.C.TRUST_FLOOR, (f, ev)   # 0.03 worse: the floor
    f2, ev2 = tuning.decide_trust(recs[:100], starts)
    assert all(v == 1.0 for v in f2.values())                                                     # too few matches: no change


def test_understat_parse_and_attach():
    import datetime as dt, json
    from sbms.sources import understat
    data = [dict(id='1', isResult=True, h=dict(title='Manchester United'), a=dict(title='Wolverhampton Wanderers'),
                 goals=dict(h='1', a='0'), xG=dict(h='1.8', a='0.4'), datetime='2025-08-16 19:00:00'),
            dict(id='2', isResult=False, h=dict(title='Arsenal'), a=dict(title='Chelsea'), goals=dict(h=None, a=None),
                 xG=dict(h=None, a=None), datetime='2026-10-20 15:00:00')]
    enc = json.dumps(data).replace('"', '\\x22')          # Understat hex-escapes the quotes inside JSON.parse('...')
    html = "<script>var datesData = JSON.parse('" + enc + "');</script>"
    xs = understat.parse(html)
    assert xs == [dict(date=dt.date(2025, 8, 16), home='Manchester United', away='Wolverhampton Wanderers', hxg=1.8, axg=0.4)]
    try:
        understat.parse('<html>nothing</html>'); assert False
    except ValueError as e:
        assert 'format changed' in str(e)
    ms = [dict(date=dt.date(2025, 8, 16), home='Man United', away='Wolves', hg=1, ag=0)]
    understat.season_matches = lambda code, y: xs if y == 2025 else []
    miss = understat.attach(ms, 'E0', dt.date(2025, 9, 1), 1)
    assert ms[0]['hxg'] == 1.8 and ms[0]['axg'] == 0.4 and miss == []
    assert understat.attach(ms, 'N1', dt.date(2025, 9, 1), 1) == []       # not an Understat league: nothing


def test_extra_markets_from_the_grid():
    from sbms import pricing
    g = pricing.score_grid(1.5, 1.0, -0.05)
    x = pricing.extra_markets(g); p = pricing.market_probs(g)
    assert abs(sum(v for k, v in x.items() if k.startswith('CS_')) - 1) < 1e-9
    assert abs(x['AH_H_-0.5']['win'] - p['H']) < 1e-9 and x['AH_H_-0.5']['push'] == 0      # -0.5 is the plain home win
    assert abs(x['AH_H_+0']['win'] - p['H']) < 1e-9 and abs(x['AH_H_+0']['push'] - p['D']) < 1e-9   # level ball = draw no bet
    assert abs(pricing.ah_ev(x['AH_H_+0'], 1 / p['DNB_H'], comm=0.0)) < 1e-9                 # fair DNB price has zero EV
    q = x['AH_H_-0.25']                                                                       # quarter line = half on 0, half on -0.5
    assert abs(pricing.ah_ev(q, 2.0, 0.0) - 0.5 * (pricing.ah_ev(x['AH_H_+0'], 2.0, 0.0) + pricing.ah_ev(x['AH_H_-0.5'], 2.0, 0.0))) < 1e-9


def test_integrity_flags_a_sharp_move_only():
    import datetime as dt
    from sbms import integrity
    now = dt.datetime(2026, 10, 3, 13, 0, tzinfo=dt.timezone.utc); ko = now + dt.timedelta(hours=2)
    before = {'H': dict(mid_novig=0.45), 'D': dict(mid_novig=0.28), 'A': dict(mid_novig=0.27)}
    after = {'H': dict(mid_novig=0.55, back_depth3=900), 'D': dict(mid_novig=0.25), 'A': dict(mid_novig=0.20)}
    f = integrity.check((now - dt.timedelta(minutes=60), before), after, now, ko)
    assert f['key'] == 'H' and abs(f['move'] - 0.10) < 1e-9 and f['minutes'] == 60 and f['hours_to_kickoff'] == 2.0
    small = {'H': dict(mid_novig=0.49), 'D': dict(mid_novig=0.27), 'A': dict(mid_novig=0.24)}
    assert integrity.check((now - dt.timedelta(minutes=60), before), small, now, ko) is None      # 4 points: normal
    assert integrity.check((now - dt.timedelta(hours=5), before), after, now, ko) is None          # too slow to count
    assert integrity.check(None, after, now, ko) is None


def test_ratings_from_prices_recover_the_markets_view():
    """Closing prices made from the true goal expectations: ratings fitted to them recover those expectations far more
    closely than ratings fitted to the (noisy) scores."""
    from sbms import pricing
    from sbms.models import prices, fastdc, dc
    hist, today = _synthetic_league(drift=0.0, n_teams=12)
    import numpy as np
    truth = {}
    fit_true = fastdc.fit(hist, today, 0.0018)                     # stand-in "true" strengths: a fit on lots of data
    for m in hist:
        lh, la = dc.lambdas(fit_true, m['home'], m['away']); truth[(m['home'], m['away'])] = (lh, la)
        p = pricing.market_probs(pricing.score_grid(lh, la, -0.05))
        m['close_1x2'] = tuple(1 / (p[k] * 1.03) for k in 'HDA'); m['close_ou25'] = (1 / (p['O2.5'] * 1.03), 1 / (p['U2.5'] * 1.03))
    recent = [m for m in hist if (today - m['date']).days < 120]   # little data: 4 months
    fp = prices.fit(recent, today, 0.0018); fg = fastdc.fit(recent, today, 0.0018)
    err = lambda f: np.mean([abs(math.log(dc.lambdas(f, h, a)[0]) - math.log(t[0])) for (h, a), t in truth.items() if h in f['attack'] and a in f['attack']])
    assert err(fp) < 0.5 * err(fg), (err(fp), err(fg))
    assert prices.usable(recent) and not prices.usable([dict(m, close_ou25=None) for m in recent])


def test_season_simulation_and_stakes():
    import time, datetime as dt, random
    from sbms import stakes
    from sbms.models import fastdc
    rnd = random.Random(4); npr = __import__('numpy').random.default_rng(4)
    teams = [f'T{i}' for i in range(20)]; st = {t: 0.6 - 0.06 * i for i, t in enumerate(teams)}
    played = []
    day = dt.date(2025, 8, 16)
    for rd in range(10):                                                  # ten rounds played
        o = teams[:]; rnd.shuffle(o)
        for i in range(0, 20, 2):
            h, a = o[i], o[i + 1]
            played.append(dict(date=day, home=h, away=a, hg=int(npr.poisson(math.exp(0.25 + st[h] - st[a]))), ag=int(npr.poisson(math.exp(st[a] - st[h])))))
        day += dt.timedelta(days=7)
    params = dict(attack={t: st[t] / 2 for t in teams}, defence={t: -st[t] / 2 for t in teams}, home_advantage=0.25, rho=0.0)
    t0 = time.time(); sim = stakes.simulate('E0', played, params, sims=4000); took = time.time() - t0
    assert sim and took < 20, took
    title = [(sim['pos'][:, sim['ix'][t]] == 1).mean() for t in teams]
    assert abs(sum(title) - 1) < 1e-9 and sum(title[:6]) > 0.95                  # the title goes to one of the strong sides
    assert (sim['pos'][:, sim['ix']['T19']] >= 18).mean() > 0.5                  # the weakest side mostly goes down
    pair = next(p for p in sim['rem'])                                   # any remaining fixture
    h, a = sim['teams'][pair[0]], sim['teams'][pair[1]]
    s = stakes.for_match(sim, h, a)
    for team in (h, a):
        for zone, v in s[team].items():
            assert all(0 <= x <= 1 for x in (v['now'], v['if_win'], v['if_lose']))
            if zone in ('title', 'top_four'): assert v['if_win'] >= v['if_lose'] - 0.02
            if zone == 'relegation': assert v['if_win'] <= v['if_lose'] + 0.02
    assert stakes.simulate('SP1', played, params) is None                 # zones not configured: nothing guessed
    assert stakes.for_match(sim, 'T0', 'Nobody') is None


def test_pinnacle_prices_from_the_odds_api():
    import datetime as dt
    from sbms.sources import oddsapi
    ev = dict(id='e', commence_time='2026-10-04T14:00:00Z', home_team='Brighton and Hove Albion', away_team='Wolverhampton Wanderers',
              bookmakers=[dict(key='bet365', markets=[]),
                          dict(key='pinnacle', markets=[dict(key='h2h', outcomes=[dict(name='Brighton and Hove Albion', price=1.95),
                                                                                  dict(name='Wolverhampton Wanderers', price=4.2), dict(name='Draw', price=3.7)]),
                                                        dict(key='totals', outcomes=[dict(name='Over', price=1.9, point=2.5), dict(name='Under', price=2.0, point=2.5)])])])
    p = oddsapi.pinnacle_probs(ev)
    assert abs(p['H'] + p['D'] + p['A'] - 1) < 1e-12 and p['H'] > p['A'] and abs(p['O2.5'] + p['U2.5'] - 1) < 1e-12
    ko = dt.datetime(2026, 10, 4, 14, 0, tzinfo=dt.timezone.utc)
    assert oddsapi.find([ev], 'Brighton', 'Wolves', ko) is ev
    assert oddsapi.find([ev], 'Brighton', 'Wolves', ko + dt.timedelta(hours=5)) is None      # a different match day
    assert oddsapi.pinnacle_probs(dict(ev, bookmakers=[])) is None


def test_weather_summary_buckets_and_venues():
    import datetime as dt
    from sbms.sources import weather, venues
    ko = dt.datetime(2026, 10, 3, 14, 0, tzinfo=dt.timezone.utc)
    series = {'2026-10-03T14:00': (0.6, 22.0, 11.0), '2026-10-03T15:00': (0.7, 26.0, 10.0), '2026-10-03T16:00': (0.1, 30.0, 10.0)}
    w = weather.summarise(series, ko)
    assert w == dict(rain=1.4, wind=26.0, temp=10.3) and weather.bucket(w) == 'wet'
    assert weather.bucket(dict(rain=0.2, wind=35.0, temp=8)) == 'windy' and weather.bucket(dict(rain=0, wind=10, temp=8)) == 'fair'
    assert weather.summarise({}, ko) is None
    assert venues.parse_point('Point(-0.1086 51.5549)') == (51.5549, -0.1086)
    wd = [dict(club='Arsenal F.C.', venue='Emirates Stadium', lat=51.555, lon=-0.108), dict(club='Sheffield Wednesday F.C.', venue='Hillsborough', lat=53.41, lon=-1.50)]
    got, miss = venues.match_teams(['Arsenal', 'Sheffield Weds', 'Nowhere Town'], wd)
    assert got['Arsenal']['venue'] == 'Emirates Stadium' and got['Sheffield Weds']['venue'] == 'Hillsborough' and miss == ['Nowhere Town']


def test_group_factors_learn_a_weather_effect_only_when_real():
    import random, datetime as dt
    from sbms import tuning
    npr = __import__('numpy').random.default_rng(9); rnd = random.Random(9)
    def recs(wet_effect):
        out = []
        for i in range(1500):
            lh, la = rnd.uniform(1.0, 1.9), rnd.uniform(0.8, 1.4); wx = rnd.choice(['wet', 'fair', 'fair', 'windy'])
            f = wet_effect if wx == 'wet' else 1.0
            out.append(dict(key=i, date=dt.date(2024, 8, 1) + dt.timedelta(days=i // 3), lh=lh, la=la, rho=-0.05, wx=wx,
                            hg=int(npr.poisson(lh * f)), ag=int(npr.poisson(la * f))))
        return out
    ok, val, ev = tuning.review_group_factors(recs(0.85), 'wx', 100)
    assert ok and val['factors']['wet'] < 0.94 and abs(val['factors']['fair'] - 1) < 0.05, (val, ev)
    ok2, val2, ev2 = tuning.review_group_factors(recs(1.0), 'wx', 100)
    assert (not ok2 and val2 == {'off': True}) or all(abs(v - 1) < 0.05 for v in val2['factors'].values()), (val2, ev2)
    t = tuning.in_force([dict(league='EC', kind='weather', decided_at=None, adopted=True, value=dict(factors=dict(wet=0.93, fair=1.0)))])['EC']
    assert t['weather'] == {'wet': 0.93, 'fair': 1.0}


def test_kickoff_time_uk_to_utc():
    import datetime as dt
    from sbms.jobs import backtest
    assert backtest._kickoff_utc(dict(date=dt.date(2025, 8, 16), time='15:00')).hour == 14      # British Summer Time
    assert backtest._kickoff_utc(dict(date=dt.date(2025, 12, 13), time=None)).hour == 15        # GMT, default 15:00


def test_referees_names_matching_and_factors():
    import datetime as dt
    from sbms.sources import apifootball as af
    assert af.norm_ref('Michael Oliver, England') == af.norm_ref('M. Oliver') == af.norm_ref('M Oliver') == 'm oliver'
    raw = dict(fixture=dict(id=7, referee='Anthony Taylor, England', date='2025-08-16T14:00:00+00:00', status=dict(short='FT', elapsed=90)),
               league=dict(id=39, name='Premier League'), teams=dict(home=dict(name='Manchester United'), away=dict(name='Wolves')), goals=dict(home=1, away=0))
    x = af.simple(raw)
    assert x['referee'] == 'a taylor' and x['hg'] == 1 and x['date'].hour == 14
    ms = [dict(date=dt.date(2025, 8, 16), home='Man United', away='Wolves', hg=1, ag=0)]
    assert af.attach_referees(ms, [x]) == 1 and ms[0]['referee'] == 'a taylor'
    assert af.find([x], 'Man United', 'Wolves', dt.datetime(2025, 8, 16, 14, 0, tzinfo=dt.timezone.utc)) is x
    # a referee with far more goals than expected earns a factor above 1, pulled in by the small sample
    from sbms import tuning
    recs = [dict(referee='x y', hg=3, ag=2, lh=1.4, la=1.1)] * 20 + [dict(referee='a b', hg=1, ag=1, lh=1.4, la=1.1)] * 200
    f, n = tuning.fit_group_factors(recs, 'referee', 40)
    assert 1.0 < f['x y'] <= 1.10 and n['x y'] == 20


def test_inplay_probabilities():
    from sbms import inplay, pricing
    p0 = inplay.probs(1.5, 1.1, 0, 0, 0); pre = pricing.market_probs(pricing.score_grid(1.5, 1.1, 0.0))
    assert all(abs(p0[k] - pre[k]) < 1e-6 for k in ('H', 'D', 'A', 'O2.5', 'BTTS_Y'))       # at kick-off: the pre-match model
    late = inplay.probs(1.5, 1.1, 89, 1, 0)
    assert late['H'] > 0.9 and late['O2.5'] < 0.1 and abs(late['H'] + late['D'] + late['A'] - 1) < 1e-9
    assert inplay.probs(1.5, 1.1, 60, 2, 2)['O2.5'] > 0.999999 and inplay.probs(1.5, 1.1, 60, 1, 1)['BTTS_Y'] > 0.999999
    assert inplay.remaining_share(0) == 1.0 and inplay.remaining_share(200) == 0.0
    ht = inplay.remaining_share(47)
    assert 0.5 < ht < 0.6                                   # after half-time more than half the goal-time remains
    assert inplay.safe_to_bet(30, [0.01, -0.02]) and not inplay.safe_to_bet(300, [0.0]) and not inplay.safe_to_bet(30, [0.12])


def test_news_layer_and_adjustment_validation():
    import sys, types
    from sbms import layers
    ctx = dict(news=[dict(side='home', attack=0.9, defence=1.1, reason='striker out, centre-back injured')])
    lh, la, note = layers.news(ctx, 1.5, 1.0)
    assert abs(lh - 1.35) < 1e-12 and abs(la - 1.1) < 1e-12 and 'striker out' in note
    assert layers.news(dict(news=[]), 1.5, 1.0) == (1.5, 1.0, 'no news')
    if 'psycopg' not in sys.modules:   # web.py imports psycopg; validation happens before any database call
        fake = types.ModuleType('psycopg'); fake.Error = Exception; rows = types.ModuleType('psycopg.rows'); rows.dict_row = None
        sys.modules['psycopg'] = fake; sys.modules['psycopg.rows'] = rows
    from sbms import web
    q = lambda **k: {a: [str(b)] for a, b in k.items()}
    assert web.add_adjustment(q(fixture='x', side='home', reason='r'))[0] == 400
    assert web.add_adjustment(q(fixture=1, side='middle', reason='r'))[0] == 400
    assert web.add_adjustment(q(fixture=1, side='home'))[0] == 400                          # a reason is required
    assert web.add_adjustment(q(fixture=1, side='home', reason='r', attack=1.5))[0] == 400  # outside 0.85-1.15


def test_goal_reaction_trading_maths():
    from sbms import trading
    assert trading.green(3.0, 2.5, 50, 0.02) == 9.8               # lay 60 at 2.5: +10 whichever way it goes, less 2%
    back, lay, stake = 3.0, 2.5, 50; lay_stake = stake * back / lay
    assert abs((stake * (back - 1) - lay_stake * (lay - 1)) - (-stake + lay_stake)) < 1e-9   # the same both ways
    assert trading.green(2.0, 2.5, 50, 0.02) == -10.0              # the price drifted: a locked loss (no commission)
    assert trading.hold(3.0, True, 50, 0.02) == 98.0 and trading.hold(3.0, False, 50, 0.02) == -50
    prev = {'H': dict(mid_novig=0.45), 'D': dict(mid_novig=0.28), 'A': dict(mid_novig=0.27)}
    goal = {'H': dict(mid_novig=0.66), 'D': dict(mid_novig=0.21), 'A': dict(mid_novig=0.13)}
    j = trading.jump(prev, goal)
    assert j['key'] == 'H' and j['up_key'] == 'H' and abs(j['move'] - 0.21) < 1e-9
    assert trading.jump(prev, {'H': dict(mid_novig=0.47), 'D': dict(mid_novig=0.27), 'A': dict(mid_novig=0.26)}) is None
    b = lambda h, d, a: {'H': dict(back=h, lay=round(h * 1.02, 2)), 'D': dict(back=d, lay=round(d * 1.02, 2)), 'A': dict(back=a, lay=round(a * 1.02, 2))}
    path = [(0, b(1.40, 4.6, 7.5)), (60, b(1.45, 4.5, 7.0)), (120, b(1.50, 4.4, 7.0)), (180, b(1.52, 4.3, 7.2)), (300, b(1.55, 4.2, 7.4))]
    t = trading.trades(path, 'H')
    assert t['H']['side'] == 'follow' and t['D']['side'] == 'fade' and set(t['H']['green']) == {60, 120, 180, 300}
    assert t['H']['green'][300] < 0 and t['D']['green'][300] > 0   # the home price drifted back: following lost, fading the draw paid


def test_suspension_book_open_and_classify():
    from sbms import trading
    assert not trading.book_open({}) and not trading.book_open({'H': {}, 'D': dict(back=None, lay=None)})
    assert trading.book_open({'H': dict(back=2.0)}) and trading.book_open({'A': dict(lay=3.1)})
    assert trading.classify(0.2, True) == 'goal or red card' and trading.classify(-0.1, True) == 'goal or red card'
    assert trading.classify(0.01, True) == 'check, no change' and trading.classify(0.3, False) == 'jump, no suspension'
    prev = {'H': dict(mid_novig=0.45), 'D': dict(mid_novig=0.28), 'A': dict(mid_novig=0.27)}
    same = {'H': dict(mid_novig=0.451), 'D': dict(mid_novig=0.279), 'A': dict(mid_novig=0.27)}
    assert trading.jump(prev, same) is None and trading.jump(prev, same, min_move=0.0)['up_key'] == 'H'


def test_committee_weights_and_pool():
    from sbms import committee
    w = committee.weights({}, ['a', 'b', 'c'])
    assert all(abs(v - 1 / 3) < 1e-12 for v in w.values())                       # no history: an equal vote
    w = committee.weights({'a': (100, 0.97), 'b': (100, 0.98), 'c': (5, 0.50)}, ['a', 'b', 'c'], eta=1.0, min_n=30)
    assert abs(w['b'] / w['a'] - math.exp(-1.0)) < 1e-9                         # 0.01 worse over 100 matches: e^-1 of the weight
    assert abs(w['c'] - w['b']) < 1e-12 and abs(sum(w.values()) - 1) < 1e-12     # too little history: the smallest proven weight
    p = committee.pool({'a': dict(H=0.5, D=0.3, A=0.2, **{'O2.5': 0.6}), 'b': dict(H=0.4, D=0.3, A=0.3)}, dict(a=0.75, b=0.25))
    assert abs(p['H'] - 0.475) < 1e-12 and abs(p['H'] + p['D'] + p['A'] - 1) < 1e-12 and abs(p['O2.5'] - 0.6) < 1e-12
    assert committee.disagreement({'a': dict(H=0.5), 'b': dict(H=0.42), 'c': dict(H=0.47)}, 'H') == 0.08
    assert committee.disagreement({'a': dict(H=0.5)}, 'H') is None


def test_guardian_checks():
    from sbms import guardian
    ok = {'H': dict(back=2.0, lay=2.04, mid=0.495, mid_novig=0.49), 'D': dict(back=3.5, lay=3.6, mid=0.282, mid_novig=0.28), 'A': dict(back=4.2, lay=4.3, mid=0.235, mid_novig=0.23)}
    assert guardian.book_problem(ok) is None
    assert 'imply' in guardian.book_problem(dict(ok, H=dict(back=1.2, lay=1.21, mid=0.83)))
    # a thin but sane book (1 Oct, League Two two days out): wide spreads, mids still add up -> not blocked
    thin = {'H': dict(back=1.9, lay=3.2, mid=0.42), 'D': dict(back=2.6, lay=4.6, mid=0.30), 'A': dict(back=2.4, lay=4.8, mid=0.31)}
    assert guardian.book_problem(thin) is None
    assert guardian.book_problem(dict(ok, H=dict(back=1.2, lay=None, mid=0.83))) is None     # one-sided: not judged on mids
    assert 'crossed' in guardian.book_problem(dict(ok, D=dict(back=3.5, lay=3.4)))
    assert guardian.prediction_problem(1.4, 1.1, dict(H=0.45, D=0.27, A=0.28)) is None
    assert guardian.prediction_problem(7.0, 1.1, dict(H=0.9, D=0.05, A=0.05)) and guardian.prediction_problem(1.4, 1.1, dict(H=0.5, D=0.5, A=0.5))
    assert guardian.prediction_problem(None, None, dict(H=float('nan'), D=0.3, A=0.3))
    assert guardian.gap_problem(dict(H=0.52, D=0.26, A=0.22), ok) is None and guardian.gap_problem(dict(H=0.80, D=0.12, A=0.08), ok)
    assert guardian.stale_problem('2026-08-01', dt.date(2026, 9, 30)) and guardian.stale_problem('2026-09-27', dt.date(2026, 9, 30)) is None


def _reaction_events(n, seed=1):
    """Synthetic goal events where fading a big jump pays and following it loses (plus noise)."""
    rnd = random.Random(seed); out = []
    for i in range(n):
        mv = rnd.uniform(0.08, 0.30); tr = {}
        for k in ('H', 'D', 'A'):
            fol = k == 'H'; base = (-12 if fol else 8) * (mv - 0.05)
            tr[k] = dict(side='follow' if fol else 'fade', entry=rnd.uniform(1.5, 8.0), entry_depth=rnd.uniform(0, 500),
                         green={str(s): round(base * s / 180 + rnd.gauss(0, 0.4), 2) for s in C.EXIT_SECONDS})
        out.append(dict(at=i, minute=rnd.uniform(5, 88), move=mv, up_key='H', kind='goal or red card', trades=tr,
                        pre=[[-90, {'H': dict(mid_novig=0.4)}], [-15, {'H': dict(mid_novig=0.4 + rnd.uniform(-0.02, 0.03))}]]))
    return out


def test_reaction_model_learns_and_scores_out_of_sample():
    from sbms import trading
    evs = _reaction_events(200)
    model = trading.fit_reaction(trading.samples(evs))
    assert set(model) == set(C.EXIT_SECONDS)
    big = dict(move=0.28, up_key='H', minute=60, kind='goal or red card')
    rows = {'H': dict(back=1.6, back_depth3=100), 'D': dict(back=4.0, back_depth3=100), 'A': dict(back=7.0, back_depth3=100)}
    p = trading.plan(model, big, rows, edge=0.5)
    assert p and p['side'] == 'fade' and p['exit'] == 300, p          # fade a big jump, and hold the lay-back longest
    assert trading.plan(model, dict(big, move=0.06), rows, edge=0.5) is None   # a small move: nothing clears the edge
    wf = trading.walk_forward(evs, start=60, edge=0.5)
    assert wf['planned'] > 50 and wf['mean'] > wf['all_mean'] and wf['hit'] > 0.8, wf
    assert trading.walk_forward(evs[:40], start=60)['planned'] == 0


def test_api_football_by_id_checks_the_name_and_budget():
    from sbms.sources import results as rs, apifootball as af
    calls = []
    def fake(path, key, kind='other', **p):
        calls.append((path, kind, p))
        if path == '/leagues':
            return [dict(league=dict(id=p['id'], name='National League - North'), country=dict(name='England'), seasons=[dict(year=y) for y in (2023, 2024, 2025, 2026)])]
        return [dict(fixture=dict(date=f"{p['season']}-10-04T14:00:00+00:00"), goals=dict(home=2, away=1), teams=dict(home=dict(name='A'), away=dict(name='B')))]
    old = af._get; af._get = fake
    try:
        rows, src = rs.api_football_id((50, 'National League - North', 'England'), dt.date(2024, 1, 1), key='k')
        assert len(rows) == 3 and rows[0]['hg'] == 2 and 'National League - North' in src
        assert all(k == 'results' for _, k, _ in calls) and [p['season'] for pth, _, p in calls if pth == '/fixtures'] == [2024, 2025, 2026]
        rows, src = rs.api_football_id((50, 'Serie B', 'Brazil'), dt.date(2024, 1, 1), key='k')
        assert rows == [] and 'not used' in src
        assert rs.api_football_id((50, 'x', 'y'), dt.date(2024, 1, 1), key='')[0] == []
    finally:
        af._get = old
    seen = []
    af.set_budget(lambda k: seen.append(k) or False)
    try:
        try: af.live('k'); assert False
        except RuntimeError as e: assert 'budget' in str(e) and seen == ['live']
    finally:
        af.set_budget(None)


def test_mistakes_model_and_closing_price_model():
    from sbms import learn
    rnd = random.Random(5); rows = []
    for i in range(600):                      # bets on goals markets with a small edge beat the close less often
        key = rnd.choice(['H', 'D', 'A', 'O2.5', 'U2.5']); ev = rnd.uniform(0.04, 0.15)
        pb = 0.3 + (0.25 if key in ('H', 'D', 'A') else 0) + 2 * (ev - 0.04)
        beat = rnd.random() < pb; clv = rnd.uniform(0, 0.05) if beat else -rnd.uniform(0, 0.05)
        rows.append(dict(x=learn.meta_x(ev, rnd.uniform(1.5, 5), key, 'full', rnd.uniform(1, 40), 2, 1000, 0.03), beat=int(beat), clv=clv))
    got = learn.meta_fit(rows)
    t = got['test']
    assert got['n'] == 600 and t['logloss'] < t['logloss_base_rate'], t          # beats simply using the base rate
    assert learn.meta_fit(rows[:100]) is None
    m = got['model']
    assert learn.predict_logistic(m, learn.meta_x(0.12, 2.5, 'H', 'full', 10, 2, 1000, 0.03)) > learn.predict_logistic(m, learn.meta_x(0.045, 2.5, 'O2.5', 'full', 10, 2, 1000, 0.03))
    # closing price: money waiting on the back side (imbalance) pushes the price up (a synthetic market)
    crow = []
    for f in range(300):
        for key in ('H', 'D', 'A'):
            for h in (24, 6, 1):
                p = rnd.uniform(0.15, 0.6); bd = rnd.uniform(0, 1000); ld = rnd.uniform(0, 1000)
                imb = (bd - ld) / (bd + ld); move = 0.03 * imb + rnd.gauss(0, 0.01)
                crow.append(dict(fid=f, x=learn.close_x(p, bd, ld, 5000, h, p + 0.02), move=move))
    cg = learn.close_fit(crow)
    assert cg['fixtures'] == 300 and cg['test']['r2'] > 0.5 and cg['test']['mae'] < cg['test']['mae_no_move'], cg['test']
    assert learn.predict_ridge(cg['model'], learn.close_x(0.4, 900, 50, 5000, 6, 0.42)) > 0.015
    assert learn.close_fit(crow[:90]) is None
    assert learn.market_of('DNB_H') == 'dnb' and learn.market_of('BTTS_Y') == 'btts' and learn.market_of('U2.5') == 'goals'


def test_correct_score_market():
    from sbms import pricing
    from sbms.sources import smarkets as sm
    g = pricing.score_grid(1.6, 1.0, -0.06); p = pricing.cs_probs(g)
    assert len(p) == 19 and abs(sum(p.values()) - 1) < 1e-9
    m = pricing.market_probs(g)
    home = sum(v for k, v in p.items() if k == 'CS_oh' or (k[3:4].isdigit() and int(k[3]) > int(k[5])))
    assert abs(home - m['H']) < 1e-9                               # the scores add back up to the result market
    assert sm.contract_key('CORRECT_SCORE', None, 'SCORE', '3-1') == 'CS_3-1' and sm.contract_key('CORRECT_SCORE', None, 'ANY_OTHER_AWAY_WIN') == 'CS_oa'
    assert pricing.threshold_for('CS_0-0') == C.THRESH_CS


def test_api_football_routes_direct_and_rapidapi():
    from sbms.sources import apifootball as af
    old = C.API_FOOTBALL_VIA
    try:
        C.API_FOOTBALL_VIA = 'direct'; base, h = af._route('k')
        assert base == 'https://v3.football.api-sports.io' and h == {'x-apisports-key': 'k'}
        C.API_FOOTBALL_VIA = 'rapidapi'; base, h = af._route('k')
        assert base.endswith('rapidapi.com/v3') and h['x-rapidapi-key'] == 'k' and h['x-rapidapi-host'] == af.RAPID_HOST
    finally:
        C.API_FOOTBALL_VIA = old
