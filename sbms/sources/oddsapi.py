"""Idea 7 (30 Sep 2026): follow the sharp bookmaker. Pinnacle is where professional money moves prices first; when its
price has moved and Smarkets has not caught up, Smarkets is the one that is wrong. Prices come from The Odds API
(the-odds-api.com, v4). Switched on by setting ODDS_API_KEY; without it nothing here runs.

Budget: the free plan has 500 credits a month and each request costs one credit per market per region. So a league is
fetched only when it has a fixture in the next ODDS_API_WINDOW_H hours, at most once every ODDS_API_EVERY_H hours,
and only the markets in ODDS_API_MARKETS ('h2h' = the result market; add ',totals' on a paid plan). The response is
cached in model_params ('ODDS:<sport>') so the hourly job does not spend credits twice."""
import datetime as dt
import requests
from .. import config as C
from .. import names

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT
BASE = 'https://api.the-odds-api.com/v4'
# Our league code -> The Odds API sport key. Keys are checked against /v4/sports (free) before use; unknown ones are skipped.
SPORTS = {'E0': 'soccer_epl', 'E1': 'soccer_efl_champ', 'E2': 'soccer_england_league1', 'E3': 'soccer_england_league2',
          'SC0': 'soccer_spl', 'D1': 'soccer_germany_bundesliga', 'I1': 'soccer_italy_serie_a', 'SP1': 'soccer_spain_la_liga',
          'F1': 'soccer_france_ligue_one', 'N1': 'soccer_netherlands_eredivisie', 'B1': 'soccer_belgium_first_div',
          'P1': 'soccer_portugal_primeira_liga', 'T1': 'soccer_turkey_super_league', 'G1': 'soccer_greece_super_league'}


def available(key):
    r = S.get(f'{BASE}/sports', params=dict(apiKey=key), timeout=30); r.raise_for_status()
    return {x['key'] for x in r.json()}


def fetch(sport, key, markets):
    r = S.get(f'{BASE}/sports/{sport}/odds', params=dict(apiKey=key, regions='eu', markets=markets, bookmakers='pinnacle',
                                                         oddsFormat='decimal', dateFormat='iso'), timeout=30)
    r.raise_for_status()
    return dict(events=r.json(), remaining=r.headers.get('x-requests-remaining'))


def pinnacle_probs(event):
    """-> no-vig probabilities {H, D, A, DNB_H, DNB_A[, O2.5, U2.5]} from Pinnacle's prices on one Odds API event."""
    bk = next((b for b in event.get('bookmakers', []) if b.get('key') == 'pinnacle'), None)
    if not bk: return None
    out = {}
    for mk in bk.get('markets', []):
        oc = mk.get('outcomes', [])
        if mk.get('key') == 'h2h':
            price = {o['name']: float(o['price']) for o in oc}
            h, a, d = price.get(event['home_team']), price.get(event['away_team']), price.get('Draw')
            if h and a and d:
                inv = {'H': 1 / h, 'D': 1 / d, 'A': 1 / a}; s = sum(inv.values())
                out.update({k: v / s for k, v in inv.items()})
                out['DNB_H'] = out['H'] / (out['H'] + out['A']); out['DNB_A'] = out['A'] / (out['H'] + out['A'])
        elif mk.get('key') == 'totals':
            o = next((x for x in oc if x.get('name') == 'Over' and float(x.get('point', 0)) == 2.5), None)
            u = next((x for x in oc if x.get('name') == 'Under' and float(x.get('point', 0)) == 2.5), None)
            if o and u:
                io, iu = 1 / float(o['price']), 1 / float(u['price'])
                out['O2.5'], out['U2.5'] = io / (io + iu), iu / (io + iu)
    return out or None


def find(events, home, away, kickoff):
    """The Odds API event for a Smarkets fixture: kick-off within 3 hours and both names matching."""
    for ev in events or []:
        t = dt.datetime.fromisoformat(ev['commence_time'].replace('Z', '+00:00'))
        if abs((t - kickoff).total_seconds()) > 3 * 3600: continue
        h, _ = names.match(ev['home_team'], [home]); a, _ = names.match(ev['away_team'], [away])
        if h and a: return ev
    return None
