"""API-Football (api-sports.io, v3) for referees (idea 22) and in-play scores (idea 11). Needs API_FOOTBALL_KEY; the free
plan allows 100 requests a day, so every call here is cached and budgeted by the caller.

Response shape used (v3): response[] -> fixture{id, referee, date, status{short, elapsed}}, league{id, name, season},
teams{home{name}, away{name}}, goals{home, away}."""
import datetime as dt
import re
import unicodedata
import requests
from .. import config as C
from .. import names

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT
BASE = 'https://v3.football.api-sports.io'
# The same API is sold through RapidAPI (1 Oct: api-football.com's own dashboard was misbehaving for Mitch). A RapidAPI
# key needs RapidAPI's host and headers: set API_FOOTBALL_VIA=rapidapi beside the key.
RAPID_HOST = 'api-football-v1.p.rapidapi.com'


def _route(key):
    if C.API_FOOTBALL_VIA == 'rapidapi':
        return f'https://{RAPID_HOST}/v3', {'x-rapidapi-key': key, 'x-rapidapi-host': RAPID_HOST}
    return BASE, {'x-apisports-key': key}
# our league code -> API-Football league id (checked against the league name returned; a mismatch is logged, not used)
LEAGUE_IDS = {'E0': (39, 'Premier League'), 'E1': (40, 'Championship'), 'E2': (41, 'League One'), 'E3': (42, 'League Two'),
              'EC': (43, 'National League'), 'SC0': (179, 'Premiership'), 'D1': (78, 'Bundesliga'), 'I1': (135, 'Serie A'),
              'SP1': (140, 'La Liga'), 'F1': (61, 'Ligue 1'), 'N1': (88, 'Eredivisie'), 'B1': (144, 'Jupiler Pro League'),
              'P1': (94, 'Primeira Liga'), 'T1': (203, 'Süper Lig'), 'G1': (197, 'Super League 1')}


_BUDGET = None      # set by each job: fn(kind) -> True if one more request may be made today (counted in the database,
                    # shared by the pricing job and the in-play worker; see db.af_allow)


def set_budget(fn):
    global _BUDGET
    _BUDGET = fn


def _get(path, key, kind='other', **params):
    if _BUDGET is not None and not _BUDGET(kind): raise RuntimeError(f'API-Football daily budget reached ({kind})')
    base, headers = _route(key)
    r = S.get(base + path, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    j = r.json()
    if j.get('errors'): raise RuntimeError(f"API-Football: {j['errors']}")
    return j.get('response', [])


def fixtures_on(day, key):
    """Every fixture on a day, all competitions (one request)."""
    return _get('/fixtures', key, 'referees', date=day.isoformat(), timezone='UTC')


def league_season(league_id, season, key):
    return _get('/fixtures', key, 'results', league=league_id, season=season)


def live(key):
    """Every fixture in play right now (one request)."""
    return _get('/fixtures', key, 'live', live='all')


def norm_ref(name):
    """'Michael Oliver, England' / 'M. Oliver' / 'M Oliver' -> 'm oliver'."""
    if not name: return None
    s = unicodedata.normalize('NFKD', str(name).split(',')[0]).encode('ascii', 'ignore').decode().lower()
    parts = [p for p in re.split(r'[\s\.]+', s) if p]
    if not parts: return None
    return parts[0][0] + ' ' + parts[-1] if len(parts) > 1 else parts[0]


def simple(fx):
    """-> dict(id, date (UTC datetime), home, away, referee, hg, ag, status, elapsed, league_id)"""
    f, t, g = fx.get('fixture', {}), fx.get('teams', {}), fx.get('goals', {})
    return dict(id=f.get('id'), date=dt.datetime.fromisoformat(f['date'].replace('Z', '+00:00')) if f.get('date') else None,
                home=(t.get('home') or {}).get('name'), away=(t.get('away') or {}).get('name'), referee=norm_ref(f.get('referee')),
                hg=g.get('home'), ag=g.get('away'), status=(f.get('status') or {}).get('short'),
                elapsed=(f.get('status') or {}).get('elapsed'), league_id=(fx.get('league') or {}).get('id'))


def lineups(fixture_id, key):
    """Ideas 4 / 21: the two starting line-ups (published about an hour before kick-off; empty until then).
    -> [dict(team, team_id, formation, players[ids], names[...])]"""
    out = []
    for t in _get('/fixtures/lineups', key, 'lineups', fixture=fixture_id):
        xi = [p.get('player') or {} for p in (t.get('startXI') or [])]
        if len(xi) < 11: continue
        out.append(dict(team=(t.get('team') or {}).get('name'), team_id=(t.get('team') or {}).get('id'), formation=t.get('formation'),
                        players=[p.get('id') for p in xi], names=[p.get('name') for p in xi]))
    return out if len(out) == 2 else []


def find(fixtures, home, away, kickoff, hours=3):
    """The API-Football fixture for one of ours: kick-off within `hours` and both names matching."""
    for x in fixtures:
        if not x.get('date') or abs((x['date'] - kickoff).total_seconds()) > hours * 3600: continue
        if names.match(x['home'] or '', [home])[0] and names.match(x['away'] or '', [away])[0]: return x
    return None


def attach_referees(matches, fixtures):
    """Set m['referee'] on football-data matches from API-Football fixtures (same date, names matching)."""
    by_date = {}
    for x in fixtures:
        if x.get('date') and x.get('referee'): by_date.setdefault(x['date'].date(), []).append(x)
    n = 0
    for m in matches:
        if m.get('referee'): m['referee'] = norm_ref(m['referee']); continue
        for d in (m['date'], m['date'] - dt.timedelta(days=1), m['date'] + dt.timedelta(days=1)):
            x = next((x for x in by_date.get(d, []) if names.match(x['home'] or '', [m['home']])[0] and names.match(x['away'] or '', [m['away']])[0]), None)
            if x: m['referee'] = x['referee']; n += 1; break
    return n
