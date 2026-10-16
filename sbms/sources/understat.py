"""Expected goals (xG) from understat.com for the five leagues it covers that we price (England, Spain, Germany, Italy,
France). Read-only. The league page embeds its matches as JSON (`var datesData = JSON.parse('...')`); if Understat
changes that format this raises a clear error, the job records it, and the 'xg' method is simply not used.

Understat team names are matched to football-data.co.uk names inside the league with names.match; unmatched names
are returned so the job can log them."""
import datetime as dt
import json
import re
import requests
from .. import config as C
from .. import names

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT
LEAGUES = {'E0': 'EPL', 'SP1': 'La_liga', 'D1': 'Bundesliga', 'I1': 'Serie_A', 'F1': 'Ligue_1'}
_RX = re.compile(r"datesData\s*=\s*JSON\.parse\('(.*?)'\)", re.S)


def parse(html):
    """-> [dict(date, home, away, hxg, axg)] for finished matches. Raises ValueError if the page format is unknown."""
    m = _RX.search(html)
    if not m: raise ValueError('Understat page format changed: datesData not found')
    raw = m.group(1).encode('utf-8').decode('unicode_escape')
    out = []
    for x in json.loads(raw):
        if not x.get('isResult'): continue
        xg = x.get('xG') or {}
        if xg.get('h') in (None, '') or xg.get('a') in (None, ''): continue
        out.append(dict(date=dt.datetime.strptime(x['datetime'][:10], '%Y-%m-%d').date(), home=x['h']['title'], away=x['a']['title'],
                        hxg=float(xg['h']), axg=float(xg['a'])))
    return out


def season_matches(code, start_year):
    r = S.get(f"https://understat.com/league/{LEAGUES[code]}/{start_year}", timeout=60)
    r.raise_for_status()
    return parse(r.text)


def attach(matches, code, today, years):
    """Add hxg / axg to football-data matches of league `code` (same date, teams matched by name). Returns the names
    Understat used that could not be matched. Does nothing for leagues Understat does not cover."""
    if code not in LEAGUES or not matches: return []
    y = today.year if today.month >= 7 else today.year - 1
    xs = []
    for k in range(years + 1):
        xs += season_matches(code, y - k)
    fd_teams = sorted({m['home'] for m in matches} | {m['away'] for m in matches})
    tmap, misses = {}, set()
    for t in {x['home'] for x in xs} | {x['away'] for x in xs}:
        got, _ = names.match(t, fd_teams)
        if got: tmap[t] = got
        else: misses.add(t)
    idx = {(x['date'], tmap.get(x['home']), tmap.get(x['away'])): x for x in xs}
    for m in matches:
        x = idx.get((m['date'], m['home'], m['away']))
        if x is None:   # kick-off dates can differ by a day between sources (time zones)
            for d in (-1, 1):
                x = idx.get((m['date'] + dt.timedelta(days=d), m['home'], m['away']))
                if x: break
        if x: m['hxg'], m['axg'] = x['hxg'], x['axg']
    return sorted(misses)
