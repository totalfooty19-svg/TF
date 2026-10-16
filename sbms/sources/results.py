"""Historical results for fitting: football-data.co.uk (season files and multi-season 'new' files) and, for leagues it does
not cover, API-Football (needs API_FOOTBALL_KEY; free tier ~100 requests/day — the job caches a league for REFIT_HOURS)."""
import datetime as dt
import io
import requests
import pandas as pd
from .. import config as C

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT


def season_codes(today, n=C.DC_SEASONS):
    """football-data season folder codes, newest first: Aug-Jun seasons -> '2627', '2526', ..."""
    y = today.year if today.month >= 7 else today.year - 1
    return [f"{str(y - k)[-2:]}{str(y - k + 1)[-2:]}" for k in range(n)]


def _parse_date(s):
    for f in ('%d/%m/%Y', '%d/%m/%y'):
        try: return dt.datetime.strptime(s, f).date()
        except Exception: pass
    return None


def _int(v):
    try:
        return None if pd.isna(v) else int(v)
    except Exception:
        return None


def _rows(df, hcol, acol, hg, ag, odds_cols, div=None):
    out = []
    shots = 'HST' in df.columns and 'AST' in df.columns       # shots on target, where football-data records them
    for _, r in df.iterrows():
        d = _parse_date(str(r.get('Date')))
        if d is None or pd.isna(r.get(hg)) or pd.isna(r.get(ag)): continue
        close = None
        for trio in odds_cols:
            if all(c in df.columns and not pd.isna(r.get(c)) for c in trio):
                close = tuple(float(r[c]) for c in trio); break
        row = dict(date=d, home=str(r[hcol]).strip(), away=str(r[acol]).strip(), hg=int(r[hg]), ag=int(r[ag]), close_1x2=close)
        if isinstance(r.get('Time'), str) and ':' in r['Time']: row['time'] = r['Time'].strip()[:5]   # UK time (idea 10)
        for pair in CLOSE_OU25:                     # closing over/under 2.5 odds (idea 6: ratings from prices)
            if all(c in df.columns and not pd.isna(r.get(c)) for c in pair):
                row['close_ou25'] = tuple(float(r[c]) for c in pair); break
        if shots:
            row['hst'], row['ast'] = _int(r.get('HST')), _int(r.get('AST'))
        if 'Referee' in df.columns and isinstance(r.get('Referee'), str):
            row['referee'] = r['Referee'].strip()
        if div: row['div'] = div
        out.append(row)
    return out


CLOSE_MAIN = [('PSCH', 'PSCD', 'PSCA'), ('AvgCH', 'AvgCD', 'AvgCA'), ('B365CH', 'B365CD', 'B365CA'), ('PSH', 'PSD', 'PSA'), ('AvgH', 'AvgD', 'AvgA')]
CLOSE_OU25 = [('PC>2.5', 'PC<2.5'), ('AvgC>2.5', 'AvgC<2.5'), ('B365C>2.5', 'B365C<2.5'), ('P>2.5', 'P<2.5'), ('Avg>2.5', 'Avg<2.5')]
CLOSE_EXTRA = [('PSCH', 'PSCD', 'PSCA'), ('AvgCH', 'AvgCD', 'AvgCA'), ('PH', 'PD', 'PA'), ('AvgH', 'AvgD', 'AvgA')]


def footballdata_season(code, season):
    r = S.get(f'https://www.football-data.co.uk/mmz4281/{season}/{code}.csv', timeout=60)
    if r.status_code == 404: return []
    r.raise_for_status()
    df = pd.read_csv(io.StringIO(r.content.decode('latin-1')), on_bad_lines='skip')
    return _rows(df, 'HomeTeam', 'AwayTeam', 'FTHG', 'FTAG', CLOSE_MAIN, div=code)


def footballdata_extra(code, since):
    r = S.get(f'https://www.football-data.co.uk/new/{code}.csv', timeout=60)
    r.raise_for_status()
    df = pd.read_csv(io.StringIO(r.content.decode('latin-1')), on_bad_lines='skip')
    rows = _rows(df, 'Home', 'Away', 'HG', 'AG', CLOSE_EXTRA)
    return [x for x in rows if x['date'] >= since]


def _af_rows(league_id, seasons, since, key):
    from . import apifootball as af
    rows = []
    for yr in seasons:
        for f in af._get('/fixtures', key, 'results', league=league_id, season=yr, status='FT-AET-PEN'):
            d = dt.date.fromisoformat(f['fixture']['date'][:10])
            g = f['goals']
            if d < since or g['home'] is None: continue
            rows.append(dict(date=d, home=f['teams']['home']['name'], away=f['teams']['away']['name'], hg=int(g['home']), ag=int(g['away']),
                             close_1x2=None, time=f['fixture']['date'][11:16]))
    return rows


def _af_seasons(entry, since):
    """The seasons that overlap the fit window (at most three; each is one request)."""
    yrs = sorted(s['year'] for s in entry.get('seasons', []))
    return [y for y in yrs if y >= since.year - 1][-3:]


def api_football(country, since, key=C.API_FOOTBALL_KEY):
    """Top division of a country: the first league API-Football lists for it (the chosen league is named in the source
    line, so a wrong choice is visible on the Health tab)."""
    if not key: return [], 'no API_FOOTBALL_KEY'
    from . import apifootball as af
    leagues = af._get('/leagues', key, 'results', country=country, type='league', current='true')
    if not leagues: return [], f'no league found for {country}'
    league = leagues[0]['league']
    return _af_rows(league['id'], _af_seasons(leagues[0], since), since, key), f"API-Football league {league['id']} {league['name']}"


def api_football_id(spec, since, key=C.API_FOOTBALL_KEY):
    """spec = (league id, expected name, expected country). The league API-Football returns for the id must carry that
    name and country, otherwise nothing is loaded (ids written from memory are checked, never trusted)."""
    if not key: return [], 'no API_FOOTBALL_KEY'
    from . import apifootball as af
    lid, name, country = spec
    got = af._get('/leagues', key, 'results', id=lid)
    if not got: return [], f'API-Football league {lid} not found'
    lg, ct = got[0]['league'], (got[0].get('country') or {}).get('name', '')
    if name.lower() not in lg['name'].lower() or country.lower() != ct.lower():
        return [], f"API-Football league {lid} is '{lg['name']}' ({ct}), expected '{name}' ({country}): not used"
    return _af_rows(lid, _af_seasons(got[0], since), since, key), f"API-Football league {lid} {lg['name']}"


def load_league(lg, today, years=C.DC_SEASONS):
    """Results of the last `years` years (the widest fit window any recipe uses; each fit then takes its own window)."""
    src, code = lg['source']; since = today - dt.timedelta(days=365 * years)
    if src == 'fd':
        rows = [x for s in season_codes(today, years + 1) for x in footballdata_season(code, s) if x['date'] >= since]
        return rows, f'football-data {code}'
    if src == 'fdx':
        return footballdata_extra(code, since), f'football-data new/{code}'
    if src == 'af':
        return api_football(code, since)
    if src == 'afid':
        return api_football_id(code, since)
    return [], 'unknown source'


def load_pyramid(codes, today, years):
    """Every division of a country's pyramid (football-data codes, top first) for the last `years` years, each row
    tagged with its division."""
    since = today - dt.timedelta(days=365 * years)
    return [x for code in codes for s in season_codes(today, years + 1) for x in footballdata_season(code, s) if x['date'] >= since]


def clubelo(day):
    r = S.get(f'http://api.clubelo.com/{day.isoformat()}', timeout=60)
    r.raise_for_status()
    df = pd.read_csv(io.StringIO(r.text))
    return {str(row['Club']): float(row['Elo']) for _, row in df.iterrows()}
