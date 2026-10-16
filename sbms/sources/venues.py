"""Stadium locations for idea 10 (weather): each club's home ground and its coordinates from Wikidata (free, no key).
Wikidata: clubs that are an association football club (Q476028) in the country, with a home venue (P115) that has
coordinates (P625). Matched to our team names inside each league with names.match; unmatched teams are returned so
the job can log them, and a wrong or missing ground can be fixed by a row in the `venues` table (source 'manual')."""
import requests
from .. import config as C
from .. import names

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT + ' (sports model; weather at football grounds)'
ENDPOINT = 'https://query.wikidata.org/sparql'
# country -> Wikidata items for the country (English and Scottish clubs are recorded as UK or as England / Scotland)
COUNTRY_QIDS = {'england': ['Q145', 'Q21'], 'scotland': ['Q145', 'Q22'], 'germany': ['Q183'], 'italy': ['Q38'], 'spain': ['Q29'],
                'france': ['Q142'], 'netherlands': ['Q55'], 'belgium': ['Q31'], 'portugal': ['Q45'], 'turkey': ['Q43'], 'greece': ['Q41']}

QUERY = """SELECT ?club ?clubLabel ?venueLabel ?coord WHERE {
  VALUES ?country { %s }
  ?club wdt:P31 wd:Q476028; wdt:P17 ?country; wdt:P115 ?venue.
  ?venue wdt:P625 ?coord.
  FILTER NOT EXISTS { ?club wdt:P576 ?dissolved }          # clubs that no longer exist (e.g. Wimbledon F.C.)
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}"""


def parse_point(s):
    """'Point(-0.1086 51.5549)' -> (lat, lon)"""
    lon, lat = s.replace('Point(', '').replace(')', '').split()
    return float(lat), float(lon)


def clubs(country):
    """-> [dict(club, venue, lat, lon)] from Wikidata for a country (one request)."""
    qids = COUNTRY_QIDS.get(country)
    if not qids: return []
    r = S.get(ENDPOINT, params=dict(query=QUERY % ' '.join('wd:' + q for q in qids), format='json'), timeout=90)
    r.raise_for_status()
    out = []
    for b in r.json()['results']['bindings']:
        try:
            lat, lon = parse_point(b['coord']['value'])
        except Exception:
            continue
        out.append(dict(club=b['clubLabel']['value'], venue=b.get('venueLabel', {}).get('value'), lat=lat, lon=lon))
    return out


def match_teams(teams, wd):
    """teams: our names in one league. wd: clubs(). -> ({team: dict(venue, lat, lon, club)}, [unmatched])"""
    by_name = {}
    for c in wd: by_name.setdefault(c['club'], c)
    got, miss = {}, []
    for t in teams:
        m, _ = names.match(t, list(by_name))
        if m: got[t] = dict(by_name[m], matched=m)
        else: miss.append(t)
    return got, miss
