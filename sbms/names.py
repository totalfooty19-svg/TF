"""Team-name matching between Smarkets, football-data.co.uk, API-Football and ClubElo. Match only inside a known set of
names (a league's teams), exact-normalised first, then the alias table, then a fuzzy match that must be clearly best."""
import difflib
import re
import unicodedata

STOP = {'fc', 'afc', 'cf', 'sc', 'ac', 'as', 'fk', 'nk', 'sk', 'if', 'bk', 'ik', 'cd', 'ud', 'sd', 'rc', 'rcd', 'sv', 'vfl', 'vfb',
        'tsg', 'fsv', 'club', 'calcio', 'football', 'futbol', 'de', 'the'}
REPL = [(r'\ba f c\b', 'afc'), (r'\bf c\b', 'fc'), (r'\bc f\b', 'cf'), (r'\butd\b', 'united'), (r'\bman\b', 'manchester'), (r'\bst\b', 'saint'), (r'\bspurs\b', 'tottenham'), (r'&', ' and '),
        (r'\bwolves\b', 'wolverhampton'), (r'\bnottm\b', 'nottingham'), (r'\bsheff\b', 'sheffield'), (r'\bweds\b', 'wednesday'), (r'\bqpr\b', 'queens park rangers'),
        (r'\bpsg\b', 'paris saint germain'), (r'\bpsv\b', 'psv eindhoven')]
# Hand aliases (normalised forms). Add here when the competitions_seen / name_misses tables show a miss.
ALIASES = {
    'wolverhampton': 'wolverhampton wanderers', 'brighton': 'brighton and hove albion', 'west ham': 'west ham united',
    'newcastle': 'newcastle united', 'tottenham': 'tottenham hotspur', 'leeds': 'leeds united', 'sheffield united': 'sheffield united',
    'inter': 'internazionale', 'inter milan': 'internazionale', 'bayern munich': 'bayern munchen', 'bayern': 'bayern munchen',
    # seen on the live run of 1 Oct 2026 (name_misses)
    'mk dons': 'milton keynes dons', 'airdrieonians': 'airdrie united', 'sporting kc': 'sporting kansas city',
    'gimnasia y esgrima la plata': 'gimnasia l p',
}


def norm(s: str) -> str:
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode().lower()
    s = re.sub(r'[\.\'’\-/]', ' ', s)
    for a, b in REPL:
        s = re.sub(a, b, s)
    toks = [t for t in re.split(r'\s+', s) if t and t not in STOP and not re.fullmatch(r'\d{4}', t)]
    return ' '.join(toks)


def match(name: str, candidates, cutoff=0.78):
    """Return (candidate, method) or (None, reason)."""
    n = norm(name); table = {norm(c): c for c in candidates}
    if n in table: return table[n], 'exact'
    a = ALIASES.get(n)
    if a and a in table: return table[a], 'alias'
    # containment: 'wolverhampton wanderers' v 'wolves' style, only when unique
    cont = [c for k, c in table.items() if (n in k or k in n) and min(len(n), len(k)) >= 4]
    if len(cont) == 1: return cont[0], 'contains'
    scored = sorted(((difflib.SequenceMatcher(None, n, k).ratio(), c) for k, c in table.items()), reverse=True)
    if scored and scored[0][0] >= cutoff and (len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.08):
        return scored[0][1], f'fuzzy {scored[0][0]:.2f}'
    return None, f'no match (best {scored[0][1]} {scored[0][0]:.2f})' if scored else 'no candidates'
