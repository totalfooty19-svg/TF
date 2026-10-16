"""Smarkets competition slug -> league config."""
from . import config as C


def classify(slug):
    """-> (league_dict | 'EUROPE' | None, how)"""
    if not slug: return None, 'no slug'
    for lg in C.LEAGUES:
        if slug in lg['slugs']: return lg, 'exact'
    if any(w in slug for w in C.EUROPE_SLUG_WORDS) and not any(w in slug for w in C.EUROPE_EXCLUDE):
        return 'EUROPE', 'europe'
    for lg in C.LEAGUES:
        if lg['country'] == 'england': continue          # England: exact slugs only (five divisions share a prefix)
        if slug.startswith(lg['country'] + '-') and not any(w in slug[len(lg['country']):] for w in C.EXCLUDE_WORDS):
            return lg, 'inferred'
    return None, 'not covered'
