"""Smarkets public API v3 (read-only; no account, no login, no bet placement anywhere in this repo).
Fair usage: one events page per call, markets/contracts/quotes/volumes batched per event, a pause between calls."""
import re
import time
from urllib.parse import parse_qsl
import requests
from .. import config as C

BASE = 'https://api.smarkets.com/v3'
S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT
PAUSE = 0.35
KEY = {('WINNER_3_WAY', 'HOME'): 'H', ('WINNER_3_WAY', 'DRAW'): 'D', ('WINNER_3_WAY', 'AWAY'): 'A',
       ('WINNER_DNB', 'HOME'): 'DNB_H', ('WINNER_DNB', 'AWAY'): 'DNB_A', ('BTTS', 'YES'): 'BTTS_Y', ('BTTS', 'NO'): 'BTTS_N'}


def _get(path, params=None, tries=3):
    for i in range(tries):
        r = S.get(BASE + path, params=params, timeout=30)
        if r.status_code == 429:
            time.sleep(5 * (i + 1)); continue
        r.raise_for_status(); time.sleep(PAUSE)
        return r.json()
    r.raise_for_status()


def upcoming_events(start_min, start_max):
    """All upcoming single football events between two ISO timestamps, following pagination."""
    out, params = [], dict(type_domain='football', type_scope='single_event', state='upcoming', sort='start_datetime,id', limit=200,
                           start_datetime_min=start_min, start_datetime_max=start_max)
    while True:
        j = _get('/events/', params)
        out += j.get('events', [])
        nxt = (j.get('pagination') or {}).get('next_page')
        if not nxt: break
        params = next_params(nxt)
    return out


def next_params(next_page):
    """Smarkets' next_page is an already-encoded query string ('?...&start_datetime_min=2026-09-29T15%3A01%3A00Z').
    Decode it before handing it back to requests, which encodes again (the 29 Sep first-run failure: %3A became %253A
    and Smarkets answered 400)."""
    return dict(parse_qsl(next_page.split('?', 1)[-1], keep_blank_values=True))


def competition_slug(event):
    parts = (event.get('full_slug') or '').split('/')
    return parts[3] if len(parts) > 3 and parts[1] == 'sport' and parts[2] == 'football' else None


def split_name(event):
    n = event.get('name') or ''
    return tuple(x.strip() for x in n.split(' vs ', 1)) if ' vs ' in n else (None, None)


SEEN_TYPES = {}   # (market type, param) -> count, every market type seen this run (idea 16: learn the real names first)
UNKNOWN = {}      # market type name -> a few market ids of that type seen this run (their contracts are sampled, idea 16)


def event_markets(event_id):
    ms = _get(f'/events/{event_id}/markets/').get('markets', [])
    keep = []
    for m in ms:
        t = (m.get('market_type') or {}); name, param = t.get('name'), t.get('param')
        k = (str(name), None if param is None else str(param)); SEEN_TYPES[k] = SEEN_TYPES.get(k, 0) + 1
        if name == 'OVER_UNDER':
            ok = str(param) in ('1.5', '2.5', '3.5')
        else:
            ok = name in ('WINNER_3_WAY', 'WINNER_DNB', 'BTTS', 'CORRECT_SCORE')     # correct score from 1 Oct (idea 16)
        if ok:
            keep.append(dict(id=m['id'], type=name, param=None if param is None else str(param)))
        else:
            ids = UNKNOWN.setdefault(str(name), [])
            if len(ids) < 3: ids.append(m['id'])
    return keep


def book(market_ids):
    """contracts + quotes + volumes for up to ~8 markets in one batch each."""
    ids = ','.join(market_ids)
    contracts = _get(f'/markets/{ids}/contracts/').get('contracts', [])
    quotes = _get(f'/markets/{ids}/quotes/')
    vols = {v['market_id']: v.get('volume') for v in _get(f'/markets/{ids}/volumes/').get('volumes', [])}
    return contracts, quotes, vols


def quotes(market_ids):
    """Just the order books (one request), for the in-play worker, which already knows each contract's selection."""
    return _get(f"/markets/{','.join(market_ids)}/quotes/")


def sample_contracts(market_ids):
    """Idea 16: the contracts of markets the bot does not price yet (one request), so their selections' real names are
    known before anything is wired to them. -> [dict(market_id, type, param, name, slug)]"""
    cs = _get(f"/markets/{','.join(market_ids)}/contracts/").get('contracts', [])
    return [dict(market_id=c.get('market_id'), type=(c.get('contract_type') or {}).get('name'), param=(c.get('contract_type') or {}).get('param'),
                 name=c.get('name'), slug=c.get('slug')) for c in cs]


CS_OTHER = {'ANY_OTHER_HOME_WIN': 'CS_oh', 'ANY_OTHER_DRAW': 'CS_od', 'ANY_OTHER_AWAY_WIN': 'CS_oa'}


def contract_key(mtype, param, ctype, cparam=None):
    if mtype == 'OVER_UNDER':
        return ('O' if ctype == 'OVER' else 'U') + str(param)
    if mtype == 'CORRECT_SCORE':
        # names seen on the live API on 1 Oct 2026: contract type SCORE with param '0-0' ... '3-3' (home-away), plus
        # ANY_OTHER_HOME_WIN / ANY_OTHER_DRAW / ANY_OTHER_AWAY_WIN
        if ctype == 'SCORE' and cparam and re.fullmatch(r'\d+-\d+', str(cparam)): return 'CS_' + str(cparam)
        return CS_OTHER.get(ctype)
    return KEY.get((mtype, ctype))


def outcomes(market_ids):
    """After the event: {contract_id: 'winner'|'loser'|'void'|...} from state_or_outcome."""
    cs = _get(f"/markets/{','.join(market_ids)}/contracts/").get('contracts', [])
    return {c['id']: c.get('state_or_outcome') for c in cs}
