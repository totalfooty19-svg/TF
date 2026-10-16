"""Improvement layers on top of the Dixon-Coles foundation (Mitch, 29 Sep 2026: "use the penaltyblog model and improve
that — use it as a head start and better foundation").

The foundation is the penaltyblog Dixon-Coles fit (models/dc.py). Each layer is one of our researched improvements, ported
as a multiplier on the foundation's lambdas. A layer is TESTING until the scoreboard says otherwise:
  - every run prices the foundation ('dixon_coles') AND foundation + each testing layer ('dixon_coles+<layer>');
  - each variant gets its own prediction and its own paper suggestion (same rules), so v_scoreboard / v_paper compare them;
  - only LIVE layers feed the featured suggestions;
  - a layer goes LIVE when, over >= PROMOTE_MIN fixtures, its 1X2 log loss beats the variant without it (same rule
    Mitch set for P-1 on 29 Sep: switch on automatically if it wins). The promotion is written in the register and here
    by the next chat — the job never edits itself.
Nothing here is deleted when a layer loses: its status becomes 'retired' and it stays in the file (register rule).

A layer: apply(ctx, lh, la) -> (lh, la, note). ctx has home, away (fit names), league, kickoff (datetime), elo (ClubElo
table or None), manager_changes (list of dicts), neutral."""
import datetime as dt
import math
from . import config as C
from . import names
from .models import elo as elo_model

PROMOTE_MIN = 30        # fixtures before a layer can be promoted (Mitch's P-1 rule, 29 Sep)


def _clip(x, lo=0.90, hi=1.10):
    return min(max(x, lo), hi)


def elo_blend(ctx, lh, la, w=0.30):
    """Blend the league fit with ClubElo (a second, independent rating that reacts faster to transfers and to results in
    other competitions). Geometric blend with weight w on the Elo lambdas. Weight 0.30: assistant's judgement, 29 Sep."""
    tab = ctx.get('elo') or {}
    if not tab: return lh, la, 'no ClubElo table'
    h, _ = names.match(ctx['home'], tab.keys(), cutoff=0.85); a, _ = names.match(ctx['away'], tab.keys(), cutoff=0.85)
    if not (h and a): return lh, la, 'ClubElo name not matched'
    eh, ea = elo_model.lambdas(tab[h], tab[a], total=lh + la, neutral=ctx.get('neutral', False))
    return lh ** (1 - w) * eh ** w, la ** (1 - w) * ea ** w, f'ClubElo {tab[h]:.0f} v {tab[a]:.0f}'


def manager_change(ctx, lh, la, factor=0.95, days=42):
    """The live 'manager change x0.95' of club v1.4 / I-1.0, on the side whose manager changed within `days` (42 days:
    the assistant's stand-in for the chat's 'first matches' count, which the bot cannot see). Changes come from the
    manager_changes table (team, league, changed_on, manager), filled by the chat's research — the bot never guesses."""
    note = []
    for side in ('home', 'away'):
        for mc in ctx.get('manager_changes') or []:
            if mc['league'] != ctx['league']: continue
            if names.match(ctx[side], [mc['team']], cutoff=0.85)[0] is None: continue
            age = (ctx['kickoff'].date() - mc['changed_on']).days
            if 0 <= age <= days:
                if side == 'home': lh *= factor
                else: la *= factor
                note.append(f"{side} new manager {mc.get('manager') or ''} ({age}d)")
    return lh, la, '; '.join(note) or 'no change'


def news(ctx, lh, la):
    """Idea 5: team-news adjustments recorded by the scheduled news analyst (news_adjustments table), each a multiplier
    on one side's goals scored (attack) and conceded (defence), capped at 0.85-1.15 when recorded. The bot never
    writes news itself; with none in force for the fixture the layer changes nothing."""
    notes = []
    for a in ctx.get('news') or []:
        if a['side'] == 'home':
            lh *= a['attack']; la *= a['defence']
        else:
            la *= a['attack']; lh *= a['defence']
        notes.append(f"{a['side']}: attack x{a['attack']:.2f}, defence x{a['defence']:.2f} ({a['reason'][:80]})")
    return lh, la, '; '.join(notes) or 'no news'


# name -> (function, status). Status: 'live' | 'testing' | 'retired'. Order is the order of application.
LAYERS = {
    'elo_blend': (elo_blend, 'testing'),
    'manager_change': (manager_change, 'testing'),
    'news': (news, 'testing'),
}


def live_name():
    return 'dixon_coles' + ''.join('+' + n for n, (_, s) in LAYERS.items() if s == 'live')


def variants(ctx, lh0, la0):
    """Returns [(model_name, lh, la, notes, is_live_variant)]: the foundation, the live stack, and live stack + each
    testing layer. With no live layers the live stack IS the foundation."""
    live = [n for n, (_, s) in LAYERS.items() if s == 'live']
    lh, la, notes = lh0, la0, {}
    for n in live:
        lh, la, notes[n] = LAYERS[n][0](ctx, lh, la)
    base_name = 'dixon_coles' + ''.join('+' + n for n in live)
    out = [(base_name, lh, la, dict(notes), True)]
    if live:
        out.append(('dixon_coles', lh0, la0, {}, False))
    for n, (f, s) in LAYERS.items():
        if s != 'testing': continue
        l2h, l2a, note = f(ctx, lh, la)
        out.append((base_name + '+' + n, l2h, l2a, dict(notes, **{n: note}), False))
    return out
