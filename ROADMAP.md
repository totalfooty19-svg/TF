# SB-MS-2026 roadmap: the 36 ideas (agreed with Mitch, 29–30 Sep 2026)

Every idea that changes a prediction goes in as a **challenger**: it is priced beside the champion, scored against the champion and the closing market, and takes over only when it wins (see the README, "It tunes itself"). Ideas that measure something go in the page's **Research** tab. Paper only throughout.

Status: **built** (in the repo), **collecting** (data being gathered; the idea switches on when there is enough), **next** (the phase being built), **later**.

## Phase 1: nothing new needed (built 30 Sep)

| # | Idea | How it is built | Status |
|---|---|---|---|
| 1 | Smarkets checked against itself | `models/consensus.py`: fits the scoreline odds that best explain all of a fixture's markets at once; challenger `market_consensus` | built |
| 3 | Are resting orders picked off? | view `v_research_fills`, Research tab: filled v unfilled resting orders v bets, against the close | built (verdict at 30 + 30 orders) |
| 12 | Popular-team / closing-price bias | view `v_research_close`, Research tab: implied v actual by price band, market busyness, home / draw / away | built (meaningful at hundreds of fixtures) |
| 14 | Promoted and relegated teams | `models/fastdc.py` + method `pyramid`: one fit across a country's divisions (England 5, Scotland 4, Germany, Italy, Spain, France 2) | built, challenger `dixon_coles~pyramid` |
| 17 | Shots-based ratings (xG stand-in) | `models/shots.py` + method `shots`: goals blended with shots on target (football-data HST/AST) | built, challenger `dixon_coles~shots` |
| 23 | Kick-off slot effects | view `v_research_slots`, Research tab | built |
| — | Order-book depth | `pricing.contract_view` stores quantity at the best price and in the best three levels, both sides | collecting (feeds 2, 20, 25) |

## Phase 2: still no new data (built 30 Sep, except where it says collecting)

| # | Idea | Plan | Status |
|---|---|---|---|
| 13 | A margin of error on every rating | `tuning.shrink`: ratings pulled to the average by k/(n+k), n = time-weighted matches; recipe option `shrink`, challenger `dixon_coles~shrunk`, in the grid | built (30 Sep) |
| 18 | Draw specialist | A multiplier on drawn scores in the grid, fitted with the bias correction and adopted only if it improves unseen matches | built (30 Sep) |
| 19 | Trust by week of the season | Weekly review: the model's gap to the market in the early / mid / late season → a factor on the anchor per phase (`trust`) | built (30 Sep) |
| 15 | A model of its own mistakes | `learn.py` ('META'): logistic regression on each settled bet (edge, price, market, thin data, hours before, spread, volume, variant disagreement) → will it beat the close? Fitted daily from 300 bets, tested on the newest 30%; every suggestion records `meta_p`; `META_SKIP` skips low ones once shown to work; Research tab | built 30 Sep (fits itself at 300 bets) |
| 25 | Integrity filter | `integrity.py`: moves of 8+ points within 3 hours flagged on the fixture; Research tab tests whether they were informed; `INTEGRITY_BLOCK` switches blocking on | built (recording only, 30 Sep) |
| — | xG (top five leagues we price) | `sources/understat.py` reads Understat's league pages; method `xg` = goals blended with xG; challenger `dixon_coles~xg` | built (30 Sep; untested against the live site) |
| 16 | More markets | Every Smarkets market type is recorded (`market_types_seen`), and from 30 Sep a sample of each unpriced type's selections (names, types, parameters) so correct score and Asian handicaps are wired to the real names, not guesses; pricing ready in `pricing.extra_markets` / `ah_ev` | groundwork built; wired once the samples are in (first full run after upload) |
| 2 + 20 | Predict the closing price (incl. weight of money) | `price_path` keeps each settled fixture's prices and depth at 48/24/12/6/3/1 h and the close; `learn.py` ('CLOSE'): ridge regression on price, back v lay depth, volume, hours, model gap; fitted daily from 150 fixtures, tested on the newest 30%; every suggestion records `pred_move`; Research tab | built 30 Sep (fits itself at 150 fixtures) |

## Phase 3: free sign-ups from Mitch (built 30 Sep; parts switch on with the keys)

| # | Idea | Needs | Status |
|---|---|---|---|
| 4 + 21 | Line-up shock; squad continuity | `capture_lineups` (every 15-minute run, 80 to 15 minutes before kick-off): API-Football line-ups, starters changed since the side's previous line-up (`lineups`); `v_research_lineups`: price before v after v results by changes. API-Football requests budgeted across all jobs (`api_budget`) | built 30 Sep, switches on with `API_FOOTBALL_KEY` |
| 24 | Weaker markets | Second tiers (Germany, Italy, Spain, France, Scotland x3), MLS, Brazil, Argentina, Mexico, Japan, China from football-data; National League North / South, Brazil Serie B, USL Championship (by league id, checked against the name returned), Colombia, Peru, Uruguay, Canada from API-Football. Women's and youth: no free results source yet | built 30 Sep (football-data ones now; API-Football ones with the key) |
| 7 | Follow the sharp bookmaker | `sources/oddsapi.py`: Pinnacle's no-vig prices as challenger `sharp_pinnacle`; set `ODDS_API_KEY` on sbms-model (free plan: kept to ~250 credits a month) | built, switches on with the key |
| 9 | Fatigue and travel | Every football event on Smarkets is recorded (`events_seen`), so rest days include cups and Europe; `v_research_travel`: distance between the grounds (Wikidata) v away prices and results. A layer follows only if either shows the market misses it | built (collecting) |
| 10 | Weather and pitches | Grounds from Wikidata (`sources/venues.py`, correctable in `venues`), forecasts and history from Open-Meteo (`sources/weather.py`); the weekly review learns a goal factor for wet / windy / fair, used only if it improves unseen matches; challenger `~no_weather`. Pitches (3G) not yet | built (30 Sep) |
| 22 | Referees | API-Football appointments (one request per day, cached) and history, plus football-data's referee column; per-referee goal factor, shrunk hard, adopted only if it improves unseen matches; challenger `~no_referee` | built, switches on with `API_FOOTBALL_KEY` |

## Phase 4: bigger builds (built 30 Sep)

| # | Idea | Plan | Status |
|---|---|---|---|
| 5 | Claude as news analyst | sbms-page `/upcoming` and `/adjust` (only with `NEWS_KEY`, capped 0.85–1.15, reason and source required); layer `news` (testing); daily scheduled task, prompt in `SCHEDULED-TASKS.md` | built; the task is created once the page is live |
| 26 | Claude as researcher | Weekly scheduled task reading `/page-data`: a one-page brief and one proposed experiment (read-only); prompt in `SCHEDULED-TASKS.md` | built; the task is created once the page is live |
| 8 | What's at stake | `stakes.py`: the season simulated 10,000 times from the table and the champion's ratings; each side's chance of each zone if it wins / draws / loses; England's five divisions (rules certain); shown on the page, stored in `stakes` for research | built (30 Sep) |
| 6 | Ratings from prices | `models/prices.py`: the goal expectations each past match's closing 1X2 and over/under 2.5 implied, then ratings fitted to them; method `prices`, challenger `dixon_coles~prices` | built (30 Sep) |
| 11 | In-play | `inplay.py` (scoreline by minute and score), worker `jobs/inplay.py` with API-Football live scores, snapshots and a separate in-play paper book (+6% floor, fresh score and calm book required); In-play tab | built; off until switched on in render.yaml (needs `API_FOOTBALL_KEY`) |

## Goal reaction (Mitch, 30 Sep): trade out or hold after a goal

`trading.py` + the in-play worker: a jump of 8+ points in the result market between two 15-second reads is an event
(a goal or a red card, seen in the prices). The book is recorded for 5 minutes; for each selection the paper trades are
worked out: back at the first price after the jump, then lay back at 1 / 2 / 3 / 5 minutes (locked profit or loss,
the same whatever happens) or hold to the end. "Follow the move" v "fade the overreaction". In-play tab. Needs the
in-play worker switched on (no API key needed for this part). Next: once a few hundred events exist, a model that
chooses which jumps to trade and when to get out (jump size, minute, score, pre-match strengths, depth).

Suspensions (Mitch, 30 Sep: "you'll see the market suspended as well"): an empty result market after a live one marks a
suspension; the reopening ends it and is recorded as an event whatever the prices did, with how long it lasted and the
two minutes of reads before it (prices often drift as pressure builds). Three kinds: **goal or red card** (reopened 8+
points away), **check, no change** (VAR, a penalty review, a disallowed goal; kept out of the strategy table and counted
apart), and **jump, no suspension** (a big move between two reads with no empty book seen). Entry is the first price
after the reopening, the earliest a bet could really be made, with the depth recorded. An empty book longer than 15
minutes is the market closing, not an event.

## Ideas 27–36 (Mitch, 30 Sep: "build as much as you can"), built 30 Sep

| # | Idea | How it is built | Status |
|---|---|---|---|
| 27 | The committee | `committee.py`: every variant priced for a fixture votes, weighted exp(-n x (its log loss - the best)) over the league's last six months; linear pool; variant `committee`, scored like every challenger | built (equal votes until 30 settled fixtures per member) |
| 28 | Staking plans compared | P&L tab: the same bets staked flat, by edge, and quarter Kelly from a £5,000 paper bank: P&L, turnover, worst fall | built |
| 29 | When to bet | `v_research_timing`: bets by hours before kick-off, with CLV | built (meaningful at ~30 bets a bucket) |
| 30 | Pressure before a goal | `v_research_pregoal`: the two minutes of prices before each suspension, goals v checks | built (needs the in-play worker) |
| 31 | Disagreement as a warning | `suggestions.disagreement` (highest minus lowest variant probability) and `v_research_disagree`; `DISAGREE_BLOCK` skips wide ones once shown to matter | built (recording; block off) |
| 32 | Circuit breaker | `run.breaker`: a league whose last 30 live bets average CLV below -3% is not featured until the average is back above 0; logged in `league_tuning` (kind `breaker`), Health tab | built (on) |
| 33 | Data guardian | `guardian.py`: broken / crossed books, impossible predictions, model and market 25+ points apart, stale results; blocks the bet (still predicted and scored), logged in `guardian_log`, Health tab | built (on) |
| 34 | Nothing to play for | `v_research_stakes`: sides with nothing at stake v a lot, implied v actual win rate (from idea 8's simulations) | built (meaningful from the spring) |
| 35 | Reaction model | `trading.fit_reaction / plan / walk_forward`: ridge regression per exit time on the goal-reaction events; the in-play worker refits hourly and plans at most one paper trade per event once 60 events exist; out-of-sample record on the In-play tab | built (needs the in-play worker and 60 events) |
| 36 | Ready for real money? | P&L tab: eight tests that must all pass before real money is even discussed | built |

## The daily card and the honest scorecard (Mitch, 16 Oct: "3-5 per day ... rest these 5, 5 real bets, 5 forced bets")

Evidence on 16 Oct (400 settled fixtures since 29 Sep): 3 bets and 570 resting orders from the live model; the 110 filled
rests averaged -2.9% against the closing price (26% beat it), the unfilled ones +5.6%: rests are filled mostly when the
market is about to move against them. Blending any weight of the model into the Smarkets price at 24/12/6/3/1 h or the
close made predictions worse (340+ fixtures); the back-test agrees (+0.021 v Pinnacle's close over 12,848 matches). The
closing-price model finds no pattern in price moves (R2 below 0); Pinnacle's prices were no sharper than Smarkets' on 129
fixtures.

Built: the daily card, made once a day after 09:00 UK and fixed: **bets** (cleared the floor; up to 5 a day), **forced
picks** (the 5 prices on offer the model rates best, floor or not: a fast paper test of the model's ranking) and **rest
these** (the 5 resting orders likeliest to be matched). Each tier is scored on its own (P&L tab, `v_card`). And the test
that decides whether any edge is real: **does the model add anything to the market?** (`v_research_blend`, Research tab).

**The model's say (16 Oct, Mitch: "do 3").** Each league's weight on the model is now the blend weight (0 to 0.6) that
has predicted results best: live, against the Smarkets close, once a league has 200 settled fixtures; otherwise in the
weekly back-test against Pinnacle's close (300+ matches). It may be zero, and on the evidence so far most leagues will
go to zero: no bets there until the model earns a say back. Forced picks keep ranking at a fixed 0.30 so the model's
ranking is still tested every day. Not done (Mitch's choice): the in-play worker and a paid Odds API plan.
