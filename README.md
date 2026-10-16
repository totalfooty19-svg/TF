# SB-MS-2026 — football pricing bot (paper only)

Every 15 minutes on Render this job reads upcoming football on the Smarkets exchange. It prices the covered leagues with a Dixon-Coles model (penaltyblog) fitted on recent results — **the foundation** — with our researched improvements layered on top of it (`sbms/layers.py`), or with ClubElo for European club competitions. It records every prediction, every quote, a paper suggestion when a price clears the rules, the price at kick-off, and the result. Everything lands in `totalfooty-db` (in its own `sbms` schema), and a small read-only web service, `sbms-page`, shows it as a live page you can open on your phone.

**It never places a bet.** There is no login, no account key and no order code anywhere in this repo, and a unit test checks for that. Every suggestion is a paper record, settled at a notional £50 so the model can prove itself — or not — before any money is involved.

## What it covers

- **England**: Premier League, Championship, League One, League Two, National League.
- **Every UEFA top flight** whose clubs enter the Champions League, Europa League or Conference League. About 25 run on free data from football-data.co.uk. The rest (Bulgaria, Croatia, Serbia, Czechia, Hungary, Cyprus, …) switch on when `API_FOOTBALL_KEY` is set. API-Football has a free tier of 100 requests/day: every job shares one daily allowance (`api_budget`: 95 a day, at most 55 for results and 25 for line-ups), and each API-Football league is refitted every three days.
- **Second tiers and beyond Europe** (idea 24, 30 Sep): Germany, Italy, Spain and France's second divisions, Scotland's three lower divisions, MLS, Brazil, Argentina, Mexico, Japan and China on football-data; National League North and South, Brazil Serie B, USL Championship, Colombia, Peru, Uruguay and Canada with the API-Football key.
- **European club competitions** (Champions League, Europa League, Conference League), priced from ClubElo ratings, because a league model cannot compare clubs from different leagues.
- **No internationals.** The researched I-1.0 model stays in the chat-based process.

## How a suggestion is made (rules carried over from the model built 16–29 Sep 2026)

1. **Model probability.** Model probabilities for 1X2, draw-no-bet, BTTS and over/under 1.5 / 2.5 / 3.5 come from the Dixon-Coles score grid.
2. **Market probability.** The market probability is the exchange mid-price with the small margin removed.
3. **Cap and anchor.** The model is capped to within 15% of the market (10% for thin data or European ties). It is then anchored at w × model + (1 − w) × market. w starts at 0.30; since 16 Oct each league's w is whichever blend of model and market has predicted results best (live, or in the weekly back-test), and it can fall to 0 where the model adds nothing, in which case that league produces no bets until the model earns a say back. Forced picks on the daily card always rank prices at 0.30, because they exist to test the model's ranking.
4. **Gates.** A row must be rated at least 40% by the model (result rows) or at least 60% (goals rows).
5. **Take or rest (rule L-1, Mitch, 29 Sep 2026: "if a bet is there and we think it's value we can take it; if we have capital we aren't using, we can place it where we want it").**
   - **Take:** if the best back price on offer now is worth at least **+4% EV after 2% commission**, the suggestion is taken at that price. The spread and the traded volume no longer block it (they are still recorded).
   - **Rest:** otherwise the suggestion is an order resting at the lowest price on the Smarkets ladder that clears +4%. It counts **only if the book reaches that price before kick-off** (checked on every quote read). An unfilled rest is settled as if taken but kept in its own `unfilled` column, apart from the real paper record — the same fill rule the chat's paper book uses.
   - The old spread (6 points) and "has traded" gates are kept in `config.py` switched off (`LIQUIDITY_GATES = False`) so the change can be reversed in one line.
6. **Bets, not resting orders (Mitch, 29 Sep 2026: "rests are treated like bets, they are rarely bets, especially illiquid. The 4 picks should be the best 4 bets available to take there and then").** Only a *take* is a bet. The four featured each day are bets only: prices on offer that cleared +4% when found, best EV first, fixed once made. Fewer is correct, and on most days there will be none. Resting orders are still recorded, apart from the bets and outside every P&L total, so we can see how often waiting would have been matched. Each fixture and model can have one bet and one resting order, so an earlier resting order never blocks a price that becomes takeable later.
7. **Fixed once made.** A suggestion is fixed when made, like a bet taken at that price. Later runs never move it.
8. **Kick-off and settlement.** The price at kick-off is captured, and the closing-line value (CLV) is computed. Settlement uses Smarkets' own winner/loser result on the contract.

The anchor and cap mean the model can only disagree with the market by a few points, so prices you can **take** will be rare; most suggestions will be resting orders, and many will never fill. That is deliberate. The weight is tuned automatically (Model → Self-tuning shows each league's weight and why).

## The foundation and the layers (Mitch, 29 Sep 2026: "use the penaltyblog model and improve that")

- **Foundation:** penaltyblog's Dixon-Coles fit per league (`models/dc.py`). It is recorded as model `dixon_coles`.
- **Layers** (`sbms/layers.py`): each of our researched improvements, ported as a multiplier on the foundation's goal expectations. Every run prices the foundation **and** foundation + each testing layer, as separate model variants (`dixon_coles+elo_blend`, `dixon_coles+manager_change`), each with its own prediction and its own paper suggestion under the same rules. `/model/scoreboard` compares them side by side.
- **Promotion:** a layer switches on (status `live` in `LAYERS`) when, over at least 30 fixtures, its log loss beats the stack without it — the rule Mitch set for the manager test on 29 Sep. The next chat makes the change and records it in the component register; the job never edits itself. A layer that loses is marked `retired`, never deleted.
- **Layers now:** `elo_blend` (ClubElo blended in at weight 0.30 — reacts faster to transfers and to other competitions; the weight is the assistant's judgement) and `manager_change` (the live ×0.95 on the side whose manager changed in the last 42 days, from the `manager_changes` table, which the chat's research fills — the bot never guesses a manager).
- **Next layers** (need data the bot does not yet read; order in PLAN-SB-MS-2026 §3): key attacker / key defender out and squad availability (API-Football injuries and line-ups), P-1 manager profile, xG-based ratings, fatigue.

## It tunes itself — the model competing with itself (Mitch, 29 Sep 2026: "running the current variant and slight variations at the same time — trying to outperform not only the market, but also itself")

Each league has a **recipe** in force (how fast old results fade, and how many years of results the fit uses), an optional **bias correction**, and a **say** against the market (the anchor weight). The recipe in force is the **champion**.

- **Every hour**, beside the champion, the bot prices its **challengers**: the same recipe with old results fading *half as fast* and *twice as fast*, and (when a bias correction is in force) the champion *without* it. Each is its own model variant (`dixon_coles~fade_slower`, `~fade_faster`, `~uncalibrated`) with its own predictions and paper bets, never featured.
- **Every week** (`sbms-backtest`, Mondays), league by league, every decision written to `league_tuning` and shown on the page (Model → Self-tuning):
  1. **The model v its variations on past matches.** A walk-forward replay of the last year for six recipes (fade ×0.5 / ×1 / ×2, 2 or 3 years). A variation takes over only if it beats the champion's log loss by 0.002 over 300+ matches.
  2. **The model v its variations live.** A challenger takes over if it beats the champion by 0.01 over 100+ settled fixtures since the last change.
  3. **Bias correction.** The champion's replayed predictions are compared with what happened (goals scored home and away). A correction is fitted on the earlier two thirds and **adopted only if it improves the latest third**, which it never saw. It is shrunk towards none and never moves a goal expectation by more than 10%.
  4. **Earning more say.** When the champion's own probabilities beat the closing market over a league's latest 200 settled fixtures, its weight rises ×1.2 (from 0.30, at most 0.60); when they trail, it falls back (never below 0.30). At least 100 new fixtures between steps.
- **Methods compete too (30 Sep).** Besides the fade variations, each league's champion is priced beside the other *methods* it can use: `goals` (Dixon-Coles on scores), `shots` (goals blended with shots on target, the xG stand-in; idea 17) and `pyramid` (one fit across the country's divisions, so promoted and relegated teams keep a rating; idea 14). A method that wins takes over like any other variation. And `market_consensus` (idea 1) prices every fixture from what all of its own markets jointly imply, with no football model, so a market that disagrees with the rest stands out.
- **Research tab (30 Sep):** are resting orders picked off (idea 3), is the closing price biased (idea 12), kick-off slots (idea 23). The full list of 26 ideas and their status is in `ROADMAP.md`.
- A league's recipe changes at most once every 28 days. All thresholds are in `config.py`; they are the assistant's judgement (29 Sep) and can be changed there.
- The database is kept small: one prediction per fixture and variant (updated until kick-off), and after a week only each fixture's last price before kick-off is kept.

## Is it any good? — the scoreboard

- `GET /model/scoreboard`: log loss per league, model vs the closing market (lower is better), plus the paper totals and the weekly back-test.
- `sbms-backtest` (Mondays): a walk-forward test over the last two seasons of every football-data league. It refits every week on past matches only, then scores the model against Pinnacle's closing prices. This is the fast answer: thousands of matches in one run instead of months of waiting. Run it once by hand after the first deploy.

- **Ready for real money?** (P&L tab, idea 36): eight tests (enough bets, CLV above zero and unlikely to be luck, beats the close often, beats the market's log loss, back-test close to Pinnacle, a survivable losing run, no league on the circuit breaker, clean data). A checklist, not a switch: nothing places a bet.

## Real bets ("I took this bet", 16 Oct)

Every pick on the page, and every selection in a fixture's working, has an **I took this** button: enter the odds you
got and your stake, see the model's EV at those odds (after commission), the break-even odds and the return, and log it.
Logged bets go in `real_bets`, settle themselves from the exchange's result, get a closing-price value (CLV) at kick-off,
and appear on the **Real P&L** tab: totals, return on stakes, CLV and EV (both stake-weighted), by tier (bets, forced
picks, rests, own picks), open bets (with Undo) and settled bets. Needs `BETS_KEY` set on sbms-page; the page asks for
the key once and keeps it in that browser. Settled bets cannot be undone.

## Set-up on Render (about 10 minutes)

1. **Upload the code.** Put this code in the GitHub repo `SB-MS-2026`. From the zip: open the repo → **Add file → Upload files** → drag in everything inside the zip folder → **Commit changes**.
2. **Create the jobs.** In Render: **New → Blueprint → pick SB-MS-2026**. It reads `render.yaml` and creates two cron jobs (`sbms-model`, `sbms-backtest`) wired to `totalfooty-db`. If you'd rather click: **New → Cron Job → SB-MS-2026**, with runtime Python, build `pip install -r requirements.txt`, and:
   - `sbms-model`: command `python -m sbms.jobs.run auto`, schedule `*/15 * * * *`.
   - `sbms-backtest`: command `python -m sbms.jobs.backtest --seasons 2 --step 7`, schedule `0 5 * * 1`.
   - **Environment:** add `DATABASE_URL` = totalfooty-db's *Internal Database URL*.
3. **Optional: switch on the smaller leagues.** Sign up at api-football.com (free plan) and add `API_FOOTBALL_KEY` to `sbms-model`'s environment.
   **Optional: follow the sharp bookmaker (idea 7).** Sign up at the-odds-api.com (free plan) and add `ODDS_API_KEY` to `sbms-model`: each fixture is then also priced from Pinnacle's prices, as the challenger `sharp_pinnacle`.
4. **Run each job once.** Click **Trigger Run** on `sbms-backtest` and on `sbms-model` to start now. Tables are created on the first run.
5. **The live page.** The Blueprint also creates `sbms-page`, a web service (Starter plan, about $7 a month; set `plan: free` in `render.yaml` to pay nothing and accept a ~30-second wake-up). Open its `onrender.com` address. To lock it, set `MODEL_PAGE_KEY` on `sbms-page` and open it as `…/?key=<password>`. To use your own domain, add it under `sbms-page` → Settings → Custom Domains and create the CNAME record Render shows in Namecheap (Domain List → Manage → Advanced DNS).
6. **Check it's working.** The page's Health tab lists competitions the job saw but didn't map, and team names it couldn't match. Send those to Claude to add to `sbms/config.py` / `sbms/names.py`.
   (`node/model-routes.js` is optional: the same page and feeds mounted inside `totalfooty-api` instead.)

Costs: Render bills cron jobs by run time. A full run takes a few minutes an hour and the close runs take seconds. Check the Render dashboard after a day.

## Files

| Path | What |
|---|---|
| `sbms/config.py` | every threshold and the league list (Smarkets slugs marked `seen` were observed on 29 Sep 2026; the rest are expected names — `/model/health` shows misses) |
| `sbms/jobs/run.py` | the scheduled job (full on the hour, close captures each quarter, settlement every run) |
| `sbms/jobs/backtest.py` | walk-forward historical test |
| `sbms/models/dc.py` | Dixon-Coles via penaltyblog (with an equivalent scipy fallback) |
| `sbms/models/elo.py` | ClubElo cross-league pricing for European ties |
| `sbms/pricing.py` | score grid → markets, exchange book → no-vig, the rules (take / rest) |
| `sbms/layers.py` | the improvement layers on top of the Dixon-Coles foundation, with their status |
| `sbms/models/consensus.py`, `fastdc.py`, `shots.py` | the markets' own consensus; the fast fitter (pyramids); the shots blend |
| `ROADMAP.md` | the 36 ideas, phase and status |
| `sbms/committee.py` | idea 27: every variant votes, weighted by its recent record; idea 31: how much they disagree |
| `sbms/guardian.py` | idea 33: data checks that stop bad data becoming a bet (Health tab) |
| `sbms/learn.py` | ideas 15 and 2 / 20: models that learn from the bot's own records (will a bet beat the close? where will the price close?) |
| `sbms/trading.py` | goal reaction and suspensions; idea 35: the reaction model (which post-goal trades lock in a profit) |
| `SCHEDULED-TASKS.md` | the news analyst and researcher (scheduled Claude tasks) and how to set them up |
| `sbms/jobs/inplay.py`, `sbms/inplay.py` | the in-play worker (off until switched on in render.yaml) and its scoreline model |
| `sbms/tuning.py` | self-tuning: the champion, its challengers, the weekly grid, bias correction and the earned anchor |
| `sbms/sources/` | Smarkets public API (read-only), football-data.co.uk, API-Football, ClubElo |
| `schema.sql` | tables and the `v_scoreboard` / `v_paper` views |
| `sbms/web.py`, `web/page.html` | the live page (`sbms-page`): read-only server and the Ultimate HTML page |
| `node/model-routes.js` | optional: the same page and feeds inside totalfooty-api |
| `tests/` | `python tests/run_tests.py` (unit tests) and `python tests/smoke_run.py` (offline run of the pricing path) |

## Known limits (stated, not hidden)

- **Unverified Smarkets slugs.** Smarkets competition slugs for leagues not seen on 29 Sep are expected names. Unmatched ones show on `/model/health`. A competition matched by country alone ("inferred") is listed there but **not priced** until its slug is added to `config.py` (29 Sep: `serbia-prva-liga`, the second tier, was inferred as the SuperLiga).
- **Team-name matching** is exact, then an alias table, then a strict fuzzy match. Misses are logged, never forced.
- **European ties** rest on two stated assumptions: ClubElo home advantage of 65 points and 2.75 expected goals.
- **The foundation knows nothing** about injuries or suspensions, and only what the `manager_changes` table tells it about managers, until the next layers are built. That's the researched model's job in the chat process meanwhile, and a reason for the heavy market anchor.
- **Resting orders** are judged filled from quotes read every 15 minutes, so a price touched briefly between reads is missed (counted unfilled — the cautious side).
- **The kick-off price** is the last read before kick-off, up to 20 minutes before.
