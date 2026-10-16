"""Configuration. Every threshold here is carried over from the model rules built 16–29 Sep 2026
(MODEL-architecture.md / RUN-ANALYSIS.md) unless marked NEW. Change values here, never inline."""
import os

# ---------------------------------------------------------------- mode
# PAPER ONLY. There is deliberately no code path that places a bet. (Mitch lost his bankroll on 27 Sep 2026 and chose
# paper testing; auto-placement is not built. Revisit only after a paper record of 200+ suggestions beats the close.)
MODE = 'paper'

DATABASE_URL = os.environ.get('DATABASE_URL', '')
API_FOOTBALL_KEY = os.environ.get('API_FOOTBALL_KEY', '')
API_FOOTBALL_VIA = os.environ.get('API_FOOTBALL_VIA', 'direct').strip().lower()   # 'rapidapi' for a key bought through RapidAPI
ODDS_API_KEY = os.environ.get('ODDS_API_KEY', '')              # optional (idea 7): Pinnacle prices via the-odds-api.com
ODDS_API_MARKETS = os.environ.get('ODDS_API_MARKETS', 'h2h')   # 'h2h,totals' doubles the credits per request
ODDS_API_EVERY_H = 20                                          # at most one request per league per this many hours...
ODDS_API_WINDOW_H = 24                                         # ...and only for leagues with a fixture in the next 24 hours      # optional: switches on leagues football-data.co.uk lacks
USER_AGENT = 'SB-MS-2026 model (paper; contact via repo owner)'

# ---------------------------------------------------------------- pricing rules (carried over)
COMMISSION = 0.02            # Smarkets commission on net winnings
FLOOR_EV = 0.04              # the user's hard floor: +4% EV after commission at a fillable price
PREFERRED_EV = 0.075         # preferred target (resting-order suggestion)
THRESH_RESULT = 0.40         # O-1c: result / DNB rows need model probability >= 40%
THRESH_GOALS = 0.60          # O-1c: BTTS and totals rows need >= 60%
# L-1 (Mitch, 29 Sep 2026): a value price on offer is taken whatever the spread or volume; otherwise the order rests at
# the floor price and counts only if filled. The old gates are kept (off) so the change can be reversed in one line.
LIQUIDITY_GATES = False
MAX_SPREAD_PTS = 6.0         # RETIRED as a blocker 29 Sep (L-1); was the v1.2 §3 liquidity line, the assistant's number
MIN_VOLUME = 1               # RETIRED as a blocker 29 Sep (L-1); was S-1a: the market must have traded
ANCHOR_MODEL_WEIGHT = 0.30   # anchored fair: 0.30 x capped model + 0.70 x market (evidence 29 Sep: model trails market)
BAND_CAP = {'full': 0.15, 'thin': 0.10}   # Stage 3: max relative distance of the model from the market
MAX_FEATURED_PER_DAY = 5     # at most five featured bets a day (Mitch, 16 Oct: "3-5 per day"); fewer is correct
# The daily card (Mitch, 16 Oct: "rest these 5, 5 real bets, 5 forced bets"). Chosen once a day by the first full run
# after CARD_HOUR_UTC, from that day's fixtures not yet started, and fixed (like a bet taken at that price):
#   bets   - the featured bets (prices that cleared FLOOR_EV), as before;
#   forced - the CARD_SIZE best prices on offer by the model's EV whether or not they clear the floor (one per fixture,
#            not already a bet), a paper test of whether the model's ranking has any signal;
#   rests  - the CARD_SIZE resting orders closest to being filled.
CARD_SIZE = 5
CARD_HOUR_UTC = 8            # 09:00 UK in summer time, 08:00 in winter
LEAN_MIN_P = 0.25            # forced picks: no long shots (the anchored probability must be 25%+)...
LEAN_MAX_PRICE = 6.0         # ...no price above 6.0...
LEAN_MAX_SPREAD = 8.0        # ...and a two-sided book no wider than 8 points, so the price is one that could be taken
ONE_PER_FIXTURE = True
PAPER_STAKE = 50.0

# ---------------------------------------------------------------- models
DC_XI = 0.0018               # Dixon-Coles time decay (penaltyblog default; half-life ~ 385 days)
DC_SEASONS = 3               # current + two previous seasons in the fit
DC_MIN_MATCHES = 150         # below this a league is 'thin' (10% band) and needs >= 5 matches per team
REFIT_HOURS = 20             # refit a league at most once a day
AF_REFIT_HOURS = 70          # ...and an API-Football league every three days (results cost requests)
AF_DAILY_BUDGET = 95         # API-Football requests a day across every job (free plan: 100)...
AF_RESULTS_BUDGET = 55       # ...of which results loading may use at most this many, leaving the rest for live scores and referees
AF_LINEUPS_BUDGET = 25       # ...and line-ups at most this many (ideas 4 / 21; one request per fixture per attempt)
LINEUP_WINDOW_MIN = (15, 80) # line-ups are looked for between 80 and 15 minutes before kick-off
ELO_HFA = 65                 # NEW: ClubElo home advantage in Elo points for European ties (assumption, logged)
ELO_TOTAL_GOALS = 2.75       # NEW: expected total goals in a European tie (assumption, logged)
MAX_GOALS = 12

# ---------------------------------------------------------------- scheduling
PRICE_WINDOW_HOURS = 48      # price every event kicking off within this window
CLOSE_WINDOW_MIN = 20        # 'close' runs capture quotes for events kicking off within this many minutes
SETTLE_AFTER_HOURS = 3

# ---------------------------------------------------------------- self-tuning (Mitch, 29 Sep 2026: "the model running the
# current variant and slight variations at the same time - trying to outperform not only the market, but also itself")
# Each league has a RECIPE in force (how fast old results fade, how many years the fit uses), an optional CALIBRATION (a
# correction for a consistent lean, e.g. too few goals) and an ANCHOR weight (how much say the model gets v the market).
# Every hour the recipe in force ("the champion") is priced alongside slight variations ("challengers"). The weekly job
# (sbms-backtest) reviews the evidence and changes a league's recipe only when a variation beats it. All numbers below
# are the assistant's judgement (29 Sep) unless marked; every decision is written to the league_tuning table.
TUNE_XI_MULTS = (0.5, 1.0, 2.0)     # variations of the fade: half as fast, as now, twice as fast
TUNE_FIT_YEARS = (2, 3)             # variations of the fit window
TUNE_MAX_FIT_YEARS = 3
TUNE_WINDOW_DAYS = 365              # the back-test grid scores each variation on the last year, walk-forward
TUNE_STEP_DAYS = 14                 # refit every two weeks inside the grid (the reporting back-test refits weekly)
TUNE_MIN_MATCHES = 300              # a grid decision needs at least this many scored matches
TUNE_MARGIN = 0.002                 # ...and the variation must beat the champion's 1X2 log loss by at least this
LIVE_CHALLENGE_MIN = 100            # a live challenger needs this many settled fixtures (since the last recipe change)
LIVE_CHALLENGE_MARGIN = 0.01        # ...and must beat the champion's log loss by this much to take over
RECIPE_COOLDOWN_DAYS = 28           # a league's recipe changes at most once in this many days
XI_BOUNDS = (0.0003, 0.012)         # the fade never goes beyond a half-life of ~6 years or ~2 months
CAL_SHRINK = 300                    # bias correction is shrunk towards none: weight n / (n + CAL_SHRINK)
CAL_CLIP = (0.90, 1.10)             # ...and never moves a goal expectation by more than 10%
CAL_DRAW_CLIP = (0.85, 1.20)        # idea 18: the draw correction (a multiplier on every drawn score) stays in this range
CAL_HOLDOUT = 1 / 3                 # it is adopted only if it improves the latest third of the matches it was NOT fitted on
ANCHOR_DEFAULT = ANCHOR_MODEL_WEIGHT  # 0.30: the model's say v the market until it earns more
ANCHOR_MAX = 0.60
ANCHOR_STEP = 1.2                   # a step is x1.2 up or /1.2 down (the plan of 29 Sep: "at most 20% a step")
ANCHOR_WINDOW = 200                 # judged on the league's latest 200 settled fixtures (plan: "200+ fixtures")
ANCHOR_MARGIN = 0.005               # (before 16 Oct) model log loss had to beat (or trail) the closing market by this much
# 16 Oct (Mitch: "do 3"): the model's say is now set to whatever blend of model and market predicts results best, and it
# may fall to zero where the model adds nothing. The weight w in (w x model + (1 - w) x market) is chosen from ANCHOR_GRID
# on the league's settled fixtures (live: the latest ANCHOR_WINDOW against the Smarkets close; otherwise the weekly
# back-test's matches against Pinnacle's close, at least ANCHOR_BT_MIN), and changed only when the best weight beats the
# weight in force by ANCHOR_BLEND_MARGIN log loss per match.
ANCHOR_MIN = 0.0
ANCHOR_GRID = (0.0, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6)
ANCHOR_BLEND_MARGIN = 0.0002
ANCHOR_BT_MIN = 300
FORCED_WEIGHT = 0.30                # forced picks rank prices by the model's own view at this fixed weight, whatever the
                                    # tuned weight, since their purpose is to test the model's ranking
ANCHOR_MIN_NEW = 100                # at least this many newly settled fixtures between two steps in a league
# Model methods a league's recipe can use (29 Sep, ideas 14 and 17). 'goals': Dixon-Coles on scores (the foundation).
# 'shots': goals blended with shots on target, which are far more frequent than goals, so less noisy.
# 'pyramid': one fit across a country's divisions, so promoted and relegated teams keep a rating on one scale.
SHRINK_K = 8                        # idea 13: a team's rating is pulled to the average by k / (n + k), n = its time-weighted
                                    # match count (a promoted side with 9 games moves about half way; 35 games, 20%)
SHOTS_WEIGHT = 0.5                  # share of the shots-on-target model in the blend (assistant's judgement; the grid tests it)
PYRAMIDS = {                        # football-data.co.uk division codes, top first
    'england': ['E0', 'E1', 'E2', 'E3', 'EC'], 'scotland': ['SC0', 'SC1', 'SC2', 'SC3'], 'germany': ['D1', 'D2'],
    'italy': ['I1', 'I2'], 'spain': ['SP1', 'SP2'], 'france': ['F1', 'F2'],
}
TRUST_PHASES = ((0, 'early'), (7, 'mid'), (16, 'late'))   # idea 19: weeks since the season started
TRUST_MIN = 150                     # matches per phase before the phase can change the model's say
TRUST_SCALE = 0.03                  # a phase whose gap to the market is this much worse than the best phase gets no say...
TRUST_FLOOR = 0.4                   # ...but never less than 40% of the league's anchor
INTEGRITY_MOVE = 0.08               # idea 25: a no-vig probability moving 8 points or more...
INTEGRITY_WINDOW_MIN = 180          # ...within three hours is flagged on the fixture
INTEGRITY_BLOCK = False             # recording only; switch on (no new bets on flagged fixtures) if the Research tab shows the moves are informed
PATH_HOURS = (48, 24, 12, 6, 3, 1, 0)   # ideas 2 and 20: each settled fixture's prices kept at these hours before kick-off
WEATHER_WET_MM = 1.0                # idea 10: 1 mm or more of rain in the two hours from kick-off is 'wet'...
WEATHER_WINDY_KMH = 30              # ...otherwise a mean wind of 30 km/h or more is 'windy'; everything else 'fair'
WEATHER_SHRINK = 100                # a bucket's goal factor is shrunk towards 1 by n / (n + 100) and clipped to +-10%
REFEREE_SHRINK = 40                 # idea 22: a referee's goal factor is shrunk by n / (n + 40): referees have few matches
REFEREE_EVERY_H = 6                 # appointments (API-Football, one request per day of fixtures) refreshed every 6 hours
INPLAY_EVERY_S = int(os.environ.get('INPLAY_EVERY_S', '15'))   # idea 11: the in-play worker reads the books this often...
INPLAY_SCORE_EVERY_S = int(os.environ.get('INPLAY_SCORE_EVERY_S', '600'))   # ...and the live scores this often (API-Football free
                                    # plan: 100 requests a day, so 10 minutes; set 60 on a paid plan)
INPLAY_MAX_SCORE_AGE_S = 120        # no in-play bet unless the score was read in the last two minutes...
INPLAY_JUMP = 0.08                  # ...and no result price has jumped 8 points since the last read (a goal the feed has not seen)
INPLAY_FLOOR_EV = 0.06              # in-play bets need +6% (no red-card model, prices move during the bet delay)
JUMP_MIN = 0.08                     # goal reaction: a result price moving 8+ points between two reads is a goal (or a red card)
EXIT_SECONDS = (60, 120, 180, 300)  # ...and the paper trades are traded out (laid back) this long after the jump
EVENT_WINDOW_S = 330                # the book is recorded for this long after each jump
SUSP_MAX_S = 900                 # an empty book longer than this is the market closing (full time), not a goal check
COMMITTEE_ETA = 1.0                 # idea 27: the committee's weights, exp(-ETA x n x (loss - best loss)) per member...
COMMITTEE_MIN_N = 30                # ...over at least 30 settled fixtures in the league (fewer: the smallest proven weight)
COMMITTEE_DAYS = 180                # ...from the last six months
DISAGREE_BLOCK = None               # idea 31: e.g. 0.12 = no bet when the variants' probabilities span 12+ points (off until tested)
GUARD_OVERROUND = (0.95, 1.10)      # idea 33: a result book whose MID prices imply outside this is broken: no bet on the fixture
                                    # (mids, not backs: on 1 Oct thin League One / Two books 2 days out had back prices
                                    # implying 122-183% simply because the spreads were wide; that is thin, not broken)
THRESH_CS = 0.0                     # correct score: no probability gate (every score is a long shot); the EV floor still applies
GUARD_GAP = 0.25                    # ...nor when the model and the market are 25+ points apart on a result (a wrong team match?)
GUARD_LAMBDA = (0.15, 4.5)          # ...nor when a goal expectation falls outside this
GUARD_STALE_DAYS = 28               # results data this old in a league still being priced is a warning
BREAKER_N = 30                      # idea 32: a league's last 30 settled bets of the live model...
BREAKER_CLV = -0.03                 # ...averaging a closing-line value below -3% stops that league being featured...
BREAKER_RESUME = 0.0                # ...until its last 30 (featured or not) average back above 0
META_MIN = 300                      # idea 15: settled bets (with a closing price) before the mistakes model is fitted
META_SKIP_TEST = 0.40               # ...the threshold its out-of-sample test reports on
META_SKIP = None                    # ...e.g. 0.40 = skip bets predicted to beat the close less than 40% of the time (off until tested)
CLOSE_MIN = 150                     # ideas 2 / 20: settled fixtures with a price path before the closing-price model is fitted
CLOSE_RIDGE = 5.0                   # ...its ridge penalty
LEARN_EVERY_H = 24                  # both refitted by the pricing job once a day
REACTION_MIN = 60                   # idea 35: goal-reaction events needed before the reaction model plans paper trades
REACTION_RIDGE = 3.0                # ...its ridge penalty
REACTION_EDGE = 0.50                # ...and the predicted locked profit (per 50 staked) a trade must clear
REACTION_REFIT_S = 3600             # ...refitted by the in-play worker hourly
KEEP_SNAPSHOTS_DAYS = 14            # in-play snapshots are pruned after this (events keep their own price paths)
KEEP_QUOTES_DAYS = 7                # after this, only a fixture's last quote before kick-off is kept (disk: 1 GB)
KEEP_PARAMS_DAYS = 14

# ---------------------------------------------------------------- leagues
# source: ('fd', code) = football-data.co.uk season file mmz4281/<yyyy>/<code>.csv
#         ('fdx', code) = football-data.co.uk multi-season file new/<code>.csv
#         ('af', country) = API-Football top division of that country (needs API_FOOTBALL_KEY)
# slugs: Smarkets competition slugs. 'seen' = observed on the Smarkets API on 29 Sep 2026; the rest are expected names.
# Every slug the job sees is written to the competitions_seen table, so unmatched ones can be added here.
LEAGUES = [
    # England — every division the user asked for
    dict(code='E0', name='Premier League', country='england', source=('fd', 'E0'), slugs=['england-premier-league'], seen=True),
    dict(code='E1', name='Championship', country='england', source=('fd', 'E1'), slugs=['england-championship'], seen=True),
    dict(code='E2', name='League One', country='england', source=('fd', 'E2'), slugs=['england-league-1', 'england-league-one']),
    dict(code='E3', name='League Two', country='england', source=('fd', 'E3'), slugs=['england-league-2', 'england-league-two']),
    dict(code='EC', name='National League', country='england', source=('fd', 'EC'), slugs=['england-national-league']),
    # Idea 24 (30 Sep): more leagues, weaker markets. Second tiers with football-data season files (the pyramid fit
    # already reads them). Exact slugs only: slugs matched by country alone are never priced.
    dict(code='D2', name='2. Bundesliga', country='germany', source=('fd', 'D2'), slugs=['germany-2-bundesliga', 'germany-bundesliga-2']),
    dict(code='I2', name='Serie B', country='italy', source=('fd', 'I2'), slugs=['italy-serie-b']),
    dict(code='SP2', name='Segunda Division', country='spain', source=('fd', 'SP2'), slugs=['spain-segunda-division', 'spain-la-liga-2', 'spain-laliga-2']),
    dict(code='F2', name='Ligue 2', country='france', source=('fd', 'F2'), slugs=['france-ligue-2']),
    dict(code='SC1', name='Scottish Championship', country='scotland', source=('fd', 'SC1'), slugs=['scotland-championship']),
    dict(code='SC2', name='Scottish League One', country='scotland', source=('fd', 'SC2'), slugs=['scotland-league-one', 'scotland-league-1']),
    dict(code='SC3', name='Scottish League Two', country='scotland', source=('fd', 'SC3'), slugs=['scotland-league-two', 'scotland-league-2']),
    # Outside Europe, football-data multi-season files (MLS's slug seen on Smarkets on 30 Sep 2026; the rest expected)
    dict(code='USA', name='Major League Soccer', country='us', source=('fdx', 'USA'), slugs=['us-major-league-soccer'], seen=True),
    dict(code='BRA', name='Brasileirao Serie A', country='brazil', source=('fdx', 'BRA'), slugs=['brazil-serie-a']),
    dict(code='ARG', name='Argentine Primera', country='argentina', source=('fdx', 'ARG'), slugs=['argentina-liga-profesional-de-futbol', 'argentina-liga-profesional', 'argentina-primera-division'], seen=True),
    dict(code='MEX', name='Liga MX', country='mexico', source=('fdx', 'MEX'), slugs=['mexico-liga-mx', 'mexico-primera-division']),
    dict(code='JPN', name='J1 League', country='japan', source=('fdx', 'JPN'), slugs=['japan-j1-league', 'japan-j-league', 'japan-j-league-1']),
    dict(code='CHN', name='Chinese Super League', country='china', source=('fdx', 'CHN'), slugs=['china-super-league']),
    # API-Football by league id (needs API_FOOTBALL_KEY). Ids written from memory: each is checked against the name
    # and country API-Football returns and not used if they differ. Slugs seen on Smarkets on 29-30 Sep 2026.
    dict(code='ENN', name='National League North', country='england-n', source=('afid', (50, 'National League - North', 'England')), slugs=['england-national-league-north'], seen=True),
    dict(code='ENS', name='National League South', country='england-s', source=('afid', (51, 'National League - South', 'England')), slugs=['england-national-league-south'], seen=True),
    dict(code='BR2', name='Brasileirao Serie B', country='brazil-b', source=('afid', (72, 'Serie B', 'Brazil')), slugs=['brazil-serie-b'], seen=True),
    dict(code='USL', name='USL Championship', country='us-usl', source=('afid', (255, 'USL Championship', 'USA')), slugs=['us-usl-championship'], seen=True),
    dict(code='COL', name='Colombian Primera A', country='colombia', source=('af', 'Colombia'), slugs=['colombia-categoria-primera-a'], seen=True),
    dict(code='PER', name='Peruvian Liga 1', country='peru', source=('af', 'Peru'), slugs=['peru-liga-1'], seen=True),
    dict(code='URU', name='Uruguayan Primera', country='uruguay', source=('af', 'Uruguay'), slugs=['uruguay-primera-division'], seen=True),
    dict(code='CAN', name='Canadian Premier League', country='canada', source=('af', 'Canada'), slugs=['canada-premier-league'], seen=True),
    # Top flights feeding UEFA competitions — football-data.co.uk season files
    dict(code='SC0', name='Scottish Premiership', country='scotland', source=('fd', 'SC0'), slugs=['scotland-premiership']),
    dict(code='D1', name='Bundesliga', country='germany', source=('fd', 'D1'), slugs=['germany-bundesliga'], seen=True),
    dict(code='I1', name='Serie A', country='italy', source=('fd', 'I1'), slugs=['italy-serie-a']),
    dict(code='SP1', name='La Liga', country='spain', source=('fd', 'SP1'), slugs=['spain-la-liga'], seen=True),
    dict(code='F1', name='Ligue 1', country='france', source=('fd', 'F1'), slugs=['france-ligue-1'], seen=True),
    dict(code='N1', name='Eredivisie', country='netherlands', source=('fd', 'N1'), slugs=['netherlands-eredivisie'], seen=True),
    dict(code='B1', name='Belgian First Division A', country='belgium', source=('fd', 'B1'), slugs=['belgium-first-division-a'], seen=True),
    dict(code='P1', name='Primeira Liga', country='portugal', source=('fd', 'P1'), slugs=['portugal-primeira-liga'], seen=True),
    dict(code='T1', name='Super Lig', country='turkey', source=('fd', 'T1'), slugs=['turkey-super-lig'], seen=True),
    dict(code='G1', name='Greek Super League', country='greece', source=('fd', 'G1'), slugs=['greece-super-league']),
    # football-data.co.uk multi-season files
    dict(code='AUT', name='Austrian Bundesliga', country='austria', source=('fdx', 'AUT'), slugs=['austria-bundesliga']),
    dict(code='SWZ', name='Swiss Super League', country='switzerland', source=('fdx', 'SWZ'), slugs=['switzerland-super-league']),
    dict(code='DNK', name='Danish Superliga', country='denmark', source=('fdx', 'DNK'), slugs=['denmark-superliga'], seen=True),
    dict(code='NOR', name='Eliteserien', country='norway', source=('fdx', 'NOR'), slugs=['norway-premier-league', 'norway-eliteserien'], seen=True),
    dict(code='SWE', name='Allsvenskan', country='sweden', source=('fdx', 'SWE'), slugs=['sweden-allsvenskan']),
    dict(code='FIN', name='Veikkausliiga', country='finland', source=('fdx', 'FIN'), slugs=['finland-veikkausliiga']),
    dict(code='POL', name='Ekstraklasa', country='poland', source=('fdx', 'POL'), slugs=['poland-ekstraklasa']),
    dict(code='ROU', name='Liga I', country='romania', source=('fdx', 'ROU'), slugs=['romania-liga-1'], seen=True),
    dict(code='IRL', name='League of Ireland Premier', country='ireland', source=('fdx', 'IRL'), slugs=['ireland-premier-division'], seen=True),
    # API-Football (switch on by setting API_FOOTBALL_KEY). Top division looked up by country at run time.
    dict(code='CZE', name='Czech First League', country='czech-republic', source=('af', 'Czech-Republic'), slugs=['czech-republic-premier-league', 'czech-republic-first-league'], seen=True),
    dict(code='CYP', name='Cypriot First Division', country='cyprus', source=('af', 'Cyprus'), slugs=['cyprus-1-division'], seen=True),
    dict(code='BGR', name='Bulgarian First League', country='bulgaria', source=('af', 'Bulgaria'), slugs=['bulgaria-first-league', 'bulgaria-parva-liga', 'bulgaria-a-pfg']),
    dict(code='HRV', name='Croatian HNL', country='croatia', source=('af', 'Croatia'), slugs=['croatia-hnl', 'croatia-1-hnl', 'croatia-first-league']),
    dict(code='SRB', name='Serbian SuperLiga', country='serbia', source=('af', 'Serbia'), slugs=['serbia-superliga', 'serbia-super-liga']),
    dict(code='HUN', name='Hungarian NB I', country='hungary', source=('af', 'Hungary'), slugs=['hungary-nb-i', 'hungary-otp-bank-liga']),
    dict(code='SVK', name='Slovak Super Liga', country='slovakia', source=('af', 'Slovakia'), slugs=['slovakia-super-liga']),
    dict(code='SVN', name='Slovenian PrvaLiga', country='slovenia', source=('af', 'Slovenia'), slugs=['slovenia-prvaliga', 'slovenia-1-snl']),
    dict(code='ISR', name='Israeli Premier League', country='israel', source=('af', 'Israel'), slugs=['israel-premier-league']),
    dict(code='UKR', name='Ukrainian Premier League', country='ukraine', source=('af', 'Ukraine'), slugs=['ukraine-premier-league']),
    dict(code='KAZ', name='Kazakhstan Premier League', country='kazakhstan', source=('af', 'Kazakhstan'), slugs=['kazakhstan-premier-league']),
    dict(code='AZE', name='Azerbaijan Premier League', country='azerbaijan', source=('af', 'Azerbaijan'), slugs=['azerbaijan-premier-league']),
    dict(code='GEO', name='Erovnuli Liga', country='georgia', source=('af', 'Georgia'), slugs=['georgia-erovnuli-liga']),
    dict(code='ARM', name='Armenian Premier League', country='armenia', source=('af', 'Armenia'), slugs=['armenia-premier-league']),
    dict(code='BIH', name='Bosnian Premier League', country='bosnia-and-herzegovina', source=('af', 'Bosnia'), slugs=['bosnia-and-herzegovina-premier-league']),
    dict(code='MNE', name='Montenegrin First League', country='montenegro', source=('af', 'Montenegro'), slugs=['montenegro-first-league']),
    dict(code='MKD', name='Macedonian First League', country='north-macedonia', source=('af', 'Macedonia'), slugs=['north-macedonia-first-league']),
    dict(code='ALB', name='Albanian Superliga', country='albania', source=('af', 'Albania'), slugs=['albania-superliga']),
    dict(code='KOS', name='Kosovo Superleague', country='kosovo', source=('af', 'Kosovo'), slugs=['kosovo-superleague']),
    dict(code='MDA', name='Moldovan Super Liga', country='moldova', source=('af', 'Moldova'), slugs=['moldova-super-liga']),
    dict(code='LTU', name='A Lyga', country='lithuania', source=('af', 'Lithuania'), slugs=['lithuania-a-lyga']),
    dict(code='LVA', name='Latvian Virsliga', country='latvia', source=('af', 'Latvia'), slugs=['latvia-virsliga']),
    dict(code='EST', name='Meistriliiga', country='estonia', source=('af', 'Estonia'), slugs=['estonia-meistriliiga']),
    dict(code='ISL', name='Besta deild', country='iceland', source=('af', 'Iceland'), slugs=['iceland-besta-deild', 'iceland-premier-league']),
    dict(code='FRO', name='Faroe Islands Premier League', country='faroe-islands', source=('af', 'Faroe-Islands'), slugs=['faroe-islands-premier-league']),
    dict(code='WAL', name='Cymru Premier', country='wales', source=('af', 'Wales'), slugs=['wales-cymru-premier', 'wales-premier-league']),
    dict(code='NIR', name='NIFL Premiership', country='northern-ireland', source=('af', 'Northern-Ireland'), slugs=['northern-ireland-premiership']),
    dict(code='MLT', name='Maltese Premier League', country='malta', source=('af', 'Malta'), slugs=['malta-premier-league']),
    dict(code='LUX', name='Luxembourg National Division', country='luxembourg', source=('af', 'Luxembourg'), slugs=['luxembourg-national-division']),
    dict(code='AND', name='Andorran Primera Divisio', country='andorra', source=('af', 'Andorra'), slugs=['andorra-primera-divisio']),
    dict(code='SMR', name='Campionato Sammarinese', country='san-marino', source=('af', 'San-Marino'), slugs=['san-marino-campionato']),
    dict(code='GIB', name='Gibraltar Football League', country='gibraltar', source=('af', 'Gibraltar'), slugs=['gibraltar-premier-division']),
]
# Words in a Smarkets slug that mark a competition we do NOT price even if its country matches (lower tiers, cups, youth)
EXCLUDE_WORDS = ['2-', '-2', 'second', 'serie-b', 'ligue-2', '3-liga', 'third', 'cup', 'pokal', 'copa', 'coppa', 'coupe', 'women',
                 'u19', 'u21', 'u23', 'youth', 'reserve', 'play-off', 'playoff', 'friendl', 'super-cup', 'supercup', 'liga-2', 'division-2']
# European club competitions — priced from ClubElo (cross-league), band 'thin'
EUROPE_SLUG_WORDS = ['champions-league', 'europa-league', 'conference-league']
EUROPE_EXCLUDE = ['women', 'youth', 'afc', 'caf', 'concacaf', 'asia', 'africa', 'u19', 'qualif']   # qualifiers: add later if wanted
