"""Weather for idea 10 from Open-Meteo (free, no key): the forecast for an upcoming match and the recorded weather for
past matches. Summarised over the two hours from kick-off: rain (mm, summed), wind (km/h, mean) and temperature (C)."""
import datetime as dt
import requests
from .. import config as C

S = requests.Session(); S.headers['User-Agent'] = C.USER_AGENT
FORECAST = 'https://api.open-meteo.com/v1/forecast'
ARCHIVE = 'https://archive-api.open-meteo.com/v1/archive'
HOURLY = 'precipitation,wind_speed_10m,temperature_2m'


def _get(url, lat, lon, start, end):
    r = S.get(url, params=dict(latitude=round(lat, 4), longitude=round(lon, 4), hourly=HOURLY, start_date=start.isoformat(),
                               end_date=end.isoformat(), timezone='UTC'), timeout=60)
    r.raise_for_status()
    h = r.json().get('hourly') or {}
    return {t: (p, w, tc) for t, p, w, tc in zip(h.get('time', []), h.get('precipitation', []), h.get('wind_speed_10m', []), h.get('temperature_2m', []))}


def summarise(series, kickoff):
    """series: {'YYYY-MM-DDTHH:00': (rain, wind, temp)} in UTC. -> dict(rain, wind, temp) over kick-off + 2h, or None."""
    k = kickoff.replace(minute=0, second=0, microsecond=0, tzinfo=None)
    hrs = [series.get((k + dt.timedelta(hours=i)).strftime('%Y-%m-%dT%H:00')) for i in range(3)]
    hrs = [x for x in hrs if x and x[0] is not None]
    if not hrs: return None
    return dict(rain=round(sum(x[0] for x in hrs), 2), wind=round(sum(x[1] or 0 for x in hrs) / len(hrs), 1),
                temp=round(sum(x[2] or 0 for x in hrs) / len(hrs), 1))


def forecast(lat, lon, kickoff):
    d = kickoff.date()
    return summarise(_get(FORECAST, lat, lon, d, d + dt.timedelta(days=1)), kickoff)


def history(lat, lon, start, end):
    """Recorded hourly weather between two dates (one request); summarise() per match."""
    return _get(ARCHIVE, lat, lon, start, end)


def bucket(w):
    """The weather bucket a match falls in (C.WEATHER_* thresholds)."""
    if not w: return None
    if w['rain'] >= C.WEATHER_WET_MM: return 'wet'
    if w['wind'] >= C.WEATHER_WINDY_KMH: return 'windy'
    return 'fair'
