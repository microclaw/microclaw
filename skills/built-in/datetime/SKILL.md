---
name: datetime
description: "Do date and time math: differences between dates, 'days until' a deadline, add/subtract durations, weekday of a date, and timezone conversions. Use when users ask how many days until X, what day of the week a date is, convert a time between zones, or compute an age/duration. Triggers on mentions of days until, how long until, what day is, weekday, timezone, time difference, countdown, 还有几天, 倒计时, 星期几, 时区, 时间差, 几点."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# Date & Time

Compute dates with code — humans miscount days, leap years, and DST. Prefer the bot's
`get_current_time` / `compare_time` tools for "now" and deltas; use this for richer math.

## Difference between two dates

```bash
python3 -c "from datetime import date; print((date(2026,12,31)-date(2026,5,31)).days, 'days')"
```

## Days until a deadline (from today)

```bash
python3 -c "from datetime import date; d=date(2026,9,1); print((d-date.today()).days, 'days to go')"
```

## Weekday of a date

```bash
python3 -c "from datetime import date; print(date(2026,5,31).strftime('%A'))"
```

## Add / subtract a duration

```bash
python3 -c "from datetime import date,timedelta; print(date.today()+timedelta(days=90))"
```

## Timezone conversion

```bash
python3 -c "
from datetime import datetime
from zoneinfo import ZoneInfo
t = datetime(2026,5,31,9,0,tzinfo=ZoneInfo('America/New_York'))
print(t.astimezone(ZoneInfo('Asia/Shanghai')))
"
```

## Guidance

- Use IANA zone names (`Asia/Shanghai`, `Europe/London`), not raw offsets — they handle DST.
- State the timezone in your answer when it matters; ambiguity here causes real mistakes.
- For business-day counts (excluding weekends/holidays), say so and compute explicitly.
