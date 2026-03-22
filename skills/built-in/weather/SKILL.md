---
name: weather
description: "Get current weather conditions and short forecasts using `wttr.in` (no API key required). Use when users ask for weather, temperature, forecast, or conditions for a city, region, or location. Triggers on mentions of weather, forecast, temperature, rain, sunny, or climate."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires curl. Works on macOS, Linux, and Windows."
---

# Weather

Use this skill for quick weather lookups without API keys.

## Current weather

```bash
curl -s "wttr.in/San+Francisco?format=3"
```

## Compact format

```bash
curl -s "wttr.in/San+Francisco?format=%l:+%c+%t+%h+%w"
```

## Multi-day forecast

```bash
curl -s "wttr.in/San+Francisco?m"
```

## Usage guidance

- URL-encode spaces with `+`.
- Use `?m` for metric and `?u` for US units.
- For ambiguous place names, clarify state/country first.
