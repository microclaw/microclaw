---
name: unit-converter
description: "Convert between units of measurement precisely: length, mass/weight, temperature, area, volume, speed, data sizes, and time. Use when users ask to convert X to Y, 'how many cm in an inch', 'what's 70F in C', 'GB to MB', or mix metric and imperial. Triggers on mentions of convert, conversion, in inches/cm/km/miles, kg/lb, Celsius/Fahrenheit, 换算, 转换, 多少厘米, 多少公斤, 摄氏, 华氏."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# Unit Converter

Compute conversions, don't approximate from memory. Use Python so the factor is exact.

## Common conversions

```bash
python3 -c "print(5*2.54, 'cm')"                 # inches -> cm
python3 -c "print(70*9/5+32, 'F')"               # 70C -> F (use (F-32)*5/9 for F->C)
python3 -c "print(round(100/1.609344,3), 'mi')"  # km -> miles
python3 -c "print(180/2.2046226218, 'kg')"       # lb -> kg
```

## Data sizes (binary vs decimal)

```bash
python3 -c "print(5*1024, 'MiB =', 5, 'GiB (binary)')"
python3 -c "print(5*1000, 'MB  =', 5, 'GB (decimal)')"
```
State which convention you used — `GiB` (1024) vs `GB` (1000) — they differ ~7%.

## Reference factors

- Length: 1 in = 2.54 cm; 1 ft = 0.3048 m; 1 mi = 1.609344 km; 1 nmi = 1.852 km.
- Mass: 1 lb = 0.45359237 kg; 1 oz = 28.349523125 g; 1 stone = 6.35029 kg.
- Temp: C = (F−32)·5/9; F = C·9/5+32; K = C+273.15.
- Volume: 1 US gal = 3.785411784 L; 1 imp gal = 4.54609 L; 1 cup(US) = 236.588 mL.
- Speed: 1 mph = 1.609344 km/h; 1 knot = 1.852 km/h; 1 m/s = 3.6 km/h.

## Guidance

- Always show the resulting number AND the unit; round sensibly (don't report 11 decimals).
- For US vs Imperial gallons/pints, ask or assume US and say so.
- For currency, this is not the right skill — exchange rates change; use a live source.
