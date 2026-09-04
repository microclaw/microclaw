---
name: color-tools
description: "Work with colors: convert between HEX/RGB/HSL, build palettes, find complementary/analogous colors, and check text contrast for accessibility (WCAG). Use when users ask to convert a color, lighten/darken it, build a color scheme, or check if a color combo is readable. Triggers on mentions of color, colour, hex, rgb, hsl, palette, contrast, complementary, shade, 颜色, 配色, 色值, 对比度, 调色板."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3. Works on macOS, Linux, and Windows."
---

# Color Tools

Compute color math; don't eyeball hex values.

## HEX ↔ RGB ↔ HSL

```bash
python3 - <<'PY'
import colorsys
def hex_to_rgb(h): h=h.lstrip('#'); return tuple(int(h[i:i+2],16) for i in (0,2,4))
def rgb_to_hex(r,g,b): return '#%02x%02x%02x'%(r,g,b)
r,g,b = hex_to_rgb('#3b82f6')
h,l,s = colorsys.rgb_to_hls(r/255,g/255,b/255)
print('rgb', (r,g,b))
print('hsl', (round(h*360), round(s*100), round(l*100)))
print('hex', rgb_to_hex(r,g,b))
PY
```

## Lighten / darken (adjust HSL lightness)

```bash
python3 - <<'PY'
import colorsys
def adjust(hex_, dl):
    h=hex_.lstrip('#'); r,g,b=(int(h[i:i+2],16)/255 for i in (0,2,4))
    H,L,S=colorsys.rgb_to_hls(r,g,b); L=max(0,min(1,L+dl))
    r,g,b=colorsys.hls_to_rgb(H,L,S); return '#%02x%02x%02x'%(int(r*255),int(g*255),int(b*255))
print('lighter', adjust('#3b82f6', +0.15))
print('darker ', adjust('#3b82f6', -0.15))
PY
```

## Contrast ratio (accessibility, WCAG)

```bash
python3 - <<'PY'
def lin(c): c/=255; return c/12.92 if c<=0.03928 else ((c+0.055)/1.055)**2.4
def lum(h): h=h.lstrip('#'); r,g,b=(int(h[i:i+2],16) for i in (0,2,4)); return 0.2126*lin(r)+0.7152*lin(g)+0.0722*lin(b)
def ratio(a,b): L1,L2=sorted([lum(a),lum(b)],reverse=True); return (L1+0.05)/(L2+0.05)
r=ratio('#ffffff','#3b82f6'); print(f'contrast {r:.2f}:1', '(AA body needs >=4.5)')
PY
```

## Guidance

- Palettes: complementary = +180° hue; analogous = ±30°; triadic = ±120°.
- For body text, aim for contrast ≥ 4.5:1 (AA); ≥ 3:1 for large text.
- Always state colors as hex in the answer so they're copy-pasteable.
