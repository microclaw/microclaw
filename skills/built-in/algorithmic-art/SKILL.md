---
name: algorithmic-art
description: "Create generative / algorithmic art and visual patterns with code — fractals, geometric tilings, flow fields, color gradients, parametric shapes — rendered to an image. Use when users want procedurally generated art, a cool pattern, a wallpaper, or 'make something with code'. Triggers on mentions of generative art, algorithmic art, fractal, pattern, procedural, flow field, wallpaper, 生成艺术, 算法艺术, 分形, 图案, 壁纸."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires python3 with Pillow (PIL) for raster output, or stdlib for SVG. Works on macOS, Linux, and Windows."
---

# Algorithmic Art

Make art from rules. Render to a file under `tmp/`, then send it with `send_message`.
For raster, check `python3 -c "import PIL"`; if Pillow is missing, generate SVG with the stdlib (no deps).

## SVG (no dependencies) — generative grid

```bash
python3 - <<'PY'
import random, math
W=H=600; cells=20; s=W//cells
parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}">',
       f'<rect width="{W}" height="{H}" fill="#0b1021"/>']
for i in range(cells):
    for j in range(cells):
        hue=(i*j*7)%360
        r=random.uniform(3, s/2)
        parts.append(f'<circle cx="{i*s+s//2}" cy="{j*s+s//2}" r="{r:.1f}" '
                     f'fill="hsl({hue},70%,60%)" opacity="0.8"/>')
parts.append('</svg>')
open("tmp/art.svg","w").write("\n".join(parts))
print("wrote tmp/art.svg")
PY
```

## Raster with Pillow — fractal (Mandelbrot)

```bash
python3 - <<'PY'
from PIL import Image
W=H=700; img=Image.new("RGB",(W,H))
px=img.load()
for x in range(W):
    for y in range(H):
        c=complex(-2.2+3.0*x/W, -1.5+3.0*y/H); z=0; i=0
        while abs(z)<=2 and i<60: z=z*z+c; i+=1
        px[x,y]=(i*4%256, i*7%256, i*11%256)
img.save("tmp/mandelbrot.png")
print("wrote tmp/mandelbrot.png")
PY
```

## Ideas to vary

- Fractals (Mandelbrot/Julia), flow fields (Perlin-ish noise on a vector grid),
  recursive trees, circle/Truchet tilings, color-gradient meshes, parametric curves (Lissajous).
- Expose a few parameters (palette, density, seed) and iterate with the user.

## Guidance

- Save under `tmp/` and deliver via `send_message` with `attachment_path`.
- SVG scales crisply and needs no deps — prefer it for geometric work; use Pillow for per-pixel.
- Keep render sizes reasonable (≤ ~1000px) so it's fast; offer to upscale if they like it.
- For prompt-driven realistic images (not code-based art), use the `generate_image` tool instead.
