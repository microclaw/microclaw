---
name: qrcode
description: "Generate a QR code from text, a URL, Wi-Fi credentials, or contact info, as a PNG file or terminal art. Use when users want to make/create a QR code for a link, password, or message. Triggers on mentions of QR code, qrcode, generate qr, scan code, 二维码, 生成二维码, 扫码."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Prefers the qrencode CLI; falls back to python3 (qrcode/segno) if installed. Works on macOS, Linux, and Windows."
---

# QR Code

Generate the QR code to a file, then send it with `send_message` (attachment). Check for a
tool first: `command -v qrencode`, else try Python.

## With qrencode (preferred)

```bash
qrencode -o tmp/qr.png -s 8 "https://example.com"      # PNG
qrencode -t ANSIUTF8 "https://example.com"             # preview in terminal
```

## Python fallback

```bash
# Try whichever is installed: segno (no deps) or qrcode (needs Pillow)
python3 - <<'PY'
try:
    import segno
    segno.make("https://example.com").save("tmp/qr.png", scale=8)
except ImportError:
    import qrcode
    qrcode.make("https://example.com").save("tmp/qr.png")
print("wrote tmp/qr.png")
PY
```

## Useful payload formats

- URL: `https://example.com`
- Wi-Fi: `WIFI:T:WPA;S:<ssid>;P:<password>;;`
- Email: `mailto:someone@example.com`
- Phone: `tel:+15551234567`
- Plain text: any string.

## Guidance

- Write images under the chat working directory's `tmp/`, then send via `send_message` with `attachment_path`.
- Keep the payload short — dense QR codes scan poorly; for long URLs consider shortening first.
- If neither qrencode nor a Python QR lib is available, say so and offer the terminal-art form or installation hint.
