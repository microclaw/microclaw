# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> Untuk produksi, gunakan branch [`stable`](https://github.com/microclaw/microclaw/tree/stable). `main` berubah dengan cepat dan dapat berisi perubahan yang tidak kompatibel.

**Runtime agen yang andal untuk setiap antarmuka percakapan.**

MicroClaw adalah runtime agen self-hosted yang ditulis dengan Rust. Satu agent loop yang tidak bergantung pada channel dan satu lapisan LLM yang tidak bergantung pada provider membagikan tools, memory, policy, dan recovery yang sama ke Telegram, Discord, Slack, Feishu/Lark, Web, dan adapter lainnya.

MicroClaw dirancang untuk pekerjaan yang berlangsung lebih dari satu permintaan: penggunaan tools bertahap, sesi yang dapat dilanjutkan, pengiriman yang tahan gangguan, memory persisten, tugas terjadwal, skills, MCP, dan subagent berjalan dalam runtime yang sama.

## Mulai cepat

Instal di macOS atau Linux:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Di Windows PowerShell:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Konfigurasikan dan jalankan:

```sh
microclaw doctor
microclaw setup
microclaw start
```

Kemudian buka [http://127.0.0.1:10961](http://127.0.0.1:10961). Lihat [panduan memulai](../getting-started.md) untuk Homebrew, Docker, build dari source, kompatibilitas Linux, dan instalasi sebagai service.

## Mengapa MicroClaw

- **Satu runtime, banyak antarmuka:** perilaku dan kebijakan keamanan yang sama di semua channel.
- **Pekerjaan dapat dipulihkan:** sesi, checkpoint aman, tugas terjadwal, dan pengiriman dapat dilanjutkan setelah restart.
- **Bebas memilih provider:** Anthropic, layanan OpenAI-compatible, dan model lokal memakai model internal yang sama.
- **Titik ekstensi yang jelas:** skills, MCP server, plugin, hook, tool, dan channel adapter.
- **Self-hosting sederhana:** layanan Rust dengan SQLite tertanam, tanpa mewajibkan vector database terpisah.
- **Keamanan terpadu:** persetujuan tool, izin terbatas, kontrol egress, sandbox, redaction, dan audit trail.

## Kemampuan utama

- Tool bertahap, perencanaan, pembaruan progres, dan subagent
- Memory persisten berbasis file/SQLite, semantic recall, dan governed learning
- Tugas terjadwal, context compaction, dan sesi yang dapat dilanjutkan
- Telegram, Discord, Slack, Feishu/Lark, Web, dan banyak channel lainnya
- Web UI lokal serta antarmuka HTTP, SSE, WebSocket, A2A, ACP, dan MCP
- Docker sandbox, access policy, diagnostics, metrics, dan traces

Lihat [katalog tool yang dibuat otomatis](../generated/tools.md) dan [matriks provider](../generated/provider-matrix.md) untuk daftar terkini.

## Dokumentasi

- [Peta dokumentasi](../README.md)
- [Panduan memulai](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Default konfigurasi](../generated/config-defaults.md)
- [Runbook operasi](../operations/runbook.md)
- [Runtime aman](../security/secure-runtime.md)

Dokumentasi teknis terperinci dipelihara dalam bahasa Inggris sebagai sumber kanonis agar command dan konfigurasi tidak berbeda antar-terjemahan. Lihat [kebijakan terjemahan](README.md).

## Komunitas dan lisensi

Bergabunglah dengan komunitas di [Discord](https://discord.gg/eGzEaP6TzR) dan [Reddit](https://www.reddit.com/r/microclaw/). Baca [CONTRIBUTING.md](../../CONTRIBUTING.md) sebelum berkontribusi.

MicroClaw tersedia di bawah [Lisensi MIT](../../LICENSE).
