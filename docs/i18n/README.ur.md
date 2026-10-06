# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> پروڈکشن کے لیے [`stable`](https://github.com/microclaw/microclaw/tree/stable) برانچ استعمال کریں۔ `main` تیزی سے تبدیل ہوتی ہے اور اس میں غیر موافق تبدیلیاں شامل ہو سکتی ہیں۔

**ہر گفتگو کے ذریعے کے لیے ایک قابلِ اعتماد agent runtime۔**

MicroClaw، Rust میں بنایا گیا self-hosted agent runtime ہے۔ ایک channel-independent agent loop اور provider-independent LLM layer، Telegram، Discord، Slack، Feishu/Lark، Web اور دیگر adapters میں یکساں tools، memory، policy اور recovery model فراہم کرتی ہے۔

یہ ایک درخواست سے زیادہ دیر چلنے والے کام کے لیے بنایا گیا ہے: multi-step tool use، resumable sessions، durable delivery، persistent memory، scheduled tasks، skills، MCP اور subagents ایک ہی runtime میں کام کرتے ہیں۔

## فوری آغاز

macOS یا Linux پر انسٹال کریں:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Windows PowerShell پر:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

ترتیب دے کر چلائیں:

```sh
microclaw doctor
microclaw setup
microclaw start
```

پھر [http://127.0.0.1:10961](http://127.0.0.1:10961) کھولیں۔ Homebrew، Docker، source build، Linux compatibility اور service installation کے لیے [Getting Started guide](../getting-started.md) دیکھیں۔

## MicroClaw کیوں

- **ایک runtime، کئی interfaces:** تمام channels میں یکساں behavior اور safety policy۔
- **قابلِ بحالی کام:** sessions، محفوظ checkpoints، scheduled work اور delivery، restart کے بعد دوبارہ جاری رہ سکتے ہیں۔
- **Provider کے انتخاب کی آزادی:** Anthropic، OpenAI-compatible services اور local models ایک مشترک internal model استعمال کرتے ہیں۔
- **واضح extension points:** skills، MCP servers، plugins، hooks، tools اور channel adapters۔
- **سادہ self-hosting:** Rust service اور embedded SQLite؛ الگ vector database ضروری نہیں۔
- **مشترک سکیورٹی:** tool approvals، محدود grants، egress control، sandbox، redaction اور audit trails۔

## اہم صلاحیتیں

- Multi-step tools، planning، progress updates اور subagents
- Persistent file/SQLite memory، semantic recall اور governed learning
- Scheduled tasks، context compaction اور resumable sessions
- Telegram، Discord، Slack، Feishu/Lark، Web اور متعدد دیگر channels
- Local Web UI اور HTTP، SSE، WebSocket، A2A، ACP اور MCP interfaces
- Docker sandbox، access policies، diagnostics، metrics اور traces

موجودہ فہرستوں کے لیے [generated tool catalog](../generated/tools.md) اور [provider matrix](../generated/provider-matrix.md) دیکھیں۔

## دستاویزات

- [Documentation map](../README.md)
- [Getting started](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Configuration defaults](../generated/config-defaults.md)
- [Operations runbook](../operations/runbook.md)
- [Secure runtime](../security/secure-runtime.md)

Commands اور configuration کے لیے ایک قابلِ اعتماد ماخذ برقرار رکھنے کی خاطر تفصیلی technical documentation انگریزی میں canonical ہے۔ [Translation policy](README.md) دیکھیں۔

## کمیونٹی اور لائسنس

[Discord](https://discord.gg/eGzEaP6TzR) اور [Reddit](https://www.reddit.com/r/microclaw/) پر کمیونٹی میں شامل ہوں۔ تعاون سے پہلے [CONTRIBUTING.md](../../CONTRIBUTING.md) پڑھیں۔

MicroClaw [MIT License](../../LICENSE) کے تحت دستیاب ہے۔
