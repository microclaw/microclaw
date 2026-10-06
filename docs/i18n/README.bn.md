# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> প্রোডাকশনের জন্য [`stable`](https://github.com/microclaw/microclaw/tree/stable) ব্রাঞ্চ ব্যবহার করুন। `main` দ্রুত পরিবর্তিত হয় এবং এতে breaking change থাকতে পারে।

**সব কথোপকথন মাধ্যমের জন্য একটি নির্ভরযোগ্য agent runtime।**

MicroClaw হলো Rust-এ তৈরি একটি self-hosted agent runtime। একটি channel-independent agent loop এবং provider-independent LLM layer Telegram, Discord, Slack, Feishu/Lark, Web ও অন্যান্য adapter-এর মধ্যে একই tools, memory, policy এবং recovery model ভাগ করে।

এটি একটি অনুরোধের চেয়ে দীর্ঘ কাজের জন্য তৈরি: multi-step tool use, resumable session, durable delivery, persistent memory, scheduled task, skills, MCP এবং subagent একই runtime-এ কাজ করে।

## দ্রুত শুরু

macOS বা Linux-এ ইনস্টল করুন:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Windows PowerShell-এ:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

কনফিগার করে চালু করুন:

```sh
microclaw doctor
microclaw setup
microclaw start
```

এরপর [http://127.0.0.1:10961](http://127.0.0.1:10961) খুলুন। Homebrew, Docker, source build, Linux compatibility এবং service installation-এর জন্য [Getting Started guide](../getting-started.md) দেখুন।

## কেন MicroClaw

- **এক runtime, অনেক interface:** সব channel-এ একই behavior এবং safety policy।
- **পুনরুদ্ধারযোগ্য কাজ:** session, safe checkpoint, scheduled work এবং delivery restart-এর পর আবার চলতে পারে।
- **Provider বেছে নেওয়ার স্বাধীনতা:** Anthropic, OpenAI-compatible service এবং local model একই internal model ব্যবহার করে।
- **পরিষ্কার extension point:** skills, MCP server, plugin, hook, tool এবং channel adapter।
- **সহজ self-hosting:** Rust service ও embedded SQLite; আলাদা vector database বাধ্যতামূলক নয়।
- **একীভূত নিরাপত্তা:** tool approval, scoped grant, egress control, sandbox, redaction এবং audit trail।

## প্রধান সক্ষমতা

- Multi-step tool, planning, progress update এবং subagent
- Persistent file/SQLite memory, semantic recall এবং governed learning
- Scheduled task, context compaction এবং resumable session
- Telegram, Discord, Slack, Feishu/Lark, Web এবং আরও অনেক channel
- Local Web UI ও HTTP, SSE, WebSocket, A2A, ACP এবং MCP interface
- Docker sandbox, access policy, diagnostics, metrics এবং traces

বর্তমান তালিকার জন্য [generated tool catalog](../generated/tools.md) এবং [provider matrix](../generated/provider-matrix.md) দেখুন।

## ডকুমেন্টেশন

- [Documentation map](../README.md)
- [Getting started](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Configuration defaults](../generated/config-defaults.md)
- [Operations runbook](../operations/runbook.md)
- [Secure runtime](../security/secure-runtime.md)

Command ও configuration-এর একটিমাত্র নির্ভরযোগ্য উৎস বজায় রাখতে বিস্তারিত technical documentation ইংরেজিতে canonical রাখা হয়। [Translation policy](README.md) দেখুন।

## কমিউনিটি ও লাইসেন্স

[Discord](https://discord.gg/eGzEaP6TzR) এবং [Reddit](https://www.reddit.com/r/microclaw/)-এ কমিউনিটিতে যোগ দিন। অবদান রাখার আগে [CONTRIBUTING.md](../../CONTRIBUTING.md) পড়ুন।

MicroClaw [MIT License](../../LICENSE)-এর অধীনে প্রকাশিত।
