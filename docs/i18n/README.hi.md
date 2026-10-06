# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> उत्पादन के लिए [`stable`](https://github.com/microclaw/microclaw/tree/stable) ब्रांच का उपयोग करें। `main` तेज़ी से बदलती है और इसमें breaking changes हो सकते हैं।

**हर संवाद माध्यम के लिए एक भरोसेमंद एजेंट रनटाइम।**

MicroClaw Rust में बना एक self-hosted agent runtime है। इसका एक channel-independent agent loop और provider-independent LLM layer Telegram, Discord, Slack, Feishu/Lark, Web और अन्य adapters को एक ही tools, memory, policy और recovery model देता है।

यह केवल एक प्रश्न का उत्तर देने के लिए नहीं, बल्कि लंबे समय तक चलने वाले काम के लिए बनाया गया है: multi-step tool use, resumable sessions, durable delivery, persistent memory, scheduled tasks, skills, MCP और subagents एक ही runtime में काम करते हैं।

## त्वरित शुरुआत

macOS या Linux पर install करें:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Windows PowerShell पर:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Configuration बनाकर runtime शुरू करें:

```sh
microclaw doctor
microclaw setup
microclaw start
```

फिर [http://127.0.0.1:10961](http://127.0.0.1:10961) खोलें। Homebrew, Docker, source build, Linux compatibility और service installation के लिए [Getting Started guide](../getting-started.md) देखें।

## MicroClaw क्यों

- **एक runtime, कई interfaces:** सभी channels पर समान agent behavior और safety policy।
- **काम बीच में नहीं खोता:** sessions, safe checkpoints, scheduled work और outbound delivery restart के बाद फिर चल सकते हैं।
- **Provider की स्वतंत्रता:** Anthropic, OpenAI-compatible services और local models के लिए साझा internal model।
- **स्पष्ट extension points:** skills, MCP servers, plugins, hooks, tools और channel adapters।
- **सरल self-hosting:** Rust service और embedded SQLite; अलग vector database अनिवार्य नहीं।
- **साझी सुरक्षा:** tool approvals, scoped grants, egress control, sandboxing, redaction और audit trails।

## मुख्य क्षमताएँ

- Multi-step tools, planning, progress updates और subagents
- Persistent file/SQLite memory, semantic recall और governed learning
- Scheduled tasks, context compaction और resumable sessions
- Telegram, Discord, Slack, Feishu/Lark, Web तथा अनेक अन्य channels
- Local Web UI और HTTP, SSE, WebSocket, A2A, ACP तथा MCP interfaces
- Docker sandbox, access policies, diagnostics, metrics और traces

वर्तमान tools और providers के लिए [generated tool catalog](../generated/tools.md) और [provider matrix](../generated/provider-matrix.md) देखें।

## दस्तावेज़

- [Documentation map](../README.md)
- [Getting started](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Configuration defaults](../generated/config-defaults.md)
- [Operations runbook](../operations/runbook.md)
- [Secure runtime](../security/secure-runtime.md)

Commands और configuration की एक ही भरोसेमंद source बनाए रखने के लिए विस्तृत technical documentation अंग्रेज़ी में canonical है। भाषा संबंधी नियम [translation policy](README.md) में हैं।

## समुदाय और लाइसेंस

[Discord](https://discord.gg/eGzEaP6TzR) और [Reddit](https://www.reddit.com/r/microclaw/) पर समुदाय से जुड़ें। योगदान देने से पहले [CONTRIBUTING.md](../../CONTRIBUTING.md) पढ़ें।

MicroClaw [MIT License](../../LICENSE) के अंतर्गत उपलब्ध है।
