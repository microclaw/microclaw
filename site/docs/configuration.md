---
id: configuration
title: Configuration
sidebar_position: 4
---

All configuration is via `microclaw.config.yaml`.

For anti-drift defaults, use [Generated Config Defaults](./generated-config-defaults) and [Generated Provider Matrix](./generated-provider-matrix), produced from code by `scripts/generate_docs_artifacts.mjs`.

## Required

| Key | Description |
|---|---|
| `api_key` | LLM API key (`ollama` can be empty; `openai-codex` supports OAuth or `api_key`) |

At runtime, at least one channel must be enabled:
- Telegram (`channels.telegram.accounts.<id>.bot_token`)
- Discord (`channels.discord.accounts.<id>.bot_token`)
- Slack (per-account tokens under `channels.slack.accounts.<id>`)
- Feishu/Lark (per-account credentials under `channels.feishu.accounts.<id>`)
- IRC (`channels.irc.server` + `channels.irc.nick` + `channels.irc.channels`)
- Web UI (`web_enabled: true`)

## Optional

| Key | Default | Description |
|---|---|---|
| `channels.telegram.default_account` | unset | Default Telegram account ID in multi-account mode. If unset, uses `default` when present, otherwise first account key (sorted) |
| `channels.telegram.provider_preset` | unset | Optional Telegram channel-level provider profile override |
| `channels.telegram.accounts.<id>.bot_token` | unset | Telegram bot token for a specific account (recommended multi-account mode) |
| `channels.telegram.accounts.<id>.bot_username` | unset | Telegram username for a specific account (without `@`) |
| `channels.telegram.accounts.<id>.provider_preset` | unset | Optional per-bot provider profile override for this Telegram account |
| `channels.telegram.accounts.<id>.model` | unset | Optional per-bot model override for this Telegram account |
| `channels.telegram.accounts.<id>.soul_path` | unset | Optional per-bot SOUL file path for this Telegram account |
| `channels.telegram.topic_routing.enabled` | `false` | If true, Telegram forum topics are routed as separate chats via `external_chat_id=<chat_id>:<thread_id>` |
| `channels.telegram.accounts.<id>.topic_routing.enabled` | inherit channel-level | Optional per-account override for Telegram topic routing |
| `channels.telegram.accounts.<id>.allowed_groups` | `[]` | Optional Telegram group allowlist scoped to that account |
| `channels.telegram.allowed_user_ids` | `[]` | Optional Telegram private-chat sender allowlist at channel scope |
| `channels.telegram.accounts.<id>.allowed_user_ids` | `[]` | Optional Telegram private-chat sender allowlist scoped to that account (merged with channel scope) |
| `channels.discord.default_account` | unset | Default Discord account ID in multi-account mode. If unset, uses `default` when present, otherwise first account key (sorted) |
| `channels.discord.provider_preset` | unset | Optional Discord channel-level provider profile override |
| `channels.discord.accounts.<id>.bot_token` | unset | Discord bot token for a specific account |
| `channels.discord.accounts.<id>.allowed_channels` | `[]` | Optional Discord channel allowlist scoped to that account |
| `channels.discord.accounts.<id>.no_mention` | `false` | If true, that Discord account replies in guild channels without mention |
| `channels.discord.accounts.<id>.provider_preset` | unset | Optional per-bot provider profile override for this Discord account |
| `channels.discord.accounts.<id>.model` | unset | Optional per-bot model override for this Discord account |
| `channels.discord.accounts.<id>.soul_path` | unset | Optional per-bot SOUL file path for this Discord account |
| `allow_group_slash_without_mention` | `false` | If true, group/server/channel slash commands can run without @mention (default remains mention-gated in groups/channels) |
| `channels.slack.default_account` | unset | Default Slack account ID in multi-account mode |
| `channels.slack.accounts.<id>.bot_token` | unset | Slack bot token for a specific account |
| `channels.slack.accounts.<id>.app_token` | unset | Slack app token (Socket Mode) for a specific account |
| `channels.slack.accounts.<id>.allowed_channels` | `[]` | Optional Slack channel allowlist scoped to that account |
| `channels.slack.accounts.<id>.model` | unset | Optional per-bot model override for this Slack account |
| `channels.slack.accounts.<id>.soul_path` | unset | Optional per-bot SOUL file path for this Slack account |
| `channels.feishu.default_account` | unset | Default Feishu/Lark account ID in multi-account mode |
| `channels.feishu.accounts.<id>.app_id` | unset | Feishu/Lark app ID for a specific account |
| `channels.feishu.accounts.<id>.app_secret` | unset | Feishu/Lark app secret for a specific account |
| `channels.feishu.accounts.<id>.domain` | `feishu` | Domain for that account (`feishu`, `lark`, or custom URL) |
| `channels.feishu.accounts.<id>.allowed_chats` | `[]` | Optional Feishu chat allowlist scoped to that account |
| `channels.feishu.accounts.<id>.provider_preset` | unset | Optional per-bot provider profile override for this Feishu/Lark account |
| `channels.feishu.accounts.<id>.model` | unset | Optional per-bot model override for this Feishu/Lark account |
| `channels.feishu.accounts.<id>.soul_path` | unset | Optional per-bot SOUL file path for this Feishu/Lark account |
| `channels.feishu.accounts.<id>.topic_mode` | `false` | Optional per-bot threaded reply mode; only supported for account domain `feishu` or `lark` |
| `bot_username` | `""` | Global default bot username (used by all channels unless overridden) |
| `web_enabled` | `true` | Enable local Web UI channel |
| `llm_provider` | `anthropic` | Global main LLM provider profile. Built-ins include `anthropic`, `openai`, `google`, `aliyun-bailian`, `nvidia`, `openrouter`, `ollama`, and `custom` |
| `model` | provider-specific | Model name |
| `provider_presets.<id>` | `{}` | Optional reusable provider profiles for channel/bot overrides. Each profile can define `provider`, `api_key`, `llm_base_url`, `llm_user_agent`, `default_model`, and `show_thinking` |
| `show_thinking` | `false` | Show model reasoning/thinking text in channel output when the selected provider/profile supports it |
| `llm_base_url` | provider preset default | Optional custom base URL |
| `openai_compat_body_overrides` | `{}` | Global request-body overrides for OpenAI-compatible providers (`openai`, `openrouter`, `deepseek`, `ollama`, etc.) |
| `openai_compat_body_overrides_by_provider` | `{}` | Provider-specific OpenAI-compatible request-body overrides (keyed by provider name, case-insensitive) |
| `openai_compat_body_overrides_by_model` | `{}` | Model-specific OpenAI-compatible request-body overrides (keyed by exact model name) |
| `data_dir` | `~/.microclaw` | Data root (`runtime` data in `data_dir/runtime`, skills in `data_dir/skills`) |
| `working_dir` | `~/.microclaw/working_dir` | Default working directory for `bash/read_file/write_file/edit_file/glob/grep`; relative paths resolve from here |
| `override_timezone` | unset | Optional IANA timezone override (for example `Asia/Shanghai`). Default behavior uses detected system timezone; override is applied only when this field is set. |
| `working_dir_isolation` | `chat` | Working directory isolation mode for `bash/read_file/write_file/edit_file/glob/grep`: `shared` uses `working_dir/shared`, `chat` isolates each chat under `working_dir/chat/<channel>/<chat_id>` |
| `high_risk_tool_user_confirmation_required` | `true` | Require explicit user confirmation before high-risk tool execution (for example `bash`) |
| `sandbox.mode` | `off` | Bash execution mode: `off` runs on host; `all` routes bash tool calls to sandbox containers |
| `sandbox.backend` | `auto` | Sandbox backend (`auto`/`docker`/`podman`) |
| `sandbox.image` | `ubuntu:25.10` | Base image used for sandbox containers |
| `sandbox.container_prefix` | `microclaw-sandbox` | Prefix for sandbox container names |
| `sandbox.security_profile` | `hardened` | Sandbox privilege profile: `hardened` (`--cap-drop ALL --security-opt no-new-privileges`), `standard` (default container caps), `privileged` (`--privileged`) |
| `sandbox.cap_add` | `[]` | Optional extra Linux capabilities added with `--cap-add` (applies to `hardened` and `standard`) |
| `sandbox.no_network` | `true` | If true, sandbox containers run with `--network=none` |
| `sandbox.require_runtime` | `true` | If true and configured container runtime is unavailable while `sandbox.mode=all`, command fails fast instead of host fallback |
| `sandbox.mount_allowlist_path` | unset | Optional external mount allowlist file (one allowed root path per line) |
| `max_tokens` | `8192` | Max tokens per LLM response |
| `max_tool_iterations` | `100` | Max tool-use loop iterations per message |
| `max_document_size_mb` | `100` | Maximum allowed inbound Telegram document size (files above limit are rejected with a hint message) |
| `max_history_messages` | `50` | Number of recent messages sent as context |
| `control_chat_ids` | `[]` | Chat IDs allowed to perform cross-chat tool actions |
| `plugins.enabled` | `false` | Enable plugin manifest loading and plugin command/tool/context runtime |
| `plugins.dir` | `<data_dir>/plugins` | Optional plugin manifest directory override |
| `max_session_messages` | `40` | Message threshold that triggers context compaction |
| `compact_keep_recent` | `20` | Number of recent messages kept verbatim during compaction |
| `anthropic_prompt_cache_enabled` | `true` | Add up to 4 `cache_control` breakpoints (system + last 3 messages) to every Anthropic request so multi-turn chats hit the prompt cache. Anthropic-only; OpenAI-compat path is untouched. |
| `anthropic_prompt_cache_ttl` | `"5m"` | Cache TTL marker for the breakpoints. `"5m"` (default) or `"1h"`; `"1h"` requires extended-cache opt-in on the API key. |
| `checkpoints_enabled` | `false` | Snapshot the chat's working directory into a shadow git repo under `<data_dir>/checkpoints/<hash>/` at the start of every agent turn. Required for `/rewind`. Needs `git` on PATH. |
| `reflector_enabled` | `true` | Enable the background memory reflector (see [Memory System](./memory)) |
| `reflector_interval_mins` | `15` | How often the reflector runs (minutes) |
| `memory_token_budget` | `1500` | Estimated token budget for layered structured-memory injection (L0+L1+L2) |
| `memory_l0_identity_pct` | `20` | Percentage of `memory_token_budget` reserved for L0 identity (`PROFILE`) memories |
| `memory_l1_essential_pct` | `30` | Percentage of `memory_token_budget` reserved for L1 essential high-confidence memories |
| `memory_max_entries_per_chat` | `200` | Max active structured memories per chat (`0` = unlimited) |
| `memory_max_global_entries` | `500` | Max active global structured memories (`0` = unlimited) |
| `kg_max_triples_per_chat` | `1000` | Max active knowledge-graph triples per chat (`0` = unlimited) |
| `skill_review_min_tool_calls` | `0` | Enables post-reflector autonomous skill review when tool-call count threshold is met (`0` disables) |
| `subagents.max_concurrent` | `4` | Maximum number of active sub-agent runs across the runtime |
| `subagents.max_active_per_chat` | `5` | Maximum number of active sub-agent runs allowed per chat |
| `subagents.run_timeout_secs` | `900` | Timeout for one sub-agent run |
| `subagents.max_spawn_depth` | `1` | Maximum recursive sub-agent depth |
| `subagents.max_children_per_run` | `5` | Maximum child runs created from one parent run |
| `subagents.announce_relay_interval_secs` | `15` | Polling interval for retrying pending completion notices back to parent chats |
| `subagents.max_tokens_per_run` | `400000` | Per-run token budget ceiling used by `sessions_spawn` and `subagents_orchestrate` |
| `subagents.orchestrate_max_workers` | `5` | Worker cap for `subagents_orchestrate` fan-out |
| `subagents.announce_to_chat` | `true` | Post sub-agent completion notices back into the parent chat |
| `subagents.thread_bound_routing_enabled` | `true` | Route thread replies to the currently focused sub-agent when supported |
| `subagents.acp.enabled` | `false` | Enable ACP-backed external subagent execution for `sessions_spawn(runtime="acp")` |
| `subagents.acp.command` | unset | Inline default ACP worker command used when no named target is selected |
| `subagents.acp.args` | `[]` | Argument list for the inline default ACP worker command |
| `subagents.acp.env` | `{}` | Extra environment variables for the inline default ACP worker |
| `subagents.acp.auto_approve` | `true` | Whether the inline default ACP worker auto-approves ACP permission requests |
| `subagents.acp.default_target` | unset | Optional default named ACP worker target used by plain `runtime="acp"` |
| `subagents.acp.targets` | `{}` | Map of named ACP worker targets, each with `enabled`, `command`, `args`, `env`, and `auto_approve` |
| `embedding_provider` | unset | Runtime embedding provider (`openai` or `ollama`) for semantic memory; leave unset to disable |
| `embedding_api_key` | unset | API key for embedding provider (if required) |
| `embedding_base_url` | unset | Optional custom embedding API base URL |
| `embedding_model` | provider default | Embedding model name |
| `embedding_dim` | provider default | Embedding vector dimension used by sqlite-vec index |
| `channels.<name>.soul_path` | unset | Optional channel-level SOUL file path fallback |
| `soul_path` | unset | Path to a `SOUL.md` file that defines bot personality, voice, and values. If unset, checks `data_dir/SOUL.md` then `./SOUL.md` |

Path compatibility:
- If users already configured `data_dir` / `skills_dir` / `working_dir`, those values keep working unchanged.
- If not configured, defaults are `data_dir=~/.microclaw`, `skills_dir=<data_dir>/skills`, `working_dir=~/.microclaw/working_dir`.

## ACP-backed subagent targets

`subagents.acp` supports two patterns:

- inline default worker: configure `enabled`, `command`, and `args`
- named workers: configure `targets` and optionally `default_target`

Example:

```yaml
subagents:
  acp:
    enabled: true
    default_target: "reviewer"
    targets:
      reviewer:
        enabled: true
        command: codex
        args: ["--model", "gpt-5.4"]
      fast-fix:
        enabled: true
        command: codex
        args: ["--model", "gpt-5.3-codex"]
        auto_approve: false
```

Resolution order for `sessions_spawn(runtime="acp")`:

1. explicit `runtime_target`
2. `subagents.acp.default_target`
3. inline `subagents.acp.command`
4. the only enabled named target, if exactly one exists

If multiple named targets are enabled and no default is set, MicroClaw returns a configuration error and asks for `runtime_target`.

## OpenAI-compatible body overrides

Use these keys when a provider/model needs extra OpenAI-compatible request body parameters.

Merge order (later wins):
1. `openai_compat_body_overrides` (global)
2. `openai_compat_body_overrides_by_provider[llm_provider]`
3. `openai_compat_body_overrides_by_model[model]`

Set a value to `null` to remove that key from the outgoing JSON body.

```yaml
llm_provider: "deepseek"
model: "deepseek-chat"

openai_compat_body_overrides:
  temperature: 0.2
  max_tokens: 4096

openai_compat_body_overrides_by_provider:
  deepseek:
    top_p: null
    reasoning_effort: "high"

openai_compat_body_overrides_by_model:
  deepseek-chat:
    temperature: 0.0
```

Behavior details:
- provider keys are normalized to lowercase during config load
- model keys are trim-normalized and matched by exact model string
- runtime-controlled fields such as stream mode and tool payload can still be set by MicroClaw depending on request path

### With provider profiles

The global `llm_provider` + `api_key` + `model` act as the `main` profile.
If you need a channel or bot to use a different provider, key, base URL, or model, define a reusable `provider_presets.<id>` profile and point `channels.<name>.provider_preset` or `channels.<name>.accounts.<id>.provider_preset` at it.
`openai_compat_body_overrides_by_model` still matches against the effective model chosen by that profile.

For a single bot/account model override without changing the shared preset, set `channels.<name>.accounts.<id>.model`.
Slash commands follow the same scope: `/provider` and `/model` persist to the current bot/account fields, not to all bots sharing the same provider preset.

```yaml
llm_provider: "anthropic"
api_key: "sk-ant-..."
model: "claude-sonnet-4-5-20250929" # global main profile

provider_presets:
  ops-openrouter:
    provider: "openrouter"
    api_key: "sk-or-..."
    llm_base_url: "https://openrouter.ai/api/v1" # optional; defaults from provider matrix
    llm_user_agent: "microclaw-ops/1.0" # optional
    default_model: "openai/gpt-4o-mini"
    show_thinking: false
  deepseek-ops:
    provider: "deepseek"
    api_key: "sk-ds-..."
    default_model: "deepseek/deepseek-chat"

channels:
  telegram:
    provider_preset: "ops-openrouter"
    default_account: "main"
    accounts:
      main:
        enabled: true
        bot_token: "xxx"
      ops:
        enabled: true
        bot_token: "yyy"
        provider_preset: "deepseek-ops"
        model: "deepseek/deepseek-chat"

openai_compat_body_overrides:
  temperature: 0.2

openai_compat_body_overrides_by_model:
  "openai/gpt-4o-mini":
    temperature: 0.0
  "deepseek/deepseek-chat":
    top_p: null
    reasoning_effort: "high"
```

Notes:
- `llm_provider` + global `api_key` + `model` act as the `main` profile.
- `provider_presets` are the supported reusable LLM profile surface for channels/bots.
- `channels.<name>.accounts.<id>.model` is the bot/account-local model override surface.
- If two bots share the same model string, they share the same `by_model` override block.

## Container sandbox

To run `bash` tool calls in containers, set:

```yaml
sandbox:
  mode: "all"
  backend: "auto" # auto|docker|podman
  security_profile: "hardened" # hardened|standard|privileged
  # cap_add: ["SETUID", "SETGID", "CHOWN"]
  image: "ubuntu:25.10"
  container_prefix: "microclaw-sandbox"
  no_network: true
  require_runtime: true
```

Behavior:
- `sandbox.mode: "off"` (default): host execution.
- `sandbox.security_profile` defaults to `hardened`:
  - `hardened`: `--cap-drop ALL --security-opt no-new-privileges` (most restrictive)
  - `standard`: Docker default capabilities (useful when sandbox commands need `apt/chown/su`)
  - `privileged`: full container privilege (`--privileged`), debugging only
- `sandbox.cap_add` appends `--cap-add` entries for `hardened` and `standard`.
- Runtime backend selection:
  - `backend: "auto"`: Docker only (backward-compatible default behavior)
  - `backend: "docker"`: Docker only
  - `backend: "podman"`: Podman only
- `sandbox.mode: "all"` + configured runtime unavailable:
  - `require_runtime: false`: fallback to host with warning.
  - `require_runtime: true`: fail fast.

Quick opt-in:

```sh
microclaw setup --enable-sandbox
microclaw doctor sandbox
```

Optional hardening files:
- mount allowlist: `~/.microclaw/sandbox-mount-allowlist.txt`
- file path allowlist: `~/.microclaw/sandbox-path-allowlist.txt`

Each file supports one absolute path per line (`#` comments allowed).

## Channel-specific required fields

`channels.<name>.bot_username` is optional for all channels.  
If set, it overrides global `bot_username` for that channel.

- Telegram enabled:
  - At least one enabled `channels.telegram.accounts.<id>.bot_token`
- Discord enabled:
  - At least one enabled `channels.discord.accounts.<id>.bot_token`
- Slack enabled:
  - At least one enabled `channels.slack.accounts.<id>` with both `bot_token` and `app_token`
- Feishu/Lark enabled:
  - At least one enabled account with `channels.feishu.accounts.<id>.app_id` and `channels.feishu.accounts.<id>.app_secret`
- IRC enabled: `channels.irc.server`, `channels.irc.nick`, and `channels.irc.channels` are required. Optional: `port`, `password`, `mention_required`, `tls`, `tls_server_name`, `tls_danger_accept_invalid_certs`.
- Web-only mode is valid: keep `web_enabled: true` (default) and leave other channel tokens empty.

### IRC channel keys

| Key | Default | Description |
|---|---|---|
| `channels.irc.server` | unset | IRC server host or IP |
| `channels.irc.port` | `"6667"` | IRC port |
| `channels.irc.nick` | unset | IRC bot nick |
| `channels.irc.username` | unset | IRC username (defaults to nick when empty) |
| `channels.irc.real_name` | `"MicroClaw"` | IRC real name sent in USER command |
| `channels.irc.channels` | unset | Comma-separated channel list (for example `#general,#ops`) |
| `channels.irc.password` | unset | Optional IRC server password |
| `channels.irc.model` | unset | Optional model override for IRC bot |
| `channels.irc.mention_required` | `"true"` | Whether channel messages require mention to trigger reply |
| `channels.irc.tls` | `"false"` | Enable IRC TLS connection |
| `channels.irc.tls_server_name` | unset | Optional TLS SNI/server name override |
| `channels.irc.tls_danger_accept_invalid_certs` | `"false"` | Accept invalid TLS certs (testing only) |

## Supported `llm_provider` values

`openai`, `openai-codex`, `openrouter`, `anthropic`, `ollama`, `google`, `alibaba`, `aliyun-bailian`, `nvidia`, `qwen-code`, `deepseek`, `moonshot`, `mistral`, `azure`, `bedrock`, `zhipu`, `minimax`, `cohere`, `tencent`, `xai`, `huggingface`, `together`, `custom`.

`ollama` is supported as a local OpenAI-compatible provider. Recommended defaults:
- `llm_base_url`: `http://127.0.0.1:11434/v1`
- `api_key`: optional
- `model`: one of your local pulled models (for example `llama3.2`)

`aliyun-bailian` is an OpenAI-compatible preset with recommended defaults:
- `llm_base_url`: `https://coding.dashscope.aliyuncs.com/v1`
- `model`: `qwen3.5-plus`

`nvidia` is an OpenAI-compatible preset with recommended defaults:
- `llm_base_url`: `https://integrate.api.nvidia.com/v1`
- `model`: `meta/llama-3.3-70b-instruct`
- browse models: `https://build.nvidia.com/models`

`openai-codex` supports two auth modes:
- run `codex login` before `microclaw start`
- OAuth token source: `~/.codex/auth.json` (or `$CODEX_HOME/auth.json`)
- or configure `api_key` for your OpenAI-compatible proxy endpoint

## Multi-chat permissions

`control_chat_ids` defines which chats can perform cross-chat tool actions.

- non-control chats: only their own `chat_id`
- control chats: can operate across chats
- global memory writes require control-chat privileges

See [Multi-Chat Permissions](./permissions) for setup and verification steps.

## Semantic memory switches (two-layer)

Semantic memory is intentionally guarded by two independent switches:

1. **Compile-time switch (default off):** build with `--features sqlite-vec`
2. **Runtime switch (default off):** set `embedding_provider` in config

If either switch is off, MicroClaw degrades gracefully to keyword retrieval + Jaccard dedup.

### Build examples

Default build (all channels except Matrix, MCP included, no sqlite-vec):

```sh
cargo build --release
```

Full build (adds Matrix channel):

```sh
cargo build --release --features full
```

Enable sqlite-vec explicitly:

```sh
cargo build --release --features sqlite-vec
```

Combine features as needed:

```sh
cargo build --release --features "full,sqlite-vec"
```

### Runtime example

```yaml
memory_token_budget: 1500

# optional semantic memory runtime config (requires --features sqlite-vec build)
embedding_provider: "openai"      # openai | ollama
embedding_api_key: "sk-..."
# embedding_base_url: "http://127.0.0.1:11434/v1"
embedding_model: "text-embedding-3-small"
# embedding_dim: 1536
```

## Setup Wizard

Run the recommended interactive Q&A flow:

```sh
microclaw setup
```

Features:
- interactive terminal UI
- provider/model list pickers (visible choices, not blind cycling)
- local + online validation
- safe `microclaw.config.yaml` write with backup in `microclaw.config.backups/` (latest 50 kept)
- supports multi-account JSON editing (`channels.<name>.accounts`) for Telegram/Discord/dynamic channels
- supports per-bot `soul_path` picker (Telegram + dynamic channels): choose from discovered `souls/*.md` or manual filename/path input
- Web Settings panel supports the same per-bot `soul_path` picker and account editing path

Preset providers:
- `openai`
- `openrouter`
- `anthropic`
- `ollama`
- `google`
- `alibaba`
- `deepseek`
- `moonshot`
- `mistral`
- `azure`
- `bedrock`
- `zhipu`
- `minimax`
- `cohere`
- `tencent`
- `xai`
- `huggingface`
- `together`
- `custom`

## Logging

Enable debug logging with:

```sh
RUST_LOG=debug microclaw start
```

Limit to MicroClaw logs:

```sh
RUST_LOG=microclaw=debug microclaw start
```
