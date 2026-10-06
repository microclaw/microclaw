# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> Para produção, use a branch [`stable`](https://github.com/microclaw/microclaw/tree/stable). A `main` muda rapidamente e pode incluir alterações incompatíveis.

**Um runtime de agentes confiável para qualquer interface de conversa.**

MicroClaw é um runtime de agentes auto-hospedado e escrito em Rust. Um único loop de agente independente do canal e uma camada de LLM independente do provedor compartilham ferramentas, memória, políticas e recuperação entre Telegram, Discord, Slack, Feishu/Lark, Web e outros adaptadores.

Ele foi projetado para trabalhos que duram mais de uma solicitação: uso de ferramentas em várias etapas, sessões retomáveis, entrega durável, memória persistente, tarefas agendadas, skills, MCP e subagentes funcionam no mesmo runtime.

## Início rápido

Instale no macOS ou Linux:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

No Windows PowerShell:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Configure e inicie:

```sh
microclaw doctor
microclaw setup
microclaw start
```

Depois, abra [http://127.0.0.1:10961](http://127.0.0.1:10961). Consulte o [guia de primeiros passos](../getting-started.md) para Homebrew, Docker, compilação do código-fonte, compatibilidade com Linux e instalação como serviço.

## Por que MicroClaw

- **Um runtime, várias interfaces:** o mesmo comportamento e as mesmas políticas de segurança em todos os canais.
- **Trabalho recuperável:** sessões, checkpoints seguros, tarefas agendadas e entrega continuam após uma reinicialização.
- **Liberdade de provedor:** Anthropic, serviços compatíveis com OpenAI e modelos locais usam um modelo interno comum.
- **Extensões bem definidas:** skills, servidores MCP, plugins, hooks, ferramentas e adaptadores de canal.
- **Auto-hospedagem simples:** um serviço Rust com SQLite integrado, sem exigir um banco vetorial separado.
- **Segurança compartilhada:** aprovação de ferramentas, permissões limitadas, controle de saída, sandbox, redação e auditoria.

## Principais recursos

- Ferramentas em várias etapas, planejamento, atualizações de progresso e subagentes
- Memória persistente em arquivos e SQLite, recuperação semântica e aprendizado governado
- Tarefas agendadas, compactação de contexto e sessões retomáveis
- Telegram, Discord, Slack, Feishu/Lark, Web e muitos outros canais
- Interface Web local e APIs HTTP, SSE, WebSocket, A2A, ACP e MCP
- Sandbox Docker, políticas de acesso, diagnósticos, métricas e traces

Consulte o [catálogo de ferramentas gerado](../generated/tools.md) e a [matriz de provedores](../generated/provider-matrix.md) para as listas atuais.

## Documentação

- [Mapa da documentação](../README.md)
- [Primeiros passos](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Padrões de configuração](../generated/config-defaults.md)
- [Manual de operações](../operations/runbook.md)
- [Runtime seguro](../security/secure-runtime.md)

A documentação técnica detalhada é mantida em inglês como fonte canônica para evitar divergências de comandos e configuração entre traduções. Consulte a [política de tradução](README.md).

## Comunidade e licença

Participe da comunidade no [Discord](https://discord.gg/eGzEaP6TzR) e no [Reddit](https://www.reddit.com/r/microclaw/). Leia [CONTRIBUTING.md](../../CONTRIBUTING.md) antes de contribuir.

MicroClaw é disponibilizado sob a [licença MIT](../../LICENSE).
