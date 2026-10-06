# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> Para producción, utiliza la rama [`stable`](https://github.com/microclaw/microclaw/tree/stable). `main` cambia rápidamente y puede incluir cambios incompatibles.

**Un entorno de ejecución de agentes fiable para cualquier canal de conversación.**

MicroClaw es un runtime de agentes autoalojado y escrito en Rust. Un único bucle de agente independiente del canal y una capa LLM independiente del proveedor comparten herramientas, memoria, políticas y recuperación entre Telegram, Discord, Slack, Feishu/Lark, Web y otros adaptadores.

Está diseñado para trabajos que duran más de una petición: uso de herramientas en varios pasos, sesiones reanudables, entrega duradera, memoria persistente, tareas programadas, skills, MCP y subagentes conviven en el mismo runtime.

## Inicio rápido

Instala en macOS o Linux:

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

En Windows PowerShell:

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Configura e inicia:

```sh
microclaw doctor
microclaw setup
microclaw start
```

Después abre [http://127.0.0.1:10961](http://127.0.0.1:10961). Consulta la [guía de inicio](../getting-started.md) para Homebrew, Docker, compilación desde código fuente, compatibilidad con Linux e instalación como servicio.

## Por qué MicroClaw

- **Un runtime, muchas interfaces:** el mismo comportamiento y las mismas políticas de seguridad en todos los canales.
- **Trabajo recuperable:** las sesiones, los puntos de control seguros, las tareas programadas y la entrega continúan después de un reinicio.
- **Libertad de proveedor:** Anthropic, servicios compatibles con OpenAI y modelos locales usan un modelo interno común.
- **Extensión con límites claros:** skills, servidores MCP, plugins, hooks, herramientas y adaptadores de canal.
- **Autoalojamiento sencillo:** un servicio Rust con SQLite integrado, sin exigir una base de datos vectorial independiente.
- **Seguridad compartida:** aprobaciones de herramientas, permisos acotados, control de salida, sandbox, redacción y auditoría.

## Capacidades principales

- Herramientas de varios pasos, planificación, actualizaciones de progreso y subagentes
- Memoria persistente en archivos y SQLite, recuperación semántica y aprendizaje gobernado
- Tareas programadas, compactación de contexto y sesiones reanudables
- Telegram, Discord, Slack, Feishu/Lark, Web y muchos otros canales
- Interfaz Web local y APIs HTTP, SSE, WebSocket, A2A, ACP y MCP
- Sandbox Docker, políticas de acceso, diagnósticos, métricas y trazas

Consulta el [catálogo de herramientas generado](../generated/tools.md) y la [matriz de proveedores](../generated/provider-matrix.md) para conocer la lista actual.

## Documentación

- [Mapa de documentación](../README.md)
- [Primeros pasos](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Valores de configuración](../generated/config-defaults.md)
- [Manual de operaciones](../operations/runbook.md)
- [Runtime seguro](../security/secure-runtime.md)

La documentación técnica detallada se mantiene en inglés como fuente canónica para que comandos y configuración no diverjan entre traducciones. Consulta la [política de traducción](README.md).

## Comunidad y licencia

Únete a la comunidad en [Discord](https://discord.gg/eGzEaP6TzR) y [Reddit](https://www.reddit.com/r/microclaw/). Lee [CONTRIBUTING.md](../../CONTRIBUTING.md) antes de contribuir.

MicroClaw se distribuye bajo la [licencia MIT](../../LICENSE).
