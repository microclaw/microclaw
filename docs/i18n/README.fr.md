# MicroClaw

[English](../../README.md) · [简体中文](../../README_CN.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [العربية](README.ar.md) · [Français](README.fr.md) · [বাংলা](README.bn.md) · [Português](README.pt.md) · [Bahasa Indonesia](README.id.md) · [اردو](README.ur.md)

> [!IMPORTANT]
> Pour la production, utilisez la branche [`stable`](https://github.com/microclaw/microclaw/tree/stable). `main` évolue rapidement et peut contenir des changements incompatibles.

**Un environnement d'exécution d'agents fiable pour toutes les interfaces de conversation.**

MicroClaw est un runtime d'agents auto-hébergé écrit en Rust. Une boucle d'agent indépendante du canal et une couche LLM indépendante du fournisseur partagent les mêmes outils, mémoire, règles et mécanismes de reprise entre Telegram, Discord, Slack, Feishu/Lark, le Web et d'autres adaptateurs.

Il est conçu pour les travaux qui dépassent une seule requête : outils en plusieurs étapes, sessions récupérables, livraison durable, mémoire persistante, tâches planifiées, skills, MCP et sous-agents fonctionnent dans le même runtime.

## Démarrage rapide

Installation sur macOS ou Linux :

```sh
curl -fsSL https://microclaw.org/install.sh | bash
```

Sous Windows PowerShell :

```powershell
iwr https://microclaw.org/install.ps1 -UseBasicParsing | iex
```

Configuration et démarrage :

```sh
microclaw doctor
microclaw setup
microclaw start
```

Ouvrez ensuite [http://127.0.0.1:10961](http://127.0.0.1:10961). Consultez le [guide de démarrage](../getting-started.md) pour Homebrew, Docker, la compilation depuis les sources, la compatibilité Linux et l'installation en service.

## Pourquoi MicroClaw

- **Un runtime, plusieurs interfaces :** le même comportement et les mêmes règles de sécurité sur tous les canaux.
- **Travail récupérable :** sessions, points de contrôle sûrs, tâches planifiées et livraison reprennent après un redémarrage.
- **Liberté de fournisseur :** Anthropic, les services compatibles OpenAI et les modèles locaux utilisent un modèle interne commun.
- **Extensions bien délimitées :** skills, serveurs MCP, plugins, hooks, outils et adaptateurs de canal.
- **Auto-hébergement simple :** un service Rust avec SQLite intégré, sans base vectorielle séparée obligatoire.
- **Sécurité partagée :** approbations d'outils, droits limités, contrôle des sorties réseau, sandbox, masquage et audit.

## Capacités principales

- Outils en plusieurs étapes, planification, suivi de progression et sous-agents
- Mémoire persistante dans des fichiers et SQLite, rappel sémantique et apprentissage gouverné
- Tâches planifiées, compactage du contexte et sessions récupérables
- Telegram, Discord, Slack, Feishu/Lark, Web et de nombreux autres canaux
- Interface Web locale et APIs HTTP, SSE, WebSocket, A2A, ACP et MCP
- Sandbox Docker, politiques d'accès, diagnostics, métriques et traces

Consultez le [catalogue d'outils généré](../generated/tools.md) et la [matrice des fournisseurs](../generated/provider-matrix.md) pour les listes à jour.

## Documentation

- [Carte de la documentation](../README.md)
- [Premiers pas](../getting-started.md)
- [Cookbook](../cookbook.md)
- [Valeurs de configuration](../generated/config-defaults.md)
- [Guide d'exploitation](../operations/runbook.md)
- [Runtime sécurisé](../security/secure-runtime.md)

La documentation technique détaillée reste en anglais comme source canonique afin d'éviter que les commandes et la configuration divergent entre traductions. Consultez la [politique de traduction](README.md).

## Communauté et licence

Rejoignez la communauté sur [Discord](https://discord.gg/eGzEaP6TzR) et [Reddit](https://www.reddit.com/r/microclaw/). Lisez [CONTRIBUTING.md](../../CONTRIBUTING.md) avant de contribuer.

MicroClaw est distribué sous [licence MIT](../../LICENSE).
