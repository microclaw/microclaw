# MicroClaw Website

This folder contains the MicroClaw docs website (Docusaurus), published at https://microclaw.org.
It includes docs + blog content and can be developed/deployed independently from the Rust bot.

## Install

```sh
npm install
```

## Local development

```sh
npm start
```

## Build

```sh
npm run build
```

The production build validates every configured locale.

## Languages

The site supports English, Simplified Chinese, Hindi, Spanish, Arabic, French,
Bengali, Portuguese, Indonesian, and Urdu. The landing page, navigation, and
footer are localized; technical reference pages fall back to the canonical
English source until a maintained translation is available.

Preview a locale locally with:

```sh
npm start -- --locale zh-CN
```

Landing-page copy lives in `src/home-i18n.js`. Theme labels live under
`i18n/<locale>/docusaurus-theme-classic/`. Keep technical content in `docs/`
as the single source of truth unless a translation is actively maintained.

## Serve build output

```sh
npm run serve
```

## Deploy

Commit website changes, then run:

```sh
./deploy_pages.sh
```

The script syncs the installer artifacts from the parent repository, pushes the
site source branch, builds once, and deploys `build/` to `gh-pages`. The
Pages push uses SSH keepalive settings and retries up to three times by default.

To use HTTPS credentials instead of SSH, run:

```sh
USE_SSH=false GIT_USER=microclaw ./deploy_pages.sh
```

`DEPLOY_ATTEMPTS` and `DEPLOY_RETRY_DELAY_SECONDS` can be set to override the
retry count and delay.
