// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'MicroClaw',
  tagline: 'Agentic AI assistant for modern chat surfaces, built in Rust.',
  favicon: 'img/favicon.ico',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: 'https://microclaw.org',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'microclaw',
  // Deploy target repo for GitHub Pages.
  projectName: 'microclaw.github.io',
  deploymentBranch: 'gh-pages',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh-CN', 'hi', 'es', 'ar', 'fr', 'bn', 'pt', 'id', 'ur'],
    localeConfigs: {
      en: {label: 'English', htmlLang: 'en'},
      'zh-CN': {label: '简体中文', htmlLang: 'zh-CN'},
      hi: {label: 'हिन्दी', htmlLang: 'hi'},
      es: {label: 'Español', htmlLang: 'es'},
      ar: {label: 'العربية', htmlLang: 'ar', direction: 'rtl'},
      fr: {label: 'Français', htmlLang: 'fr'},
      bn: {label: 'বাংলা', htmlLang: 'bn'},
      pt: {label: 'Português', htmlLang: 'pt'},
      id: {label: 'Bahasa Indonesia', htmlLang: 'id'},
      ur: {label: 'اردو', htmlLang: 'ur', direction: 'rtl'},
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/microclaw/microclaw/tree/main/',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          editUrl: 'https://github.com/microclaw/microclaw/tree/main/',
          // Useful options to enforce blogging best practices
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  plugins: [
    [
      '@easyops-cn/docusaurus-search-local',
      {
        // Search docs/blog pages without external services.
        indexDocs: true,
        indexBlog: true,
        docsRouteBasePath: '/docs',
        hashed: true,
        language: ['en'],
      },
    ],
    [
      '@docusaurus/plugin-google-gtag',
      {
        trackingID: 'G-6MJPZ80E4Z',
        anonymizeIP: true,
      },
    ],
  ],

  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '32x32',
        href: '/img/favicon-32x32.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '16x16',
        href: '/img/favicon-16x16.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'apple-touch-icon',
        sizes: '180x180',
        href: '/img/apple-touch-icon.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'manifest',
        href: '/site.webmanifest',
      },
    },
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/social-card.svg',
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'MicroClaw',
        logo: {
          alt: 'MicroClaw Logo',
          src: 'img/logo.png',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docs',
            position: 'left',
            label: 'Docs',
          },
          {to: '/docs/quickstart', label: 'Quickstart', position: 'left'},
          {to: '/blog', label: 'Blog', position: 'left'},
          {type: 'localeDropdown', position: 'right'},
          {type: 'search', position: 'right'},
          {
            href: 'https://github.com/microclaw/microclaw',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Overview',
                to: '/docs/overview',
              },
              {
                label: 'Quickstart',
                to: '/docs/quickstart',
              },
            ],
          },
          {
            title: 'Project',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/microclaw/microclaw',
              },
              {
                label: 'Issues',
                href: 'https://github.com/microclaw/microclaw/issues',
              },
              {
                label: 'Releases',
                href: 'https://github.com/microclaw/microclaw/releases',
              },
              {
                label: 'Discord',
                href: 'https://discord.gg/pvmezwkAk5',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
              {
                label: 'License',
                to: '/docs/license',
              },
              {
                label: 'Security',
                to: '/docs/security-policy',
              },
              {
                label: 'Support',
                to: '/docs/support-policy',
              },
              {
                label: 'X (Author)',
                href: 'https://x.com/everettjf',
              },
              {
                label: 'X (MicroClaw)',
                href: 'https://x.com/microclaw',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} MicroClaw.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
    }),
};

export default config;
