// @ts-check

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.

 @type {import('@docusaurus/plugin-content-docs').SidebarsConfig}
 */
const sidebars = {
  docs: [
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'overview',
        'quickstart',
        'installation',
        {
          type: 'category',
          label: 'Channel Setup',
          items: [
            'channel-setup',
            'channel-setup-telegram',
            'channel-setup-discord',
            'channel-setup-slack',
            'channel-setup-feishu-lark',
            'channel-setup-weixin',
            'channel-setup-irc',
          ],
        },
        'configuration',
        'acp',
        'permissions',
      ],
    },
    {
      type: 'category',
      label: 'Usage',
      items: ['usage', 'commands', 'plugins', 'web-operator-api', 'http-hook-trigger', 'skills', 'learning-foundry', 'tools', 'memory', 'scheduler'],
    },
    {
      type: 'category',
      label: 'Architecture',
      items: [
        'architecture',
        'architecture-context',
        'architecture-skills',
        'architecture-mcp',
        'architecture-channels',
      ],
    },
    {
      type: 'category',
      label: 'Developer',
      items: ['developer-guide', 'skills-mcp-tutorial', 'testing'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'project-files',
        'generated-tools',
        'generated-config-defaults',
        'generated-provider-matrix',
        'license',
        'security-policy',
        'support-policy',
        'release-policy',
        'faq',
        'runbook',
        'roadmap',
        'release-checklist',
        'about',
      ],
    },
  ],
};

export default sidebars;
