// ---------------------------------------------------------------------------
// Declarative dynamic-channel definitions for the Settings panel.
// To add a new channel, just append an entry here — no other UI code changes.
// ---------------------------------------------------------------------------
export interface DynChannelField {
  /** YAML key inside channels.<name>, e.g. "bot_token" */
  yamlKey: string
  /** Label shown in the settings panel */
  label: string
  /** Input placeholder */
  placeholder: string
  /** Description shown in ConfigFieldCard */
  description: string
  /** If true, field value is a secret (not pre-filled from server config) */
  secret: boolean
  /** Value type for payload encoding */
  valueType?: 'string' | 'bool' | 'number'
}
export interface DynChannelDef {
  /** Channel name, e.g. "slack" */
  name: string
  /** Display title for the tab header */
  title: string
  /** Emoji icon for the tab trigger */
  icon: string
  /** Setup steps shown in ConfigStepsCard */
  steps: string[]
  /** Hint text below the steps */
  hint: string
  /** Optional channel-level config fields */
  channelFields?: DynChannelField[]
  /** Config fields */
  fields: DynChannelField[]
}

export const DYNAMIC_CHANNELS: DynChannelDef[] = [
  {
    name: 'slack',
    title: 'Slack',
    icon: '🔗',
    steps: [
      'Go to api.slack.com/apps and create a new app.',
      'Enable Socket Mode and create an app-level token (xapp-).',
      'Add bot token scopes: chat:write, channels:history, groups:history, im:history, mpim:history, app_mentions:read.',
      'Install to workspace and copy the Bot User OAuth Token (xoxb-).',
      'Enable Event Subscriptions and subscribe to: message.channels, message.groups, message.im, message.mpim, app_mention.',
    ],
    hint: 'Required: bot token and app token. Leave tokens blank to keep current secrets unchanged.',
    fields: [
      { yamlKey: 'bot_token', label: 'slack_bot_token', placeholder: 'xoxb-...', description: 'Bot User OAuth Token (xoxb-) for sending messages. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'app_token', label: 'slack_app_token', placeholder: 'xapp-...', description: 'App-level token (xapp-) for Socket Mode connection. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'bot_username', label: 'slack_bot_username', placeholder: 'slack_bot_name', description: 'Optional Slack-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'slack_provider_preset', placeholder: 'provider1', description: 'Optional Slack bot LLM provider profile override for this account.', secret: false },
      { yamlKey: 'capture_unmentioned_images', label: 'slack_capture_unmentioned_images', placeholder: 'false', description: 'Capture inbound images without @mention in group channels (true/false). Default: false.', secret: false, valueType: 'bool' },
      { yamlKey: 'inbound_image_max_mb', label: 'slack_inbound_image_max_mb', placeholder: '20', description: 'Max inbound Slack image size in MB. Default: 20.', secret: false, valueType: 'number' },
    ],
  },
  {
    name: 'feishu',
    title: 'Feishu / Lark',
    icon: '🐦',
    steps: [
      'Go to Feishu Open Platform (or Lark Developer for international) and create a custom app.',
      'Copy the App ID and App Secret from Credentials.',
      'Add permissions: im:message, im:message:send_as_bot, im:resource.',
      'Enable Long Connection mode (recommended) or configure a webhook URL.',
      'Subscribe to event: im.message.receive_v1.',
    ],
    hint: 'Required: App ID and App Secret. Domain defaults to "feishu" (China); use "lark" for international.',
    fields: [
      { yamlKey: 'app_id', label: 'feishu_app_id', placeholder: 'cli_xxx', description: 'App ID from Feishu Open Platform credentials.', secret: false },
      { yamlKey: 'app_secret', label: 'feishu_app_secret', placeholder: 'xxx', description: 'App Secret from Feishu Open Platform. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'domain', label: 'feishu_domain', placeholder: 'feishu', description: 'Use "feishu" for China, "lark" for international, or a custom base URL.', secret: false },
      { yamlKey: 'bot_username', label: 'feishu_bot_username', placeholder: 'feishu_bot_name', description: 'Optional Feishu-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'feishu_provider_preset', placeholder: 'provider1', description: 'Optional Feishu bot LLM provider profile override for this account.', secret: false },
      { yamlKey: 'topic_mode', label: 'feishu_topic_mode', placeholder: 'false', description: 'Optional topic mode (true/false).', secret: false, valueType: 'bool' },
      { yamlKey: 'show_progress', label: 'feishu_show_progress', placeholder: 'false', description: 'Optional progress updates in topic mode (true/false).', secret: false, valueType: 'bool' },
    ],
  },
  {
    name: 'weixin',
    title: 'Weixin',
    icon: '💚',
    steps: [
      'Minimal config is enough: enable Weixin and log in once per account.',
      'Run `microclaw weixin login` (or `microclaw weixin login --account ops`) to persist local credentials.',
      'Optional: configure webhook forwarding only if you are relaying inbound traffic externally.',
    ],
    hint: 'Native polling works after login. Leave secrets blank to keep existing values unchanged.',
    channelFields: [
      { yamlKey: 'webhook_path', label: 'weixin_webhook_path', placeholder: '/weixin/messages', description: 'Optional inbound webhook path override.', secret: false },
      { yamlKey: 'webhook_token', label: 'weixin_webhook_token', placeholder: 'bridge-token', description: 'Optional channel-level webhook token. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'allowed_user_ids', label: 'weixin_allowed_user_ids', placeholder: 'alice@im.wechat,bob@im.wechat', description: 'Optional channel-level allowlist csv for the default single-account runtime.', secret: false },
      { yamlKey: 'model', label: 'weixin_model', placeholder: 'gpt-5.2', description: 'Optional channel-level model override.', secret: false },
      { yamlKey: 'base_url', label: 'weixin_base_url', placeholder: 'https://ilinkai.weixin.qq.com', description: 'Optional default Weixin API base URL.', secret: false },
      { yamlKey: 'cdn_base_url', label: 'weixin_cdn_base_url', placeholder: 'https://novac2c.cdn.weixin.qq.com/c2c', description: 'Optional default Weixin CDN base URL.', secret: false },
    ],
    fields: [
      { yamlKey: 'allowed_user_ids', label: 'weixin_allowed_user_ids', placeholder: 'alice@im.wechat,bob@im.wechat', description: 'Optional per-account allowlist csv.', secret: false },
      { yamlKey: 'webhook_token', label: 'weixin_webhook_token', placeholder: 'bridge-token', description: 'Optional per-account webhook token. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'bot_username', label: 'weixin_bot_username', placeholder: 'weixin_bot_name', description: 'Optional per-account bot username override.', secret: false },
      { yamlKey: 'model', label: 'weixin_model', placeholder: 'gpt-5.2', description: 'Optional per-account model override.', secret: false },
      { yamlKey: 'base_url', label: 'weixin_base_url', placeholder: 'https://ilinkai.weixin.qq.com', description: 'Optional per-account Weixin API base URL override.', secret: false },
      { yamlKey: 'cdn_base_url', label: 'weixin_cdn_base_url', placeholder: 'https://novac2c.cdn.weixin.qq.com/c2c', description: 'Optional per-account Weixin CDN base URL override.', secret: false },
    ],
  },
  {
    name: 'matrix',
    title: 'Matrix',
    icon: '🧩',
    steps: [
      'Prepare a Matrix bot account on your homeserver.',
      'Get homeserver URL, bot user ID, and access token.',
      'Invite the bot to target rooms/chats.',
    ],
    hint: 'Required: homeserver_url, access_token, bot_user_id.',
    fields: [
      { yamlKey: 'homeserver_url', label: 'matrix_homeserver_url', placeholder: 'https://matrix.org', description: 'Matrix homeserver URL.', secret: false },
      { yamlKey: 'access_token', label: 'matrix_access_token', placeholder: 'syt_xxx', description: 'Matrix access token for the bot account.', secret: true },
      { yamlKey: 'bot_user_id', label: 'matrix_bot_user_id', placeholder: '@bot:example.org', description: 'Matrix bot user ID.', secret: false },
      { yamlKey: 'bot_username', label: 'matrix_bot_username', placeholder: 'matrix_bot_name', description: 'Optional Matrix-specific bot username override.', secret: false },
    ],
  },
  {
    name: 'whatsapp',
    title: 'WhatsApp',
    icon: '🟢',
    steps: [
      'Create WhatsApp Cloud API app in Meta Developer dashboard.',
      'Copy access token and phone number ID.',
      'Configure webhook and verify token if needed.',
    ],
    hint: 'Required: access_token and phone_number_id.',
    fields: [
      { yamlKey: 'access_token', label: 'whatsapp_access_token', placeholder: 'EAAG...', description: 'WhatsApp Cloud API access token.', secret: true },
      { yamlKey: 'phone_number_id', label: 'whatsapp_phone_number_id', placeholder: '1234567890', description: 'WhatsApp phone number ID.', secret: false },
      { yamlKey: 'webhook_verify_token', label: 'whatsapp_webhook_verify_token', placeholder: 'verify-token', description: 'Optional webhook verify token.', secret: true },
      { yamlKey: 'api_version', label: 'whatsapp_api_version', placeholder: 'v21.0', description: 'Graph API version.', secret: false },
      { yamlKey: 'webhook_path', label: 'whatsapp_webhook_path', placeholder: '/whatsapp/webhook', description: 'Webhook path.', secret: false },
      { yamlKey: 'allowed_user_ids', label: 'whatsapp_allowed_user_ids', placeholder: 'user1,user2', description: 'Optional allowed user IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'whatsapp_bot_username', placeholder: 'whatsapp_bot_name', description: 'Optional WhatsApp-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'whatsapp_provider_preset', placeholder: 'provider1', description: 'Optional WhatsApp bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'imessage',
    title: 'iMessage',
    icon: '💬',
    steps: [
      'Run on macOS with osascript support.',
      'Choose service type and connect sender workflow.',
    ],
    hint: 'Default service is iMessage.',
    fields: [
      { yamlKey: 'service', label: 'imessage_service', placeholder: 'iMessage', description: 'Service type (iMessage/SMS relay setup dependent).', secret: false },
      { yamlKey: 'bot_username', label: 'imessage_bot_username', placeholder: 'imessage_bot_name', description: 'Optional iMessage-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'imessage_provider_preset', placeholder: 'provider1', description: 'Optional iMessage bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'email',
    title: 'Email',
    icon: '✉️',
    steps: [
      'Set sender address and sendmail path.',
      'Expose webhook endpoint if receiving inbound events.',
      'Optionally restrict allowed senders.',
    ],
    hint: 'Required: from_address.',
    fields: [
      { yamlKey: 'from_address', label: 'email_from_address', placeholder: 'bot@example.com', description: 'Email sender address.', secret: false },
      { yamlKey: 'sendmail_path', label: 'email_sendmail_path', placeholder: '/usr/sbin/sendmail', description: 'sendmail binary path.', secret: false },
      { yamlKey: 'webhook_path', label: 'email_webhook_path', placeholder: '/email/webhook', description: 'Inbound webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'email_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_senders', label: 'email_allowed_senders', placeholder: 'a@example.com,b@example.com', description: 'Optional allowed sender list csv.', secret: false },
      { yamlKey: 'bot_username', label: 'email_bot_username', placeholder: 'email_bot_name', description: 'Optional Email-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'email_provider_preset', placeholder: 'provider1', description: 'Optional Email bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'nostr',
    title: 'Nostr',
    icon: '🟣',
    steps: [
      'Configure publish command used to send outgoing replies.',
      'Configure webhook endpoint for incoming events.',
    ],
    hint: 'Recommended: set publish_command and webhook token.',
    fields: [
      { yamlKey: 'publish_command', label: 'nostr_publish_command', placeholder: 'nostril publish ...', description: 'Command used to publish messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'nostr_webhook_path', placeholder: '/nostr/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'nostr_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_pubkeys', label: 'nostr_allowed_pubkeys', placeholder: 'npub1...,npub1...', description: 'Optional allowed pubkeys csv.', secret: false },
      { yamlKey: 'bot_username', label: 'nostr_bot_username', placeholder: 'nostr_bot_name', description: 'Optional Nostr-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'nostr_provider_preset', placeholder: 'provider1', description: 'Optional Nostr bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'signal',
    title: 'Signal',
    icon: '🔐',
    steps: [
      'Configure send command used to send outgoing replies.',
      'Configure webhook endpoint for incoming messages.',
    ],
    hint: 'Recommended: set send_command and webhook token.',
    fields: [
      { yamlKey: 'send_command', label: 'signal_send_command', placeholder: 'signal-cli send ...', description: 'Command used to send Signal messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'signal_webhook_path', placeholder: '/signal/messages', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'signal_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_numbers', label: 'signal_allowed_numbers', placeholder: '+15551234567,+15559876543', description: 'Optional allowed numbers csv.', secret: false },
      { yamlKey: 'bot_username', label: 'signal_bot_username', placeholder: 'signal_bot_name', description: 'Optional Signal-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'signal_provider_preset', placeholder: 'provider1', description: 'Optional Signal bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'dingtalk',
    title: 'DingTalk',
    icon: '🟡',
    steps: [
      'Create DingTalk robot integration.',
      'Set robot webhook URL and inbound webhook route.',
    ],
    hint: 'Recommended: set robot_webhook_url and webhook token.',
    fields: [
      { yamlKey: 'robot_webhook_url', label: 'dingtalk_robot_webhook_url', placeholder: 'https://oapi.dingtalk.com/robot/send?...', description: 'DingTalk robot webhook URL.', secret: true },
      { yamlKey: 'webhook_path', label: 'dingtalk_webhook_path', placeholder: '/dingtalk/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'dingtalk_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_chat_ids', label: 'dingtalk_allowed_chat_ids', placeholder: 'chat1,chat2', description: 'Optional allowed chat IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'dingtalk_bot_username', placeholder: 'dingtalk_bot_name', description: 'Optional DingTalk-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'dingtalk_provider_preset', placeholder: 'provider1', description: 'Optional DingTalk bot LLM provider profile override for this account.', secret: false },
    ],
  },
  {
    name: 'qq',
    title: 'QQ',
    icon: '🐧',
    steps: [
      'Configure send command used to send outgoing replies.',
      'Configure webhook endpoint for incoming messages.',
    ],
    hint: 'Recommended: set send_command and webhook token.',
    fields: [
      { yamlKey: 'send_command', label: 'qq_send_command', placeholder: 'qq-send ...', description: 'Command used to send QQ messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'qq_webhook_path', placeholder: '/qq/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'qq_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_user_ids', label: 'qq_allowed_user_ids', placeholder: '10001,10002', description: 'Optional allowed user IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'qq_bot_username', placeholder: 'qq_bot_name', description: 'Optional QQ-specific bot username override.', secret: false },
      { yamlKey: 'provider_preset', label: 'qq_provider_preset', placeholder: 'provider1', description: 'Optional QQ bot LLM provider profile override for this account.', secret: false },
    ],
  },
]
