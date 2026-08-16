// Per-channel settings tabs for the config dialog. Each component renders a
// self-contained <Tabs.Content> and receives only the App state it edits.
import type React from 'react'
import { Badge, Button, Callout, Card, Flex, Select, Tabs, Text, TextField } from '@radix-ui/themes'
import { ConfigFieldCard } from './config-field-card'
import { ConfigStepsCard, ConfigToggleCard, SoulPathPickerField } from './config-controls'
import type { A2APeerDraft, ConfigSelfCheck, ProviderProfileDraft } from '../lib/backend-types'
import { warningDocUrl } from '../lib/backend-types'
import type { DynChannelDef } from '../lib/channels'
import {
  BOT_SLOT_MAX,
  DEFAULT_CONFIG_VALUES,
  MAIN_PROFILE_VALUE,
  defaultAccountIdForSlot,
  defaultTelegramAccountIdForSlot,
  dynamicFieldDraftValue,
  normalizeBotCount,
  providerProfileOptions,
} from '../lib/config-model'

type SectionCardProps = {
  configDraft: Record<string, unknown>
  setConfigField: (field: string, value: unknown) => void
  sectionCardClass: string
  sectionCardStyle?: React.CSSProperties
}

type TelegramSettingsTabProps = SectionCardProps & {
  soulFiles: string[]
  providerProfileDrafts: ProviderProfileDraft[]
}

export function TelegramSettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, soulFiles, providerProfileDrafts }: TelegramSettingsTabProps) {
  return (
        <Tabs.Content value="telegram">
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">Telegram</Text>
            <ConfigStepsCard
              steps={[
                <>Open Telegram and chat with <code>@BotFather</code>.</>,
                <>Run <code>/newbot</code>, set name and username (must end with <code>bot</code>).</>,
                <>Copy the bot token and paste below.</>,
                <>Configure one or more bot accounts; each account can set its own username.</>,
                <>In groups, mention the bot to trigger replies.</>,
              ]}
            />
            <Text size="1" color="gray" className="mt-3 block">
              Configure one or more bots (up to 10). Leave token blank to keep existing secret unchanged.
            </Text>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="telegram_default_account" description={<>Default account id under <code>channels.telegram.accounts</code>.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.telegram_account_id || 'main')}
                  onChange={(e) => setConfigField('telegram_account_id', e.target.value)}
                  placeholder="main"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="telegram_bot_count" description={<>Number of Telegram bot accounts to configure (1-10).</>}>
                <TextField.Root
                  className="mt-2"
                  type="number"
                  min="1"
                  max={String(BOT_SLOT_MAX)}
                  value={String(configDraft.telegram_bot_count || 1)}
                  onChange={(e) => setConfigField('telegram_bot_count', normalizeBotCount(e.target.value))}
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="telegram_provider_preset" description={<>Optional Telegram channel-level LLM provider profile override.</>}>
                <div className="mt-2">
                  <Select.Root
                    value={String(configDraft.telegram_provider_preset || '') || MAIN_PROFILE_VALUE}
                    onValueChange={(value) => setConfigField('telegram_provider_preset', value === MAIN_PROFILE_VALUE ? '' : value)}
                  >
                    <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                    <Select.Content>
                      {providerProfileOptions(providerProfileDrafts, configDraft.telegram_provider_preset).map((option) => (
                        <Select.Item key={`telegram-provider-preset-${option.value}`} value={option.value}>
                          {option.label}
                        </Select.Item>
                      ))}
                    </Select.Content>
                  </Select.Root>
                </div>
              </ConfigFieldCard>
              <ConfigFieldCard label="telegram_allowed_user_ids" description={<>Optional channel-level allowlist. Accepts CSV or JSON array (for example <code>123,456</code> or <code>[123,456]</code>). Merged with each bot account&apos;s <code>allowed_user_ids</code>.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.telegram_allowed_user_ids || '')}
                  onChange={(e) => setConfigField('telegram_allowed_user_ids', e.target.value)}
                  placeholder="123456789,987654321"
                />
              </ConfigFieldCard>
              {Array.from({ length: normalizeBotCount(configDraft.telegram_bot_count || 1) }).map((_, idx) => {
                const slot = idx + 1
                return (
                  <Card key={`telegram-bot-${slot}`} className="p-3">
                    <Text size="2" weight="medium">Telegram bot #{slot}</Text>
                    <div className="mt-2 space-y-3">
                      <ConfigFieldCard label={`telegram_bot_${slot}_account_id`} description={<>Bot account id used under <code>channels.telegram.accounts</code>.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`telegram_bot_${slot}_account_id`] || defaultTelegramAccountIdForSlot(slot))}
                          onChange={(e) => setConfigField(`telegram_bot_${slot}_account_id`, e.target.value)}
                          placeholder={defaultTelegramAccountIdForSlot(slot)}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`telegram_bot_${slot}_token`} description={<>BotFather token for this account. Leave blank to keep current secret unchanged.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`telegram_bot_${slot}_token`] || '')}
                          onChange={(e) => setConfigField(`telegram_bot_${slot}_token`, e.target.value)}
                          placeholder="123456789:AA..."
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`telegram_bot_${slot}_username`} description={<>Telegram username without <code>@</code>, used for group mention trigger.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`telegram_bot_${slot}_username`] || '')}
                          onChange={(e) => setConfigField(`telegram_bot_${slot}_username`, e.target.value)}
                          placeholder={slot === 1 ? 'my_main_bot' : `my_bot_${slot}`}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`telegram_bot_${slot}_provider_preset`} description={<>Optional Telegram bot LLM provider profile override.</>}>
                        <div className="mt-2">
                          <Select.Root
                            value={String(configDraft[`telegram_bot_${slot}_provider_preset`] || '') || MAIN_PROFILE_VALUE}
                            onValueChange={(value) => setConfigField(`telegram_bot_${slot}_provider_preset`, value === MAIN_PROFILE_VALUE ? '' : value)}
                          >
                            <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                            <Select.Content>
                              {providerProfileOptions(providerProfileDrafts, configDraft[`telegram_bot_${slot}_provider_preset`]).map((option) => (
                                <Select.Item key={`telegram-bot-${slot}-provider-preset-${option.value}`} value={option.value}>
                                  {option.label}
                                </Select.Item>
                              ))}
                            </Select.Content>
                          </Select.Root>
                        </div>
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`telegram_bot_${slot}_soul_path`} description={<>Per-bot soul file. Select from <code>{String(configDraft.souls_dir || '').trim() || 'souls'}/*.md</code> or input a custom filename/path.</>}>
                        <SoulPathPickerField
                          value={configDraft[`telegram_bot_${slot}_soul_path`]}
                          soulsDir={configDraft.souls_dir}
                          soulFiles={soulFiles}
                          onChange={(next) => setConfigField(`telegram_bot_${slot}_soul_path`, next)}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`telegram_bot_${slot}_allowed_user_ids`} description={<>Optional per-bot private-chat allowlist (CSV or JSON array).</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`telegram_bot_${slot}_allowed_user_ids`] || '')}
                          onChange={(e) => setConfigField(`telegram_bot_${slot}_allowed_user_ids`, e.target.value)}
                          placeholder="123456789,987654321"
                        />
                      </ConfigFieldCard>
                    </div>
                  </Card>
                )
              })}
            </div>
          </div>
        </Tabs.Content>
  )
}

type DiscordSettingsTabProps = SectionCardProps & {
  providerProfileDrafts: ProviderProfileDraft[]
}

export function DiscordSettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, providerProfileDrafts }: DiscordSettingsTabProps) {
  return (
        <Tabs.Content value="discord">
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">Discord</Text>
            <ConfigStepsCard
              steps={[
                <>Open Discord Developer Portal and create an application + bot.</>,
                <>Enable <code>Message Content Intent</code> under Bot settings.</>,
                <>Invite bot with scopes/permissions: bot, View Channels, Send Messages, Read Message History.</>,
                <>Paste bot token below.</>,
                <>Optional: limit handling to specific channel IDs.</>,
              ]}
            />
            <Text size="1" color="gray" className="mt-3 block">
              Configure one or more Discord bot accounts (up to 10).
            </Text>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="discord_default_account" description={<>Default account id under <code>channels.discord.accounts</code>.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.discord_account_id || 'main')}
                  onChange={(e) => setConfigField('discord_account_id', e.target.value)}
                  placeholder="main"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="discord_bot_count" description={<>Number of Discord bot accounts to configure (1-10).</>}>
                <TextField.Root
                  className="mt-2"
                  type="number"
                  min="1"
                  max={String(BOT_SLOT_MAX)}
                  value={String(configDraft.discord_bot_count || 1)}
                  onChange={(e) => setConfigField('discord_bot_count', normalizeBotCount(e.target.value))}
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="discord_provider_preset" description={<>Optional Discord channel-level LLM provider profile override.</>}>
                <div className="mt-2">
                  <Select.Root
                    value={String(configDraft.discord_provider_preset || '') || MAIN_PROFILE_VALUE}
                    onValueChange={(value) => setConfigField('discord_provider_preset', value === MAIN_PROFILE_VALUE ? '' : value)}
                  >
                    <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                    <Select.Content>
                      {providerProfileOptions(providerProfileDrafts, configDraft.discord_provider_preset).map((option) => (
                        <Select.Item key={`discord-provider-preset-${option.value}`} value={option.value}>
                          {option.label}
                        </Select.Item>
                      ))}
                    </Select.Content>
                  </Select.Root>
                </div>
              </ConfigFieldCard>
              {Array.from({ length: normalizeBotCount(configDraft.discord_bot_count || 1) }).map((_, idx) => {
                const slot = idx + 1
                return (
                  <Card key={`discord-bot-${slot}`} className="p-3">
                    <Text size="2" weight="medium">Discord bot #{slot}</Text>
                    <div className="mt-2 space-y-3">
                      <ConfigFieldCard label={`discord_bot_${slot}_account_id`} description={<>Bot account id used under <code>channels.discord.accounts</code>.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`discord_bot_${slot}_account_id`] || defaultAccountIdForSlot(slot))}
                          onChange={(e) => setConfigField(`discord_bot_${slot}_account_id`, e.target.value)}
                          placeholder={defaultAccountIdForSlot(slot)}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`discord_bot_${slot}_token`} description={<>Discord bot token for this account. Leave blank to keep current secret unchanged.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`discord_bot_${slot}_token`] || '')}
                          onChange={(e) => setConfigField(`discord_bot_${slot}_token`, e.target.value)}
                          placeholder="MTAx..."
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`discord_bot_${slot}_allowed_channels`} description={<>Optional allowlist. Only listed channel IDs can trigger this bot.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`discord_bot_${slot}_allowed_channels_csv`] || '')}
                          onChange={(e) => setConfigField(`discord_bot_${slot}_allowed_channels_csv`, e.target.value)}
                          placeholder="1234567890,9876543210"
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`discord_bot_${slot}_username`} description={<>Optional Discord bot username override.</>}>
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`discord_bot_${slot}_username`] || '')}
                          onChange={(e) => setConfigField(`discord_bot_${slot}_username`, e.target.value)}
                          placeholder={slot === 1 ? 'discord_main_bot' : `discord_bot_${slot}`}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard label={`discord_bot_${slot}_provider_preset`} description={<>Optional Discord bot LLM provider profile override.</>}>
                        <div className="mt-2">
                          <Select.Root
                            value={String(configDraft[`discord_bot_${slot}_provider_preset`] || '') || MAIN_PROFILE_VALUE}
                            onValueChange={(value) => setConfigField(`discord_bot_${slot}_provider_preset`, value === MAIN_PROFILE_VALUE ? '' : value)}
                          >
                            <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                            <Select.Content>
                              {providerProfileOptions(providerProfileDrafts, configDraft[`discord_bot_${slot}_provider_preset`]).map((option) => (
                                <Select.Item key={`discord-bot-${slot}-provider-preset-${option.value}`} value={option.value}>
                                  {option.label}
                                </Select.Item>
                              ))}
                            </Select.Content>
                          </Select.Root>
                        </div>
                      </ConfigFieldCard>
                    </div>
                  </Card>
                )
              })}
            </div>
          </div>
        </Tabs.Content>
  )
}

type IrcSettingsTabProps = SectionCardProps & {
  providerProfileDrafts: ProviderProfileDraft[]
}

export function IrcSettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, providerProfileDrafts }: IrcSettingsTabProps) {
  return (
        <Tabs.Content value="irc">
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">IRC</Text>
            <ConfigStepsCard
              steps={[
                <>Set IRC server and nick.</>,
                <>Set channels as comma-separated list, for example <code>#general,#bot</code>.</>,
                <>Use TLS fields when connecting to secure endpoints.</>,
              ]}
            />
            <Text size="1" color="gray" className="mt-3 block">
              Required for IRC runtime: server and nick.
            </Text>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="irc_server" description={<>IRC server hostname.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_server || '')}
                  onChange={(e) => setConfigField('irc_server', e.target.value)}
                  placeholder="irc.libera.chat"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_port" description={<>IRC server port. Typical values: 6667 or 6697 (TLS).</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_port || '')}
                  onChange={(e) => setConfigField('irc_port', e.target.value)}
                  placeholder="6667"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_nick" description={<>Bot nickname.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_nick || '')}
                  onChange={(e) => setConfigField('irc_nick', e.target.value)}
                  placeholder="microclaw"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_username" description={<>Optional IRC username. Defaults to nick when empty.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_username || '')}
                  onChange={(e) => setConfigField('irc_username', e.target.value)}
                  placeholder="microclaw"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_real_name" description={<>Optional IRC real name/gecos field.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_real_name || '')}
                  onChange={(e) => setConfigField('irc_real_name', e.target.value)}
                  placeholder="MicroClaw"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_channels" description={<>Comma-separated target channels.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_channels || '')}
                  onChange={(e) => setConfigField('irc_channels', e.target.value)}
                  placeholder="#general,#support"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_password" description={<>Optional IRC server password. Leave blank to keep current secret unchanged.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_password || '')}
                  onChange={(e) => setConfigField('irc_password', e.target.value)}
                  placeholder="password"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_mention_required" description={<>In channels, require bot mention before responding (<code>true</code>/<code>false</code>).</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_mention_required || '')}
                  onChange={(e) => setConfigField('irc_mention_required', e.target.value)}
                  placeholder="true"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_tls" description={<>Enable TLS (<code>true</code>/<code>false</code>).</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_tls || '')}
                  onChange={(e) => setConfigField('irc_tls', e.target.value)}
                  placeholder="false"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_tls_server_name" description={<>Optional TLS SNI server name. Defaults to server.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_tls_server_name || '')}
                  onChange={(e) => setConfigField('irc_tls_server_name', e.target.value)}
                  placeholder="irc.libera.chat"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_tls_danger_accept_invalid_certs" description={<>Allow invalid TLS certs (<code>true</code>/<code>false</code>). Only for testing.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.irc_tls_danger_accept_invalid_certs || '')}
                  onChange={(e) => setConfigField('irc_tls_danger_accept_invalid_certs', e.target.value)}
                  placeholder="false"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="irc_provider_preset" description={<>Optional IRC LLM provider profile override.</>}>
                <div className="mt-2">
                  <Select.Root
                    value={String(configDraft.irc_provider_preset || '') || MAIN_PROFILE_VALUE}
                    onValueChange={(value) => setConfigField('irc_provider_preset', value === MAIN_PROFILE_VALUE ? '' : value)}
                  >
                    <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                    <Select.Content>
                      {providerProfileOptions(providerProfileDrafts, configDraft.irc_provider_preset).map((option) => (
                        <Select.Item key={`irc-provider-preset-${option.value}`} value={option.value}>
                          {option.label}
                        </Select.Item>
                      ))}
                    </Select.Content>
                  </Select.Root>
                </div>
              </ConfigFieldCard>
            </div>
          </div>
        </Tabs.Content>
  )
}

type DynamicChannelSettingsTabProps = SectionCardProps & {
  ch: DynChannelDef
  soulFiles: string[]
  providerProfileDrafts: ProviderProfileDraft[]
}

export function DynamicChannelSettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, ch, soulFiles, providerProfileDrafts }: DynamicChannelSettingsTabProps) {
  return (
        <Tabs.Content value={ch.name}>
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">{ch.title}</Text>
            <ConfigStepsCard steps={ch.steps.map((s, i) => <span key={i}>{s}</span>)} />
          <Text size="1" color="gray" className="mt-3 block">{ch.hint}</Text>
          <div className="mt-4 space-y-3">
            {(ch.channelFields || []).map((f) => {
              const stateKey = `${ch.name}__${f.yamlKey}`
              const hasExistingSecret = f.secret ? Boolean(configDraft[`${ch.name}__has__${f.yamlKey}`]) : false
              return (
                <ConfigFieldCard
                  key={stateKey}
                  label={`${ch.name}_${f.yamlKey}`}
                  description={<>{f.description}</>}
                >
                  <TextField.Root
                    className="mt-2"
                    type={f.valueType === 'number' ? 'number' : 'text'}
                    min={f.valueType === 'number' ? '0' : undefined}
                    step={f.valueType === 'number' ? '1' : undefined}
                    value={String(configDraft[stateKey] || '')}
                    onChange={(e) => setConfigField(stateKey, e.target.value)}
                    placeholder={f.placeholder}
                  />
                  {hasExistingSecret && !String(configDraft[stateKey] || '').trim() ? (
                    <Text size="1" color="gray" className="mt-2 block">
                      Existing secret is configured and will be preserved.
                    </Text>
                  ) : null}
                </ConfigFieldCard>
              )
            })}
            <ConfigFieldCard
              key={`${ch.name}__account_id`}
              label={`${ch.name}_default_account`}
                description={<>Default account id under <code>channels.{ch.name}.accounts</code>.</>}
              >
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft[`${ch.name}__account_id`] || 'main')}
                  onChange={(e) => setConfigField(`${ch.name}__account_id`, e.target.value)}
                  placeholder="main"
                />
              </ConfigFieldCard>
              <ConfigFieldCard
                key={`${ch.name}__bot_count`}
                label={`${ch.name}_bot_count`}
                description={<>Number of bot accounts to configure for <code>{ch.name}</code> (1-10).</>}
              >
                <TextField.Root
                  className="mt-2"
                  type="number"
                  min="1"
                  max={String(BOT_SLOT_MAX)}
                  value={String(configDraft[`${ch.name}__bot_count`] || 1)}
                  onChange={(e) => setConfigField(`${ch.name}__bot_count`, normalizeBotCount(e.target.value))}
                />
              </ConfigFieldCard>
              {Array.from({ length: normalizeBotCount(configDraft[`${ch.name}__bot_count`] || 1) }).map((_, idx) => {
                const slot = idx + 1
                return (
                  <Card key={`${ch.name}-bot-${slot}`} className="p-3">
                    <Text size="2" weight="medium">{ch.title} bot #{slot}</Text>
                    <div className="mt-2 space-y-3">
                      <ConfigFieldCard
                        key={`${ch.name}__bot_${slot}__account_id`}
                        label={`${ch.name}_bot_${slot}_account_id`}
                        description={<>Bot account id used under <code>channels.{ch.name}.accounts</code>.</>}
                      >
                        <TextField.Root
                          className="mt-2"
                          value={String(configDraft[`${ch.name}__bot_${slot}__account_id`] || defaultAccountIdForSlot(slot))}
                          onChange={(e) => setConfigField(`${ch.name}__bot_${slot}__account_id`, e.target.value)}
                          placeholder={defaultAccountIdForSlot(slot)}
                        />
                      </ConfigFieldCard>
                      <ConfigFieldCard
                        key={`${ch.name}__bot_${slot}__soul_path`}
                        label={`${ch.name}_bot_${slot}_soul_path`}
                        description={<>Per-bot soul file. Select from <code>{String(configDraft.souls_dir || '').trim() || 'souls'}/*.md</code> or input a custom filename/path.</>}
                      >
                        <SoulPathPickerField
                          value={configDraft[`${ch.name}__bot_${slot}__soul_path`]}
                          soulsDir={configDraft.souls_dir}
                          soulFiles={soulFiles}
                          onChange={(next) => setConfigField(`${ch.name}__bot_${slot}__soul_path`, next)}
                        />
                      </ConfigFieldCard>
                      {ch.fields.map((f) => {
                        const stateKey = `${ch.name}__bot_${slot}__${f.yamlKey}`
                        const hasExistingSecret = f.secret
                          ? Boolean(configDraft[`${ch.name}__bot_${slot}__has__${f.yamlKey}`])
                          : false
                        if (f.yamlKey === 'provider_preset') {
                          return (
                            <ConfigFieldCard key={stateKey} label={`${ch.name}_bot_${slot}_${f.yamlKey}`} description={<>{f.description}</>}>
                              <div className="mt-2">
                                <Select.Root
                                  value={String(configDraft[stateKey] || '') || MAIN_PROFILE_VALUE}
                                  onValueChange={(value) => setConfigField(stateKey, value === MAIN_PROFILE_VALUE ? '' : value)}
                                >
                                  <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider profile" />
                                  <Select.Content>
                                    {providerProfileOptions(providerProfileDrafts, configDraft[stateKey]).map((option) => (
                                      <Select.Item key={`${stateKey}-${option.value}`} value={option.value}>
                                        {option.label}
                                      </Select.Item>
                                    ))}
                                  </Select.Content>
                                </Select.Root>
                              </div>
                            </ConfigFieldCard>
                          )
                        }
                        return (
                          <ConfigFieldCard key={stateKey} label={`${ch.name}_bot_${slot}_${f.yamlKey}`} description={<>{f.description}</>}>
                            <TextField.Root
                              className="mt-2"
                              type={f.valueType === 'number' ? 'number' : 'text'}
                              min={f.valueType === 'number' ? '0' : undefined}
                              step={f.valueType === 'number' ? '1' : undefined}
                              value={String(configDraft[stateKey] || '')}
                              onChange={(e) => setConfigField(stateKey, e.target.value)}
                              placeholder={f.placeholder}
                            />
                            {hasExistingSecret && !String(configDraft[stateKey] || '').trim() ? (
                              <Text size="1" color="gray" className="mt-2 block">
                                Existing secret is configured and will be preserved.
                              </Text>
                            ) : null}
                          </ConfigFieldCard>
                        )
                      })}
                    </div>
                  </Card>
                )
              })}
            </div>
          </div>
        </Tabs.Content>
  )
}

type WebSettingsTabProps = SectionCardProps & {
  configSelfCheck: ConfigSelfCheck | null
}

export function WebSettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, configSelfCheck }: WebSettingsTabProps) {
  return (
        <Tabs.Content value="web">
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">Web</Text>
            <ConfigStepsCard
              steps={[
                <>Keep <code>web_enabled</code> on for local UI access.</>,
                <>Use <code>127.0.0.1</code> for local-only host, or set LAN host explicitly.</>,
                <>Choose web port (default <code>10961</code>).</>,
              ]}
            />
            <Text size="1" color="gray" className="mt-3 block">
              For local only, keep host as 127.0.0.1. Use 0.0.0.0 only behind trusted network controls.
            </Text>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="web_host" description={<>Use <code>127.0.0.1</code> for local-only. Use <code>0.0.0.0</code> only when intentionally exposing on LAN.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.web_host || DEFAULT_CONFIG_VALUES.web_host)}
                  onChange={(e) => setConfigField('web_host', e.target.value)}
                  placeholder="127.0.0.1"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="web_port" description={<>HTTP port for Web UI and API endpoint.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.web_port || DEFAULT_CONFIG_VALUES.web_port)}
                  onChange={(e) => setConfigField('web_port', e.target.value)}
                  placeholder="10961"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="web_bot_username" description={<>Optional Web-specific bot username override.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.web_bot_username || '')}
                  onChange={(e) => setConfigField('web_bot_username', e.target.value)}
                  placeholder="web_bot_name"
                />
              </ConfigFieldCard>
            </div>
            {Array.isArray(configSelfCheck?.warnings) && configSelfCheck!.warnings!.length > 0 ? (
              <details className="mt-4">
                <summary className="cursor-pointer text-sm text-[color:var(--gray-11)]">
                  Critical config warnings ({configSelfCheck!.warnings!.length})
                </summary>
                <Card className="mt-2 p-3">
                  <Text size="2" weight="bold">Critical Config Warnings</Text>
                  <div className="mt-2 space-y-2">
                    {configSelfCheck!.warnings!.map((w, idx) => (
                      <Callout.Root
                        key={`${w.code || 'warning'}-${idx}`}
                        color={w.severity === 'high' ? 'red' : 'orange'}
                        size="1"
                        variant="soft"
                      >
                        <Callout.Text>
                          [{String(w.severity || 'unknown')}] {String(w.code || 'warning')}: {String(w.message || '')}
                          {' '}
                          <a
                            href={warningDocUrl(w.code)}
                            target="_blank"
                            rel="noreferrer"
                            className="underline"
                          >
                            Docs
                          </a>
                        </Callout.Text>
                      </Callout.Root>
                    ))}
                  </div>
                </Card>
              </details>
            ) : null}
          </div>
        </Tabs.Content>
  )
}

type A2ASettingsTabProps = SectionCardProps & {
  toggleCardClass: string
  toggleCardStyle?: React.CSSProperties
  updateA2APeer: (index: number, patch: Partial<A2APeerDraft>) => void
  addA2APeer: () => void
  removeA2APeer: (index: number) => void
}

export function A2ASettingsTab({ configDraft, setConfigField, sectionCardClass, sectionCardStyle, toggleCardClass, toggleCardStyle, updateA2APeer, addA2APeer, removeA2APeer }: A2ASettingsTabProps) {
  return (
        <Tabs.Content value="a2a">
          <div className={sectionCardClass} style={sectionCardStyle}>
            <Text size="3" weight="bold">A2A</Text>
            <ConfigStepsCard
              steps={[
                <>Enable A2A only on instances that should accept or send agent-to-agent HTTP traffic.</>,
                <>Set <code>public_base_url</code> to the externally reachable HTTPS origin for this instance.</>,
                <>Configure shared bearer tokens for inbound auth and peers JSON for outbound targets.</>,
              ]}
            />
            <Text size="1" color="gray" className="mt-3 block">
              <code>a2a.shared_tokens</code> is write-only here for safety. Leave it blank to keep existing tokens unchanged.
            </Text>
            <div className="mt-4 grid grid-cols-1 gap-3">
              <ConfigToggleCard
                label="a2a_enabled"
                description={<>Enable A2A HTTP endpoints and built-in delegation tools.</>}
                checked={Boolean(configDraft.a2a_enabled)}
                onCheckedChange={(checked) => setConfigField('a2a_enabled', checked)}
                className={toggleCardClass}
                style={toggleCardStyle}
              />
            </div>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="a2a_public_base_url" description={<>Public HTTPS base URL advertised in the agent card.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.a2a_public_base_url || '')}
                  onChange={(e) => setConfigField('a2a_public_base_url', e.target.value)}
                  placeholder="https://planner.example.com"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="a2a_agent_name" description={<>Friendly agent name shown to remote peers.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.a2a_agent_name || '')}
                  onChange={(e) => setConfigField('a2a_agent_name', e.target.value)}
                  placeholder="Planner"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="a2a_agent_description" description={<>Optional short description for the A2A agent card.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.a2a_agent_description || '')}
                  onChange={(e) => setConfigField('a2a_agent_description', e.target.value)}
                  placeholder="Routes work to specialized agents"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="a2a_shared_tokens" description={<>Inbound bearer tokens accepted by <code>/api/a2a/message</code>. CSV or JSON array. Leave blank to keep unchanged.</>}>
                <TextField.Root
                  className="mt-2"
                  value={String(configDraft.a2a_shared_tokens || '')}
                  onChange={(e) => setConfigField('a2a_shared_tokens', e.target.value)}
                  placeholder='["shared-a2a-token"]'
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="a2a_peers" description={<>Outbound peers used by <code>a2a_send</code>. Add one card per remote agent.</>}>
                <div className="space-y-3">
                  {Array.isArray(configDraft.a2a_peers) && (configDraft.a2a_peers as A2APeerDraft[]).length > 0 ? (
                    (configDraft.a2a_peers as A2APeerDraft[]).map((peer, index) => (
                      <Card key={`a2a-peer-${index}`} className="p-3">
                        <div className="flex items-center justify-between gap-3">
                          <Text size="2" weight="medium">
                            {String(peer.name || '').trim() || `Peer #${index + 1}`}
                          </Text>
                          <Button variant="soft" color="red" size="1" onClick={() => removeA2APeer(index)}>
                            Remove
                          </Button>
                        </div>
                        <div className="mt-3 grid grid-cols-1 gap-3">
                          <ConfigToggleCard
                            label={`a2a_peer_${index + 1}_enabled`}
                            description={<>Whether this peer can be targeted by outbound delegation.</>}
                            checked={peer.enabled !== false}
                            onCheckedChange={(checked) => updateA2APeer(index, { enabled: checked })}
                            className={toggleCardClass}
                            style={toggleCardStyle}
                          />
                          <ConfigFieldCard label={`a2a_peer_${index + 1}_name`} description={<>Peer key used in <code>a2a_send</code>, for example <code>worker</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={peer.name}
                              onChange={(e) => updateA2APeer(index, { name: e.target.value })}
                              placeholder="worker"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label={`a2a_peer_${index + 1}_base_url`} description={<>Remote base URL, for example <code>https://worker.example.com</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={peer.base_url}
                              onChange={(e) => updateA2APeer(index, { base_url: e.target.value })}
                              placeholder="https://worker.example.com"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label={`a2a_peer_${index + 1}_bearer_token`} description={<>Optional outbound bearer token. Leave blank to keep existing token unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={peer.bearer_token}
                              onChange={(e) => updateA2APeer(index, { bearer_token: e.target.value })}
                              placeholder="shared-a2a-token"
                            />
                            {peer.has_bearer_token && !String(peer.bearer_token || '').trim() ? (
                              <Text size="1" color="gray" className="mt-2 block">Existing token is configured and will be preserved.</Text>
                            ) : null}
                          </ConfigFieldCard>
                          <ConfigFieldCard label={`a2a_peer_${index + 1}_description`} description={<>Optional description shown by <code>a2a_list_peers</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={peer.description}
                              onChange={(e) => updateA2APeer(index, { description: e.target.value })}
                              placeholder="Executes implementation tasks"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label={`a2a_peer_${index + 1}_default_session_key`} description={<>Optional default remote session key.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={peer.default_session_key}
                              onChange={(e) => updateA2APeer(index, { default_session_key: e.target.value })}
                              placeholder="a2a:worker"
                            />
                          </ConfigFieldCard>
                        </div>
                      </Card>
                    ))
                  ) : (
                    <Text size="1" color="gray">No peers configured yet.</Text>
                  )}
                  <Button variant="soft" onClick={() => addA2APeer()}>
                    Add Peer
                  </Button>
                </div>
              </ConfigFieldCard>
            </div>
          </div>
        </Tabs.Content>
  )
}
