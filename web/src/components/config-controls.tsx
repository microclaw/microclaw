// Reusable settings-panel controls: soul-file picker, labelled toggle card,
// and numbered setup-steps card.
import type React from 'react'
import { Card, Flex, Select, Switch, Text, TextField } from '@radix-ui/themes'
import { normalizeSoulPathInput, soulPickerValue } from '../lib/config-model'

type SoulPathPickerFieldProps = {
  value: unknown
  soulsDir?: unknown
  soulFiles: string[]
  onChange: (next: string) => void
}

export function SoulPathPickerField({ value, soulsDir, soulFiles, onChange }: SoulPathPickerFieldProps) {
  const pickerVal = soulPickerValue(value, soulFiles, soulsDir)
  const soulsDirText = String(soulsDir || '').trim() || 'souls'
  return (
    <Flex direction="column" gap="2">
      <Select.Root
        value={pickerVal}
        onValueChange={(next) => {
          if (next === '__none__') {
            onChange('')
            return
          }
          if (next === '__custom__') return
          onChange(normalizeSoulPathInput(next, soulsDir))
        }}
      >
        <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select soul file" />
        <Select.Content position="popper">
          <Select.Item value="__none__">(None)</Select.Item>
          <Select.Item value="__custom__">Custom filename/path</Select.Item>
          {soulFiles.map((name) => (
            <Select.Item key={name} value={name}>
              {name}
            </Select.Item>
          ))}
        </Select.Content>
      </Select.Root>
      {pickerVal === '__custom__' ? (
        <TextField.Root
          value={String(value || '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder="my-bot.md or /abs/path/my-bot.md"
        />
      ) : null}
      <Text size="1" color="gray">
        Select from <code>{soulsDirText}/*.md</code> or use custom input (file may not exist yet).
      </Text>
    </Flex>
  )
}

type ConfigToggleCardProps = {
  label: string
  description?: React.ReactNode
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  className: string
  style?: React.CSSProperties
}

export function ConfigToggleCard({ label, description, checked, onCheckedChange, className, style }: ConfigToggleCardProps) {
  return (
    <div className={className} style={style}>
      <Flex justify="between" align="center">
        <div>
          <Text size="2">{label}</Text>
          {description ? (
            <Text size="1" color="gray" className="mt-1 block">
              {description}
            </Text>
          ) : null}
        </div>
        <Switch checked={checked} onCheckedChange={onCheckedChange} />
      </Flex>
    </div>
  )
}

type ConfigStepsCardProps = {
  title?: string
  steps: React.ReactNode[]
}

export function ConfigStepsCard({ title = 'Setup Steps', steps }: ConfigStepsCardProps) {
  return (
    <Card className="mt-3 p-3">
      <Text size="2" weight="bold">{title}</Text>
      <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-400">
        {steps.map((step, index) => (
          <li key={index}>{step}</li>
        ))}
      </ol>
    </Card>
  )
}
