import React, { useEffect, useMemo, useState } from 'react'
import { Badge, Button, Callout, Card, Flex, Text, TextField } from '@radix-ui/themes'
import { api, ApiError } from '../lib/api'

type PairedDeviceRecord = {
  id: number
  device_id: string
  label: string
  platform?: string | null
  prefix: string
  created_at?: string | null
  last_seen_at?: string | null
  revoked_at?: string | null
  scopes?: string[]
}

type PairedDeviceListResponse = {
  ok?: boolean
  devices?: PairedDeviceRecord[]
  pending_codes?: number
}

type PairingCodeResponse = {
  ok?: boolean
  code?: string
  label?: string
  expires_at?: string | null
  expires_minutes?: number
}

type IssuedCode = {
  code: string
  label: string
  expiresAt?: string | null
}

export function PairedDevicesSettings({
  open,
  authenticated,
}: {
  open: boolean
  authenticated: boolean
}) {
  const [devices, setDevices] = useState<PairedDeviceRecord[]>([])
  const [pendingCodes, setPendingCodes] = useState<number>(0)
  const [loading, setLoading] = useState<boolean>(false)
  const [busyAction, setBusyAction] = useState<string>('')
  const [error, setError] = useState<string>('')
  const [notice, setNotice] = useState<string>('')
  const [codeLabel, setCodeLabel] = useState<string>('')
  const [expiresMinutes, setExpiresMinutes] = useState<string>('10')
  const [issuedCode, setIssuedCode] = useState<IssuedCode | null>(null)

  useEffect(() => {
    if (!open || !authenticated) return
    void loadDevices()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, authenticated])

  const sortedDevices = useMemo(() => {
    return [...devices].sort((a, b) => {
      const aRevoked = Boolean(a.revoked_at)
      const bRevoked = Boolean(b.revoked_at)
      if (aRevoked !== bRevoked) return aRevoked ? 1 : -1
      return b.id - a.id
    })
  }, [devices])

  async function loadDevices(): Promise<void> {
    setLoading(true)
    setError('')
    try {
      const data = await api<PairedDeviceListResponse>('/api/pairing/devices')
      setDevices(Array.isArray(data.devices) ? data.devices : [])
      setPendingCodes(Number(data.pending_codes || 0))
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError('Current session cannot manage paired devices. Sign in with an operator session.')
        return
      }
      if (e instanceof ApiError && e.status === 401) {
        setError('Sign in again to manage paired devices.')
        return
      }
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  async function createCode(): Promise<void> {
    const trimmedMinutes = expiresMinutes.trim()
    const minutes = trimmedMinutes ? Number(trimmedMinutes) : 10
    if (!Number.isFinite(minutes) || minutes < 1 || minutes > 60) {
      setError('Expiry must be between 1 and 60 minutes.')
      return
    }
    setBusyAction('create')
    setError('')
    setNotice('')
    try {
      const data = await api<PairingCodeResponse>('/api/pairing/codes', {
        method: 'POST',
        body: JSON.stringify({
          label: codeLabel.trim() || null,
          expires_minutes: minutes,
        }),
      })
      if (!data.code) {
        throw new Error('missing code in response')
      }
      setIssuedCode({
        code: data.code,
        label: String(data.label || ''),
        expiresAt: data.expires_at ?? null,
      })
      setNotice('Pairing code ready. Enter it in the client that should connect to this Server.')
      await loadDevices()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusyAction('')
    }
  }

  async function revokeDevice(item: PairedDeviceRecord): Promise<void> {
    if (!window.confirm(`Revoke device "${item.label}" (${item.prefix})? It will have to pair again.`)) return
    setBusyAction(`revoke:${item.id}`)
    setError('')
    setNotice('')
    try {
      await api(`/api/pairing/devices/${item.id}`, { method: 'DELETE' })
      setNotice(`Revoked device "${item.label}".`)
      await loadDevices()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusyAction('')
    }
  }

  async function copyIssuedCode(): Promise<void> {
    if (!issuedCode?.code) return
    try {
      await navigator.clipboard.writeText(issuedCode.code)
      setNotice('Copied pairing code to clipboard.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Clipboard copy failed.')
    }
  }

  return (
    <div className="space-y-4">
      <Callout.Root size="1" variant="soft">
        <Callout.Text>
          Pair a local MicroClaw client with this Server. A pairing code is single-use and short-lived;
          the device token it issues carries <code>operator.read</code> and <code>operator.write</code> only
          and can be revoked here at any time.
        </Callout.Text>
      </Callout.Root>

      {issuedCode ? (
        <Card className="p-3">
          <Flex align="center" justify="between" gap="3" wrap="wrap">
            <div>
              <Text size="2" weight="bold">Pairing code</Text>
              <Text size="1" color="gray" className="mt-1 block">
                Valid once, until {formatTimestamp(issuedCode.expiresAt, 'it is claimed')}.
              </Text>
            </div>
            <Button variant="soft" onClick={() => void copyIssuedCode()}>
              Copy
            </Button>
          </Flex>
          <TextField.Root
            className="mt-3"
            value={issuedCode.code}
            readOnly
            style={{ fontFamily: 'monospace', letterSpacing: '0.2em', fontSize: '1.25rem' }}
          />
          {issuedCode.label ? (
            <Badge variant="soft" color="blue" className="mt-3">{issuedCode.label}</Badge>
          ) : null}
        </Card>
      ) : null}

      <Card className="p-3">
        <Text size="3" weight="bold">Create pairing code</Text>
        <Text size="1" color="gray" className="mt-1 block">
          Changes here apply immediately. Pending codes: {pendingCodes}.
        </Text>
        <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
          <Card className="p-3">
            <Text size="2" weight="medium">Label</Text>
            <Text size="1" color="gray" className="mt-1 block">
              Optional prefix for the device name the client reports.
            </Text>
            <TextField.Root
              className="mt-3"
              value={codeLabel}
              onChange={(e) => setCodeLabel(e.target.value)}
              placeholder="Laptop"
            />
          </Card>
          <Card className="p-3">
            <Text size="2" weight="medium">Expiry (minutes)</Text>
            <Text size="1" color="gray" className="mt-1 block">
              Between 1 and 60. Unclaimed codes are discarded on Server restart.
            </Text>
            <TextField.Root
              className="mt-3"
              type="number"
              min="1"
              max="60"
              value={expiresMinutes}
              onChange={(e) => setExpiresMinutes(e.target.value)}
              placeholder="10"
            />
          </Card>
        </div>
        <Flex justify="end" className="mt-3">
          <Button onClick={() => void createCode()} disabled={busyAction === 'create'}>
            {busyAction === 'create' ? 'Creating...' : 'Create pairing code'}
          </Button>
        </Flex>
      </Card>

      {error ? (
        <Callout.Root color="red" size="1" variant="soft">
          <Callout.Text>{error}</Callout.Text>
        </Callout.Root>
      ) : null}
      {notice ? (
        <Callout.Root color="green" size="1" variant="soft">
          <Callout.Text>{notice}</Callout.Text>
        </Callout.Root>
      ) : null}

      <Card className="p-3">
        <Flex align="center" justify="between" gap="3" wrap="wrap">
          <div>
            <Text size="3" weight="bold">Paired devices</Text>
            <Text size="1" color="gray" className="mt-1 block">
              Active devices are shown first. Revoked devices remain listed for auditability.
            </Text>
          </div>
          <Button variant="soft" onClick={() => void loadDevices()} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </Button>
        </Flex>

        <div className="mt-3 space-y-3">
          {!loading && sortedDevices.length === 0 ? (
            <Text size="2" color="gray">No paired devices yet.</Text>
          ) : null}
          {sortedDevices.map((item) => {
            const actionKey = `revoke:${item.id}`
            const revoked = Boolean(item.revoked_at)
            return (
              <Card key={item.id} className="p-3">
                <Flex align="start" justify="between" gap="3" wrap="wrap">
                  <div>
                    <Flex align="center" gap="2" wrap="wrap">
                      <Text size="2" weight="medium">{item.label}</Text>
                      <Badge variant="soft" color={revoked ? 'gray' : 'green'}>
                        {revoked ? 'revoked' : 'active'}
                      </Badge>
                      <Badge variant="soft" color="blue">{item.prefix}</Badge>
                      {item.platform ? (
                        <Badge variant="soft" color="gray">{item.platform}</Badge>
                      ) : null}
                    </Flex>
                    <Flex gap="2" wrap="wrap" className="mt-2">
                      {(item.scopes || []).map((scope) => (
                        <Badge key={`${item.id}-${scope}`} variant="soft" color="indigo">
                          {scope}
                        </Badge>
                      ))}
                    </Flex>
                    <Text size="1" color="gray" className="mt-2 block">
                      paired {formatTimestamp(item.created_at)} | last seen {formatTimestamp(item.last_seen_at, 'never')}
                    </Text>
                    <Text size="1" color="gray" className="mt-1 block">
                      device {item.device_id} | revoked {formatTimestamp(item.revoked_at, 'not revoked')}
                    </Text>
                  </div>
                  <Flex gap="2" wrap="wrap">
                    <Button
                      variant="soft"
                      color="red"
                      disabled={revoked || busyAction === actionKey}
                      onClick={() => void revokeDevice(item)}
                    >
                      {busyAction === actionKey ? 'Revoking...' : 'Revoke'}
                    </Button>
                  </Flex>
                </Flex>
              </Card>
            )
          })}
        </div>
      </Card>
    </div>
  )
}

function formatTimestamp(value?: string | null, emptyLabel = 'Unknown'): string {
  if (!value) return emptyLabel
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed)) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(parsed))
}
