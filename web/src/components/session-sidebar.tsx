import React, { useEffect, useRef, useState } from 'react'
import { Badge, Button, Flex, ScrollArea, Separator, Text } from '@radix-ui/themes'
import type { SessionItem } from '../types'

type SessionSidebarProps = {
  appearance: 'dark' | 'light'
  onToggleAppearance: () => void
  onToggleDesktopSidebar?: () => void
  uiTheme: string
  onUiThemeChange: (theme: string) => void
  uiThemeOptions: Array<{ key: string; label: string; color: string }>
  sessionItems: SessionItem[]
  selectedSessionKey: string
  onSessionSelect: (key: string) => void
  onRefreshSession: (key: string) => void
  onResetSession: (key: string) => void
  onDeleteSession: (key: string) => void
  onOpenConfig: () => Promise<void>
  onOpenUsage: () => Promise<void>
  onNewSession: () => void
  appVersion: string
}

function parseSessionKeyCreatedAt(sessionKey: string): Date | null {
  const matched = /^session-(\d{14})$/.exec(sessionKey.trim())
  if (!matched) return null
  const raw = matched[1]
  const y = Number(raw.slice(0, 4))
  const m = Number(raw.slice(4, 6))
  const d = Number(raw.slice(6, 8))
  const hh = Number(raw.slice(8, 10))
  const mm = Number(raw.slice(10, 12))
  const ss = Number(raw.slice(12, 14))
  if (!Number.isFinite(y) || !Number.isFinite(m) || !Number.isFinite(d)) return null
  const dt = new Date(y, m - 1, d, hh, mm, ss)
  if (Number.isNaN(dt.getTime())) return null
  return dt
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

function formatCreatedLabel(item: SessionItem): string {
  const createdAt = parseSessionKeyCreatedAt(item.session_key)
  const fallback = Date.parse(item.last_message_time || '')
  const date = createdAt || (Number.isFinite(fallback) ? new Date(fallback) : null)
  if (!date) return 'created --'
  return `created ${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}`
}

export function SessionSidebar({
  appearance,
  onToggleAppearance,
  onToggleDesktopSidebar,
  uiTheme,
  onUiThemeChange,
  uiThemeOptions,
  sessionItems,
  selectedSessionKey,
  onSessionSelect,
  onRefreshSession,
  onResetSession,
  onDeleteSession,
  onOpenConfig,
  onOpenUsage,
  onNewSession,
  appVersion,
}: SessionSidebarProps) {
  const isDark = appearance === 'dark'
  const [menu, setMenu] = useState<{ x: number; y: number; key: string } | null>(null)
  const [themeMenuOpen, setThemeMenuOpen] = useState(false)
  const themeMenuRef = useRef<HTMLDivElement | null>(null)
  const themeButtonRef = useRef<HTMLButtonElement | null>(null)
  const sessionMenuRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null
      if (!target) return

      if (themeButtonRef.current?.contains(target)) return
      if (themeMenuRef.current?.contains(target)) return
      if (sessionMenuRef.current?.contains(target)) return

      setMenu(null)
      setThemeMenuOpen(false)
    }

    const closeOnScroll = () => {
      setMenu(null)
      setThemeMenuOpen(false)
    }

    window.addEventListener('pointerdown', onPointerDown)
    window.addEventListener('scroll', closeOnScroll, true)
    return () => {
      window.removeEventListener('pointerdown', onPointerDown)
      window.removeEventListener('scroll', closeOnScroll, true)
    }
  }, [])

  return (
    <aside
      className={isDark ? 'mc-sidebar flex h-full min-h-0 flex-col border-r p-4' : 'mc-sidebar flex h-full min-h-0 flex-col border-r p-4'}
      style={isDark ? { borderColor: 'var(--mc-border-soft)', background: 'var(--mc-bg-sidebar)' } : undefined}
    >
      <Flex justify="between" align="center" className="mc-brand-row mb-5">
        <div className="flex items-center gap-2">
          <img
            src="/icon.png"
            alt="MicroClaw"
            className="h-7 w-7 rounded-md border border-black/10 object-cover"
            loading="eager"
            decoding="async"
          />
          <div className="flex flex-col">
            <Text size="4" weight="bold" className="leading-none">MicroClaw</Text>
            <Text size="1" className="mc-brand-kicker">Agent runtime</Text>
          </div>
        </div>
        <div className="relative flex items-center gap-2">
          <button
            ref={themeButtonRef}
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              setThemeMenuOpen((v) => !v)
            }}
            aria-label="Change UI theme color"
            className={
              isDark
                ? 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)] text-slate-200 hover:brightness-110'
                : 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'
            }
          >
            <span className="text-sm">🎨</span>
          </button>
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              onToggleAppearance()
            }}
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            className={
              isDark
                ? 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)] text-slate-200 hover:brightness-110'
                : 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'
            }
          >
            <span className="text-sm">{isDark ? '☀' : '☾'}</span>
          </button>
          {onToggleDesktopSidebar ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onToggleDesktopSidebar()
              }}
              aria-label="Collapse sessions sidebar"
              className={
                isDark
                  ? 'hidden md:inline-flex h-8 w-8 items-center justify-center rounded-md border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)] text-slate-200 hover:brightness-110'
                  : 'hidden md:inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'
              }
            >
              <span className="text-sm">⟨</span>
            </button>
          ) : null}
          {themeMenuOpen ? (
            <div
              ref={themeMenuRef}
              className={
                isDark
                  ? 'absolute right-0 top-10 z-50 w-56 rounded-lg border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-sidebar)] p-2 shadow-xl'
                  : 'absolute right-0 top-10 z-50 w-56 rounded-lg border border-slate-300 bg-white p-2 shadow-xl'
              }
            >
              <Text size="1" color="gray">Theme</Text>
              <div className="mt-2 grid grid-cols-2 gap-1">
                {uiThemeOptions.map((theme) => (
                  <button
                    key={theme.key}
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onUiThemeChange(theme.key)
                      setThemeMenuOpen(false)
                    }}
                    className={
                      uiTheme === theme.key
                        ? isDark
                          ? 'flex items-center gap-2 rounded-md border border-[color:var(--mc-accent)] bg-[color:var(--mc-bg-panel)] px-2 py-1 text-left text-xs text-slate-100'
                          : 'flex items-center gap-2 rounded-md border px-2 py-1 text-left text-xs text-slate-900'
                        : isDark
                          ? 'flex items-center gap-2 rounded-md border border-transparent px-2 py-1 text-left text-xs text-slate-300 hover:border-[color:var(--mc-border-soft)] hover:bg-[color:var(--mc-bg-panel)]'
                          : 'flex items-center gap-2 rounded-md border border-transparent px-2 py-1 text-left text-xs text-slate-600 hover:border-slate-200 hover:bg-slate-50'
                    }
                    style={!isDark && uiTheme === theme.key ? { borderColor: 'var(--mc-accent)', backgroundColor: 'color-mix(in srgb, var(--mc-accent) 12%, white)' } : undefined}
                  >
                    <span
                      className={isDark ? 'h-3 w-3 rounded-sm border border-white/20' : 'h-3 w-3 rounded-sm border border-slate-300'}
                      style={{ backgroundColor: theme.color }}
                      aria-hidden="true"
                    />
                    {theme.label}
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </Flex>

      <Flex direction="column" gap="2" className="mb-4">
        <button
          type="button"
          onClick={onNewSession}
          className="mc-new-session inline-flex h-10 w-full items-center justify-center rounded-lg border border-transparent text-[14px] font-semibold transition hover:brightness-110 active:brightness-95"
          style={isDark ? { backgroundColor: 'var(--mc-accent)', color: '#06110f' } : { backgroundColor: 'var(--mc-accent)', color: '#ffffff' }}
        >
          <span aria-hidden="true" className="mr-2 text-lg leading-none">+</span> New session
        </button>
      </Flex>

      <Separator size="4" className="my-4" />

      <Flex justify="between" align="center" className="mb-2">
        <Text size="2" weight="medium" color="gray">
          Sessions
        </Text>
        <Badge variant="surface">{sessionItems.length}</Badge>
      </Flex>

      <div
        data-testid="session-list"
        className={
          isDark
            ? 'mc-session-list flex min-h-0 flex-1 flex-col rounded-xl border p-2'
            : 'mc-session-list flex min-h-0 flex-1 flex-col rounded-xl border p-2'
        }
      >
        <ScrollArea type="auto" className="min-h-0 flex-1">
          <div className="mb-2">
            <Text size="1" color="gray">
              Chats
            </Text>
          </div>
          <div className="flex flex-col gap-1.5 pr-4">
            {sessionItems.map((item) => (
              <button
                key={item.session_key}
                type="button"
                onClick={() => onSessionSelect(item.session_key)}
                onContextMenu={(e) => {
                  e.preventDefault()
                  setMenu({ x: e.clientX, y: e.clientY, key: item.session_key })
                }}
                className={
                  selectedSessionKey === item.session_key
                    ? isDark
                      ? 'mc-session-item is-active flex w-full max-w-full flex-col items-start rounded-lg border px-3 py-2.5 text-left'
                      : 'mc-session-item is-active flex w-full max-w-full flex-col items-start rounded-lg border px-3 py-2.5 text-left'
                    : isDark
                      ? 'mc-session-item flex w-full max-w-full flex-col items-start rounded-lg border px-3 py-2.5 text-left text-slate-300'
                      : 'mc-session-item flex w-full max-w-full flex-col items-start rounded-lg border px-3 py-2.5 text-left text-slate-600'
                }
                style={
                  !isDark && selectedSessionKey === item.session_key
                    ? {
                        borderColor: 'color-mix(in srgb, var(--mc-accent) 36%, #94a3b8)',
                        boxShadow: '0 4px 12px color-mix(in srgb, var(--mc-accent) 12%, transparent)',
                      }
                    : undefined
                }
              >
                <span className="max-w-full truncate text-sm font-medium">{item.label}</span>
                <span className={isDark ? 'mt-0.5 text-[11px] uppercase tracking-wide text-slate-500' : 'mt-0.5 text-[11px] uppercase tracking-wide text-slate-400'}>
                  {item.chat_type}
                </span>
                <span className={isDark ? 'mt-0.5 text-[11px] text-slate-500' : 'mt-0.5 text-[11px] text-slate-400'}>
                  {formatCreatedLabel(item)}
                </span>
              </button>
            ))}
          </div>
        </ScrollArea>
      </div>

      <div className="mc-sidebar-footer mt-4 border-t pt-3">
        <Button size="2" variant="soft" onClick={() => void onOpenUsage()} style={{ width: '100%' }}>
          Usage Panel
        </Button>
        <Button size="2" variant="soft" onClick={() => void onOpenConfig()} style={{ width: '100%', marginTop: '8px' }}>
          Runtime Config
        </Button>
        <div className="mt-3 flex items-center justify-between gap-3">
          <a
            href="https://microclaw.org"
            target="_blank"
            rel="noreferrer"
            className={isDark ? 'text-xs text-slate-400 hover:text-slate-200' : 'text-xs text-slate-600 hover:text-slate-900'}
          >
            microclaw.org
          </a>
          <Text size="1" className={isDark ? 'text-slate-500' : 'text-slate-500'}>
            {appVersion ? `v${appVersion}` : 'v--'}
          </Text>
        </div>
      </div>

      {menu ? (
        <div
          ref={sessionMenuRef}
          className={
            isDark
              ? 'fixed z-50 min-w-[170px] rounded-lg border border-emerald-900/80 bg-[#092018] p-1.5 shadow-xl'
              : 'fixed z-50 min-w-[170px] rounded-lg border border-slate-300 bg-white p-1.5 shadow-xl'
          }
          style={{ left: menu.x, top: menu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            className={
              isDark
                ? 'flex w-full rounded-md px-3 py-2 text-left text-sm text-slate-100 hover:bg-emerald-900/50'
                : 'flex w-full rounded-md px-3 py-2 text-left text-sm text-slate-700 hover:bg-slate-100'
            }
            onClick={() => {
              onRefreshSession(menu.key)
              setMenu(null)
            }}
          >
            Refresh
          </button>
          <button
            type="button"
            className={
              isDark
                ? 'mt-1 flex w-full rounded-md px-3 py-2 text-left text-sm text-amber-300 hover:bg-amber-900/20'
                : 'mt-1 flex w-full rounded-md px-3 py-2 text-left text-sm text-amber-700 hover:bg-amber-50'
            }
            onClick={() => {
              onResetSession(menu.key)
              setMenu(null)
            }}
          >
            Clear Context
          </button>
          <button
            type="button"
            className={
              isDark
                ? 'mt-1 flex w-full rounded-md px-3 py-2 text-left text-sm text-red-300 hover:bg-red-900/20'
                : 'mt-1 flex w-full rounded-md px-3 py-2 text-left text-sm text-red-700 hover:bg-red-50'
            }
            onClick={() => {
              onDeleteSession(menu.key)
              setMenu(null)
            }}
          >
            Delete
          </button>
        </div>
      ) : null}
    </aside>
  )
}
