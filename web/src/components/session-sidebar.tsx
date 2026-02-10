import React, { useEffect, useRef, useState } from 'react'
import { Badge, Button, Flex, ScrollArea, Separator, Text } from '@radix-ui/themes'

type SessionSidebarProps = {
  appearance: 'dark' | 'light'
  onToggleAppearance: () => void
  uiTheme: string
  onUiThemeChange: (theme: string) => void
  uiThemeOptions: Array<{ key: string; label: string; color: string }>
  sessionKeys: string[]
  sessionKey: string
  onSessionSelect: (key: string) => void
  onRefreshSession: (key: string) => void
  onResetSession: (key: string) => void
  onDeleteSession: (key: string) => void
  onOpenConfig: () => Promise<void>
  onNewSession: () => void
}

export function SessionSidebar({
  appearance,
  onToggleAppearance,
  uiTheme,
  onUiThemeChange,
  uiThemeOptions,
  sessionKeys,
  sessionKey,
  onSessionSelect,
  onRefreshSession,
  onResetSession,
  onDeleteSession,
  onOpenConfig,
  onNewSession,
}: SessionSidebarProps) {
  const isDark = appearance === 'dark'
  const [menu, setMenu] = useState<{ x: number; y: number; key: string } | null>(null)
  const [themeMenuOpen, setThemeMenuOpen] = useState(false)
  const themeMenuRef = useRef<HTMLDivElement | null>(null)
  const themeButtonRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null
      if (!target) return

      if (themeButtonRef.current?.contains(target)) return
      if (themeMenuRef.current?.contains(target)) return

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
      className={isDark ? 'flex h-full min-h-0 flex-col border-r p-4' : 'flex h-full min-h-0 flex-col border-r border-slate-200 bg-white p-4'}
      style={isDark ? { borderColor: 'var(--mc-border-soft)', background: 'var(--mc-bg-sidebar)' } : undefined}
    >
      <Flex justify="between" align="center" className="mb-4">
        <div className="flex items-center gap-2">
          <img
            src="/icon.png"
            alt="MicroClaw"
            className="h-7 w-7 rounded-md border border-black/10 object-cover"
            loading="eager"
            decoding="async"
          />
          <Text size="5" weight="bold">
            MicroClaw
          </Text>
        </div>
        <div className="relative flex items-center gap-2">
          {isDark ? (
            <button
              ref={themeButtonRef}
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setThemeMenuOpen((v) => !v)
              }}
              aria-label="Change UI theme color"
              className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)] text-slate-200 hover:brightness-110"
            >
              <span className="text-sm">🎨</span>
            </button>
          ) : null}
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
          {isDark && themeMenuOpen ? (
            <div
              ref={themeMenuRef}
              className="absolute right-0 top-10 z-50 w-56 rounded-lg border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-sidebar)] p-2 shadow-xl"
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
                        ? 'flex items-center gap-2 rounded-md border border-[color:var(--mc-accent)] bg-[color:var(--mc-bg-panel)] px-2 py-1 text-left text-xs text-slate-100'
                        : 'flex items-center gap-2 rounded-md border border-transparent px-2 py-1 text-left text-xs text-slate-300 hover:border-[color:var(--mc-border-soft)] hover:bg-[color:var(--mc-bg-panel)]'
                    }
                  >
                    <span
                      className="h-3 w-3 rounded-sm border border-white/20"
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
          className={
            isDark
              ? 'inline-flex h-9 w-full items-center justify-center rounded-md border border-transparent text-[15px] font-medium transition hover:brightness-110 active:brightness-95'
              : 'inline-flex h-9 w-full items-center justify-center rounded-md border border-slate-300 bg-slate-900 text-[15px] font-medium text-white transition hover:bg-slate-800 active:bg-slate-700'
          }
          style={isDark ? { backgroundColor: 'var(--mc-accent)', color: '#06110f' } : undefined}
        >
          New Session
        </button>
      </Flex>

      <Separator size="4" className="my-4" />

      <Flex justify="between" align="center" className="mb-2">
        <Text size="2" weight="medium" color="gray">
          Sessions
        </Text>
        <Badge variant="surface">{sessionKeys.length}</Badge>
      </Flex>

      <div
        className={
          isDark
            ? 'min-h-0 flex-1 rounded-xl border border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)] p-2'
            : 'min-h-0 flex-1 rounded-xl border border-slate-200 bg-slate-50/70 p-2'
        }
      >
        <ScrollArea type="auto" style={{ height: '100%' }}>
          <div className="mb-2">
            <Text size="1" color="gray">
              Chats
            </Text>
          </div>
          <div className="flex flex-col gap-1.5 pr-1">
            {sessionKeys.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => onSessionSelect(key)}
                onContextMenu={(e) => {
                  e.preventDefault()
                  setMenu({ x: e.clientX, y: e.clientY, key })
                }}
                className={
                  sessionKey === key
                    ? isDark
                      ? 'flex w-full items-center rounded-lg border border-[color:var(--mc-accent)] bg-[color:var(--mc-bg-panel)] px-3 py-2 text-left shadow-sm'
                      : 'flex w-full items-center rounded-lg border border-slate-300 bg-white px-3 py-2 text-left shadow-sm'
                    : isDark
                      ? 'flex w-full items-center rounded-lg border border-transparent px-3 py-2 text-left text-slate-300 hover:border-[color:var(--mc-border-soft)] hover:bg-[color:var(--mc-bg-panel)]'
                      : 'flex w-full items-center rounded-lg border border-transparent px-3 py-2 text-left text-slate-600 hover:border-slate-200 hover:bg-white'
                }
              >
                <span className="max-w-[220px] truncate text-sm font-medium">{key}</span>
              </button>
            ))}
          </div>
        </ScrollArea>
      </div>

      <div className={isDark ? 'mt-4 border-t border-[color:var(--mc-border-soft)] pt-3' : 'mt-4 border-t border-slate-200 pt-3'}>
        <Button size="2" variant="soft" onClick={() => void onOpenConfig()} style={{ width: '100%' }}>
          Runtime Config
        </Button>
        <div className="mt-3 flex flex-col items-center gap-1">
          <a
            href="https://microclaw.ai"
            target="_blank"
            rel="noreferrer"
            className={isDark ? 'text-xs text-slate-400 hover:text-slate-200' : 'text-xs text-slate-600 hover:text-slate-900'}
          >
            microclaw.ai
          </a>
        </div>
      </div>

      {menu ? (
        <div
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
