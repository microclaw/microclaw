import React, { useEffect, useState } from 'react'
import { Badge, Button, Flex, ScrollArea, Separator, Text } from '@radix-ui/themes'

type SessionSidebarProps = {
  appearance: 'dark' | 'light'
  onToggleAppearance: () => void
  sessionKeys: string[]
  sessionKey: string
  onSessionSelect: (key: string) => void
  onRefreshSession: (key: string) => void
  onResetSession: (key: string) => void
  onOpenConfig: () => Promise<void>
  onNewSession: () => void
}

export function SessionSidebar({
  appearance,
  onToggleAppearance,
  sessionKeys,
  sessionKey,
  onSessionSelect,
  onRefreshSession,
  onResetSession,
  onOpenConfig,
  onNewSession,
}: SessionSidebarProps) {
  const isDark = appearance === 'dark'
  const [menu, setMenu] = useState<{ x: number; y: number; key: string } | null>(null)

  useEffect(() => {
    const close = () => setMenu(null)
    window.addEventListener('click', close)
    window.addEventListener('scroll', close, true)
    return () => {
      window.removeEventListener('click', close)
      window.removeEventListener('scroll', close, true)
    }
  }, [])

  return (
    <aside
      className={
        isDark
          ? 'flex h-full min-h-0 flex-col border-r border-emerald-950/80 bg-[#03110d] p-4'
          : 'flex h-full min-h-0 flex-col border-r border-slate-200 bg-white p-4'
      }
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
        <button
          type="button"
          onClick={onToggleAppearance}
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          className={
            isDark
              ? 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-emerald-900/70 bg-emerald-950/50 text-slate-200 hover:bg-emerald-900/40'
              : 'inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'
          }
        >
          <span className="text-sm">{isDark ? '☀' : '☾'}</span>
        </button>
      </Flex>

      <Flex direction="column" gap="2" className="mb-4">
        <Button size="2" variant="solid" color="green" onClick={onNewSession}>
          New Session
        </Button>
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
            ? 'min-h-0 flex-1 rounded-xl border border-emerald-950/60 bg-emerald-950/25 p-2'
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
                      ? 'flex w-full items-center rounded-lg border border-emerald-900/80 bg-emerald-950/70 px-3 py-2 text-left shadow-sm'
                      : 'flex w-full items-center rounded-lg border border-slate-300 bg-white px-3 py-2 text-left shadow-sm'
                    : isDark
                      ? 'flex w-full items-center rounded-lg border border-transparent px-3 py-2 text-left text-slate-300 hover:border-emerald-900/70 hover:bg-emerald-950/50'
                      : 'flex w-full items-center rounded-lg border border-transparent px-3 py-2 text-left text-slate-600 hover:border-slate-200 hover:bg-white'
                }
              >
                <span className="max-w-[220px] truncate text-sm font-medium">{key}</span>
              </button>
            ))}
          </div>
        </ScrollArea>
      </div>

      <div className={isDark ? 'mt-4 border-t border-emerald-950/40 pt-3' : 'mt-4 border-t border-slate-200 pt-3'}>
        <Button size="2" variant="soft" onClick={() => void onOpenConfig()} style={{ width: '100%' }}>
          Runtime Config
        </Button>
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
            Refresh Session
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
            Reset Session
          </button>
        </div>
      ) : null}
    </aside>
  )
}
