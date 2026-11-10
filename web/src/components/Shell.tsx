import {
  IconAdjustments,
  IconGauge,
  IconListDetails,
  IconShieldX,
  IconTimeline,
  IconUsers,
} from '@tabler/icons-react'
import type { ReactNode } from 'react'

import { useConnectionState, useMeta } from '../api/hooks'
import { href, type Screen } from '../lib/router'
import classes from './Shell.module.css'

interface Tab {
  screen: Screen
  label: string
  icon: typeof IconGauge
  /** Shown in the phone's tab bar (five fit). */
  phone: boolean
}

const TABS: Tab[] = [
  { screen: 'overview', label: 'Overview', icon: IconGauge, phone: true },
  { screen: 'addresses', label: 'Addresses', icon: IconUsers, phone: true },
  { screen: 'bans', label: 'Bans', icon: IconShieldX, phone: true },
  { screen: 'events', label: 'Events', icon: IconTimeline, phone: false },
  { screen: 'rules', label: 'Rules', icon: IconListDetails, phone: true },
  { screen: 'settings', label: 'Settings', icon: IconAdjustments, phone: true },
]

const CONNECTION_LABEL = { open: 'Live', connecting: 'Connecting', closed: 'Offline' } as const

export function Logo() {
  return (
    <svg viewBox="0 0 32 32" width="18" height="18" aria-hidden="true">
      <path
        d="M7 26V11l3-2v3h3V8l3-2 3 2v4h3V9l3 2v15h-6v-6a3 3 0 0 0-6 0v6z"
        fill="currentColor"
      />
    </svg>
  )
}

export function Shell({ screen, children }: { screen: Screen; children: ReactNode }) {
  const connection = useConnectionState()
  const meta = useMeta()
  return (
    <>
      <header className={classes.header}>
        <div className={classes.headerInner}>
          <a className={classes.brand} href={href('overview')}>
            <span className={classes.brandMark}>
              <Logo />
            </span>
            barbican
          </a>
          <nav className={classes.nav} aria-label="Main">
            {TABS.map(({ screen: s, label, icon: Icon }) => (
              <a
                key={s}
                className={classes.navLink}
                href={href(s)}
                aria-current={s === screen ? 'page' : undefined}
              >
                <Icon size={16} stroke={1.8} />
                {label}
              </a>
            ))}
          </nav>
          <div className={classes.spacer} />
          {meta.data?.dryRun === true && (
            <span
              className={classes.dryRun}
              title="Decisions are recorded; the firewall isn't changed"
            >
              Dry run
            </span>
          )}
          <div className={classes.connection} role="status">
            <span className={classes.dot} data-state={connection} />
            {CONNECTION_LABEL[connection]}
          </div>
        </div>
      </header>
      <main className={classes.main}>{children}</main>
      <nav className={classes.tabbar} aria-label="Main">
        {TABS.filter((t) => t.phone).map(({ screen: s, label, icon: Icon }) => (
          <a
            key={s}
            className={classes.tab}
            href={href(s)}
            aria-current={s === screen ? 'page' : undefined}
          >
            <Icon size={22} stroke={1.7} />
            {label}
          </a>
        ))}
      </nav>
    </>
  )
}
