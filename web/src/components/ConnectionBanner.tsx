import { Button } from '@mantine/core'
import { IconPlugConnectedX } from '@tabler/icons-react'
import type { ReactNode } from 'react'

import type { ProxyProblemKind } from '../api/generated/model'
import { rpc, type Connection } from '../api/rpc'
import { ago } from '../lib/format'
import { useNow } from '../lib/useNow'
import classes from './ConnectionBanner.module.css'

const PROXY_TITLES: Record<ProxyProblemKind, string> = {
  notFound: "The agent's socket isn't there",
  permissionDenied: "The UI isn't allowed to use the agent's socket",
  refused: "The agent isn't accepting connections",
  noAnswer: "The agent doesn't answer",
  other: "The agent's socket can't be used",
}

interface Description {
  title: string
  hint?: ReactNode
  /** What failed, as the system put it. */
  detail?: string
  /** Offer a reload: the page itself may be what's wrong (a session that expired). */
  reload?: boolean
}

function describe({ problem, failures, lostAt }: Connection): Description {
  const lost = lostAt !== null
  switch (problem?.kind) {
    case undefined:
      return {
        title: lost ? 'The connection to the agent was lost' : "Can't connect to the agent",
        hint: 'Finding out why…',
      }
    case 'proxy':
      return {
        title: PROXY_TITLES[problem.problem.kind],
        hint: problem.problem.hint,
        detail: `${problem.socket}: ${problem.problem.error}`,
      }
    case 'answers':
      // Right after a restart the agent answers before the next attempt, which then connects.
      if (failures < 2) return { title: 'Reconnecting to the agent' }
      return {
        title: 'The agent answers, but refuses the live connection',
        hint: (
          <>
            Plain requests reach it, the WebSocket fails. The agent&apos;s log says why: it accepts
            the UI only from pages of the host it&apos;s asked for (the request&apos;s{' '}
            <code>Origin</code> has to match its <code>Host</code>).
          </>
        ),
      }
    case 'gateway':
      return {
        title: `The server answered ${String(problem.status)}`,
        hint: "What's in front of barbican (a reverse proxy) can't reach it. Is the UI's container, or the agent, running?",
      }
    case 'foreign':
      return {
        title: "The server answered with a page that isn't barbican's",
        hint: 'A sign-in page, perhaps: the session may have expired. Reload the page.',
        reload: true,
      }
    case 'server':
      return {
        title: "The server can't be reached",
        hint: `Nothing answers at ${window.location.host}. Is barbican running (the agent, or the UI's container)? Is the network up?`,
        reload: true,
      }
  }
}

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/** While the UI isn't connected to the agent: why, as far as is known, and that it keeps trying. */
export function ConnectionBanner({ connection }: { connection: Connection }) {
  const now = useNow(1_000)
  const { title, hint, detail, reload } = describe(connection)
  const { state, retryAt, lostAt } = connection
  const retrying =
    state === 'connecting' || retryAt === null
      ? 'Retrying…'
      : `Retrying in ${String(Math.max(1, Math.ceil((retryAt - now) / 1000)))} s`
  return (
    <section className={classes.banner} role="alert" aria-live="assertive">
      <div className={classes.icon}>
        <IconPlugConnectedX size={20} stroke={1.8} />
      </div>
      <div className={classes.body}>
        <div className={classes.eyebrow}>Not connected</div>
        <div className={classes.title}>{title}</div>
        {hint !== undefined && <div className={classes.hint}>{hint}</div>}
        {detail !== undefined && <div className={classes.detail}>{detail}</div>}
        {lostAt !== null && (
          <div className={classes.stale}>
            What&apos;s shown is from {clock(lostAt)} ({ago(lostAt / 1000, now)}) and isn&apos;t
            updated until the connection is back.
          </div>
        )}
        <div className={classes.actions}>
          <span className={classes.retrying}>{retrying}</span>
          <Button
            size="compact-sm"
            variant="light"
            onClick={rpc.retry}
            disabled={state === 'connecting'}
          >
            Retry now
          </Button>
          {reload === true && (
            <Button
              size="compact-sm"
              variant="subtle"
              color="gray"
              onClick={() => {
                window.location.reload()
              }}
            >
              Reload
            </Button>
          )}
        </div>
      </div>
    </section>
  )
}
