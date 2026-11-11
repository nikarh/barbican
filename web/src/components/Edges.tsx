import { Badge, Group, Stack, Text, Tooltip } from '@mantine/core'
import type { ReactNode } from 'react'

import type { EdgeStatus } from '../api/generated/model'
import { edgeDropped } from '../lib/edges'
import { ago, approx, bytes, compact, count } from '../lib/format'
import classes from './Edges.module.css'
import status from './Status.module.css'

/** "connected for 3h", "disconnected 5min ago", "not connected since this agent started". */
function connection(e: EdgeStatus, now: number): string {
  if (e.since === null) return 'not connected since this agent started'
  const since = approx(Math.max(0, now / 1000 - e.since))
  return e.connected ? `connected for ${since}` : `disconnected ${ago(e.since, now)}`
}

function Mode({ e }: { e: EdgeStatus }) {
  if (e.enforcing === null) return null
  return e.enforcing ? (
    <Badge color="brass" variant="light">
      Enforcing
    </Badge>
  ) : (
    <Badge color="gray">Dry run</Badge>
  )
}

/** One line per edge, for the overview: whether it's connected, and what its own firewall dropped. */
export function EdgeLines({ edges, now }: { edges: EdgeStatus[]; now: number }) {
  return (
    <Stack gap={8}>
      {edges.map((e) => {
        const dropped = edgeDropped(e)
        return (
          <div key={e.name}>
            <div className={status.line}>
              <span className={status.dot} data-ok={e.connected} />
              <span className={status.value}>
                <strong>{e.name}</strong>
                {e.enforcing === false && <span className={status.faint}> · dry run</span>}
              </span>
              <span className={status.when} data-bad={!e.connected}>
                {e.connected ? 'connected' : e.since === null ? 'never connected' : 'disconnected'}
              </span>
            </div>
            <Text fz={12} c="var(--ink-faint)" pl={16}>
              {dropped === null ? (
                connection(e, now)
              ) : (
                <Tooltip
                  label={`Dropped by the edge ${e.name}’s firewall, for the bans and lists of every agent it follows`}
                  multiline
                  w={260}
                  openDelay={300}
                >
                  <span>
                    {count(dropped)} dropped at {e.name} · {compact(e.report?.blocks ?? 0)} blocks
                  </span>
                </Tooltip>
              )}
            </Text>
          </div>
        )
      })}
    </Stack>
  )
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  )
}

/** Everything known about one edge: a card. */
export function EdgeCard({ e, now }: { e: EdgeStatus; now: number }) {
  const r = e.report
  const others = r?.upstreams.filter((u) => !u.this) ?? []
  const self = r?.upstreams.find((u) => u.this)
  return (
    <div className={['panel', classes.card].join(' ')} data-connected={e.connected}>
      <Group gap={8} wrap="wrap" align="center">
        <span className={status.dot} data-ok={e.connected} />
        <Text fw={620} fz={15}>
          {e.name}
        </Text>
        <Mode e={e} />
      </Group>
      <Text fz={12} c={e.connected ? 'var(--ink-dim)' : 'var(--status-bad)'} mt={2}>
        {connection(e, now)}
        {e.address !== null && <> · from {e.address}</>}
      </Text>
      {(e.version !== null || e.backend !== null) && (
        <Text fz={12} c="var(--ink-faint)">
          {e.version !== null && <>barbican-edge {e.version}</>}
          {e.backend !== null && <> · {e.backend}</>}
        </Text>
      )}
      {r === null ? (
        <Text fz={13} c="var(--ink-dim)" mt={8}>
          No report yet.
        </Text>
      ) : (
        <>
          {r.error !== null && (
            <Text fz={13} c="var(--status-bad)" mt={8} style={{ overflowWrap: 'anywhere' }}>
              Its firewall can’t be updated: {r.error}
            </Text>
          )}
          <dl className={status.facts}>
            <Fact label="Firewall">
              {e.enforcing === false
                ? 'dry run: it follows, but changes nothing'
                : r.applied === null
                  ? 'not applied yet'
                  : `applied ${ago(r.applied, now)}`}
            </Fact>
            <Fact label="Holds">
              {count(r.blocks)} blocked addresses and prefixes, {count(r.listed)} country and list
              prefixes
            </Fact>
            <Fact label={`Dropped at ${e.name}`}>
              <span title={`Dropped by the edge ${e.name}’s firewall`}>
                {count(r.droppedBlocked)} packets ({bytes(r.droppedBlockedBytes)}) for bans,{' '}
                {count(r.droppedListed)} ({bytes(r.droppedListedBytes)}) for countries and lists
              </span>
            </Fact>
            <Fact label="Running">
              for {approx(r.uptime)}, {bytes(r.rss)} of memory
            </Fact>
            <Fact label="Reported">{ago(r.received, now)}</Fact>
            <Fact label="Follows">
              <Stack gap={2}>
                <span>this agent{self !== undefined && <> (as “{self.name}”)</>}</span>
                {others.map((u) => (
                  <span key={u.name} className={classes.upstream}>
                    <span className={status.dot} data-ok={u.connected} />
                    <span>
                      {u.name}: {u.connected ? 'connected' : 'not connected'}
                      {u.lastContact !== null && (
                        <span className={status.faint}>, heard from {ago(u.lastContact, now)}</span>
                      )}
                      {!u.connected && u.error !== null && (
                        <span className={status.faint}> ({u.error})</span>
                      )}
                    </span>
                  </span>
                ))}
              </Stack>
            </Fact>
          </dl>
          {!e.connected && (
            <Text fz={12} c="var(--ink-faint)" mt={6}>
              As it last reported, {ago(r.received, now)}.
            </Text>
          )}
        </>
      )}
    </div>
  )
}
