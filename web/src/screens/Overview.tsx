import { Alert, Group, SimpleGrid, Stack, Table, Text } from '@mantine/core'

import { useFeeds, useGeoStatus, useLive, useOverview } from '../api/hooks'
import type { Feed, Live } from '../api/generated/model'
import { Bars } from '../components/Bars'
import { GeoSummary } from '../components/Geo'
import status from '../components/Status.module.css'
import { Country, Panel, Stat } from '../components/ui'
import { ago, count, KIND_LABELS, remaining } from '../lib/format'
import { href, ipHref } from '../lib/router'
import { useNow } from '../lib/useNow'
import classes from './Overview.module.css'

function LiveFeed() {
  const events = useLive(40)
  const now = useNow(10_000)
  const label = (e: Live) => {
    switch (e.type) {
      case 'event':
        return (
          <>
            <span className={classes.kind}>{KIND_LABELS[e.kind]}</span>
            <a className="plain mono" href={ipHref(e.ip)}>
              {e.ip}
            </a>{' '}
            <Country code={e.country} /> <span className={classes.what}>{e.what}</span>
          </>
        )
      case 'ban':
        return (
          <>
            <span className={classes.banned}>Banned</span>
            <span className="mono">{e.ban.net}</span> — {e.ban.reason}
          </>
        )
      case 'lift':
        return <span className={classes.kind}>Ban #{e.id} lifted</span>
    }
  }
  return (
    <Panel title="Live">
      {events.length === 0 ? (
        <Text c="var(--ink-faint)" fz={13}>
          Waiting for something to happen…
        </Text>
      ) : (
        <ol className={classes.feed}>
          {events.map((e, i) => (
            <li key={String(events.length - i)}>
              {label(e)}
              {e.type === 'event' && <span className={classes.when}>{ago(e.at, now)}</span>}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}

/** A blocklist's line for the overview: its name, how many prefixes, and how recent the list is. */
function FeedLine({ feed: f, now }: { feed: Feed; now: number }) {
  const ok = f.error === null && f.changed !== null
  let when = f.succeeded === null ? 'not yet' : `checked ${ago(f.succeeded, now)}`
  if (!f.def.enabled) when = 'off'
  else if (f.error !== null) when = 'failing'
  return (
    <div className={status.line} title={f.error ?? undefined}>
      <span className={status.dot} data-ok={ok || !f.def.enabled} data-off={!f.def.enabled} />
      <span className={status.value}>{f.def.name}</span>
      <span className={status.faint}>{count(f.count)} prefixes</span>
      <span className={status.when} data-bad={f.error !== null && f.def.enabled}>
        {when}
      </span>
    </div>
  )
}

export function OverviewScreen() {
  const overview = useOverview()
  const geo = useGeoStatus()
  const feeds = useFeeds()
  const now = useNow(30_000)
  if (overview.error) return <Alert color="red">{overview.error.message}</Alert>
  const o = overview.data
  if (!o) return null
  const fw = o.firewall
  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} spacing="sm">
        <Stat
          label="Bans in force"
          value={count(o.bansActive)}
          hint={`${count(o.bansToday)} today`}
        />
        <Stat label="Events today" value={count(o.eventsToday)} hint="matched by a rule" />
        <Stat label="Addresses" value={count(o.ips)} hint="seen doing something" />
        <Stat label="Trusted" value={count(o.trusted)} hint="logged in recently" />
        <Stat
          label="Dropped"
          value={count(fw.droppedBlocked + fw.droppedListed)}
          hint={`${count(fw.droppedListed)} by countries and lists`}
        />
      </SimpleGrid>

      {fw.error !== null && (
        <Alert color="red" title="The firewall can't be updated">
          {fw.error}
        </Alert>
      )}

      <div className={classes.columns}>
        <Stack gap="md">
          <Panel title="Last 30 days">
            <Stack gap="lg">
              <Bars
                title="Bans"
                color="var(--mark-ban)"
                bars={o.days.map((d) => ({ day: d.day, value: d.bans }))}
              />
              <Bars
                title="Events"
                color="var(--mark-event)"
                bars={o.days.map((d) => ({ day: d.day, value: d.events }))}
              />
            </Stack>
          </Panel>

          <Panel
            title="Recent bans"
            right={
              <a className="panel-link" href={href('bans')}>
                All bans
              </a>
            }
          >
            <Table.ScrollContainer minWidth={420}>
              <Table verticalSpacing={6} fz={13}>
                <Table.Tbody>
                  {o.recent.map((b) => (
                    <Table.Tr key={b.id}>
                      <Table.Td>
                        <a className="plain mono" href={ipHref(b.ip ?? b.net)}>
                          {b.net}
                        </a>
                      </Table.Td>
                      <Table.Td>
                        <Country code={b.country} />
                      </Table.Td>
                      <Table.Td>{b.reason}</Table.Td>
                      <Table.Td c="var(--ink-dim)">{ago(b.created, now)}</Table.Td>
                      <Table.Td c="var(--ink-dim)">
                        {b.lifted === null ? remaining(b.until, now) : 'lifted'}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Panel>
          <LiveFeed />
        </Stack>

        <Stack gap="md">
          <Panel title="Firewall">
            <Stack gap={4} fz={13}>
              <Group justify="space-between">
                <span>State</span>
                <span>
                  {fw.enabled
                    ? fw.error === null
                      ? `applied ${ago(fw.applied, now)}`
                      : 'failing'
                    : 'dry run'}
                </span>
              </Group>
              <Group justify="space-between">
                <span>Blocked addresses and prefixes</span>
                <span className="num">{count(fw.blocks)}</span>
              </Group>
              <Group justify="space-between">
                <span>Country and list prefixes</span>
                <span className="num">{count(fw.listed)}</span>
              </Group>
            </Stack>
          </Panel>

          {/* Every panel that leads somewhere does it the same way: a link at the right of its title. */}
          <Panel
            title="Geolocation"
            right={
              <a className="panel-link" href={href('settings', { tab: 'geoip' })}>
                Details
              </a>
            }
          >
            <Stack gap={6}>{geo.data && <GeoSummary geo={geo.data} now={now} />}</Stack>
          </Panel>

          <Panel
            title="Blocklists"
            right={
              <a className="panel-link" href={href('settings', { tab: 'feeds' })}>
                Details
              </a>
            }
          >
            <Stack gap={6}>
              {(feeds.data ?? []).length === 0 && (
                <Text fz={13} c="var(--ink-dim)">
                  None yet
                </Text>
              )}
              {(feeds.data ?? []).map((f) => (
                <FeedLine key={f.def.id} feed={f} now={now} />
              ))}
            </Stack>
          </Panel>

          <Panel title="Sources">
            <Stack gap={8}>
              {o.sources.map((s) => (
                <div key={s.name} className={classes.source}>
                  <span className={classes.state} data-ok={s.connected} />
                  <div style={{ minWidth: 0 }}>
                    <Text fz={13} fw={600}>
                      {s.name} <span className={classes.parser}>{s.parser}</span>
                    </Text>
                    <Text fz={12} c="var(--ink-dim)" truncate>
                      {s.error ?? s.input}
                    </Text>
                    <Text fz={12} c="var(--ink-faint)">
                      {count(s.lines)} lines, {count(s.parsed)} matched · {ago(s.lastLine, now)}
                    </Text>
                  </div>
                </div>
              ))}
            </Stack>
          </Panel>

          {o.edges.length > 0 && (
            <Panel title="Edges">
              <Stack gap={6} fz={13}>
                {o.edges.map((e) => (
                  <Group key={e.name} justify="space-between">
                    <span>
                      <strong>{e.name}</strong> <span className="mono">{e.address}</span>
                    </span>
                    <span className={classes.parser}>polled {ago(e.lastPoll, now)}</span>
                  </Group>
                ))}
              </Stack>
            </Panel>
          )}

          <Panel title="Banned, by country">
            <Stack gap={4} fz={13}>
              {o.countries.map((c) => (
                <Group key={c.key} justify="space-between">
                  <Country code={c.key === '?' ? null : c.key} name />
                  <span className="num">{count(c.count)}</span>
                </Group>
              ))}
            </Stack>
          </Panel>

          <Panel title="Events, by rule">
            <Stack gap={4} fz={13}>
              {o.rules.map((r) => (
                <Group key={r.key} justify="space-between" wrap="nowrap">
                  <span>{r.key}</span>
                  <span className="num">{count(r.count)}</span>
                </Group>
              ))}
            </Stack>
          </Panel>
        </Stack>
      </div>
    </Stack>
  )
}
