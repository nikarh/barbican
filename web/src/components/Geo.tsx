import { Alert, Anchor, Badge, Group, Stack, Text } from '@mantine/core'
import type { ReactNode } from 'react'

import { useGeoStatus } from '../api/hooks'
import type { GeoDatabase, GeoStatus } from '../api/generated/model'
import { ago, date, dateTime, fromNow, month } from '../lib/format'
import { useNow } from '../lib/useNow'
import classes from './Status.module.css'

/** A database's name from its type: "DBIP-ASN-Lite (compat=GeoLite2-ASN)" is "DB-IP ASN Lite". */
function databaseName(kind: string): string {
  return kind
    .replace(/\s*\(.*\)\s*$/, '')
    .replace(/-/g, ' ')
    .replace(/^DBIP /, 'DB-IP ')
}

/** In use, missing, failing or not configured. */
function state(db: GeoDatabase): { ok: boolean; label: string } {
  if (db.path === null) return { ok: false, label: 'Not configured' }
  if (db.kind === null) return { ok: false, label: db.written === null ? 'Missing' : 'Unreadable' }
  if (db.error !== null) return { ok: false, label: 'Download failing' }
  return { ok: true, label: 'In use' }
}

/** When the next download is, in words. */
function nextDownload(geo: GeoStatus, db: GeoDatabase, now: number): string {
  if (!geo.download) return 'never: downloads are off'
  if (db.due === null) return '—'
  // It happens at the first daily check from when it is due.
  const at = geo.nextCheck === null ? db.due : Math.max(db.due, geo.nextCheck)
  return at * 1000 <= now
    ? 'at the next check'
    : `${date(at)} (${fromNow(at, now)}), at the first daily check`
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  )
}

function Database({
  title,
  db,
  geo,
  now,
}: {
  title: string
  db: GeoDatabase
  geo: GeoStatus
  now: number
}) {
  const s = state(db)
  return (
    <section className="panel" style={{ padding: 14 }}>
      <Group justify="space-between" mb={8} wrap="nowrap">
        <div className="panel-title">{title}</div>
        <Badge color={s.ok ? 'green' : 'red'} variant="light">
          {s.label}
        </Badge>
      </Group>
      {db.kind !== null && (
        <Text fw={620} fz={15}>
          {databaseName(db.kind)}
          {db.description !== null && (
            <Text span fz={12.5} fw={400} c="var(--ink-faint)" ml={8}>
              {db.description}
            </Text>
          )}
        </Text>
      )}
      <dl className={classes.facts}>
        {db.built !== null && <Fact label="Version">built {date(db.built)}</Fact>}
        <Fact label="Downloaded">
          {db.written === null ? (
            'no file yet'
          ) : (
            <>
              {ago(db.written, now)} <span className={classes.faint}>({dateTime(db.written)})</span>
            </>
          )}
        </Fact>
        <Fact label="Next download">{nextDownload(geo, db, now)}</Fact>
        {db.path !== null && (
          <Fact label="File">
            <span className="mono" style={{ wordBreak: 'break-all' }}>
              {db.path}
            </span>
          </Fact>
        )}
      </dl>
      {db.error !== null && (
        <Alert color="red" mt={10} p="xs" title="The last download failed">
          {db.error}
        </Alert>
      )}
    </section>
  )
}

/** The geolocation databases in detail, and how they are kept up to date. */
export function GeoDatabases() {
  const status = useGeoStatus()
  const now = useNow(30_000)
  if (status.error) return <Alert color="red">{status.error.message}</Alert>
  const geo = status.data
  if (!geo) return null
  return (
    <Stack gap="md">
      <Text fz={13} c="var(--ink-dim)" maw={700}>
        The countries and networks (AS) of addresses come from these databases, in the MaxMind DB
        format: what addresses are shown with, what blocked countries are made of, and what ban
        lengths by country and network go by.
      </Text>
      <div className={classes.pair}>
        <Database title="Countries" db={geo.country} geo={geo} now={now} />
        <Database title="Networks" db={geo.asn} geo={geo} now={now} />
      </div>
      <Text fz={13} c="var(--ink-dim)" maw={700}>
        {geo.download ? (
          <>
            Downloads are on. DB-IP publishes its free Lite databases every month; the agent looks
            once a day (last {geo.checked === null ? 'not yet' : ago(geo.checked, now)}
            {geo.nextCheck !== null && `, next ${fromNow(geo.nextCheck, now)}`}) and downloads a
            database when it is missing or its file is {Math.round(geo.maxAge / 86_400)} days old.
          </>
        ) : (
          <>
            Downloads are off (<code>geoip.download = false</code>): the files are used as they are,
            read when the agent starts.
          </>
        )}{' '}
        IP geolocation by{' '}
        <Anchor href="https://db-ip.com" target="_blank" rel="noreferrer" fz={13}>
          DB-IP
        </Anchor>{' '}
        (CC BY 4.0).
      </Text>
    </Stack>
  )
}

/** One line per database: which, how recent, and whether it is in order. For the overview. */
export function GeoSummary({ geo, now }: { geo: GeoStatus; now: number }) {
  return (
    <>
      {(
        [
          ['Countries', geo.country],
          ['Networks', geo.asn],
        ] as const
      ).map(([label, db]) => {
        const s = state(db)
        return (
          <div key={label} className={classes.line}>
            <span className={classes.dot} data-ok={s.ok} />
            <span className={classes.label}>{label}</span>
            <span className={classes.value}>
              {db.kind === null ? s.label : databaseName(db.kind)}
              {db.built !== null && <span className={classes.faint}> · {month(db.built)}</span>}
            </span>
            <span className={classes.when} title={db.error ?? undefined}>
              {db.error !== null ? 'failing' : db.written === null ? '' : ago(db.written, now)}
            </span>
          </div>
        )
      })}
    </>
  )
}
