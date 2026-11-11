import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Stack,
  Tabs,
  Text,
  Title,
} from '@mantine/core'
import { IconArrowLeft } from '@tabler/icons-react'
import { useCallback, useMemo, useState } from 'react'

import { useAction, useIp, useRules } from '../api/hooks'
import type { Activity, Ban, IpDetail, Kind } from '../api/generated/model'
import type { ActivitySort } from '../api/generated/rpc'
import { rpc } from '../api/rpc'
import { InfiniteGrid, type Sort } from '../components/Grid'
import { Kept } from '../components/Kept'
import { BanDialog, Country } from '../components/ui'
import { columnsFor, fit, useTier, type Column } from '../lib/columns'
import { ago, count, dateTime, KIND_LABELS, remaining, WIDEST } from '../lib/format'
import { href, navigate } from '../lib/router'
import { useNow } from '../lib/useNow'
import classes from './Ip.module.css'

const SORTS: Record<string, ActivitySort> = {
  last: 'last',
  first: 'first',
  count: 'count',
  what: 'what',
}

/** What the address did: a row per what, source and rule, newest first (or as a header sorts it). */
function ActivityGrid({ d }: { d: IpDetail }) {
  const rules = useRules()
  const tier = useTier()
  const ruleName = useCallback(
    (id: number) =>
      id === 0 ? '—' : (rules.data?.find((r) => r.id === id)?.name ?? `#${String(id)}`),
    [rules.data],
  )
  const columns = useMemo(() => {
    const all: Column<Activity>[] = [
      {
        headerName: 'Kind',
        field: 'kind',
        width: 120,
        valueFormatter: (p) => KIND_LABELS[p.value as Kind],
        phone: { width: 110 },
      },
      {
        headerName: 'What',
        field: 'what',
        flex: 2,
        minWidth: 160,
        cellClass: 'mono',
        tooltip: (p) => p.data?.what,
        sortable: true,
        phone: { minWidth: 240 },
      },
      {
        headerName: 'Rule',
        field: 'rule',
        width: 150,
        valueFormatter: (p) => ruleName(Number(p.value ?? 0)),
        phone: { width: 130 },
      },
      { headerName: 'Source', field: 'source', width: 100, phone: { width: 90 } },
      {
        headerName: 'Times',
        field: 'count',
        width: 90,
        type: 'rightAligned',
        valueFormatter: (p) => count(Number(p.value ?? 0)),
        sortable: true,
        phone: { width: 80 },
      },
      {
        headerName: 'First',
        field: 'first',
        width: fit('First', WIDEST.dateTime(), { sortable: true }),
        valueFormatter: (p) => dateTime(Number(p.value ?? 0)),
        sortable: true,
      },
      {
        headerName: 'Last',
        field: 'last',
        width: fit('Last', WIDEST.ago, { sortable: true }),
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
        sortable: true,
        initialSort: 'desc',
      },
    ]
    return columnsFor(all, tier)
  }, [tier, ruleName])
  const fetch = useCallback(
    (offset: number, limit: number, sort: Sort | null) =>
      rpc.call('ip.activity', {
        ip: d.ip,
        sort: (sort && SORTS[sort.column]) ?? 'last',
        ascending: sort !== null && !sort.descending,
        offset,
        limit,
      }),
    [d.ip],
  )
  return (
    <InfiniteGrid<Activity>
      columns={columns}
      fetch={fetch}
      query={d.ip}
      // New events (or a ban) refresh it.
      version={`${String(d.hits)}|${String(d.activityCount)}`}
      empty={{
        title: 'Nothing recorded',
        hint: 'What its events matched shows up here: the requests, user names and probes.',
      }}
    />
  )
}

/** The bans of the address, in force or not, newest first. */
function BansGrid({ d }: { d: IpDetail }) {
  const tier = useTier()
  const columns = useMemo(() => {
    const all: Column<Ban>[] = [
      {
        headerName: 'Blocked',
        field: 'net',
        width: 170,
        cellClass: 'mono',
        phone: { width: 150 },
      },
      {
        headerName: 'Reason',
        field: 'reason',
        flex: 1,
        minWidth: 160,
        tooltip: (p) => p.data?.reason,
        phone: { minWidth: 170 },
      },
      {
        headerName: 'Since',
        field: 'created',
        width: fit('Since', WIDEST.dateTime()),
        valueFormatter: (p) => dateTime(Number(p.value ?? 0)),
      },
      {
        headerName: 'Ends',
        width: fit('Ends', [...WIDEST.remaining, ...WIDEST.lifted.map((l) => `${l} (ui)`)]),
        valueGetter: (p) =>
          p.data === undefined
            ? ''
            : p.data.lifted !== null
              ? `lifted ${ago(p.data.lifted)}${p.data.liftedBy === null ? '' : ` (${p.data.liftedBy})`}`
              : remaining(p.data.until),
        tooltip: (p) => (p.data?.until == null ? undefined : `until ${dateTime(p.data.until)}`),
      },
    ]
    return columnsFor(all, tier)
  }, [tier])
  const fetch = useCallback(
    (offset: number, limit: number) =>
      rpc.call('bans.list', { ip: d.ip, active: false, offset, limit }),
    [d.ip],
  )
  return (
    <InfiniteGrid<Ban>
      columns={columns}
      fetch={fetch}
      query={d.ip}
      version={`${String(d.banCount)}|${String(d.activeBan?.id ?? '')}|${String(d.activeBan?.lifted ?? '')}`}
      empty={{
        title: 'Never banned',
        hint: 'A rule bans it once its threshold is reached, or “Ban” does by hand.',
      }}
    />
  )
}

export function IpScreen({ ip, tab }: { ip: string; tab: string | null }) {
  const detail = useIp(ip)
  const now = useNow(30_000)
  const [banning, setBanning] = useState(false)
  const lift = useAction('ban.lift', 'Ban lifted')
  const allow = useAction('entry.save', 'Saved')
  const untrust = useAction('trust.remove', 'No longer trusted')
  const phone = useTier() === 'phone'
  const back = (
    <Anchor href={href('addresses')} fz={13}>
      <Group gap={4}>
        <IconArrowLeft size={14} /> Addresses
      </Group>
    </Anchor>
  )
  if (detail.error)
    return (
      <Stack>
        {back}
        <Alert color="red">{detail.error.message}</Alert>
      </Stack>
    )
  const d = detail.data
  if (!d) return back
  const current = tab === 'bans' ? 'bans' : 'activity'
  const where = (
    <>
      <Country code={d.country} name />
      {d.asn !== null && (
        <>
          {' · '}AS{d.asn} {d.asName}
        </>
      )}
    </>
  )
  const seen =
    d.firstSeen === null
      ? 'Never seen doing anything a rule matched'
      : `${count(d.hits)} hits · first seen ${dateTime(d.firstSeen)} · last ${ago(d.lastSeen, now)}`
  const badgeSize = phone ? 'sm' : 'md'
  const badges = (
    <>
      {d.activeBan && (
        <Badge color="brass" variant="filled" size={badgeSize}>
          Banned, {remaining(d.activeBan.until, now)}
        </Badge>
      )}
      {d.trusted && (
        <Badge color="green" size={badgeSize}>
          Trusted: {d.trusted.user}
        </Badge>
      )}
      {d.allowed && (
        <Badge color="blue" size={badgeSize}>
          Allowed
        </Badge>
      )}
      {d.denied && (
        <Badge color="red" size={badgeSize}>
          On the deny list
        </Badge>
      )}
      {d.countryBlocked && (
        <Badge color="orange" size={badgeSize}>
          Country blocked
        </Badge>
      )}
      {d.listed.map((l) => (
        <Badge key={l} color="gray" size={badgeSize}>
          Listed: {l}
        </Badge>
      ))}
    </>
  )
  const buttonSize = phone ? 'compact-sm' : 'sm'
  const actions = (
    <>
      {d.activeBan ? (
        <Button
          variant="default"
          size={buttonSize}
          loading={lift.isPending}
          onClick={() => {
            if (d.activeBan) lift.mutate({ id: d.activeBan.id })
          }}
        >
          Lift the ban
        </Button>
      ) : (
        <Button
          size={buttonSize}
          onClick={() => {
            setBanning(true)
          }}
        >
          Ban
        </Button>
      )}
      {!d.allowed && (
        <Button
          variant="default"
          size={buttonSize}
          loading={allow.isPending}
          onClick={() => {
            allow.mutate({ net: d.ip, allow: true, note: '', secs: null })
          }}
        >
          Allow
        </Button>
      )}
      {d.trusted && (
        <Button
          variant="subtle"
          color="gray"
          size={buttonSize}
          onClick={() => {
            untrust.mutate({ ip: d.ip })
          }}
        >
          Stop trusting
        </Button>
      )}
    </>
  )
  return (
    <Stack gap={phone ? 8 : 'md'} className="fill">
      {phone ? (
        // On a phone, the grid gets the height: the address in a line with the way back, the facts in small
        // lines, and the states and actions in one that wraps.
        <div className={classes.head}>
          <Group gap={4} wrap="nowrap" align="center">
            <ActionIcon
              component="a"
              href={href('addresses')}
              aria-label="Addresses"
              variant="subtle"
              color="gray"
              ml={-6}
            >
              <IconArrowLeft size={18} />
            </ActionIcon>
            <Title order={2} className={['mono', classes.address].join(' ')} fz={18}>
              {d.ip}
            </Title>
          </Group>
          <Text c="var(--ink-dim)" fz={13} truncate>
            {where}
          </Text>
          <Text c="var(--ink-faint)" fz={12}>
            {seen}
          </Text>
          <Group gap={6} mt={4} align="center">
            {badges}
            <Group gap={6} ml="auto">
              {actions}
            </Group>
          </Group>
        </div>
      ) : (
        <>
          {back}
          <Group justify="space-between" align="flex-start">
            <div>
              <Title order={2} className={['mono', classes.address].join(' ')} fz={26}>
                {d.ip}
              </Title>
              <Text c="var(--ink-dim)" fz={14}>
                {where}
              </Text>
              <Text c="var(--ink-faint)" fz={12.5} mt={2}>
                {seen}
              </Text>
              <Group gap={6} mt={8}>
                {badges}
              </Group>
            </div>
            <Group gap="xs">{actions}</Group>
          </Group>
        </>
      )}

      <Tabs
        id="address"
        value={current}
        onChange={(v) => {
          navigate('addresses', { ip, ...(v === 'bans' ? { tab: 'bans' } : {}) }, true)
        }}
      >
        <Tabs.List>
          <Tabs.Tab value="activity" rightSection={<Counter n={d.activityCount} />}>
            Activity
          </Tabs.Tab>
          <Tabs.Tab value="bans" rightSection={<Counter n={d.banCount} />}>
            Bans
          </Tabs.Tab>
        </Tabs.List>
      </Tabs>
      {/* The panels are kept, not Tabs.Panel's: both grids stay laid out, so switching back shows the other's rows
       * at once. The ids are the ones the tabs refer to. */}
      <div className={classes.panels}>
        <Kept shown={current === 'activity'}>
          <div
            className={classes.panel}
            role="tabpanel"
            id="address-panel-activity"
            aria-labelledby="address-tab-activity"
          >
            <ActivityGrid d={d} />
          </div>
        </Kept>
        <Kept shown={current === 'bans'}>
          <div
            className={classes.panel}
            role="tabpanel"
            id="address-panel-bans"
            aria-labelledby="address-tab-bans"
          >
            <BansGrid d={d} />
          </div>
        </Kept>
      </div>
      <BanDialog
        opened={banning}
        onClose={() => {
          setBanning(false)
        }}
        initial={d.ip}
      />
    </Stack>
  )
}

function Counter({ n }: { n: number }) {
  return (
    <Badge variant="light" color="gray" size="sm" className="num">
      {count(n)}
    </Badge>
  )
}
