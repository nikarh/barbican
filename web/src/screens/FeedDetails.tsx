import {
  Alert,
  Anchor,
  Button,
  Chip,
  Group,
  Loader,
  NativeSelect,
  SegmentedControl,
  Stack,
  Text,
  TextInput,
} from '@mantine/core'
import { IconAlertTriangle, IconSearch } from '@tabler/icons-react'
import { useState } from 'react'

import { useAction, useFeedNetworks, useFeedOverlap } from '../api/hooks'
import type { Feed, FeedOverlap, NetworkUse, Use } from '../api/generated/model'
import { feedUse, networksSummary, USE_LABELS, withUse } from '../lib/feeds'
import { compact, count, share } from '../lib/format'
import classes from './Feeds.module.css'

/** A list's size in words: IPv4 addresses, else IPv6 /48s. */
function size(v4: number, v6: number): string {
  if (v4 > 0) return `${compact(v4)} IPv4 addresses`
  return `${compact(v6)} IPv6 /48s`
}

/** The share of `part` in `whole`, by IPv4 addresses when there are some, else by IPv6 space. */
function part(p4: number, p6: number, w4: number, w6: number): string {
  return w4 > 0 ? share(p4, w4) : share(p6, w6)
}

function overlapLines(o: FeedOverlap) {
  const byV4 = o.v4 > 0
  const whole = byV4 ? o.v4 : o.v6
  const unique = byV4 ? o.uniqueV4 : o.uniqueV6
  return { whole, unique }
}

/** How much of a list the other lists (that are on) hold too: what only it has, and each other list's share. */
export function Overlap({ feed }: { feed: Feed }) {
  const overlap = useFeedOverlap(feed.def.id)
  const [all, setAll] = useState(false)
  if (feed.def.content === 'agents' || feed.changed === null) return null
  const o = overlap.data
  if (o === undefined) {
    return (
      <Group gap={6} mt={6}>
        <Loader size={12} />
        <Text fz={12} c="var(--ink-faint)">
          Comparing with the other lists…
        </Text>
      </Group>
    )
  }
  const { whole, unique } = overlapLines(o)
  if (whole === 0) return null
  const shown = all ? o.others : o.others.slice(0, 4)
  return (
    <Stack gap={2} mt={6}>
      <Text fz={12} fw={600}>
        Overlap
      </Text>
      <Text fz={12} c="var(--ink-dim)">
        {o.others.length === 0
          ? 'No other list that is on holds any of its addresses.'
          : `${share(unique, whole)} of its addresses are in no other list that is on.`}
      </Text>
      {feed.coveredBy !== null && (
        <Text fz={12} c="var(--status-warn)">
          Almost all of it is in “{feed.coveredBy}” too, which is used the same way: with that list
          on, this one adds little.
        </Text>
      )}
      {shown.map((x) => (
        <Text key={x.id} fz={12} c="var(--ink-faint)">
          <Text span fz={12} c="var(--ink-dim)">
            {x.name}
          </Text>
          : {size(x.v4, x.v6)} in both, {part(x.v4, x.v6, o.v4, o.v6)} of this list,{' '}
          {part(x.v4, x.v6, x.otherV4, x.otherV6)} of that one
        </Text>
      ))}
      {o.others.length > 4 && (
        <Anchor
          component="button"
          fz={12}
          ta="left"
          onClick={() => {
            setAll((a) => !a)
          }}
        >
          {all ? 'Fewer' : `${String(o.others.length - 4)} more`}
        </Anchor>
      )}
    </Stack>
  )
}

const PAGE = 100

/** The networks of a list of networks, each doing what the list does or something else of its own: block a few
 * hosting networks out of a list that is data, allow the rest, leave some out. */
export function NetworksDialog({ feed, onClose }: { feed: Feed; onClose: () => void }) {
  const networks = useFeedNetworks(feed.def.id)
  const save = useAction('feed.save', 'Saved')
  const initial = feedUse({ ...feed.def, enabled: true })
  const [whole, setWhole] = useState<Use>(initial)
  const [uses, setUses] = useState(() => new Map(feed.def.networks.map((n) => [n.asn, n.use])))
  const [search, setSearch] = useState('')
  const [onlySet, setOnlySet] = useState(false)
  const [limit, setLimit] = useState(PAGE)

  const query = search.trim().toLowerCase().replace(/^as/, '')
  const rows = (networks.data ?? []).filter(
    (n) =>
      (!onlySet || uses.has(n.asn)) &&
      (query === '' ||
        String(n.asn).startsWith(query) ||
        (n.name ?? '').toLowerCase().includes(query)),
  )
  const setUse = (asn: number, u: Use | 'list') => {
    setUses((m) => {
      const next = new Map(m)
      if (u === 'list' || u === whole) next.delete(asn)
      else next.set(asn, u)
      return next
    })
  }
  const options = [
    { value: 'list', label: `As the list (${USE_LABELS[whole].toLowerCase()})` },
    ...(['block', 'allow', 'data', 'off'] as const)
      .filter((u) => u !== whole)
      .map((u) => ({ value: u, label: u === 'off' ? 'Left out' : USE_LABELS[u] })),
  ]
  const chosen: NetworkUse[] = [...uses.entries()]
    .filter(([, u]) => u !== whole)
    .map(([asn, u]) => ({ asn, use: u }))
    .sort((a, b) => a.asn - b.asn)

  return (
    <Stack gap="sm">
      <Text fz={13} c="var(--ink-dim)">
        Each network does what the list does, unless you set it otherwise: block a few networks of a
        list that is data, allow the rest, or leave some out. Prefixes come from the ASN database.
      </Text>
      <Stack gap={4}>
        <Text fz={14} fw={500}>
          The rest of the list
        </Text>
        <SegmentedControl
          fullWidth
          value={whole}
          onChange={(v) => {
            setWhole(v)
            // A network set to what the list now does follows the list.
            setUses((m) => new Map([...m].filter(([, u]) => u !== v)))
          }}
          data={(['block', 'allow', 'data'] as const).map((u) => ({
            value: u,
            label: USE_LABELS[u],
          }))}
        />
      </Stack>
      {whole === 'allow' && (
        <Alert color="yellow" variant="light" p="xs" icon={<IconAlertTriangle size={16} />}>
          <Text fz={12.5}>
            Every network not set otherwise is allowed: never banned, and let through before any
            block. For hosting networks, that is where most scanners and bots run from: allow only
            what you trust, and give the rest data or a short ban length instead.
          </Text>
        </Alert>
      )}
      <Group gap="xs" wrap="wrap">
        <TextInput
          placeholder="AS number or name"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => {
            setSearch(e.currentTarget.value)
            setLimit(PAGE)
          }}
          style={{ flex: '1 1 200px' }}
          aria-label="Search networks"
        />
        <Chip checked={onlySet} onChange={setOnlySet} size="sm" disabled={uses.size === 0}>
          Set otherwise ({uses.size})
        </Chip>
      </Group>
      {networks.isPending && <Loader size="sm" />}
      <Stack gap={0} className={classes.items}>
        {rows.slice(0, limit).map((n) => {
          const u = uses.get(n.asn)
          return (
            <div key={n.asn} className={classes.item}>
              <div className={classes.itemText}>
                <Text fz={13} fw={600}>
                  AS{n.asn}{' '}
                  <Text span fz={13} fw={400}>
                    {n.name ?? ''}
                  </Text>
                </Text>
                <Text fz={12} c="var(--ink-faint)">
                  {n.extent.prefixes === 0
                    ? 'No prefixes in the ASN database'
                    : `${count(n.extent.prefixes)} prefixes · ${size(n.extent.v4Addresses, n.extent.v6Networks)}`}
                </Text>
              </div>
              <NativeSelect
                size="xs"
                className={classes.itemUse}
                aria-label={`What AS${String(n.asn)} does`}
                value={u ?? 'list'}
                onChange={(e) => {
                  setUse(n.asn, e.currentTarget.value as Use | 'list')
                }}
                data={options}
                styles={{ input: { fontWeight: u === undefined ? 400 : 650 } }}
              />
            </div>
          )
        })}
      </Stack>
      {rows.length > limit && (
        <Button
          variant="subtle"
          size="xs"
          onClick={() => {
            setLimit((l) => l + PAGE)
          }}
        >
          Show more ({count(rows.length - limit)} left)
        </Button>
      )}
      {networks.data !== undefined && rows.length === 0 && (
        <Text fz={12.5} c="var(--ink-faint)">
          No network matches.
        </Text>
      )}
      <Group justify="space-between" wrap="wrap" className={classes.footer}>
        <Text fz={12} c="var(--ink-dim)" style={{ flex: '1 1 180px' }}>
          {chosen.length === 0
            ? `Every network: ${USE_LABELS[whole].toLowerCase()}`
            : `${networksSummary(chosen)}; the rest: ${USE_LABELS[whole].toLowerCase()}`}
        </Text>
        <Group gap="xs">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.isPending}
            onClick={() => {
              const def = withUse({ ...feed.def, networks: chosen }, whole)
              save.mutate({ ...def, enabled: feed.def.enabled }, { onSuccess: onClose })
            }}
          >
            Save
          </Button>
        </Group>
      </Group>
    </Stack>
  )
}
