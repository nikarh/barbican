import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Chip,
  Group,
  Modal,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
} from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import {
  IconChevronDown,
  IconExternalLink,
  IconInfoCircle,
  IconPencil,
  IconPlus,
  IconRefresh,
  IconTrash,
} from '@tabler/icons-react'
import { useState, type ReactNode } from 'react'

import { useAction, useFeedCatalog, useFeeds, usePolicy, useRules } from '../api/hooks'
import type { Category, Content, Feed, FeedDef, Item, Source, Use } from '../api/generated/model'
import { LengthInput } from '../components/ui'
import {
  addresses,
  catalogOf,
  entries,
  networksSummary,
  USE_EFFECTS,
  USE_LABELS,
  feedUse,
  withUse,
} from '../lib/feeds'
import { ago, count, fromNow, lengthInWords } from '../lib/format'
import { useNow } from '../lib/useNow'
import classes from './Feeds.module.css'
import { NetworksDialog, Overlap } from './FeedDetails'

const USE_COLORS: Record<Use, string> = {
  off: 'gray',
  block: 'brass',
  allow: 'green',
  data: 'blue',
}

const CATEGORIES: { value: Category; title: string; description: string }[] = [
  {
    value: 'threats',
    title: 'Attacks and abuse',
    description:
      'Addresses seen attacking, scanning or abusing: to block, or to ban sooner and for longer.',
  },
  {
    value: 'bots',
    title: 'Crawlers, bots and monitors',
    description:
      'Published addresses of search engines, AI crawlers and uptime monitors, and the user agents of AI bots: to allow the ones you want, block or watch the others.',
  },
  {
    value: 'networks',
    title: 'Networks',
    description:
      'Proxies, anonymizers and hosting networks: shared by many, for allowing or for shorter bans.',
  },
]

function UseBadge({ use: u, content }: { use: Use; content: Content }) {
  const label = {
    off: 'Off',
    block: 'Blocks',
    allow: 'Allows',
    data: content === 'agents' ? 'For rules' : 'Data',
  }[u]
  return <Badge color={USE_COLORS[u]}>{label}</Badge>
}

/** The uses a list can have: a list of user agents is for rules only. */
function usesFor(content: Content): Use[] {
  return content === 'agents' ? ['off', 'data'] : ['off', 'block', 'allow', 'data']
}

const NEW_FEED: FeedDef = {
  id: 0,
  name: '',
  url: '',
  enabled: true,
  block: false,
  allow: false,
  refreshSecs: 6 * 3_600,
  username: null,
  password: null,
  content: 'addresses',
  select: null,
  catalog: null,
  networks: [],
}

function FeedEditor({ feed, onClose }: { feed: FeedDef; onClose: () => void }) {
  const [f, setF] = useState(feed)
  const save = useAction('feed.save', 'Saved; fetching it now')
  const set = (patch: Partial<FeedDef>) => {
    setF((x) => ({ ...x, ...patch }))
  }
  const u = feedUse({ ...f, enabled: true })
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate(f, { onSuccess: onClose })
      }}
    >
      <Stack gap="sm">
        <TextInput
          label="Name"
          description="Rules and the policy refer to it"
          value={f.name}
          onChange={(e) => {
            set({ name: e.currentTarget.value })
          }}
          required
        />
        <TextInput
          label="URL"
          value={f.url}
          onChange={(e) => {
            set({ url: e.currentTarget.value })
          }}
          required
          classNames={{ input: 'mono' }}
        />
        <Select
          label="It lists"
          data={[
            { value: 'addresses', label: 'Addresses and prefixes' },
            { value: 'networks', label: 'Networks (AS numbers)' },
            { value: 'agents', label: 'User agents' },
          ]}
          value={f.content}
          onChange={(v) => {
            if (v === null) return
            const content = v
            set(content === 'agents' ? { content, block: false, allow: false } : { content })
          }}
          allowDeselect={false}
          description={
            {
              addresses:
                'One per line (comments, CSV and JSON lines are understood), or a JSON document',
              networks:
                'AS numbers, one per line (AS13335, 13335, or a CSV’s first column): their prefixes come from the ASN database',
              agents:
                'A robots.txt’s User-agent lines, or one per line: for rules (“user agent in list”) only',
            }[f.content]
          }
        />
        {f.content === 'addresses' && (
          <TextInput
            label="In the JSON document"
            description="A JSON pointer, e.g. /services/Googlebot: only the addresses under it. Empty: all of them."
            value={f.select ?? ''}
            onChange={(e) => {
              set({ select: e.currentTarget.value === '' ? null : e.currentTarget.value })
            }}
            classNames={{ input: 'mono' }}
          />
        )}
        <Stack gap={4}>
          <Text fz={14} fw={500}>
            What it does
          </Text>
          <SegmentedControl
            fullWidth
            value={u}
            onChange={(v) => {
              set({ block: v === 'block', allow: v === 'allow' })
            }}
            data={usesFor(f.content)
              .filter((x) => x !== 'off')
              .map((x) => ({
                value: x,
                label: x === 'data' && f.content === 'agents' ? 'For rules' : USE_LABELS[x],
              }))}
          />
          <Text fz={12} c="var(--ink-dim)">
            {USE_EFFECTS[u]}
          </Text>
        </Stack>
        <Group align="flex-end" wrap="wrap">
          <LengthInput
            label="Fetch every"
            value={f.refreshSecs}
            onChange={(refreshSecs) => {
              set({ refreshSecs })
            }}
          />
          <SegmentedControl
            value={f.enabled ? 'on' : 'off'}
            onChange={(v) => {
              set({ enabled: v === 'on' })
            }}
            data={[
              { value: 'on', label: 'On' },
              { value: 'off', label: 'Off' },
            ]}
          />
        </Group>
        <SimpleGrid cols={{ base: 1, sm: 2 }} style={{ alignItems: 'end' }}>
          <TextInput
            label="User"
            description="For lists behind an account"
            value={f.username ?? ''}
            onChange={(e) => {
              set({ username: e.currentTarget.value === '' ? null : e.currentTarget.value })
            }}
          />
          <TextInput
            label="Password"
            type="password"
            placeholder={feed.password === null ? '' : 'unchanged'}
            value={f.password ?? ''}
            onChange={(e) => {
              set({ password: e.currentTarget.value })
            }}
          />
        </SimpleGrid>
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            Save
          </Button>
        </Group>
      </Stack>
    </form>
  )
}

/** What a feed holds and how its fetches go: the list in use and from when, the last check, the next one, and
 * the last attempt's error. */
function FeedState({ feed: f, now }: { feed: Feed; now: number }) {
  const every = `every ${lengthInWords(f.def.refreshSecs)}`
  const space = addresses(f)
  return (
    <Stack gap={0} fz={12} mt={2}>
      <Text fz={12} c="var(--ink-dim)">
        {f.changed === null ? (
          !f.def.enabled ? (
            'Off: not fetched'
          ) : f.error === null ? (
            'Not fetched yet'
          ) : (
            'No list yet'
          )
        ) : (
          <>
            {entries(f)}
            {f.def.content === 'networks' && ` → ${count(f.extent.prefixes)} prefixes`}
            {space !== '' && ` (${space})`} · list from {ago(f.changed, now)}
            {f.succeeded !== null && f.succeeded !== f.changed && (
              <>, unchanged when checked {ago(f.succeeded, now)}</>
            )}
          </>
        )}
      </Text>
      <Text fz={12} c="var(--ink-faint)">
        {f.next === null ? (
          `Off (${every} when on)`
        ) : f.failures > 0 ? (
          <>
            Fetched {every} · failed {f.failures === 1 ? 'once' : `${String(f.failures)} times`} in
            a row, trying again {fromNow(f.next, now)}
          </>
        ) : (
          <>
            Fetched {every} · next {fromNow(f.next, now)}
          </>
        )}
      </Text>
      {f.error !== null && (
        <Text fz={12} c="var(--status-bad)" style={{ overflowWrap: 'anywhere' }}>
          Last attempt {ago(f.fetched, now)} failed: {f.error}
          {f.changed !== null && ' · the list from before stays in use'}
        </Text>
      )}
    </Stack>
  )
}

/** Where a feed is used besides its own effect: rules that ask for it, a ban length the policy gives it. */
function useUsedBy(): (name: string) => string[] {
  const rules = useRules()
  const policy = usePolicy()
  return (name) => {
    const by: string[] = []
    for (const r of rules.data ?? []) {
      if (r.conditions.listed.includes(name) || r.conditions.agents.includes(name))
        by.push(`rule “${r.name}”${r.enabled ? '' : ' (off)'}`)
    }
    const length = policy.data?.listLengths.find((l) => l.list === name)
    if (length !== undefined) by.push(`ban length ${lengthInWords(length.secs)}`)
    return by
  }
}

/** How a list is doing, as its row's dot shows it. */
function health(f: Feed): 'off' | 'failing' | 'waiting' | 'ok' {
  if (!f.def.enabled) return 'off'
  if (f.error !== null) return 'failing'
  if (f.changed === null) return 'waiting'
  return 'ok'
}

/** A list in one line (its state, name, use, size and age), opened with a tap: then what it holds, its fetches,
 * what uses it, and its buttons. An error shows in the closed row too. */
function FeedRow({
  feed: f,
  now,
  usedBy,
  onEdit,
  onNetworks,
}: {
  feed: Feed
  now: number
  usedBy: string[]
  onEdit: () => void
  onNetworks: () => void
}) {
  const [open, setOpen] = useState(false)
  const remove = useAction('feed.delete', 'Removed')
  const refresh = useAction('feed.refresh')
  const u = feedUse(f.def)
  const state = health(f)
  const meta =
    state === 'off'
      ? 'off'
      : f.changed === null
        ? 'not fetched yet'
        : `${entries(f)}${f.def.networks.length > 0 ? ` (${networksSummary(f.def.networks)})` : ''} · ${ago(f.changed, now)}`
  return (
    <div className={classes.row}>
      <button
        type="button"
        className={classes.rowHead}
        aria-expanded={open}
        onClick={() => {
          setOpen((o) => !o)
        }}
      >
        <span className={classes.dot} data-state={state} />
        <span className={classes.rowName}>{f.def.name}</span>
        <UseBadge use={u} content={f.def.content} />
        <span className={classes.rowMeta}>{meta}</span>
        <IconChevronDown size={16} className={classes.chevron} data-open={open} />
      </button>
      {state === 'failing' && !open && (
        <Text fz={12} c="var(--status-bad)" truncate className={classes.rowError}>
          {f.error}
        </Text>
      )}
      {f.coveredBy !== null && !open && (
        <Text fz={12} c="var(--status-warn)" truncate className={classes.rowError}>
          Almost all of it is in “{f.coveredBy}” too
        </Text>
      )}
      {open && (
        <div className={classes.rowBody}>
          <FeedState feed={f} now={now} />
          {f.def.enabled && (u === 'data' || usedBy.length > 0) && (
            <Text fz={12} c="var(--ink-faint)">
              {usedBy.length > 0
                ? `Used by ${usedBy.join(', ')}`
                : f.def.content === 'agents'
                  ? 'No rule asks for it yet (Rules: “User agent in list”)'
                  : u === 'data'
                    ? 'No rule or ban length uses it yet; address pages show it'
                    : null}
            </Text>
          )}
          {f.def.content === 'networks' && (
            <Text fz={12} c="var(--ink-dim)" mt={4}>
              {f.def.networks.length === 0
                ? 'Every network does what the list does.'
                : `${networksSummary(f.def.networks)}; the other networks do what the list does.`}{' '}
              <Anchor component="button" fz={12} onClick={onNetworks}>
                Choose networks
              </Anchor>
            </Text>
          )}
          <Overlap feed={f} />
          <Group gap={6} mt={8}>
            <Button
              size="xs"
              variant="default"
              leftSection={<IconRefresh size={14} />}
              loading={refresh.isPending}
              onClick={() => {
                refresh.mutate({ id: f.def.id })
              }}
            >
              Fetch now
            </Button>
            <Button
              size="xs"
              variant="default"
              leftSection={<IconPencil size={14} />}
              onClick={onEdit}
            >
              Edit
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="red"
              leftSection={<IconTrash size={14} />}
              onClick={() => {
                const warn =
                  usedBy.length > 0
                    ? `\nIt is used by ${usedBy.join(', ')}: they will find nothing in it.`
                    : ''
                if (window.confirm(`Remove the list “${f.def.name}”?${warn}`))
                  remove.mutate({ id: f.def.id })
              }}
            >
              Remove
            </Button>
          </Group>
        </div>
      )}
    </div>
  )
}

/** "3 allow · 1 data · 1 failing": a group of lists in a line. */
function groupSummary(feeds: Feed[]): { text: string; failing: number } {
  const n = { block: 0, allow: 0, data: 0, off: 0 }
  let failing = 0
  for (const f of feeds) {
    n[feedUse(f.def)] += 1
    if (health(f) === 'failing') failing += 1
  }
  const parts = (['block', 'allow', 'data', 'off'] as const)
    .filter((u) => n[u] > 0)
    .map((u) => `${String(n[u])} ${u === 'data' ? 'data' : u}`)
  return { text: parts.join(' · '), failing }
}

/** The lists of one source (or the ones added by hand), under a header that folds them away. A group of many
 * lists starts folded, unless one of them fails. */
function FeedGroup({
  title,
  homepage,
  feeds,
  forceOpen,
  action,
  children,
}: {
  title: string
  homepage: string | null
  feeds: Feed[]
  forceOpen: boolean
  action: ReactNode
  children: ReactNode
}) {
  const summary = groupSummary(feeds)
  const [open, setOpen] = useState(feeds.length <= 4 || summary.failing > 0)
  const shown = open || forceOpen
  return (
    <div className={['panel', classes.group].join(' ')}>
      <div className={classes.groupHead}>
        <button
          type="button"
          className={classes.groupToggle}
          aria-expanded={shown}
          onClick={() => {
            setOpen((o) => !o)
          }}
        >
          <IconChevronDown size={16} className={classes.chevron} data-open={shown} />
          <span className={classes.groupTitle}>{title}</span>
          <span className={classes.groupSummary}>
            {summary.text}
            {summary.failing > 0 && (
              <span style={{ color: 'var(--status-bad)' }}> · {summary.failing} failing</span>
            )}
          </span>
        </button>
        <Group gap={4} wrap="nowrap" className={classes.groupActions}>
          {homepage !== null && (
            <ActionIcon
              component="a"
              href={homepage}
              target="_blank"
              rel="noreferrer"
              aria-label={`About ${title}`}
            >
              <IconExternalLink size={15} />
            </ActionIcon>
          )}
          {action}
        </Group>
      </div>
      {shown && children}
    </div>
  )
}

/** A source's lists as they are now: the feed of each item, if any. */
function current(source: Source, feeds: Feed[], catalog: Source[]): Map<string, Feed> {
  const found = new Map<string, Feed>()
  for (const f of feeds) {
    const m = catalogOf(f.def, catalog)
    if (m?.source.id === source.id) found.set(m.item.key, f)
  }
  return found
}

/** The lists of one source, each with its use, and how often they are fetched. */
function SourceDialog({
  source,
  feeds,
  catalog,
  onClose,
}: {
  source: Source
  feeds: Feed[]
  catalog: Source[]
  onClose: () => void
}) {
  const now = current(source, feeds, catalog)
  const added = now.size > 0
  const suggested = () => new Map(source.items.map((i) => [i.key, i.suggested]))
  const [uses, setUses] = useState<Map<string, Use>>(() =>
    added
      ? new Map(
          source.items.map((i): [string, Use] => {
            const f = now.get(i.key)
            return [i.key, f === undefined ? 'off' : feedUse(f.def)]
          }),
        )
      : suggested(),
  )
  const [refresh, setRefresh] = useState(
    [...now.values()][0]?.def.refreshSecs ?? source.refreshSecs,
  )
  const apply = useAction('feeds.apply', 'Saved; fetching what is new')
  const setUse = (key: string, u: Use) => {
    setUses((m) => new Map(m).set(key, u))
  }

  const save = () => {
    const del: number[] = []
    const out: FeedDef[] = []
    const make = (item: Item, u: Use, existing: Feed | undefined): FeedDef =>
      withUse(
        {
          ...(existing?.def ?? NEW_FEED),
          // A list added before the catalog keeps its name: rules and the policy refer to it.
          name: existing?.def.name ?? item.name,
          url: item.url,
          select: item.select,
          content: item.content,
          refreshSecs: refresh,
          catalog: { source: source.id, item: item.key },
        },
        u,
      )
    if (source.pick === 'one') {
      // One feed for the source, whichever period.
      const chosen = source.items.find((i) => (uses.get(i.key) ?? 'off') !== 'off')
      const existing = [...now.values()]
      const keep = existing[0]
      for (const extra of existing.slice(1)) del.push(extra.def.id)
      if (chosen === undefined) {
        if (keep !== undefined) del.push(keep.def.id)
      } else {
        out.push(make(chosen, uses.get(chosen.key) ?? 'off', keep))
      }
    } else {
      for (const item of source.items) {
        const u = uses.get(item.key) ?? 'off'
        const existing = now.get(item.key)
        if (u === 'off') {
          if (existing !== undefined) del.push(existing.def.id)
        } else {
          out.push(make(item, u, existing))
        }
      }
    }
    apply.mutate({ delete: del, save: out }, { onSuccess: onClose })
  }

  const one = source.pick === 'one'
  const chosen = one ? source.items.find((i) => (uses.get(i.key) ?? 'off') !== 'off') : undefined
  return (
    <Stack gap="sm">
      <Text fz={13} c="var(--ink-dim)">
        {source.description}{' '}
        <Anchor href={source.homepage} target="_blank" rel="noreferrer" fz={13}>
          About the list <IconExternalLink size={12} style={{ verticalAlign: -1 }} />
        </Anchor>
      </Text>
      {source.note !== null && (
        <Alert variant="light" color="gray" icon={<IconInfoCircle size={16} />} p="xs">
          <Text fz={12.5}>{source.note}</Text>
        </Alert>
      )}
      {one ? (
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          <Select
            label="Period"
            data={[
              { value: '', label: 'Not used' },
              ...source.items.map((i) => ({
                value: i.key,
                label: `${i.label}${i.suggested !== 'off' ? ' (suggested)' : ''}`,
              })),
            ]}
            value={chosen?.key ?? ''}
            onChange={(v) => {
              const u = chosen === undefined ? 'block' : (uses.get(chosen.key) ?? 'block')
              setUses(new Map(source.items.map((i) => [i.key, i.key === v ? u : 'off'])))
            }}
            allowDeselect={false}
          />
          <Stack gap={4}>
            <Text fz={14} fw={500}>
              What it does
            </Text>
            <SegmentedControl
              fullWidth
              disabled={chosen === undefined}
              {...(chosen === undefined
                ? {}
                : { color: USE_COLORS[uses.get(chosen.key) ?? 'block'] })}
              value={chosen === undefined ? 'block' : (uses.get(chosen.key) ?? 'block')}
              onChange={(v) => {
                if (chosen !== undefined) setUse(chosen.key, v)
              }}
              data={(['block', 'allow', 'data'] as Use[]).map((u) => ({
                value: u,
                label: USE_LABELS[u],
              }))}
            />
          </Stack>
        </SimpleGrid>
      ) : (
        <Stack gap={0} className={classes.items}>
          {source.items.map((item) => {
            const u = uses.get(item.key) ?? 'off'
            const f = now.get(item.key)
            return (
              <div key={item.key} className={classes.item}>
                <div className={classes.itemText}>
                  <Text fz={13.5} fw={600}>
                    {f?.def.name ?? item.name}
                    {item.suggested !== 'off' && (
                      <Text span fz={11.5} fw={400} c="var(--ink-faint)">
                        {' '}
                        · suggested:{' '}
                        {item.content === 'agents' && item.suggested === 'data'
                          ? 'for rules'
                          : USE_LABELS[item.suggested].toLowerCase()}
                      </Text>
                    )}
                  </Text>
                  <Text fz={12} c="var(--ink-dim)">
                    {item.description}
                    {f !== undefined && f.changed !== null && ` · now ${entries(f)}`}
                  </Text>
                </div>
                <SegmentedControl
                  size="xs"
                  className={classes.itemUse}
                  {...(u === 'off' ? {} : { color: USE_COLORS[u] })}
                  value={u}
                  onChange={(v) => {
                    setUse(item.key, v)
                  }}
                  data={usesFor(item.content).map((x) => ({
                    value: x,
                    label: x === 'data' && item.content === 'agents' ? 'For rules' : USE_LABELS[x],
                  }))}
                />
              </div>
            )
          })}
        </Stack>
      )}
      <Text fz={12} c="var(--ink-dim)">
        {source.items.every((i) => i.content === 'agents') ? (
          <>
            <b>For rules</b>: a rule (HTTP, “User agent in list”) can ask whether a request’s user
            agent names one in it. Nothing happens by itself.
          </>
        ) : (
          <>
            <b>Block</b>: {USE_EFFECTS.block} <b>Allow</b>: {USE_EFFECTS.allow} <b>Data</b>:{' '}
            {USE_EFFECTS.data}
          </>
        )}
      </Text>
      <Group align="flex-end" wrap="wrap" gap="sm">
        <LengthInput label="Fetch every" value={refresh} onChange={setRefresh} />
        <Text fz={12} c="var(--ink-faint)" pb={8} style={{ flex: '1 1 200px' }}>
          {source.updates !== null && `Updated upstream: ${source.updates.toLowerCase()}. `}
          Suggested: every {lengthInWords(source.refreshSecs)}. An unchanged list costs one small
          request.
        </Text>
      </Group>
      <Group justify="space-between" wrap="wrap" className={classes.footer}>
        <Button
          variant="subtle"
          onClick={() => {
            setUses(suggested())
            setRefresh(source.refreshSecs)
          }}
        >
          Use the suggestions
        </Button>
        <Group gap="xs">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save} loading={apply.isPending}>
            Save
          </Button>
        </Group>
      </Group>
    </Stack>
  )
}

/** A source of the catalog: what it is, how many of its lists are used, and the button to pick them. */
function SourceCard({
  source,
  inUse,
  phone,
  onOpen,
}: {
  source: Source
  inUse: Feed[]
  phone: boolean
  onOpen: () => void
}) {
  const lists =
    source.pick === 'one'
      ? `${String(source.items.length)} periods`
      : source.items.length === 1
        ? '1 list'
        : `${String(source.items.length)} lists`
  return (
    <div className={['panel', classes.source].join(' ')}>
      <Group justify="space-between" wrap="nowrap" align="flex-start" gap="xs">
        <Text fw={650} fz={14}>
          {source.name}
        </Text>
        {inUse.length > 0 && (
          <Badge color="brass" variant="light" style={{ flexShrink: 0 }}>
            {inUse.length} in use
          </Badge>
        )}
      </Group>
      <Text fz={12.5} c="var(--ink-dim)" lineClamp={phone ? 2 : 3} mt={4}>
        {source.description}
      </Text>
      <Group justify="space-between" mt="auto" pt={8} wrap="nowrap">
        <Text fz={11.5} c="var(--ink-faint)" truncate>
          {lists}
          {source.updates !== null && ` · updated ${source.updates.toLowerCase()}`}
        </Text>
        <Button
          size="xs"
          variant={inUse.length > 0 ? 'default' : 'light'}
          onClick={onOpen}
          style={{ flexShrink: 0 }}
        >
          {inUse.length > 0 ? 'Change' : 'Set up'}
        </Button>
      </Group>
    </div>
  )
}

type Filter = 'all' | 'block' | 'allow' | 'data' | 'failing' | 'redundant'

const FILTER_LABELS: Record<Filter, string> = {
  all: 'All',
  block: 'Blocking',
  allow: 'Allowing',
  data: 'Data',
  failing: 'Failing',
  redundant: 'Redundant',
}

export function FeedsTab() {
  const feeds = useFeeds()
  const catalogQuery = useFeedCatalog()
  const now = useNow(30_000)
  const usedBy = useUsedBy()
  const phone = !useMediaQuery('(min-width: 48em)', true, { getInitialValueInEffect: false })
  const [editing, setEditing] = useState<FeedDef | null>(null)
  const [opened, setOpened] = useState<Source | null>(null)
  const [networksOf, setNetworksOf] = useState<number | null>(null)
  const [chosenView, setView] = useState<'used' | 'catalog' | null>(null)
  const [filter, setFilter] = useState<Filter>('all')
  const [explained, setExplained] = useState(false)
  const list = feeds.data ?? []
  const catalog = catalogQuery.data ?? []
  // Until one is picked: the lists in use, or the catalog while there are none.
  const view = chosenView ?? (feeds.data !== undefined && list.length === 0 ? 'catalog' : 'used')

  const counts: Record<Filter, number> = {
    all: list.length,
    block: 0,
    allow: 0,
    data: 0,
    failing: 0,
    redundant: 0,
  }
  let blocked = 0
  for (const f of list) {
    const u = feedUse(f.def)
    if (u !== 'off') counts[u] += 1
    if (u === 'block') blocked += f.extent.prefixes
    if (health(f) === 'failing') counts.failing += 1
    if (f.coveredBy !== null) counts.redundant += 1
  }
  const matches = (f: Feed) =>
    filter === 'all' ||
    (filter === 'failing'
      ? health(f) === 'failing'
      : filter === 'redundant'
        ? f.coveredBy !== null
        : feedUse(f.def) === filter)

  // The feeds in use, by source; the ones added by hand last.
  const bySource = new Map<string, Feed[]>()
  const own: Feed[] = []
  for (const f of list) {
    const m = catalogOf(f.def, catalog)
    if (m === null) own.push(f)
    else bySource.set(m.source.id, [...(bySource.get(m.source.id) ?? []), f])
  }
  const used = catalog.filter((s) => bySource.has(s.id))

  const row = (f: Feed) => (
    <FeedRow
      key={f.def.id}
      feed={f}
      now={now}
      usedBy={usedBy(f.def.name)}
      onEdit={() => {
        setEditing(f.def)
      }}
      onNetworks={() => {
        setNetworksOf(f.def.id)
      }}
    />
  )

  return (
    <Stack gap="md">
      <div>
        <Text fz={13} c="var(--ink-dim)" maw={760} span>
          Lists fetched from the internet and kept up to date: each one blocks, allows, or is data
          for rules and ban lengths.{' '}
        </Text>
        <Anchor
          component="button"
          fz={13}
          onClick={() => {
            setExplained((e) => !e)
          }}
        >
          {explained ? 'Less' : 'How lists work'}
        </Anchor>
        {explained && (
          <Text fz={12.5} c="var(--ink-dim)" maw={760} mt={6}>
            <b>Block</b>: {USE_EFFECTS.block} <b>Allow</b>: {USE_EFFECTS.allow} <b>Data</b>:{' '}
            {USE_EFFECTS.data} Lists are fetched on their schedule; an unchanged list costs one
            small request, and lists of one URL are fetched together. A failed fetch keeps the list
            from before and is tried again after 5 minutes, then 10, 20, and so on up to the list’s
            schedule.
          </Text>
        )}
      </div>

      <SegmentedControl
        fullWidth={phone}
        style={{ alignSelf: phone ? 'stretch' : 'flex-start' }}
        value={view}
        onChange={setView}
        data={[
          { value: 'used', label: `In use (${String(list.length)})` },
          { value: 'catalog', label: `Catalog (${String(catalog.length)})` },
        ]}
      />

      {view === 'used' && (
        <>
          {list.length > 0 && (
            <Stack gap={6}>
              <Chip.Group
                multiple={false}
                value={filter}
                onChange={(v) => {
                  setFilter(v)
                }}
              >
                <Group gap={6}>
                  {(['all', 'block', 'allow', 'data', 'failing', 'redundant'] as const)
                    .filter((k) => (k !== 'failing' && k !== 'redundant') || counts[k] > 0)
                    .map((k) => (
                      <Chip
                        key={k}
                        value={k}
                        size="xs"
                        color={k === 'failing' ? 'red' : k === 'redundant' ? 'yellow' : 'brass'}
                      >
                        {FILTER_LABELS[k]} {counts[k]}
                      </Chip>
                    ))}
                </Group>
              </Chip.Group>
              <Text fz={12} c="var(--ink-faint)">
                Blocking lists hold {count(blocked)} prefixes, here and on the edges.
              </Text>
            </Stack>
          )}

          {used.map((source) => {
            const shown = (bySource.get(source.id) ?? []).filter(matches)
            if (shown.length === 0) return null
            return (
              <FeedGroup
                key={source.id}
                title={source.name}
                homepage={source.homepage}
                feeds={bySource.get(source.id) ?? []}
                forceOpen={filter !== 'all'}
                action={
                  <Button
                    size="xs"
                    variant="default"
                    onClick={() => {
                      setOpened(source)
                    }}
                  >
                    Change
                  </Button>
                }
              >
                {shown.map(row)}
              </FeedGroup>
            )
          })}

          {(filter === 'all' || own.some(matches)) && (
            <FeedGroup
              title="Your own lists"
              homepage={null}
              feeds={own}
              forceOpen={filter !== 'all'}
              action={
                <Button
                  size="xs"
                  variant="default"
                  leftSection={<IconPlus size={14} />}
                  onClick={() => {
                    setEditing(NEW_FEED)
                  }}
                >
                  Add
                </Button>
              }
            >
              {own.length === 0 ? (
                <Text fz={12.5} c="var(--ink-faint)" px={12} pb={10}>
                  Any URL of addresses, networks or user agents, with HTTP basic authentication if
                  it needs it: CrowdSec’s blocklists, for one, through a “blocklist integration” of
                  a CrowdSec console account (its URL, user and password).
                </Text>
              ) : (
                own.filter(matches).map(row)
              )}
            </FeedGroup>
          )}

          {list.length === 0 && feeds.data !== undefined && (
            <Text fz={13} c="var(--ink-dim)">
              No lists yet: pick some from the{' '}
              <Anchor
                component="button"
                fz={13}
                onClick={() => {
                  setView('catalog')
                }}
              >
                catalog
              </Anchor>
              .
            </Text>
          )}
        </>
      )}

      {view === 'catalog' &&
        CATEGORIES.map((c) => {
          const sources = catalog.filter((s) => s.category === c.value)
          if (sources.length === 0) return null
          return (
            <Stack key={c.value} gap={6}>
              <div>
                <Text fw={620} fz={13.5}>
                  {c.title}
                </Text>
                <Text fz={12.5} c="var(--ink-dim)" maw={760}>
                  {c.description}
                </Text>
              </div>
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="sm">
                {sources.map((s) => (
                  <SourceCard
                    key={s.id}
                    source={s}
                    inUse={bySource.get(s.id) ?? []}
                    phone={phone}
                    onOpen={() => {
                      setOpened(s)
                    }}
                  />
                ))}
              </SimpleGrid>
            </Stack>
          )
        })}

      <Modal
        opened={networksOf !== null}
        onClose={() => {
          setNetworksOf(null)
        }}
        title={`Networks of “${list.find((f) => f.def.id === networksOf)?.def.name ?? ''}”`}
        size="lg"
        fullScreen={phone}
      >
        {(() => {
          const f = list.find((x) => x.def.id === networksOf)
          return f === undefined ? null : (
            <NetworksDialog
              feed={f}
              onClose={() => {
                setNetworksOf(null)
              }}
            />
          )
        })()}
      </Modal>
      <Modal
        opened={editing !== null}
        onClose={() => {
          setEditing(null)
        }}
        title={editing?.id === 0 ? 'Add a list' : 'Edit list'}
        fullScreen={phone}
      >
        {editing !== null && (
          <FeedEditor
            key={editing.id}
            feed={editing}
            onClose={() => {
              setEditing(null)
            }}
          />
        )}
      </Modal>
      <Modal
        opened={opened !== null}
        onClose={() => {
          setOpened(null)
        }}
        title={opened?.name}
        size="lg"
        fullScreen={phone}
      >
        {opened !== null && (
          <SourceDialog
            key={opened.id}
            source={opened}
            feeds={list}
            catalog={catalog}
            onClose={() => {
              setOpened(null)
            }}
          />
        )}
      </Modal>
    </Stack>
  )
}
