import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Modal,
  NumberInput,
  Select,
  Stack,
  Switch,
  Tabs,
  Text,
  TextInput,
} from '@mantine/core'
import { IconPlus, IconRefresh, IconTrash, IconWorld } from '@tabler/icons-react'
import { useState, type ReactNode } from 'react'

import { useAction, useEntries, useFeedPresets, useFeeds, useMeta, usePolicy } from '../api/hooks'
import type { FeedDef, Policy } from '../api/generated/model'
import { AddPicker, EditableList } from '../components/EditableList'
import { COUNTRY_SELECT } from '../components/countrySelect'
import { CountryLabel, LengthInput, LengthSelect, Panel } from '../components/ui'
import { ago, CONTINENTS, count, COUNTRIES, countryName, remaining } from '../lib/format'
import { navigate } from '../lib/router'
import { useNow } from '../lib/useNow'

const COUNTRY_OPTIONS = COUNTRIES.map((c) => ({ value: c.code, label: c.name }))

/** New entries of the lengths lists start at this; shared addresses are better banned briefly. */
const NEW_LENGTH = 3_600

/** A part of a panel: a heading, what it is for, and its content. */
function Section({
  title,
  description,
  children,
}: {
  title: string
  description: ReactNode
  children: ReactNode
}) {
  return (
    <Stack gap={8} mt="xs">
      <div>
        <Text fz={14} fw={620}>
          {title}
        </Text>
        <Text fz={12.5} c="var(--ink-dim)" maw={760}>
          {description}
        </Text>
      </div>
      {children}
    </Stack>
  )
}

/** The add row of the networks' lengths: an AS number, added with the button or Enter. */
function AsnAdder({ taken, onAdd }: { taken: number[]; onAdd: (asn: number) => void }) {
  const [asn, setAsn] = useState<string | number>('')
  const n = Number(asn)
  const valid = Number.isInteger(n) && n > 0 && !taken.includes(n)
  const add = () => {
    if (!valid) return
    onAdd(n)
    setAsn('')
  }
  return (
    <Group gap={8} wrap="nowrap">
      <NumberInput
        placeholder="AS number"
        prefix="AS"
        min={1}
        allowDecimal={false}
        allowNegative={false}
        hideControls
        value={asn}
        onChange={setAsn}
        onKeyDown={(e) => {
          if (e.key === 'Enter') add()
        }}
        aria-label="AS number to add"
        error={taken.includes(n) ? true : undefined}
        style={{ flex: 1 }}
        classNames={{ input: 'mono' }}
      />
      <Button
        variant="default"
        leftSection={<IconPlus size={16} />}
        disabled={!valid}
        onClick={add}
      >
        Add
      </Button>
    </Group>
  )
}

function LengthsPanel({ p, set }: { p: Policy; set: (patch: Partial<Policy>) => void }) {
  const feeds = useFeeds()
  const feedNames = (feeds.data ?? []).map((f) => f.def.name)
  const freeFeeds = feedNames.filter((n) => !p.listLengths.some((l) => l.list === n))
  return (
    <Panel title="Ban lengths">
      <Stack gap="md">
        <Group align="flex-end" wrap="wrap">
          <LengthInput
            label="Default"
            description="Rules without a length of their own"
            value={p.banSecs}
            onChange={(banSecs) => {
              set({ banSecs })
            }}
          />
          <NumberInput
            label="Repeat offenders"
            description="Each earlier ban multiplies by"
            min={1}
            max={10}
            value={p.repeatMultiplier}
            onChange={(v) => {
              set({ repeatMultiplier: Math.max(1, Number(v) || 1) })
            }}
            w={180}
          />
          <LengthInput
            label="At most"
            description="Escalation stops here"
            value={p.maxBanSecs}
            onChange={(maxBanSecs) => {
              set({ maxBanSecs })
            }}
          />
        </Group>

        <Section
          title="By country"
          description="Addresses of these countries are banned for this long instead (escalation still applies): shorter for your own country, where people you know share addresses."
        >
          <EditableList
            items={p.countryLengths}
            itemKey={(l) => l.country}
            headers={['Country', 'Ban length']}
            label={(l) => <CountryLabel code={l.country} />}
            value={(l, i) => (
              <LengthInput
                aria-label={`Ban length for ${countryName(l.country)}`}
                value={l.secs}
                onChange={(secs) => {
                  set({
                    countryLengths: p.countryLengths.map((x, j) => (j === i ? { ...x, secs } : x)),
                  })
                }}
              />
            )}
            onRemove={(i) => {
              set({ countryLengths: p.countryLengths.filter((_, j) => j !== i) })
            }}
            removeLabel={(l) => `Remove ${countryName(l.country)}`}
            empty="No country has a length of its own: the rule’s length, or the default, counts."
            add={
              <AddPicker
                placeholder="Add a country…"
                aria-label="Add a country"
                data={COUNTRY_OPTIONS.filter(
                  (c) => !p.countryLengths.some((l) => l.country === c.value),
                )}
                {...COUNTRY_SELECT}
                onAdd={(country) => {
                  set({ countryLengths: [...p.countryLengths, { country, secs: NEW_LENGTH }] })
                }}
              />
            }
          />
        </Section>

        <Section
          title="By network"
          description="Addresses many people share (a VPN, Cloudflare WARP on AS13335) are better banned briefly. The shortest of the country, network and blocklist lengths counts."
        >
          <EditableList
            items={p.asnLengths}
            itemKey={(l) => String(l.asn)}
            headers={['Network', 'Ban length']}
            label={(l) => <span className="mono">AS{l.asn}</span>}
            value={(l, i) => (
              <LengthInput
                aria-label={`Ban length for AS${String(l.asn)}`}
                value={l.secs}
                onChange={(secs) => {
                  set({ asnLengths: p.asnLengths.map((x, j) => (j === i ? { ...x, secs } : x)) })
                }}
              />
            )}
            onRemove={(i) => {
              set({ asnLengths: p.asnLengths.filter((_, j) => j !== i) })
            }}
            removeLabel={(l) => `Remove AS${String(l.asn)}`}
            empty="No network has a length of its own."
            add={
              <AsnAdder
                taken={p.asnLengths.map((l) => l.asn)}
                onAdd={(asn) => {
                  set({ asnLengths: [...p.asnLengths, { asn, secs: NEW_LENGTH }] })
                }}
              />
            }
          />
        </Section>

        <Section
          title="By blocklist"
          description="Addresses a blocklist lists, such as iCloud Private Relay’s egress addresses."
        >
          <EditableList
            items={p.listLengths}
            itemKey={(l) => l.list}
            headers={['Listed in', 'Ban length']}
            label={(l) => (
              <div className="place-text">
                <div className="place-title">{l.list}</div>
                {feeds.data !== undefined && !feedNames.includes(l.list) && (
                  <div className="place-sub" style={{ color: 'var(--status-warn)' }}>
                    No blocklist has this name any more
                  </div>
                )}
              </div>
            )}
            value={(l, i) => (
              <LengthInput
                aria-label={`Ban length for addresses listed in ${l.list}`}
                value={l.secs}
                onChange={(secs) => {
                  set({ listLengths: p.listLengths.map((x, j) => (j === i ? { ...x, secs } : x)) })
                }}
              />
            )}
            onRemove={(i) => {
              set({ listLengths: p.listLengths.filter((_, j) => j !== i) })
            }}
            removeLabel={(l) => `Remove ${l.list}`}
            empty={
              feedNames.length === 0 ? (
                <>
                  No blocklist has a length of its own. Blocklists are added under{' '}
                  <Anchor
                    component="button"
                    fz="inherit"
                    onClick={() => {
                      navigate('settings', { tab: 'feeds' }, true)
                    }}
                  >
                    Blocklists
                  </Anchor>
                  .
                </>
              ) : (
                'No blocklist has a length of its own.'
              )
            }
            add={
              <AddPicker
                placeholder={feedNames.length === 0 ? 'No blocklists yet' : 'Add a blocklist…'}
                aria-label="Add a blocklist"
                data={freeFeeds}
                disabled={freeFeeds.length === 0}
                onAdd={(list) => {
                  set({ listLengths: [...p.listLengths, { list, secs: NEW_LENGTH }] })
                }}
              />
            }
          />
        </Section>
      </Stack>
    </Panel>
  )
}

const CONTINENT_NAMES = new Map(CONTINENTS.map((c) => [c.code, c.name]))

/** A blocked country or continent. */
interface Place {
  kind: 'country' | 'continent'
  code: string
}

function placeName(place: Place): string {
  return place.kind === 'continent'
    ? (CONTINENT_NAMES.get(place.code) ?? place.code)
    : countryName(place.code)
}

function PlaceLabel({ place, sub }: { place: Place; sub?: ReactNode }) {
  if (place.kind === 'country') return <CountryLabel code={place.code} sub={sub} />
  return (
    <div className="place">
      <span className="place-flag" aria-hidden="true">
        <IconWorld size={19} stroke={1.6} />
      </span>
      <div className="place-text">
        <div className="place-name">
          <span className="place-title">{placeName(place)}</span>
          <span className="place-code mono">{place.code}</span>
        </div>
        {sub !== undefined && <div className="place-sub">{sub}</div>}
      </div>
    </div>
  )
}

function BlockedPanel({ p, set }: { p: Policy; set: (patch: Partial<Policy>) => void }) {
  const meta = useMeta()
  const places: Place[] = [
    ...p.blockedContinents.map((code) => ({ kind: 'continent' as const, code })),
    ...p.blockedCountries.map((code) => ({ kind: 'country' as const, code })),
  ]
  const options = [
    {
      group: 'Continents',
      items: CONTINENTS.filter((c) => !p.blockedContinents.includes(c.code)).map((c) => ({
        value: `continent:${c.code}`,
        label: c.name,
      })),
    },
    {
      group: 'Countries',
      items: COUNTRY_OPTIONS.filter((c) => !p.blockedCountries.includes(c.value)),
    },
  ]
  const remove = (place: Place) => {
    if (place.kind === 'continent')
      set({ blockedContinents: p.blockedContinents.filter((c) => c !== place.code) })
    else set({ blockedCountries: p.blockedCountries.filter((c) => c !== place.code) })
  }
  return (
    <Panel title="Countries blocked as a whole">
      <Stack gap="sm">
        <Text fz={12.5} c="var(--ink-dim)" maw={760}>
          Nothing from these reaches the services, on this host and on the edges. Replies to
          connections made from here still pass.
        </Text>
        {meta.data?.hasCountries === false && (
          <Alert color="yellow" variant="light">
            There is no country database: no address has a country, and none of these is blocked.
          </Alert>
        )}
        <EditableList
          items={places}
          itemKey={(x) => `${x.kind}:${x.code}`}
          label={(x) => <PlaceLabel place={x} />}
          onRemove={(i) => {
            const place = places[i]
            if (place !== undefined) remove(place)
          }}
          removeLabel={(x) => `Stop blocking ${placeName(x)}`}
          empty="No country or continent is blocked."
          add={
            <AddPicker
              placeholder="Block a country or a continent…"
              aria-label="Block a country or a continent"
              data={options}
              {...COUNTRY_SELECT}
              onAdd={(v) => {
                if (v.startsWith('continent:'))
                  set({ blockedContinents: [...p.blockedContinents, v.slice(10)].sort() })
                else set({ blockedCountries: [...p.blockedCountries, v].sort() })
              }}
            />
          }
        />
      </Stack>
    </Panel>
  )
}

function PolicyForm({ policy }: { policy: Policy }) {
  const [p, setP] = useState(policy)
  const save = useAction('policy.update', 'Saved')
  const set = (patch: Partial<Policy>) => {
    setP((x) => ({ ...x, ...patch }))
  }
  const changed = JSON.stringify(p) !== JSON.stringify(policy)
  return (
    <Stack gap="md">
      <LengthsPanel p={p} set={set} />
      <BlockedPanel p={p} set={set} />

      <Panel title="Other">
        <Group align="flex-end" wrap="wrap">
          <LengthInput
            label="Trust after a login"
            description="No rule acts on the address"
            value={p.trustSecs}
            onChange={(trustSecs) => {
              set({ trustSecs })
            }}
          />
          <NumberInput
            label="Keep events"
            description="Days"
            min={1}
            value={p.retentionDays}
            onChange={(v) => {
              set({ retentionDays: Math.max(1, Number(v) || 1) })
            }}
            w={140}
          />
        </Group>
      </Panel>

      <Group justify="flex-end">
        <Button
          variant="default"
          disabled={!changed}
          onClick={() => {
            setP(policy)
          }}
        >
          Revert
        </Button>
        <Button
          disabled={!changed}
          loading={save.isPending}
          onClick={() => {
            save.mutate(p)
          }}
        >
          Save
        </Button>
      </Group>
    </Stack>
  )
}

function PolicyTab() {
  const policy = usePolicy()
  if (policy.error) return <Alert color="red">{policy.error.message}</Alert>
  if (!policy.data) return null
  // Remounted when the saved policy changes, so the form starts from it.
  return <PolicyForm key={JSON.stringify(policy.data)} policy={policy.data} />
}

function EntriesTab() {
  const entries = useEntries()
  const now = useNow(60_000)
  const [net, setNet] = useState('')
  const [allow, setAllow] = useState(true)
  const [note, setNote] = useState('')
  const [secs, setSecs] = useState<number | null>(null)
  const save = useAction('entry.save', 'Saved')
  const remove = useAction('entry.delete', 'Removed')
  const list = entries.data ?? []
  return (
    <Stack gap="md">
      <Text fz={13} c="var(--ink-dim)" maw={700}>
        These win over every decision: no rule acts on an allowed address, and it is let through
        even when banned or in a blocked country. A denied one is blocked whatever the rules say.
        Private networks are always allowed.
      </Text>
      {entries.error && <Alert color="red">{entries.error.message}</Alert>}
      <EditableList
        items={list}
        itemKey={(e) => String(e.id)}
        headers={['Address or prefix', 'List']}
        wide
        label={(e) => (
          <div className="place-text">
            <div className="mono" style={{ overflowWrap: 'anywhere' }}>
              {e.net}
            </div>
            {e.note !== '' && <div className="place-sub">{e.note}</div>}
          </div>
        )}
        value={(e) => (
          <Group gap={10} wrap="nowrap">
            <Badge color={e.allow ? 'green' : 'red'} w={64}>
              {e.allow ? 'Allow' : 'Deny'}
            </Badge>
            <Text fz={12} c="var(--ink-faint)" w={72}>
              {e.until === null ? 'no end' : remaining(e.until, now)}
            </Text>
          </Group>
        )}
        onRemove={(i) => {
          const e = list[i]
          if (e !== undefined) remove.mutate({ id: e.id })
        }}
        removeLabel={(e) => `Remove ${e.net}`}
        empty={entries.isPending ? 'Loading…' : 'Nothing is allowed or denied by hand.'}
        add={
          <form
            onSubmit={(e) => {
              e.preventDefault()
              save.mutate(
                { net: net.trim(), allow, note, secs },
                {
                  onSuccess: () => {
                    setNet('')
                    setNote('')
                  },
                },
              )
            }}
          >
            <Group gap={8} align="flex-start" wrap="wrap">
              <TextInput
                placeholder="198.51.100.0/24"
                aria-label="Address or prefix"
                value={net}
                onChange={(e) => {
                  setNet(e.currentTarget.value)
                }}
                required
                classNames={{ input: 'mono' }}
                style={{ flex: '2 1 180px' }}
              />
              <Select
                aria-label="List"
                data={[
                  { value: 'allow', label: 'Allow' },
                  { value: 'deny', label: 'Deny' },
                ]}
                value={allow ? 'allow' : 'deny'}
                onChange={(v) => {
                  setAllow(v !== 'deny')
                }}
                allowDeselect={false}
                w={100}
              />
              <TextInput
                placeholder="Note"
                aria-label="Note"
                value={note}
                onChange={(e) => {
                  setNote(e.currentTarget.value)
                }}
                style={{ flex: '2 1 140px' }}
              />
              <div style={{ flex: '1 1 130px' }}>
                <LengthSelect label="For" hideLabel value={secs} onChange={setSecs} />
              </div>
              <Button
                type="submit"
                variant="default"
                loading={save.isPending}
                leftSection={<IconPlus size={16} />}
              >
                Add
              </Button>
            </Group>
          </form>
        }
      />
    </Stack>
  )
}

const NEW_FEED: FeedDef = {
  id: 0,
  name: '',
  url: '',
  enabled: true,
  block: false,
  refreshSecs: 6 * 3_600,
  username: null,
  password: null,
}

function FeedEditor({ feed, onClose }: { feed: FeedDef; onClose: () => void }) {
  const [f, setF] = useState(feed)
  const save = useAction('feed.save', 'Saved; fetching it now')
  const set = (patch: Partial<FeedDef>) => {
    setF((x) => ({ ...x, ...patch }))
  }
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
          description="Rules' “listed in” condition refers to it"
          value={f.name}
          onChange={(e) => {
            set({ name: e.currentTarget.value })
          }}
          required
        />
        <TextInput
          label="URL"
          description="A list with an address or prefix per line (comments, CSV and JSON lines are understood)"
          value={f.url}
          onChange={(e) => {
            set({ url: e.currentTarget.value })
          }}
          required
          classNames={{ input: 'mono' }}
        />
        <Switch
          label="Block what it lists"
          description="Otherwise it is only data, for rules and for the address pages"
          checked={f.block}
          onChange={(e) => {
            set({ block: e.currentTarget.checked })
          }}
        />
        <LengthInput
          label="Fetch every"
          value={f.refreshSecs}
          onChange={(refreshSecs) => {
            set({ refreshSecs })
          }}
        />
        <Group grow>
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
        </Group>
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

function FeedsTab() {
  const feeds = useFeeds()
  const presets = useFeedPresets()
  const now = useNow(30_000)
  const [editing, setEditing] = useState<FeedDef | null>(null)
  const remove = useAction('feed.delete', 'Removed')
  const refresh = useAction('feed.refresh')
  const save = useAction('feed.save', 'Added; fetching it now')
  const list = feeds.data ?? []
  const available = (presets.data ?? []).filter((p) => !list.some((f) => f.def.url === p.url))
  return (
    <Stack gap="md">
      <Text fz={13} c="var(--ink-dim)" maw={700}>
        Public lists of bad addresses. A list that blocks is applied as a whole, like a blocked
        country; the others are data for rules (“listed in”) and for the address pages. CrowdSec’s
        blocklists can be added through a “blocklist integration” of a CrowdSec console account: its
        URL, user and password.
      </Text>
      <Group gap="xs">
        <Button
          leftSection={<IconPlus size={16} />}
          onClick={() => {
            setEditing(NEW_FEED)
          }}
        >
          Add a list
        </Button>
        {available.map((p) => (
          <Button
            key={p.url}
            variant="default"
            onClick={() => {
              save.mutate(p)
            }}
          >
            {p.name}
          </Button>
        ))}
      </Group>
      {list.map((f) => (
        <div key={f.def.id} className="panel" style={{ padding: '10px 12px' }}>
          <Group justify="space-between" wrap="nowrap" align="flex-start">
            <div style={{ minWidth: 0 }}>
              <Group gap={8}>
                <Anchor
                  component="button"
                  fw={620}
                  fz={14}
                  c="inherit"
                  onClick={() => {
                    setEditing(f.def)
                  }}
                >
                  {f.def.name}
                </Anchor>
                {f.def.block ? (
                  <Badge color="brass">Blocks</Badge>
                ) : (
                  <Badge color="gray">Data</Badge>
                )}
                {!f.def.enabled && <Badge color="gray">Off</Badge>}
              </Group>
              <Text fz={12} c="var(--ink-faint)" className="mono" truncate>
                {f.def.url}
              </Text>
              <Text fz={12} c={f.error === null ? 'var(--ink-dim)' : 'var(--status-bad)'}>
                {count(f.count)} prefixes · fetched {ago(f.fetched, now)}
                {f.error !== null && ` · ${f.error}`}
              </Text>
            </div>
            <Group gap={2} wrap="nowrap">
              <ActionIcon
                loading={refresh.isPending && refresh.variables.id === f.def.id}
                onClick={() => {
                  refresh.mutate({ id: f.def.id })
                }}
                aria-label="Fetch now"
              >
                <IconRefresh size={16} />
              </ActionIcon>
              <ActionIcon
                color="red"
                onClick={() => {
                  if (window.confirm(`Remove the list “${f.def.name}”?`))
                    remove.mutate({ id: f.def.id })
                }}
                aria-label="Remove"
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          </Group>
        </div>
      ))}
      <Modal
        opened={editing !== null}
        onClose={() => {
          setEditing(null)
        }}
        title={editing?.id === 0 ? 'Add a list' : 'Edit list'}
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
    </Stack>
  )
}

const TABS = ['policy', 'lists', 'feeds', 'about'] as const
type Tab = (typeof TABS)[number]

export function SettingsScreen({ tab }: { tab: string | null }) {
  const meta = useMeta()
  const current: Tab = TABS.find((t) => t === tab) ?? 'policy'
  return (
    <Tabs
      value={current}
      onChange={(v) => {
        navigate('settings', { tab: v ?? 'policy' }, true)
      }}
      keepMounted={false}
    >
      <Tabs.List mb="md">
        <Tabs.Tab value="policy">Lengths and countries</Tabs.Tab>
        <Tabs.Tab value="lists">Allow and deny</Tabs.Tab>
        <Tabs.Tab value="feeds">Blocklists</Tabs.Tab>
        <Tabs.Tab value="about">About</Tabs.Tab>
      </Tabs.List>
      <Tabs.Panel value="policy">
        <PolicyTab />
      </Tabs.Panel>
      <Tabs.Panel value="lists">
        <EntriesTab />
      </Tabs.Panel>
      <Tabs.Panel value="feeds">
        <FeedsTab />
      </Tabs.Panel>
      <Tabs.Panel value="about">
        <Stack gap={6} fz={14}>
          <Text>barbican {meta.data?.version}</Text>
          <Text c="var(--ink-dim)" fz={13}>
            Sources: {meta.data?.sources.join(', ')}. Firewall:{' '}
            {meta.data?.dryRun === true ? 'dry run' : 'on'}. Edge API:{' '}
            {meta.data?.edgeApi === true ? 'on' : 'off'}.
          </Text>
          {meta.data?.edgeFingerprint != null && (
            <Text c="var(--ink-dim)" fz={13}>
              Edge API certificate (the edges’ <code>fingerprint</code>):{' '}
              <span className="mono" style={{ wordBreak: 'break-all' }}>
                {meta.data.edgeFingerprint}
              </span>
            </Text>
          )}
          <Text c="var(--ink-dim)" fz={13}>
            {meta.data?.hasCountries === true ? (
              <>
                IP geolocation by{' '}
                <Anchor href="https://db-ip.com" target="_blank" rel="noreferrer">
                  DB-IP
                </Anchor>{' '}
                (CC BY 4.0).
              </>
            ) : (
              'No country database: countries are unknown, and none can be blocked.'
            )}
          </Text>
        </Stack>
      </Tabs.Panel>
    </Tabs>
  )
}
