import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Chip,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
} from '@mantine/core'
import { IconPlus, IconRefresh, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'

import { useAction, useEntries, useFeedPresets, useFeeds, useMeta, usePolicy } from '../api/hooks'
import type { FeedDef, Policy } from '../api/generated/model'
import { Country, LengthInput, LengthSelect, Panel } from '../components/ui'
import { ago, CONTINENTS, count, COUNTRIES, remaining } from '../lib/format'
import { navigate } from '../lib/router'
import { useNow } from '../lib/useNow'

const COUNTRY_OPTIONS = COUNTRIES.map((c) => ({ value: c.code, label: `${c.name} (${c.code})` }))

/** Lengths for networks (ASNs) and blocklists: shared addresses (VPNs, relays) get short bans. */
function SharedLengths({
  policy: p,
  set,
}: {
  policy: Policy
  set: (patch: Partial<Policy>) => void
}) {
  const feeds = useFeeds()
  const [asn, setAsn] = useState<string | number>('')
  const [list, setList] = useState<string | null>(null)
  return (
    <>
      <Text fz={13} fw={620} mt="xs">
        By network or blocklist
      </Text>
      <Text fz={12} c="var(--ink-dim)" mt={-8}>
        Addresses many people share (a VPN, Cloudflare WARP on AS13335, iCloud Private Relay through
        its blocklist) are better banned briefly. The shortest of the country, network and blocklist
        lengths counts.
      </Text>
      {p.asnLengths.map((l, i) => (
        <Group key={`as${String(l.asn)}`} align="flex-end">
          <Text w={220} fz={14}>
            AS{l.asn}
          </Text>
          <LengthInput
            label="Length"
            value={l.secs}
            onChange={(secs) => {
              set({ asnLengths: p.asnLengths.map((x, j) => (j === i ? { ...x, secs } : x)) })
            }}
          />
          <ActionIcon
            color="red"
            mb={6}
            onClick={() => {
              set({ asnLengths: p.asnLengths.filter((_, j) => j !== i) })
            }}
            aria-label={`Remove AS${String(l.asn)}`}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      {p.listLengths.map((l, i) => (
        <Group key={`list${l.list}`} align="flex-end">
          <Text w={220} fz={14}>
            Listed in {l.list}
          </Text>
          <LengthInput
            label="Length"
            value={l.secs}
            onChange={(secs) => {
              set({ listLengths: p.listLengths.map((x, j) => (j === i ? { ...x, secs } : x)) })
            }}
          />
          <ActionIcon
            color="red"
            mb={6}
            onClick={() => {
              set({ listLengths: p.listLengths.filter((_, j) => j !== i) })
            }}
            aria-label={`Remove ${l.list}`}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      <Group align="flex-end">
        <NumberInput
          label="Add a network"
          placeholder="13335"
          prefix="AS"
          min={1}
          value={asn}
          onChange={setAsn}
          w={160}
        />
        <Button
          variant="default"
          disabled={Number(asn) <= 0 || p.asnLengths.some((l) => l.asn === Number(asn))}
          onClick={() => {
            set({ asnLengths: [...p.asnLengths, { asn: Number(asn), secs: 3_600 }] })
            setAsn('')
          }}
        >
          Add
        </Button>
        <Select
          label="Add a blocklist"
          placeholder="Blocklist"
          data={(feeds.data ?? [])
            .map((f) => f.def.name)
            .filter((n) => !p.listLengths.some((l) => l.list === n))}
          value={list}
          onChange={setList}
          w={200}
        />
        <Button
          variant="default"
          disabled={list === null}
          onClick={() => {
            if (list === null) return
            set({ listLengths: [...p.listLengths, { list, secs: 3_600 }] })
            setList(null)
          }}
        >
          Add
        </Button>
      </Group>
    </>
  )
}

function PolicyForm({ policy }: { policy: Policy }) {
  const [p, setP] = useState(policy)
  const [country, setCountry] = useState<string | null>(null)
  const save = useAction('policy.update', 'Saved')
  const set = (patch: Partial<Policy>) => {
    setP((x) => ({ ...x, ...patch }))
  }
  const changed = JSON.stringify(p) !== JSON.stringify(policy)
  return (
    <Stack gap="md">
      <Panel title="Ban lengths">
        <Stack gap="sm">
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
          <Text fz={13} fw={620} mt="xs">
            By country
          </Text>
          <Text fz={12} c="var(--ink-dim)" mt={-8}>
            Addresses of these countries are banned for this long instead (escalation still
            applies): shorter for your own country, where people you know share addresses.
          </Text>
          {p.countryLengths.map((l, i) => (
            <Group key={l.country} align="flex-end">
              <Text w={220} fz={14}>
                <Country code={l.country} name />
              </Text>
              <LengthInput
                label="Length"
                value={l.secs}
                onChange={(secs) => {
                  set({
                    countryLengths: p.countryLengths.map((x, j) => (j === i ? { ...x, secs } : x)),
                  })
                }}
              />
              <ActionIcon
                color="red"
                mb={6}
                onClick={() => {
                  set({ countryLengths: p.countryLengths.filter((_, j) => j !== i) })
                }}
                aria-label={`Remove ${l.country}`}
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          <Group align="flex-end">
            <Select
              label="Add a country"
              placeholder="Country"
              data={COUNTRY_OPTIONS.filter(
                (c) => !p.countryLengths.some((l) => l.country === c.value),
              )}
              value={country}
              onChange={setCountry}
              searchable
              w={260}
            />
            <Button
              variant="default"
              disabled={country === null}
              onClick={() => {
                if (country === null) return
                set({ countryLengths: [...p.countryLengths, { country, secs: 3_600 }] })
                setCountry(null)
              }}
            >
              Add
            </Button>
          </Group>
          <SharedLengths policy={p} set={set} />
        </Stack>
      </Panel>

      <Panel title="Countries blocked as a whole">
        <Stack gap="sm">
          <Text fz={12} c="var(--ink-dim)">
            Nothing from these reaches the services, on this host and on the edges. Replies to
            connections made from here still pass.
          </Text>
          <MultiSelect
            label="Countries"
            data={COUNTRY_OPTIONS}
            value={p.blockedCountries}
            onChange={(blockedCountries) => {
              set({ blockedCountries })
            }}
            searchable
            clearable
          />
          <div>
            <Text fz={14} fw={500} mb={6}>
              Continents
            </Text>
            <Chip.Group
              multiple
              value={p.blockedContinents}
              onChange={(blockedContinents) => {
                set({ blockedContinents })
              }}
            >
              <Group gap={6}>
                {CONTINENTS.map((c) => (
                  <Chip key={c.code} value={c.code} size="sm">
                    {c.name}
                  </Chip>
                ))}
              </Group>
            </Chip.Group>
          </div>
        </Stack>
      </Panel>

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
  return (
    <Stack gap="md">
      <Text fz={13} c="var(--ink-dim)" maw={700}>
        These win over every decision: no rule acts on an allowed address, and it is let through
        even when banned or in a blocked country. A denied one is blocked whatever the rules say.
        Private networks are always allowed.
      </Text>
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
        <Group align="flex-end" wrap="wrap">
          <TextInput
            label="Address or prefix"
            placeholder="198.51.100.0/24"
            value={net}
            onChange={(e) => {
              setNet(e.currentTarget.value)
            }}
            required
            classNames={{ input: 'mono' }}
            w={220}
          />
          <Select
            label="List"
            data={[
              { value: 'allow', label: 'Allow' },
              { value: 'deny', label: 'Deny' },
            ]}
            value={allow ? 'allow' : 'deny'}
            onChange={(v) => {
              setAllow(v !== 'deny')
            }}
            allowDeselect={false}
            w={110}
          />
          <TextInput
            label="Note"
            value={note}
            onChange={(e) => {
              setNote(e.currentTarget.value)
            }}
            style={{ flex: '1 1 160px' }}
          />
          <div style={{ width: 160 }}>
            <LengthSelect label="For" value={secs} onChange={setSecs} />
          </div>
          <Button type="submit" loading={save.isPending} leftSection={<IconPlus size={16} />}>
            Add
          </Button>
        </Group>
      </form>
      <Table.ScrollContainer minWidth={520}>
        <Table verticalSpacing={6} fz={13} highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Address or prefix</Table.Th>
              <Table.Th>List</Table.Th>
              <Table.Th>Note</Table.Th>
              <Table.Th>Ends</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {(entries.data ?? []).map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td className="mono">{e.net}</Table.Td>
                <Table.Td>
                  <Badge color={e.allow ? 'green' : 'red'}>{e.allow ? 'Allow' : 'Deny'}</Badge>
                </Table.Td>
                <Table.Td>{e.note}</Table.Td>
                <Table.Td c="var(--ink-dim)">
                  {e.until === null ? 'never' : remaining(e.until, now)}
                </Table.Td>
                <Table.Td ta="right">
                  <ActionIcon
                    color="red"
                    onClick={() => {
                      remove.mutate({ id: e.id })
                    }}
                    aria-label={`Remove ${e.net}`}
                  >
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
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
