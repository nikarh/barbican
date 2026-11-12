import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Menu,
  Modal,
  MultiSelect,
  NumberInput,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
} from '@mantine/core'
import { IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { useState } from 'react'

import { useAction, useFeeds, useMeta, useRules, useRulesDefaults } from '../api/hooks'
import type { BanLength, Kind, Rule } from '../api/generated/model'
import { ActionCard } from '../components/ActionCard'
import { LengthInput } from '../components/ui'
import { formatLength, KIND_LABELS } from '../lib/format'

const NEW_RULE: Rule = {
  id: 0,
  name: '',
  description: '',
  enabled: true,
  kind: 'http',
  sources: [],
  conditions: {
    path: null,
    method: null,
    status: [],
    routed: null,
    userAgent: null,
    user: null,
    what: null,
    listed: [],
  },
  threshold: 1,
  windowSecs: 3_600,
  action: 'ban',
  ban: { type: 'default' },
  prefixV4: 32,
  prefixV6: 64,
}

function lengthLabel(ban: BanLength): string {
  switch (ban.type) {
    case 'default':
      return 'default length'
    case 'forever':
      return 'until lifted'
    case 'secs':
      return formatLength(ban.secs)
  }
}

function summary(r: Rule): string {
  const when =
    r.threshold <= 1 ? 'at once' : `${String(r.threshold)} times in ${formatLength(r.windowSecs)}`
  if (r.action === 'record') return `Records, ${when === 'at once' ? 'every match' : when}`
  const scope =
    r.prefixV4 < 32 || r.prefixV6 < 128 ? ` (/${String(r.prefixV4)}, /${String(r.prefixV6)})` : ''
  return `Bans ${when}, ${lengthLabel(r.ban)}${scope}`
}

/** An optional text field: empty is "not set". */
function optional(value: string): string | null {
  return value.trim() === '' ? null : value
}

function Editor({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const [r, setR] = useState<Rule>(rule)
  const meta = useMeta()
  const feeds = useFeeds()
  const save = useAction('rule.save', 'Rule saved')
  const c = r.conditions
  const set = (patch: Partial<Rule>) => {
    setR((x) => ({ ...x, ...patch }))
  }
  const cond = (patch: Partial<Rule['conditions']>) => {
    setR((x) => ({ ...x, conditions: { ...x.conditions, ...patch } }))
  }
  const http = r.kind === 'http'
  const login = r.kind === 'auth_failure' || r.kind === 'auth_success' || r.kind === 'invalid_user'
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        const rule: Rule = http
          ? r
          : {
              ...r,
              conditions: {
                ...c,
                path: null,
                method: null,
                status: [],
                routed: null,
                userAgent: null,
              },
            }
        save.mutate(rule, { onSuccess: onClose })
      }}
    >
      <Stack gap="sm">
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          <TextInput
            label="Name"
            value={r.name}
            onChange={(e) => {
              set({ name: e.currentTarget.value })
            }}
            required
          />
          <Select
            label="Looks at"
            data={Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label }))}
            value={r.kind}
            onChange={(v) => {
              if (v !== null) set({ kind: v as Kind })
            }}
            allowDeselect={false}
          />
        </SimpleGrid>
        <Textarea
          label="Description"
          autosize
          minRows={1}
          value={r.description}
          onChange={(e) => {
            set({ description: e.currentTarget.value })
          }}
        />
        <MultiSelect
          label="Sources"
          description="Empty: every source"
          data={meta.data?.sources ?? []}
          value={r.sources}
          onChange={(v) => {
            set({ sources: v })
          }}
        />
        <Text fz={13} fw={650} mt={4}>
          Matches when
        </Text>
        <Text fz={12} c="var(--ink-dim)" mt={-8}>
          Patterns are regular expressions (anywhere in the text unless anchored); one starting with
          ! matches what the rest doesn’t.
        </Text>
        {http && (
          <>
            <TextInput
              label="Path"
              value={c.path ?? ''}
              onChange={(e) => {
                cond({ path: optional(e.currentTarget.value) })
              }}
              classNames={{ input: 'mono' }}
            />
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <TextInput
                label="Method"
                value={c.method ?? ''}
                onChange={(e) => {
                  cond({ method: optional(e.currentTarget.value) })
                }}
                classNames={{ input: 'mono' }}
              />
              <TextInput
                label="Status"
                placeholder="401, 404"
                value={c.status.join(', ')}
                onChange={(e) => {
                  cond({
                    status: e.currentTarget.value
                      .split(/[\s,]+/)
                      .map(Number)
                      .filter((n) => Number.isInteger(n) && n > 0),
                  })
                }}
              />
              <Select
                label="Known host"
                data={[
                  { value: 'any', label: 'Either' },
                  { value: 'yes', label: 'Routed' },
                  { value: 'no', label: 'No route' },
                ]}
                value={c.routed === null ? 'any' : c.routed ? 'yes' : 'no'}
                onChange={(v) => {
                  cond({ routed: v === 'yes' ? true : v === 'no' ? false : null })
                }}
                allowDeselect={false}
              />
            </SimpleGrid>
            <TextInput
              label="User agent"
              value={c.userAgent ?? ''}
              onChange={(e) => {
                cond({ userAgent: optional(e.currentTarget.value) })
              }}
              classNames={{ input: 'mono' }}
            />
          </>
        )}
        {login && (
          <TextInput
            label="User"
            value={c.user ?? ''}
            onChange={(e) => {
              cond({ user: optional(e.currentTarget.value) })
            }}
            classNames={{ input: 'mono' }}
          />
        )}
        <TextInput
          label="What happened"
          description="The event as shown elsewhere, e.g. GET example.com/x → 404"
          value={c.what ?? ''}
          onChange={(e) => {
            cond({ what: optional(e.currentTarget.value) })
          }}
          classNames={{ input: 'mono' }}
        />
        <MultiSelect
          label="Listed in"
          description="Only addresses in one of these blocklists"
          data={(feeds.data ?? []).map((f) => f.def.name)}
          value={c.listed}
          onChange={(v) => {
            cond({ listed: v })
          }}
        />
        <Text fz={13} fw={650} mt={4}>
          Then
        </Text>
        <Group align="flex-end" wrap="wrap">
          <NumberInput
            label="Times"
            min={1}
            value={r.threshold}
            onChange={(v) => {
              set({ threshold: Math.max(1, Number(v) || 1) })
            }}
            w={{ base: '100%', sm: 90 }}
          />
          <LengthInput
            label="Within"
            value={r.windowSecs}
            onChange={(windowSecs) => {
              set({ windowSecs })
            }}
          />
          <SegmentedControl
            data={[
              { value: 'ban', label: 'Ban' },
              { value: 'record', label: 'Only record' },
            ]}
            value={r.action}
            fullWidth
            w={{ base: '100%', sm: 'auto' }}
            onChange={(v) => {
              set({ action: v })
            }}
          />
        </Group>
        {r.action === 'ban' && (
          <Group align="flex-end" wrap="wrap">
            <Select
              label="For"
              data={[
                { value: 'default', label: 'The default length' },
                { value: 'secs', label: 'A length of its own' },
                { value: 'forever', label: 'Until lifted' },
              ]}
              value={r.ban.type}
              onChange={(v) => {
                set({
                  ban:
                    v === 'secs'
                      ? { type: 'secs', secs: r.ban.type === 'secs' ? r.ban.secs : 30 * 86_400 }
                      : { type: v === 'forever' ? 'forever' : 'default' },
                })
              }}
              allowDeselect={false}
              w={{ base: '100%', sm: 200 }}
            />
            {r.ban.type === 'secs' && (
              <LengthInput
                label="Length"
                value={r.ban.secs}
                onChange={(secs) => {
                  set({ ban: { type: 'secs', secs } })
                }}
              />
            )}
            <NumberInput
              label="IPv4 prefix"
              min={8}
              max={32}
              value={r.prefixV4}
              onChange={(v) => {
                set({ prefixV4: Number(v) || 32 })
              }}
              w={{ base: '100%', sm: 110 }}
            />
            <NumberInput
              label="IPv6 prefix"
              min={16}
              max={128}
              value={r.prefixV6}
              onChange={(v) => {
                set({ prefixV6: Number(v) || 64 })
              }}
              w={{ base: '100%', sm: 110 }}
            />
          </Group>
        )}
        <Text fz={12} c="var(--ink-dim)">
          Lengths are the policy’s for countries with a length of their own, and grow for repeat
          offenders (Settings).
        </Text>
        <Group justify="flex-end" mt="sm">
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

export function RulesScreen() {
  const rules = useRules()
  const defaults = useRulesDefaults()
  const [editing, setEditing] = useState<Rule | null>(null)
  const save = useAction('rule.save')
  const remove = useAction('rule.delete', 'Rule deleted')
  const order = useAction('rules.order')
  if (rules.error) return <Alert color="red">{rules.error.message}</Alert>
  const list = rules.data ?? []
  const move = (index: number, by: number) => {
    const ids = list.map((r) => r.id)
    const [id] = ids.splice(index, 1)
    if (id === undefined) return
    ids.splice(index + by, 0, id)
    order.mutate({ ids })
  }
  const missingDefaults = (defaults.data ?? []).filter((d) => !list.some((r) => r.name === d.name))
  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <Text c="var(--ink-dim)" fz={13} maw={640}>
          Every line of every source is matched against these, in this order. An event is recorded
          under the first rule it matches; every banning rule it matches counts it. Addresses on the
          allow list, and ones someone logged in from, are never banned.
        </Text>
        <Group gap="xs">
          {missingDefaults.length > 0 && (
            <Menu position="bottom-end">
              <Menu.Target>
                <Button variant="default">Add a default</Button>
              </Menu.Target>
              <Menu.Dropdown>
                {missingDefaults.map((d) => (
                  <Menu.Item
                    key={d.name}
                    onClick={() => {
                      save.mutate(d)
                    }}
                  >
                    {d.name}
                  </Menu.Item>
                ))}
              </Menu.Dropdown>
            </Menu>
          )}
          <Button
            leftSection={<IconPlus size={16} />}
            onClick={() => {
              setEditing(NEW_RULE)
            }}
          >
            New rule
          </Button>
        </Group>
      </Group>
      {list.map((r, i) => (
        <ActionCard
          key={r.id}
          count={4}
          actions={
            <>
              <ActionIcon
                disabled={i === 0}
                onClick={() => {
                  move(i, -1)
                }}
                aria-label="Move up"
              >
                <IconArrowUp size={16} />
              </ActionIcon>
              <ActionIcon
                disabled={i === list.length - 1}
                onClick={() => {
                  move(i, 1)
                }}
                aria-label="Move down"
              >
                <IconArrowDown size={16} />
              </ActionIcon>
              <ActionIcon
                onClick={() => {
                  setEditing(r)
                }}
                aria-label="Edit"
              >
                <IconPencil size={16} />
              </ActionIcon>
              <ActionIcon
                color="red"
                onClick={() => {
                  if (window.confirm(`Delete the rule “${r.name}”?`)) remove.mutate({ id: r.id })
                }}
                aria-label="Delete"
              >
                <IconTrash size={16} />
              </ActionIcon>
            </>
          }
        >
          <Group gap="sm" wrap="nowrap" align="flex-start" mih={28} pt={4}>
            <Switch
              checked={r.enabled}
              onChange={(e) => {
                save.mutate({ ...r, enabled: e.currentTarget.checked })
              }}
              aria-label={r.enabled ? `Turn ${r.name} off` : `Turn ${r.name} on`}
            />
            <Group gap={8} style={{ rowGap: 4 }}>
              <Text fw={620} fz={14} c={r.enabled ? 'var(--ink)' : 'var(--ink-faint)'}>
                {r.name}
              </Text>
              <Badge color="gray">{KIND_LABELS[r.kind]}</Badge>
              {r.sources.map((s) => (
                <Badge key={s} color="gray" variant="outline">
                  {s}
                </Badge>
              ))}
            </Group>
          </Group>
          <Text fz={13} c="var(--ink-dim)" mt={4}>
            {summary(r)}
          </Text>
          {r.description !== '' && (
            <Text fz={12} c="var(--ink-faint)" lineClamp={2}>
              {r.description}
            </Text>
          )}
        </ActionCard>
      ))}
      <Modal
        opened={editing !== null}
        onClose={() => {
          setEditing(null)
        }}
        title={editing?.id === 0 ? 'New rule' : 'Edit rule'}
        size="lg"
      >
        {editing !== null && (
          <Editor
            key={editing.id}
            rule={editing}
            onClose={() => {
              setEditing(null)
            }}
          />
        )}
      </Modal>
    </Stack>
  )
}
