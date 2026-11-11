import { Group, Select, Stack, TextInput } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { IconSearch } from '@tabler/icons-react'
import { useCallback, useMemo, useState } from 'react'

import { useMeta, useRules } from '../api/hooks'
import type { EventRow, Kind } from '../api/generated/model'
import { rpc } from '../api/rpc'
import { InfiniteGrid } from '../components/Grid'
import { Country } from '../components/ui'
import { count, dateTime, KIND_LABELS } from '../lib/format'
import { columnsFor, useTier, type Column } from '../lib/columns'
import { navigate } from '../lib/router'

export function EventsScreen() {
  const [query, setQuery] = useState('')
  const [debounced] = useDebouncedValue(query, 300)
  const [kind, setKind] = useState<Kind | null>(null)
  const [rule, setRule] = useState<string | null>(null)
  const [source, setSource] = useState<string | null>(null)
  const rules = useRules()
  const meta = useMeta()
  const tier = useTier()
  // On a phone, the search takes a line and the three filters share the next one (with shorter placeholders).
  const phone = tier === 'phone'
  const filter = phone ? { style: { flex: '1 1 0', minWidth: 0 } } : {}

  const ruleName = useCallback(
    (id: number) =>
      id === 0 ? '—' : (rules.data?.find((r) => r.id === id)?.name ?? `#${String(id)}`),
    [rules.data],
  )

  const columns = useMemo(() => {
    const all: Column<EventRow>[] = [
      {
        headerName: 'Hour',
        field: 'hour',
        width: 150,
        valueFormatter: (p) => dateTime(Number(p.value ?? 0)),
        phone: { width: 150 },
      },
      {
        headerName: 'Address',
        field: 'ip',
        width: 140,
        cellClass: 'mono',
        pin: true,
        phone: { width: 150 },
      },
      {
        headerName: '',
        field: 'country',
        width: 70,
        cellRenderer: (p: { value: string | null }) => <Country code={p.value} />,
        phone: { width: 80 },
      },
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
        phone: { minWidth: 260 },
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
        width: 80,
        type: 'rightAligned',
        valueFormatter: (p) => count(Number(p.value ?? 0)),
        phone: { width: 72 },
      },
    ]
    return columnsFor(all, tier)
  }, [tier, ruleName])

  const fetch = useCallback(
    (offset: number, limit: number) =>
      rpc.call('events.list', {
        ...(debounced.trim() === '' ? {} : { query: debounced }),
        ...(kind === null ? {} : { kind }),
        ...(rule === null ? {} : { rule: Number(rule) }),
        ...(source === null ? {} : { source }),
        offset,
        limit,
      }),
    [debounced, kind, rule, source],
  )

  return (
    <Stack gap={phone ? 8 : 'sm'} className="fill">
      <Group gap={phone ? 8 : 'sm'} wrap="wrap">
        <TextInput
          placeholder="Path, user name, probe…"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value)
          }}
          style={{ flex: phone ? '1 1 100%' : '1 1 220px' }}
        />
        <Select
          placeholder={phone ? 'Kind' : 'Any kind'}
          data={Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label }))}
          value={kind}
          onChange={(v) => {
            setKind(v as Kind | null)
          }}
          clearable
          {...(phone ? filter : { w: 150 })}
        />
        <Select
          placeholder={phone ? 'Rule' : 'Any rule'}
          data={(rules.data ?? []).map((r) => ({ value: String(r.id), label: r.name }))}
          value={rule}
          onChange={setRule}
          clearable
          {...(phone ? filter : { w: 180 })}
        />
        <Select
          placeholder={phone ? 'Source' : 'Any source'}
          data={meta.data?.sources ?? []}
          value={source}
          onChange={setSource}
          clearable
          {...(phone ? filter : { w: 140 })}
        />
      </Group>
      <InfiniteGrid<EventRow>
        columns={columns}
        fetch={fetch}
        query={`${debounced}|${kind ?? ''}|${rule ?? ''}|${source ?? ''}`}
        empty={
          debounced.trim() === '' && kind === null && rule === null && source === null
            ? {
                title: 'No events yet',
                hint: 'What the sources’ logs say addresses did shows up here as it is read.',
              }
            : { title: 'No events', hint: 'None match the search and filters.' }
        }
        onRowClick={(row) => {
          navigate('addresses', { ip: row.ip })
        }}
      />
    </Stack>
  )
}
