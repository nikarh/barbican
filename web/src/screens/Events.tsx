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
        width: 140,
        valueFormatter: (p) => dateTime(Number(p.value ?? 0)),
        from: 'tablet',
      },
      {
        headerName: 'Address',
        field: 'ip',
        width: 140,
        cellClass: 'mono',
        from: 'phone',
        phone: { width: 130 },
      },
      {
        headerName: '',
        field: 'country',
        width: 70,
        cellRenderer: (p: { value: string | null }) => <Country code={p.value} />,
      },
      {
        headerName: 'Kind',
        field: 'kind',
        width: 120,
        valueFormatter: (p) => KIND_LABELS[p.value as Kind],
      },
      {
        headerName: 'What',
        field: 'what',
        flex: 2,
        minWidth: 160,
        cellClass: 'mono',
        from: 'phone',
        phone: { minWidth: 110 },
      },
      {
        headerName: 'Rule',
        field: 'rule',
        width: 150,
        valueFormatter: (p) => ruleName(Number(p.value ?? 0)),
        from: 'tablet',
      },
      { headerName: 'Source', field: 'source', width: 100 },
      {
        headerName: 'Times',
        field: 'count',
        width: 80,
        type: 'rightAligned',
        valueFormatter: (p) => count(Number(p.value ?? 0)),
        from: 'phone',
        phone: { width: 70 },
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
    <Stack gap="sm" className="fill">
      <Group gap="sm" wrap="wrap">
        <TextInput
          placeholder="Path, user name, probe…"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value)
          }}
          style={{ flex: '1 1 220px' }}
        />
        <Select
          placeholder="Any kind"
          data={Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label }))}
          value={kind}
          onChange={(v) => {
            setKind(v as Kind | null)
          }}
          clearable
          w={150}
        />
        <Select
          placeholder="Any rule"
          data={(rules.data ?? []).map((r) => ({ value: String(r.id), label: r.name }))}
          value={rule}
          onChange={setRule}
          clearable
          w={180}
        />
        <Select
          placeholder="Any source"
          data={meta.data?.sources ?? []}
          value={source}
          onChange={setSource}
          clearable
          w={140}
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
