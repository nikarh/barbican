import { Group, SegmentedControl, Select, Stack, TextInput } from '@mantine/core'
import { useDebouncedValue, useMediaQuery } from '@mantine/hooks'
import { IconSearch } from '@tabler/icons-react'
import type { ColDef } from 'ag-grid-community'
import { useCallback, useMemo, useState } from 'react'

import type { IpRow } from '../api/generated/model'
import type { IpFilter, IpSort } from '../api/generated/rpc'
import { rpc } from '../api/rpc'
import { InfiniteGrid } from '../components/Grid'
import { Country, StatusBadge } from '../components/ui'
import { ago, count, remaining } from '../lib/format'
import { navigate } from '../lib/router'
import { IpScreen } from './Ip'

const SORTS: { value: IpSort; label: string }[] = [
  { value: 'lastSeen', label: 'Last seen' },
  { value: 'firstSeen', label: 'First seen' },
  { value: 'hits', label: 'Most active' },
  { value: 'country', label: 'Country' },
]

function List() {
  const [query, setQuery] = useState('')
  const [debounced] = useDebouncedValue(query, 300)
  const [filter, setFilter] = useState<IpFilter>('all')
  const [sort, setSort] = useState<IpSort>('lastSeen')
  const wide = useMediaQuery('(min-width: 48em)', true)

  const columns = useMemo<ColDef<IpRow>[]>(() => {
    const all: (ColDef<IpRow> & { phone?: boolean })[] = [
      {
        headerName: 'Address',
        field: 'ip',
        flex: 1.4,
        minWidth: 140,
        cellClass: 'mono',
        phone: true,
      },
      {
        headerName: 'Country',
        field: 'country',
        width: 100,
        cellRenderer: (p: { value: string | null }) => <Country code={p.value} />,
        phone: true,
      },
      { headerName: 'Network', field: 'asName', flex: 1.4, minWidth: 140 },
      {
        headerName: 'Hits',
        field: 'hits',
        width: 90,
        type: 'rightAligned',
        valueFormatter: (p) => count(Number(p.value ?? 0)),
      },
      {
        headerName: 'Last seen',
        field: 'lastSeen',
        width: 110,
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
        phone: true,
      },
      {
        headerName: 'First seen',
        field: 'firstSeen',
        width: 110,
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
      },
      {
        headerName: 'State',
        width: 200,
        cellRenderer: (p: { data?: IpRow }) =>
          p.data ? (
            <Group gap={6} wrap="nowrap" h="100%">
              <StatusBadge banned={p.data.banned} trusted={p.data.trusted} />
              {p.data.banned && (
                <span style={{ color: 'var(--ink-faint)', fontSize: 12 }}>
                  {remaining(p.data.banUntil)}
                </span>
              )}
            </Group>
          ) : null,
      },
    ]
    return all.filter((c) => wide || c.phone === true).map(({ phone: _phone, ...c }) => c)
  }, [wide])

  const fetch = useCallback(
    (offset: number, limit: number) =>
      rpc.call('ips.list', {
        query: debounced,
        filter,
        sort,
        ascending: sort === 'country',
        offset,
        limit,
      }),
    [debounced, filter, sort],
  )

  return (
    <Stack gap="sm">
      <Group gap="sm" wrap="wrap">
        <TextInput
          placeholder="Address, prefix, country code, AS1234 or network"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value)
          }}
          style={{ flex: '1 1 260px' }}
        />
        <SegmentedControl
          value={filter}
          onChange={(v) => {
            setFilter(v)
          }}
          data={[
            { value: 'all', label: 'All' },
            { value: 'banned', label: 'Banned' },
            { value: 'trusted', label: 'Trusted' },
          ]}
        />
        <Select
          data={SORTS}
          value={sort}
          onChange={(v) => {
            if (v !== null) setSort(v)
          }}
          allowDeselect={false}
          w={150}
          aria-label="Sort"
        />
      </Group>
      <InfiniteGrid<IpRow>
        columns={columns}
        fetch={fetch}
        query={`${debounced}|${filter}|${sort}`}
        onRowClick={(row) => {
          navigate('addresses', { ip: row.ip })
        }}
        height="calc(100dvh - var(--header-height) - var(--tabbar-height) - 110px)"
      />
    </Stack>
  )
}

export function AddressesScreen({ ip }: { ip: string | null }) {
  return ip === null ? <List /> : <IpScreen ip={ip} />
}
