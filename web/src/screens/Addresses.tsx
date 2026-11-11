import { Group, SegmentedControl, Select, Stack, TextInput } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { IconSearch } from '@tabler/icons-react'
import { useCallback, useMemo, useState } from 'react'

import type { IpRow } from '../api/generated/model'
import type { IpFilter, IpSort } from '../api/generated/rpc'
import { rpc } from '../api/rpc'
import { InfiniteGrid } from '../components/Grid'
import { Kept } from '../components/Kept'
import { Country, StatusBadge } from '../components/ui'
import { ago, count, remaining, WIDEST } from '../lib/format'
import { columnsFor, fit, useTier, type Column } from '../lib/columns'
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
  const tier = useTier()
  // On a phone, the search takes a line and the rest share the next one, so that the grid gets the height.
  const phone = tier === 'phone'

  const columns = useMemo(() => {
    const all: Column<IpRow>[] = [
      {
        headerName: 'Address',
        field: 'ip',
        flex: 1.4,
        minWidth: 140,
        cellClass: 'mono',
        pin: true,
        phone: { flex: null, width: fit('Address', WIDEST.address, { mono: true, tier: 'phone' }) },
      },
      {
        headerName: 'Country',
        field: 'country',
        fits: WIDEST.country,
        cellRenderer: (p: { value: string | null }) => <Country code={p.value} />,
      },
      {
        headerName: 'Network',
        field: 'asName',
        flex: 1.4,
        minWidth: 140,
        tooltip: (p) => p.data?.asName ?? undefined,
        phone: { minWidth: 150 },
      },
      {
        headerName: 'Hits',
        field: 'hits',
        fits: WIDEST.count,
        type: 'rightAligned',
        valueFormatter: (p) => count(Number(p.value ?? 0)),
      },
      {
        headerName: 'Last seen',
        field: 'lastSeen',
        fits: WIDEST.ago,
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
      },
      {
        headerName: 'First seen',
        field: 'firstSeen',
        fits: WIDEST.ago,
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
      },
      {
        headerName: 'State',
        width: 200,
        phone: { width: 150 },
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
    return columnsFor(all, tier)
  }, [tier])

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
    <Stack gap={phone ? 8 : 'sm'} className="fill">
      <Group gap={phone ? 8 : 'sm'} wrap="wrap">
        <TextInput
          placeholder="Address, prefix, country code, AS1234 or network"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value)
          }}
          style={{ flex: phone ? '1 1 100%' : '1 1 260px' }}
        />
        {/* On a phone the choices keep their full labels (narrower padding), and the sort takes what is left. */}
        <SegmentedControl
          {...(phone
            ? { style: { flex: '0 0 auto' }, styles: { label: { paddingInline: 9 } } }
            : {})}
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
          {...(phone ? { style: { flex: '1 1 0', minWidth: 0 } } : { w: 150 })}
          aria-label="Sort"
        />
      </Group>
      <InfiniteGrid<IpRow>
        columns={columns}
        fetch={fetch}
        query={`${debounced}|${filter}|${sort}`}
        empty={
          debounced.trim() === '' && filter === 'all'
            ? {
                title: 'No addresses yet',
                hint: 'Every address the sources see doing something shows up here.',
              }
            : {
                title: 'No addresses',
                hint:
                  debounced.trim() === ''
                    ? `None is ${filter} now.`
                    : 'None match the search. It takes an address, a prefix, a country code, AS1234 or a network’s name.',
              }
        }
        onRowClick={(row) => {
          navigate('addresses', { ip: row.ip })
        }}
      />
    </Stack>
  )
}

/** The list, or an address's page. The list stays mounted under an address's page, so going back shows it as it
 * was. */
export function AddressesScreen({ ip, tab }: { ip: string | null; tab: string | null }) {
  return (
    <>
      <Kept shown={ip === null}>
        <List />
      </Kept>
      {ip !== null && <IpScreen ip={ip} tab={tab} />}
    </>
  )
}
