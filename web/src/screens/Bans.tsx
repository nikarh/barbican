import { Button, Group, SegmentedControl, Stack, TextInput } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { IconPlus, IconSearch } from '@tabler/icons-react'
import { useCallback, useMemo, useState } from 'react'

import type { Ban } from '../api/generated/model'
import { rpc } from '../api/rpc'
import { InfiniteGrid } from '../components/Grid'
import { BanDialog, Country } from '../components/ui'
import { ago, remaining } from '../lib/format'
import { columnsFor, useTier, type Column } from '../lib/columns'
import { navigate } from '../lib/router'

export function BansScreen() {
  const [query, setQuery] = useState('')
  const [debounced] = useDebouncedValue(query, 300)
  const [active, setActive] = useState(true)
  const [banning, setBanning] = useState(false)
  const tier = useTier()
  // On a phone, the search takes a line and the rest share the next one.
  const phone = tier === 'phone'

  const columns = useMemo(() => {
    const all: Column<Ban>[] = [
      {
        headerName: 'Blocked',
        field: 'net',
        width: 190,
        cellClass: 'mono',
        pin: true,
        phone: { width: 150 },
      },
      {
        headerName: 'Country',
        field: 'country',
        width: 100,
        cellRenderer: (p: { value: string | null }) => <Country code={p.value} />,
        phone: { width: 80 },
      },
      {
        headerName: 'Reason',
        field: 'reason',
        flex: 1.4,
        minWidth: 140,
        tooltip: (p) => p.data?.reason,
        phone: { minWidth: 160 },
      },
      {
        headerName: 'Since',
        field: 'created',
        width: 110,
        valueFormatter: (p) => ago(Number(p.value ?? 0)),
        phone: { width: 96 },
      },
      {
        headerName: 'Ends',
        width: 120,
        valueGetter: (p) =>
          p.data === undefined
            ? ''
            : p.data.lifted !== null
              ? `lifted ${ago(p.data.lifted)}`
              : remaining(p.data.until),
        phone: { width: 110 },
      },
    ]
    return columnsFor(all, tier)
  }, [tier])

  const fetch = useCallback(
    (offset: number, limit: number) =>
      rpc.call('bans.list', {
        active,
        ...(debounced.trim() === '' ? {} : { query: debounced }),
        offset,
        limit,
      }),
    [active, debounced],
  )

  return (
    <Stack gap={phone ? 8 : 'sm'} className="fill">
      <Group gap={phone ? 8 : 'sm'} wrap="wrap">
        <TextInput
          placeholder="Address, prefix, country code or reason"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value)
          }}
          style={{ flex: phone ? '1 1 100%' : '1 1 240px' }}
        />
        <SegmentedControl
          fullWidth={phone}
          style={phone ? { flex: '1 1 0' } : undefined}
          value={active ? 'active' : 'all'}
          onChange={(v) => {
            setActive(v === 'active')
          }}
          data={[
            { value: 'active', label: 'In force' },
            { value: 'all', label: 'All' },
          ]}
        />
        <Button
          leftSection={<IconPlus size={16} />}
          onClick={() => {
            setBanning(true)
          }}
        >
          Ban
        </Button>
      </Group>
      <InfiniteGrid<Ban>
        columns={columns}
        fetch={fetch}
        query={`${String(active)}|${debounced}`}
        empty={
          debounced.trim() === ''
            ? {
                title: active ? 'No bans in force' : 'No bans yet',
                hint: 'Bans start when a rule’s threshold is reached, or by hand with “Ban”.',
              }
            : { title: 'No bans', hint: 'None match the search.' }
        }
        onRowClick={(row) => {
          navigate('addresses', { ip: row.ip ?? row.net.split('/')[0] ?? row.net })
        }}
      />
      <BanDialog
        opened={banning}
        onClose={() => {
          setBanning(false)
        }}
      />
    </Stack>
  )
}
