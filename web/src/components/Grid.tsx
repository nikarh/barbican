import {
  CellStyleModule,
  InfiniteRowModelModule,
  ModuleRegistry,
  RowStyleModule,
  TooltipModule,
  themeQuartz,
  type ColDef,
  type GridApi,
  type ICellRendererParams,
  type GridReadyEvent,
  type IDatasource,
  type RowClickedEvent,
} from 'ag-grid-community'
import { Button, Skeleton, Text } from '@mantine/core'
import { IconAlertTriangle, IconInbox } from '@tabler/icons-react'
import { AgGridReact } from 'ag-grid-react'
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import classes from './Grid.module.css'

ModuleRegistry.registerModules([
  InfiniteRowModelModule,
  CellStyleModule,
  RowStyleModule,
  TooltipModule,
])

/** The grids follow the page's own colors (CSS variables), in both schemes. The variables pick their value with
 * `light-dark()`, which follows `color-scheme`: the grid inherits the page's instead of setting its own (light). */
const gridTheme = themeQuartz.withParams({
  browserColorScheme: 'inherit',
  backgroundColor: 'var(--surface)',
  foregroundColor: 'var(--ink)',
  headerBackgroundColor: 'var(--surface)',
  headerTextColor: 'var(--ink-faint)',
  headerFontWeight: 650,
  headerFontSize: 12,
  borderColor: 'var(--hairline)',
  rowHoverColor: 'var(--row-hover)',
  accentColor: 'var(--accent)',
  fontFamily: 'inherit',
  fontSize: 13.5,
  rowHeight: 40,
  headerHeight: 38,
  wrapperBorderRadius: 'var(--mantine-radius-md)',
  oddRowBackgroundColor: 'var(--surface)',
  spacing: 7,
})

export interface PageResult<T> {
  rows: T[]
  total: number
}

/** What a grid shows when there are no rows: a title, and a hint (what to change, or why it's empty). */
export interface Empty {
  title: string
  hint?: ReactNode
}

/** How the first page of the current query went. */
type FirstPage = { query: string } & (
  | { state: 'rows' }
  | { state: 'empty' }
  | { state: 'error'; message: string }
)

/** Rows shown before the first page is in: as many as a tall window shows. */
const PLACEHOLDER_ROWS = 30

/** A grid that loads its rows page by page as it scrolls (ag-grid's infinite row model). `fetch` gets an offset
 * and a limit; whenever `query` changes (filters), the grid starts over.
 * Until the first page is in, its rows are placeholders in the real columns, so nothing moves when the rows come;
 * then the rows, what `empty` says, or the error. It takes the height its parent (a `.fill` screen) has left, and
 * no less than a few rows. */
export function InfiniteGrid<T>({
  columns,
  fetch,
  query,
  empty,
  onRowClick,
  pageSize = 100,
}: {
  columns: ColDef<T>[]
  fetch: (offset: number, limit: number) => Promise<PageResult<T>>
  query: string
  empty: Empty
  onRowClick?: (row: T) => void
  pageSize?: number
}) {
  const api = useRef<GridApi<T> | null>(null)
  const fetchRef = useRef(fetch)
  useEffect(() => {
    fetchRef.current = fetch
  }, [fetch])
  // The query the grid's rows are of: an answer to an earlier one says nothing about the first page.
  const queryRef = useRef(query)
  const [first, setFirst] = useState<FirstPage | null>(null)

  const datasource = useMemo<IDatasource>(
    () => ({
      getRows: (params) => {
        const limit = params.endRow - params.startRow
        const asked = queryRef.current
        const report = (page: FirstPage) => {
          if (params.startRow === 0 && asked === queryRef.current) setFirst(page)
        }
        fetchRef.current(params.startRow, limit).then(
          (page) => {
            const last = params.startRow + page.rows.length >= page.total ? page.total : -1
            params.successCallback(page.rows, last)
            report({ query: asked, state: last === 0 ? 'empty' : 'rows' })
          },
          (e: unknown) => {
            params.failCallback()
            report({
              query: asked,
              state: 'error',
              message: e instanceof Error ? e.message : String(e),
            })
          },
        )
      },
    }),
    [],
  )

  useEffect(() => {
    queryRef.current = query
    api.current?.setGridOption('datasource', datasource)
  }, [query, datasource])

  const onReady = useCallback(
    (e: GridReadyEvent<T>) => {
      api.current = e.api
      e.api.setGridOption('datasource', datasource)
    },
    [datasource],
  )

  const onClick = useCallback(
    (e: RowClickedEvent<T>) => {
      if (e.data !== undefined) onRowClick?.(e.data)
    },
    [onRowClick],
  )

  const retry = () => {
    setFirst(null)
    api.current?.setGridOption('datasource', datasource)
  }

  const defaultColDef = useMemo<ColDef<T>>(
    () => ({ sortable: false, resizable: true, suppressMovable: true }),
    [],
  )
  // Until a row has its data, each cell is a placeholder.
  const columnDefs = useMemo(
    () =>
      columns.map((c) => ({
        ...c,
        cellRendererSelector: (p: ICellRendererParams<T>) =>
          p.data === undefined ? { component: Placeholder } : c.cellRendererSelector?.(p),
      })),
    [columns],
  )

  const state = first?.query === query ? first : null
  return (
    <div className={classes.grid}>
      <AgGridReact<T>
        theme={gridTheme}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        rowModelType="infinite"
        cacheBlockSize={pageSize}
        maxBlocksInCache={20}
        infiniteInitialRowCount={PLACEHOLDER_ROWS}
        onGridReady={onReady}
        onRowClicked={onClick}
        {...(onRowClick ? { rowStyle: { cursor: 'pointer' } } : {})}
        suppressCellFocus
        suppressNoRowsOverlay
      />
      {state?.state === 'empty' && (
        <div className={classes.overlay}>
          <div className={classes.message}>
            <IconInbox size={28} stroke={1.5} className={classes.icon} />
            <Text fw={620} fz={15}>
              {empty.title}
            </Text>
            {empty.hint !== undefined && (
              <Text fz={13} c="var(--ink-dim)" maw={360}>
                {empty.hint}
              </Text>
            )}
          </div>
        </div>
      )}
      {state?.state === 'error' && (
        <div className={classes.overlay}>
          <div className={classes.message}>
            <IconAlertTriangle size={28} stroke={1.5} color="var(--status-bad)" />
            <Text fw={620} fz={15}>
              Couldn’t load this
            </Text>
            <Text fz={13} c="var(--ink-dim)" maw={420} style={{ overflowWrap: 'anywhere' }}>
              {state.message}
            </Text>
            <Button variant="default" size="xs" mt={4} onClick={retry}>
              Try again
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

/** A cell of a row still loading: a bar of a width that varies from row to row and column to column, as text
 * does. */
function Placeholder<T>({ node, column, colDef }: ICellRendererParams<T>) {
  const row = node.rowIndex ?? 0
  const id = column?.getColId() ?? ''
  let col = 7
  for (let i = 0; i < id.length; i++) col = (col * 31 + id.charCodeAt(i)) % 997
  return (
    <div className={classes.placeholder} data-end={colDef?.type === 'rightAligned' || undefined}>
      <Skeleton height={9} radius="xl" width={`${String(40 + ((row * 7 + col * 13) % 45))}%`} />
    </div>
  )
}
