import {
  CellStyleModule,
  InfiniteRowModelModule,
  ModuleRegistry,
  RowStyleModule,
  TooltipModule,
  themeQuartz,
  type ColDef,
  type GridApi,
  type GridReadyEvent,
  type IDatasource,
  type RowClickedEvent,
} from 'ag-grid-community'
import { AgGridReact } from 'ag-grid-react'
import { useCallback, useEffect, useMemo, useRef } from 'react'

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

/** A grid that loads its rows page by page as it scrolls (ag-grid's infinite row model). `fetch` gets an offset
 * and a limit; whenever `query` changes (filters), the grid starts over. It takes the height its parent (a `.fill`
 * screen) has left, and no less than a few rows. */
export function InfiniteGrid<T>({
  columns,
  fetch,
  query,
  onRowClick,
  pageSize = 100,
}: {
  columns: ColDef<T>[]
  fetch: (offset: number, limit: number) => Promise<PageResult<T>>
  query: string
  onRowClick?: (row: T) => void
  pageSize?: number
}) {
  const api = useRef<GridApi<T> | null>(null)
  const fetchRef = useRef(fetch)
  useEffect(() => {
    fetchRef.current = fetch
  }, [fetch])

  const datasource = useMemo<IDatasource>(
    () => ({
      getRows: (params) => {
        const limit = params.endRow - params.startRow
        fetchRef.current(params.startRow, limit).then(
          (page) => {
            const last = params.startRow + page.rows.length >= page.total ? page.total : -1
            params.successCallback(page.rows, last)
          },
          () => {
            params.failCallback()
          },
        )
      },
    }),
    [],
  )

  useEffect(() => {
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

  return (
    <div className={classes.grid}>
      <AgGridReact<T>
        theme={gridTheme}
        columnDefs={columns}
        defaultColDef={{ sortable: false, resizable: true, suppressMovable: true }}
        rowModelType="infinite"
        cacheBlockSize={pageSize}
        maxBlocksInCache={20}
        infiniteInitialRowCount={1}
        onGridReady={onReady}
        onRowClicked={onClick}
        {...(onRowClick ? { rowStyle: { cursor: 'pointer' } } : {})}
        suppressCellFocus
        overlayNoRowsTemplate="<span style='color: var(--ink-faint)'>Nothing here</span>"
      />
    </div>
  )
}
