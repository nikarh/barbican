import { useMediaQuery } from '@mantine/hooks'
import type { ColDef } from 'ag-grid-community'

/** How much room there is: a phone, a tablet or a narrow window, or a wide window (where every column fits). */
export type Tier = 'phone' | 'tablet' | 'desktop'

/** The tier of the window, known from the first render: a grid first laid out with another tier's columns would
 * lay them out again (and move) a moment later. */
export function useTier(): Tier {
  const options = { getInitialValueInEffect: false }
  const tablet = useMediaQuery('(min-width: 48em)', true, options)
  const desktop = useMediaQuery('(min-width: 70em)', true, options)
  if (desktop) return 'desktop'
  return tablet ? 'tablet' : 'phone'
}

/** A column of a grid, what changes on a phone (narrower widths, mostly), and whether it is the one that says which
 * row it is (`pin`). */
export type Column<T> = ColDef<T> & { phone?: Partial<ColDef<T>>; pin?: boolean }

/** The columns of a tier. Every tier has every column: where they don't fit (a phone, a tablet), the grid scrolls
 * sideways, and the column that says which row it is stays on the left. */
export function columnsFor<T>(columns: Column<T>[], tier: Tier): ColDef<T>[] {
  return columns.map(({ phone, pin, ...c }) => ({
    ...c,
    ...(tier === 'phone' ? phone : {}),
    ...(pin === true && tier !== 'desktop' ? { pinned: 'left' as const, lockPinned: true } : {}),
  }))
}
