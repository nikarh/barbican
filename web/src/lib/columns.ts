import { useMediaQuery } from '@mantine/hooks'
import type { ColDef } from 'ag-grid-community'

/** How much room there is: a phone, a tablet or a narrow window, or a wide window (where every column fits). */
export type Tier = 'phone' | 'tablet' | 'desktop'

/** The tier of the window, known from the first render: a grid first laid out with another tier's columns would
 * show them (and a horizontal scrollbar) for a moment. */
export function useTier(): Tier {
  const options = { getInitialValueInEffect: false }
  const tablet = useMediaQuery('(min-width: 48em)', true, options)
  const desktop = useMediaQuery('(min-width: 70em)', true, options)
  if (desktop) return 'desktop'
  return tablet ? 'tablet' : 'phone'
}

/** A column of a grid, with the smallest tier it is shown on (without `from`: only the widest), and what changes
 * on a phone. Each tier's columns fit its width, so a grid never scrolls sideways. */
export type Column<T> = ColDef<T> & { from?: Tier; phone?: Partial<ColDef<T>> }

const RANK: Record<Tier, number> = { phone: 0, tablet: 1, desktop: 2 }

/** The columns shown on a tier. */
export function columnsFor<T>(columns: Column<T>[], tier: Tier): ColDef<T>[] {
  return columns
    .filter((c) => RANK[c.from ?? 'desktop'] <= RANK[tier])
    .map(({ from: _from, phone, ...c }) => (tier === 'phone' && phone ? { ...c, ...phone } : c))
}
