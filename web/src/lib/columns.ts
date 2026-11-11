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

/** A cell's padding on both sides (ag-grid's quartz theme: three times its spacing of 7 px), and the header's sort
 * arrow. */
const CELL_PADDING = 2 * 3 * 7
const SORT_ICON = 22

let context: CanvasRenderingContext2D | null | undefined

function measure(text: string, font: string): number {
  context ??= document.createElement('canvas').getContext('2d')
  if (!context) return text.length * 8
  context.font = font
  return context.measureText(text).width
}

/** The width a column needs to show its widest value (any of `samples`, in the grid's font) and its header in full.
 * For columns of a known shape (times, durations), whatever the locale and the font. */
export function fit(header: string, samples: string[], { sortable = false } = {}): number {
  const family = getComputedStyle(document.body).fontFamily
  const cell = Math.max(0, ...samples.map((s) => measure(s, `13.5px ${family}`)))
  const head = measure(header, `650 12px ${family}`) + (sortable ? SORT_ICON : 0)
  // A little to spare: the web font may not be in yet, and the fallback measured instead is narrower or wider.
  return Math.ceil(Math.max(cell, head) * 1.08 + CELL_PADDING)
}
