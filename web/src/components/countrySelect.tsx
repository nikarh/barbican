import type { ComboboxItem, ComboboxParsedItem } from '@mantine/core'

import { flag } from '../lib/format'

/** The options of a country picker: searchable by name and code, shown with flags. */
export const COUNTRY_SELECT = {
  searchable: true,
  nothingFoundMessage: 'No such country',
  filter: ({ options, search }: { options: ComboboxParsedItem[]; search: string }) => {
    const q = search.trim().toLowerCase()
    if (q === '') return options
    const code = (o: ComboboxItem) => o.value.replace(/^continent:/, '').toLowerCase()
    // An exact code first ("de"), then names that have what was typed.
    const filter = (items: ComboboxItem[]) =>
      items
        .filter((o) => code(o) === q || o.label.toLowerCase().includes(q))
        .sort((a, b) => Number(code(b) === q) - Number(code(a) === q))
    return options.flatMap((o): ComboboxParsedItem[] => {
      if (!('group' in o)) return filter([o])
      const items = filter(o.items)
      return items.length === 0 ? [] : [{ ...o, items }]
    })
  },
  renderOption: ({ option }: { option: ComboboxItem }) =>
    option.value.length === 2 ? (
      <span className="place">
        <span className="place-flag" aria-hidden="true">
          {flag(option.value)}
        </span>
        <span className="place-title">{option.label}</span>
        <span className="place-code mono">{option.value}</span>
      </span>
    ) : (
      option.label
    ),
} as const
