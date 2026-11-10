import { ActionIcon, Select, Tooltip, type SelectProps } from '@mantine/core'
import { IconPlus, IconX } from '@tabler/icons-react'
import { useState, type ReactNode } from 'react'

import classes from './EditableList.module.css'

/**
 * A list that is edited in place: a row per item (what it is, a value, a remove button), a row to add one at
 * the bottom, and a line saying what an empty list means. Every add-and-remove list of the settings is one.
 *
 * Rows are three columns: `label` (what the item is), `value` (an input, or what the item amounts to) and the
 * remove button. In a narrow list (a phone) a `wide` value goes under the label instead of beside it.
 */
export function EditableList<T>({
  items,
  itemKey,
  label,
  value,
  onRemove,
  removeLabel,
  headers,
  empty,
  add,
  footer,
  wide = false,
}: {
  items: T[]
  itemKey: (item: T) => string
  label: (item: T) => ReactNode
  value?: (item: T, index: number) => ReactNode
  onRemove: (index: number) => void
  removeLabel: (item: T) => string
  /** The columns' names, over the rows. */
  headers?: [string, string?]
  /** Shown instead of the rows when there are none: what an empty list means. */
  empty: ReactNode
  /** The add row's content: a picker that adds what is picked, or inputs and a button. */
  add?: ReactNode
  /** Under everything: a total, a note. */
  footer?: ReactNode
  wide?: boolean
}) {
  return (
    <div className={classes.list} data-wide={wide || undefined}>
      {headers !== undefined && items.length > 0 && (
        <div className={[classes.row, classes.header].join(' ')} aria-hidden="true">
          <span>{headers[0]}</span>
          {value !== undefined && <span className={classes.value}>{headers[1]}</span>}
        </div>
      )}
      {items.length === 0 && <div className={classes.empty}>{empty}</div>}
      {items.length > 0 && (
        <ul className={classes.rows}>
          {items.map((item, i) => (
            <li key={itemKey(item)} className={classes.row}>
              <div className={classes.label}>{label(item)}</div>
              {value !== undefined && <div className={classes.value}>{value(item, i)}</div>}
              <Tooltip label={removeLabel(item)} openDelay={400}>
                <ActionIcon
                  className={classes.remove}
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    onRemove(i)
                  }}
                  aria-label={removeLabel(item)}
                >
                  <IconX size={16} />
                </ActionIcon>
              </Tooltip>
            </li>
          ))}
        </ul>
      )}
      {add !== undefined && <div className={classes.add}>{add}</div>}
      {footer !== undefined && <div className={classes.footer}>{footer}</div>}
    </div>
  )
}

/** The add row's picker: what is picked is added at once, and the picker is empty again. */
export function AddPicker({
  onAdd,
  ...props
}: Omit<SelectProps, 'value' | 'onChange' | 'searchValue' | 'onSearchChange'> & {
  onAdd: (value: string) => void
}) {
  const [search, setSearch] = useState('')
  return (
    <Select
      leftSection={<IconPlus size={16} />}
      value={null}
      searchValue={search}
      onSearchChange={setSearch}
      onChange={(v) => {
        if (v === null) return
        setSearch('')
        onAdd(v)
      }}
      maxDropdownHeight={320}
      comboboxProps={{ position: 'bottom-start' }}
      {...props}
    />
  )
}
