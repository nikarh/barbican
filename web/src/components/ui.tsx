import {
  Autocomplete,
  Badge,
  Button,
  Group,
  Modal,
  Select,
  Stack,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { useState, type ReactNode } from 'react'

import { useAction } from '../api/hooks'
import { countryName, flag, lengthInWords, parseLength } from '../lib/format'

export function Country({ code, name = false }: { code: string | null; name?: boolean }) {
  return (
    <Tooltip label={countryName(code)} disabled={name} openDelay={300}>
      <span>
        <span aria-hidden="true">{flag(code)}</span> {name ? countryName(code) : (code ?? '—')}
      </span>
    </Tooltip>
  )
}

export function StatusBadge({ banned, trusted }: { banned: boolean; trusted: boolean }) {
  if (banned)
    return (
      <Badge color="brass" variant="filled">
        Banned
      </Badge>
    )
  if (trusted) return <Badge color="green">Trusted</Badge>
  return null
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
}) {
  return (
    <div className="panel" style={{ padding: '12px 14px' }}>
      <div className="panel-title">{label}</div>
      <Text fz={26} fw={620} className="num" lh={1.25} mt={2}>
        {value}
      </Text>
      {hint !== undefined && (
        <Text fz={12} c="var(--ink-dim)">
          {hint}
        </Text>
      )}
    </div>
  )
}

export function Panel({
  title,
  right,
  children,
}: {
  title: string
  right?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="panel" style={{ padding: 14 }}>
      <Group justify="space-between" mb={10} wrap="nowrap">
        <div className="panel-title">{title}</div>
        {right}
      </Group>
      {children}
    </section>
  )
}

/** Lengths offered for bans and entries; `null` is "until lifted". */
const LENGTHS: { value: string; label: string }[] = [
  { value: '3600', label: '1 hour' },
  { value: '86400', label: '1 day' },
  { value: '604800', label: '1 week' },
  { value: '2592000', label: '30 days' },
  { value: '7776000', label: '90 days' },
  { value: '31536000', label: '1 year' },
  { value: 'forever', label: 'Until lifted' },
]

export function LengthSelect({
  value,
  onChange,
  label,
  hideLabel = false,
}: {
  value: number | null
  onChange: (secs: number | null) => void
  label: string
  /** In a row of inputs without labels: the label is for screen readers only. */
  hideLabel?: boolean
}) {
  return (
    <Select
      label={hideLabel ? undefined : label}
      aria-label={label}
      data={LENGTHS}
      value={value === null ? 'forever' : String(value)}
      onChange={(v) => {
        onChange(v === null || v === 'forever' ? null : Number(v))
      }}
      allowDeselect={false}
    />
  )
}

/** Lengths a length input offers; any other can be typed. */
const PRESETS = [3_600, 6 * 3_600, 86_400, 7 * 86_400, 30 * 86_400, 90 * 86_400, 365 * 86_400].map(
  lengthInWords,
)

/** A length, typed ("90d", "12h", "2 weeks") or picked from a few, and shown in words ("3 months") once typed. A
 * length it can't read is refused (and marked). */
export function LengthInput({
  label,
  description,
  value,
  onChange,
  w = 160,
  'aria-label': ariaLabel,
}: {
  label?: string
  description?: string
  value: number
  onChange: (secs: number) => void
  w?: number | string
  'aria-label'?: string
}) {
  const [text, setText] = useState(lengthInWords(value))
  // A new value from outside (reverted, say) replaces what is shown, unless it is what was typed.
  const [shown, setShown] = useState(value)
  if (value !== shown) {
    setShown(value)
    if (parseLength(text) !== value) setText(lengthInWords(value))
  }
  const parsed = parseLength(text)
  // In a list (no label), a mark only: the message would push the row out of line.
  const hint = 'e.g. 90d, 12h, 1y'
  return (
    <Autocomplete
      label={label}
      description={description}
      aria-label={ariaLabel ?? label}
      value={text}
      data={PRESETS}
      // What was typed narrows the choice, unless it is the current length (then all are offered).
      filter={({ options, search }) => {
        const typed = search.trim().toLowerCase()
        if (typed === '' || parseLength(typed) === value) return options
        return options.filter(
          (o) =>
            'value' in o &&
            (o.value.startsWith(typed) || parseLength(o.value) === parseLength(typed)),
        )
      }}
      error={parsed === null ? (label === undefined ? true : hint) : undefined}
      title={parsed === null ? hint : undefined}
      onChange={(next) => {
        setText(next)
        const secs = parseLength(next)
        if (secs !== null) {
          setShown(secs)
          onChange(secs)
        }
      }}
      onBlur={() => {
        if (parsed !== null) setText(lengthInWords(parsed))
      }}
      w={w}
    />
  )
}

/** A country as a list shows it: its flag, its name, and its code. */
export function CountryLabel({ code, sub }: { code: string; sub?: ReactNode }) {
  return (
    <div className="place">
      <span className="place-flag" aria-hidden="true">
        {flag(code)}
      </span>
      <div className="place-text">
        <div className="place-name">
          <span className="place-title">{countryName(code)}</span>
          <span className="place-code mono">{code}</span>
        </div>
        {sub !== undefined && <div className="place-sub">{sub}</div>}
      </div>
    </div>
  )
}

/** Bans an address or a prefix by hand. */
export function BanDialog({
  opened,
  onClose,
  initial = '',
}: {
  opened: boolean
  onClose: () => void
  initial?: string
}) {
  return (
    <Modal opened={opened} onClose={onClose} title="Ban by hand">
      {/* Remounted on every opening: it starts from `initial` each time. */}
      {opened && <BanForm initial={initial} onDone={onClose} />}
    </Modal>
  )
}

function BanForm({ initial, onDone }: { initial: string; onDone: () => void }) {
  const [net, setNet] = useState(initial)
  const [secs, setSecs] = useState<number | null>(30 * 86_400)
  const [reason, setReason] = useState('')
  const ban = useAction('ban.create', 'Banned')
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        ban.mutate(
          { net: net.trim(), secs, reason },
          {
            onSuccess: onDone,
          },
        )
      }}
    >
      <Stack>
        <TextInput
          label="Address or prefix"
          placeholder="203.0.113.7 or 203.0.113.0/24"
          value={net}
          onChange={(e) => {
            setNet(e.currentTarget.value)
          }}
          data-autofocus
          required
          classNames={{ input: 'mono' }}
        />
        <LengthSelect label="For" value={secs} onChange={setSecs} />
        <TextInput
          label="Reason"
          placeholder="By hand"
          value={reason}
          onChange={(e) => {
            setReason(e.currentTarget.value)
          }}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" loading={ban.isPending}>
            Ban
          </Button>
        </Group>
      </Stack>
    </form>
  )
}
