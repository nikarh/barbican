import { Badge, Button, Group, Modal, Select, Stack, Text, TextInput, Tooltip } from '@mantine/core'
import { useState, type ReactNode } from 'react'

import { useAction } from '../api/hooks'
import { countryName, flag, formatLength, parseLength } from '../lib/format'

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
}: {
  value: number | null
  onChange: (secs: number | null) => void
  label: string
}) {
  return (
    <Select
      label={label}
      data={LENGTHS}
      value={value === null ? 'forever' : String(value)}
      onChange={(v) => {
        onChange(v === null || v === 'forever' ? null : Number(v))
      }}
      allowDeselect={false}
    />
  )
}

/** A length typed as text (`90d`, `1h 30m`): shows what it read, and refuses what it can't. */
export function LengthInput({
  label,
  description,
  value,
  onChange,
}: {
  label: string
  description?: string
  value: number
  onChange: (secs: number) => void
}) {
  const [text, setText] = useState(formatLength(value))
  const parsed = parseLength(text)
  return (
    <TextInput
      label={label}
      description={description}
      value={text}
      error={parsed === null ? 'e.g. 90d, 12h, 1y' : undefined}
      onChange={(e) => {
        const next = e.currentTarget.value
        setText(next)
        const secs = parseLength(next)
        if (secs !== null) onChange(secs)
      }}
      onBlur={() => {
        if (parsed !== null) setText(formatLength(parsed))
      }}
      w={140}
    />
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
