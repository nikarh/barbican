import { Alert, Anchor, Badge, Button, Group, Stack, Table, Text, Title } from '@mantine/core'
import { IconArrowLeft } from '@tabler/icons-react'
import { useMediaQuery } from '@mantine/hooks'
import { useState } from 'react'

import { useAction, useIp, useRules } from '../api/hooks'
import { BanDialog, Country, Panel } from '../components/ui'
import { ago, count, dateTime, KIND_LABELS, remaining } from '../lib/format'
import { href } from '../lib/router'
import { useNow } from '../lib/useNow'

export function IpScreen({ ip }: { ip: string }) {
  const detail = useIp(ip)
  const rules = useRules()
  const now = useNow(30_000)
  const [banning, setBanning] = useState(false)
  const [all, setAll] = useState(false)
  const wide = useMediaQuery('(min-width: 48em)', true)
  const lift = useAction('ban.lift', 'Ban lifted')
  const allow = useAction('entry.save', 'Saved')
  const untrust = useAction('trust.remove', 'No longer trusted')
  const back = (
    <Anchor href={href('addresses')} fz={13}>
      <Group gap={4}>
        <IconArrowLeft size={14} /> Addresses
      </Group>
    </Anchor>
  )
  if (detail.error)
    return (
      <Stack>
        {back}
        <Alert color="red">{detail.error.message}</Alert>
      </Stack>
    )
  const d = detail.data
  if (!d) return back
  const ruleName = (id: number) =>
    id === 0 ? '—' : (rules.data?.find((r) => r.id === id)?.name ?? `#${String(id)}`)
  return (
    <Stack gap="md">
      {back}
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2} className="mono" fz={26}>
            {d.ip}
          </Title>
          <Text c="var(--ink-dim)" fz={14}>
            <Country code={d.country} name />
            {d.asn !== null && (
              <>
                {' · '}AS{d.asn} {d.asName}
              </>
            )}
          </Text>
          <Group gap={6} mt={8}>
            {d.activeBan && (
              <Badge color="brass" variant="filled">
                Banned, {remaining(d.activeBan.until, now)}
              </Badge>
            )}
            {d.trusted && <Badge color="green">Trusted: {d.trusted.user}</Badge>}
            {d.allowed && <Badge color="blue">Allowed</Badge>}
            {d.denied && <Badge color="red">On the deny list</Badge>}
            {d.countryBlocked && <Badge color="orange">Country blocked</Badge>}
            {d.listed.map((l) => (
              <Badge key={l} color="gray">
                Listed: {l}
              </Badge>
            ))}
          </Group>
        </div>
        <Group gap="xs">
          {d.activeBan ? (
            <Button
              variant="default"
              loading={lift.isPending}
              onClick={() => {
                if (d.activeBan) lift.mutate({ id: d.activeBan.id })
              }}
            >
              Lift the ban
            </Button>
          ) : (
            <Button
              onClick={() => {
                setBanning(true)
              }}
            >
              Ban
            </Button>
          )}
          {!d.allowed && (
            <Button
              variant="default"
              loading={allow.isPending}
              onClick={() => {
                allow.mutate({ net: d.ip, allow: true, note: '', secs: null })
              }}
            >
              Allow
            </Button>
          )}
          {d.trusted && (
            <Button
              variant="subtle"
              color="gray"
              onClick={() => {
                untrust.mutate({ ip: d.ip })
              }}
            >
              Stop trusting
            </Button>
          )}
        </Group>
      </Group>

      <Panel
        title="What it did"
        right={
          <Text fz={12} c="var(--ink-faint)">
            {d.firstSeen === null
              ? 'never seen'
              : `${count(d.hits)} hits · first ${dateTime(d.firstSeen)} · last ${ago(d.lastSeen, now)}`}
          </Text>
        }
      >
        {d.activity.length === 0 ? (
          <Text c="var(--ink-faint)" fz={13}>
            Nothing recorded.
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={wide ? 560 : 0}>
            <Table verticalSpacing={5} fz={13} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  {wide && <Table.Th>Kind</Table.Th>}
                  <Table.Th>What</Table.Th>
                  {wide && <Table.Th>Rule</Table.Th>}
                  {wide && <Table.Th>Source</Table.Th>}
                  <Table.Th ta="right">Times</Table.Th>
                  <Table.Th>Last</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {(all ? d.activity : d.activity.slice(0, 40)).map((a) => (
                  <Table.Tr key={`${a.kind}|${a.what}|${a.source}|${String(a.rule)}`}>
                    {wide && <Table.Td c="var(--ink-dim)">{KIND_LABELS[a.kind]}</Table.Td>}
                    <Table.Td className="mono" style={{ wordBreak: 'break-all' }}>
                      {a.what}
                    </Table.Td>
                    {wide && <Table.Td>{ruleName(a.rule)}</Table.Td>}
                    {wide && <Table.Td c="var(--ink-dim)">{a.source}</Table.Td>}
                    <Table.Td ta="right" className="num">
                      {count(a.count)}
                    </Table.Td>
                    <Table.Td c="var(--ink-dim)">{ago(a.last, now)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {!all && d.activity.length > 40 && (
              <Button
                variant="subtle"
                size="xs"
                mt={6}
                onClick={() => {
                  setAll(true)
                }}
              >
                Show all {d.activity.length}
              </Button>
            )}
          </Table.ScrollContainer>
        )}
      </Panel>

      <Panel title="Bans">
        {d.bans.length === 0 ? (
          <Text c="var(--ink-faint)" fz={13}>
            Never banned.
          </Text>
        ) : (
          <Table verticalSpacing={5} fz={13}>
            <Table.Tbody>
              {d.bans.map((b) => (
                <Table.Tr key={b.id}>
                  <Table.Td className="mono">{b.net}</Table.Td>
                  <Table.Td>{b.reason}</Table.Td>
                  <Table.Td c="var(--ink-dim)">{dateTime(b.created)}</Table.Td>
                  <Table.Td c="var(--ink-dim)">
                    {b.lifted !== null ? `lifted (${b.liftedBy ?? ''})` : remaining(b.until, now)}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Panel>
      <BanDialog
        opened={banning}
        onClose={() => {
          setBanning(false)
        }}
        initial={d.ip}
      />
    </Stack>
  )
}
