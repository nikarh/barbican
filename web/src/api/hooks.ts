import { notifications } from '@mantine/notifications'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'

import type { Live } from './generated/model'
import { rpc, type Connection, type Params, type Result } from './rpc'

export function useConnection(): Connection {
  return useSyncExternalStore(rpc.subscribeState, rpc.getConnection)
}

export function useMeta() {
  return useQuery({ queryKey: ['meta'], queryFn: () => rpc.call('meta.get'), staleTime: Infinity })
}

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: () => rpc.call('overview.get'),
    refetchInterval: 15_000,
  })
}

export function useIp(ip: string) {
  return useQuery({ queryKey: ['ip', ip], queryFn: () => rpc.call('ip.get', { ip }) })
}

export function useEntries() {
  return useQuery({ queryKey: ['entries'], queryFn: () => rpc.call('entries.list') })
}

export function useRules() {
  return useQuery({ queryKey: ['rules'], queryFn: () => rpc.call('rules.list') })
}

export function usePolicy() {
  return useQuery({ queryKey: ['policy'], queryFn: () => rpc.call('policy.get') })
}

/** How much blocking these countries and continents takes. While a new selection is counted, the previous
 * one's counts stay. */
export function useCoverage(countries: string[], continents: string[]) {
  return useQuery({
    queryKey: ['coverage', countries, continents],
    queryFn: () => rpc.call('countries.coverage', { countries, continents }),
    placeholderData: keepPreviousData,
    staleTime: 10 * 60_000,
  })
}

export function useGeoStatus() {
  return useQuery({
    queryKey: ['geoip'],
    queryFn: () => rpc.call('geoip.status'),
    refetchInterval: 60_000,
  })
}

export function useFeeds() {
  return useQuery({
    queryKey: ['feeds'],
    queryFn: () => rpc.call('feeds.list'),
    refetchInterval: 30_000,
  })
}

export function useFeedPresets() {
  return useQuery({
    queryKey: ['feedPresets'],
    queryFn: () => rpc.call('feeds.presets'),
    staleTime: Infinity,
  })
}

type Mutating =
  | 'ban.create'
  | 'ban.lift'
  | 'entry.save'
  | 'entry.delete'
  | 'trust.remove'
  | 'rule.save'
  | 'rule.delete'
  | 'rules.order'
  | 'policy.update'
  | 'feed.save'
  | 'feed.delete'
  | 'feed.refresh'

/** A call that changes something: everything shown is refetched after it, and a failure is reported. */
export function useAction<M extends Mutating>(method: M, success?: string) {
  const client = useQueryClient()
  return useMutation<Result<M>, Error, Params<M>>({
    mutationFn: (params) =>
      (rpc.call as (m: M, p: Params<M>) => Promise<Result<M>>)(method, params),
    onSuccess: () => {
      void client.invalidateQueries()
      if (success !== undefined) notifications.show({ message: success, color: 'brass' })
    },
    onError: (e) => {
      notifications.show({ title: 'That didn’t work', message: e.message, color: 'red' })
    },
  })
}

/** The latest live events (newest first), at most `max`. */
export function useLive(max: number): Live[] {
  const [events, setEvents] = useState<Live[]>([])
  const maxRef = useRef(max)
  useEffect(() => {
    maxRef.current = max
  }, [max])
  useEffect(
    () =>
      rpc.subscribe(
        'live.subscribe',
        (event) => {
          setEvents((list) => [event, ...list].slice(0, maxRef.current))
        },
        () => undefined,
      ),
    [],
  )
  return events
}
