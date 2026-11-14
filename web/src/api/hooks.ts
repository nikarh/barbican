import { notifications } from '@mantine/notifications'
import {
  keepPreviousData,
  queryOptions,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'

import type { EdgeStatus, Live } from './generated/model'
import { rpc, type Connection, type Params, type Result } from './rpc'

export function useConnection(): Connection {
  return useSyncExternalStore(rpc.subscribeState, rpc.getConnection)
}

/** What a screen shows is asked for again each time it mounts, unless it arrived this recently (it was just
 * preloaded, or another part of the screen asked): the screen shows what it has meanwhile, then the current data. */
const FRESH = 2_000

/** Every query a screen shows, in one place: the screens' hooks use them, and so does preloading (see preload.ts). */
export const queries = {
  meta: queryOptions({
    queryKey: ['meta'],
    queryFn: () => rpc.call('meta.get'),
    staleTime: Infinity,
  }),
  overview: queryOptions({
    queryKey: ['overview'],
    queryFn: () => rpc.call('overview.get'),
    refetchInterval: 15_000,
    staleTime: FRESH,
  }),
  entries: queryOptions({
    queryKey: ['entries'],
    queryFn: () => rpc.call('entries.list'),
    staleTime: FRESH,
  }),
  rules: queryOptions({
    queryKey: ['rules'],
    queryFn: () => rpc.call('rules.list'),
    staleTime: FRESH,
  }),
  rulesDefaults: queryOptions({
    queryKey: ['rulesDefaults'],
    queryFn: () => rpc.call('rules.defaults'),
    staleTime: Infinity,
  }),
  policy: queryOptions({
    queryKey: ['policy'],
    queryFn: () => rpc.call('policy.get'),
    staleTime: FRESH,
  }),
  /** How much blocking these countries and continents takes; it only changes with the geolocation database. */
  coverage: (countries: string[], continents: string[]) =>
    queryOptions({
      queryKey: ['coverage', countries, continents],
      queryFn: () => rpc.call('countries.coverage', { countries, continents }),
      staleTime: 10 * 60_000,
    }),
  geoip: queryOptions({
    queryKey: ['geoip'],
    queryFn: () => rpc.call('geoip.status'),
    refetchInterval: 60_000,
    staleTime: FRESH,
  }),
  feeds: queryOptions({
    queryKey: ['feeds'],
    queryFn: () => rpc.call('feeds.list'),
    refetchInterval: 30_000,
    staleTime: FRESH,
  }),
  feedCatalog: queryOptions({
    queryKey: ['feedCatalog'],
    queryFn: () => rpc.call('feeds.catalog'),
    staleTime: Infinity,
  }),
  /** Kept current by a subscription while shown (see useEdges). */
  edges: queryOptions({
    queryKey: ['edges'],
    queryFn: () => rpc.call('edges.list'),
    staleTime: Infinity,
  }),
}

export function useMeta() {
  return useQuery(queries.meta)
}

export function useOverview() {
  return useQuery(queries.overview)
}

export function useIp(ip: string) {
  return useQuery({ queryKey: ['ip', ip], queryFn: () => rpc.call('ip.get', { ip }) })
}

export function useEntries() {
  return useQuery(queries.entries)
}

export function useRules() {
  return useQuery(queries.rules)
}

export function useRulesDefaults() {
  return useQuery(queries.rulesDefaults)
}

export function usePolicy() {
  return useQuery(queries.policy)
}

/** How much blocking these countries and continents takes. While a new selection is counted, the previous
 * one's counts stay. */
export function useCoverage(countries: string[], continents: string[]) {
  return useQuery({ ...queries.coverage(countries, continents), placeholderData: keepPreviousData })
}

/** `enabled: false` holds the call back: the overview asks once its own data is in. */
export function useGeoStatus(enabled = true) {
  return useQuery({ ...queries.geoip, enabled })
}

export function useFeeds(enabled = true) {
  return useQuery({ ...queries.feeds, enabled })
}

export function useFeedCatalog() {
  return useQuery(queries.feedCatalog)
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
  | 'feeds.apply'
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

/** The latest live events (newest first), at most `max`: those the agent kept, then those that come. */
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
        (recent) => {
          setEvents(recent.slice(-maxRef.current).reverse())
        },
      ),
    [],
  )
  return events
}

/** Every configured edge, connected or not, with what it last reported: kept current by a subscription. */
export function useEdges(enabled = true) {
  const client = useQueryClient()
  useEffect(() => {
    if (!enabled) return undefined
    return rpc.subscribe(
      'edges.subscribe',
      (edges: EdgeStatus[]) => {
        client.setQueryData(['edges'], edges)
      },
      () => undefined,
    )
  }, [client, enabled])
  return useQuery({ ...queries.edges, enabled })
}
