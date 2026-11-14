// What the UI loads ahead: the open screen's data first, on its own, then every other screen's at once (each answer
// its own message), so that switching to a screen shows its data in the first frame. A screen still asks for its data
// again as it mounts (see `queries`), and shows the current data once that arrives.
//
// The grids (addresses, bans, events) load their rows themselves: their screens are mounted ahead (see App).

import type { QueryClient, QueryExecuteOptions } from '@tanstack/react-query'

import type { Route } from '../lib/router'
import { queries } from './hooks'

type Ask = <T, K extends readonly unknown[]>(
  options: QueryExecuteOptions<T, Error, T, T, K>,
) => Promise<unknown>

/** Asks for a query unless what is cached is fresh; a failure is left to the screen that shows it. */
function asker(client: QueryClient): Ask {
  return (options) => client.query(options).catch(() => undefined)
}

/** The open screen's own data, what it shows first. Settings asks for the open tab's alone. */
function own(route: Route, ask: Ask): Promise<unknown>[] {
  switch (route.screen) {
    case 'overview':
      // The panels after the overview ask for theirs once it's in.
      return [ask(queries.overview)]
    case 'events':
      return [ask(queries.rules)]
    case 'rules':
      return [ask(queries.rules), ask(queries.rulesDefaults), ask(queries.feeds)]
    case 'settings':
      switch (route.params.get('tab')) {
        case 'lists':
          return [ask(queries.entries)]
        case 'feeds':
          return [ask(queries.feeds), ask(queries.feedCatalog)]
        case 'geoip':
          return [ask(queries.geoip)]
        case 'edges':
          return [ask(queries.edges)]
        case 'about':
          return []
        default:
          return [ask(queries.policy)]
      }
    case 'addresses':
    case 'bans':
      return []
  }
}

/** Asks for the open screen's data; resolves once it has arrived (or failed). */
export async function preloadOwn(client: QueryClient, route: Route): Promise<void> {
  const ask = asker(client)
  await Promise.all([ask(queries.meta), ...own(route, ask)])
}

/** Asks for every screen's data at once, except what is fresh already. */
export async function preloadAll(client: QueryClient): Promise<void> {
  const ask = asker(client)
  const edgeApi = client.getQueryData(queries.meta.queryKey)?.edgeApi === true
  await Promise.all([
    ask(queries.overview),
    ask(queries.rules),
    ask(queries.rulesDefaults),
    ask(queries.policy),
    ask(queries.entries),
    ask(queries.geoip),
    ask(queries.feeds),
    ask(queries.feedCatalog),
    edgeApi ? ask(queries.edges) : undefined,
  ])
  // The policy's blocked countries are only known now.
  const policy = client.getQueryData(queries.policy.queryKey)
  if (policy !== undefined) {
    await ask(queries.coverage(policy.blockedCountries, policy.blockedContinents))
  }
}
