import { useQueryClient } from '@tanstack/react-query'
import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
  type ComponentType,
  type ReactNode,
} from 'react'

import { preloadAll, preloadOwn } from './api/preload'
import { rpc } from './api/rpc'
import { Kept } from './components/Kept'
import { Shell } from './components/Shell'
import { useRoute, type Screen } from './lib/router'
import { OverviewScreen } from './screens/Overview'

/** A screen in a script of its own: loaded on first use or ahead (`load`). Once loaded it renders at once, where
 * `lazy` alone would suspend for a frame the first time it renders, showing nothing, even when loaded ahead. */
function screen<P extends object>(
  importer: () => Promise<ComponentType<P>>,
): { load: () => Promise<unknown>; Component: ComponentType<P> } {
  let loaded: ComponentType<P> | null = null
  let loading: Promise<{ default: ComponentType<P> }> | null = null
  const load = () => {
    loading ??= importer().then((component) => {
      loaded = component
      return { default: component }
    })
    return loading
  }
  const Lazy = lazy(load)
  const Component = (props: P) => {
    const Loaded = loaded
    return Loaded === null ? <Lazy {...props} /> : <Loaded {...props} />
  }
  return { load, Component }
}

// The overview is in the first script; every other screen (the grids among them) loads after it, so that the
// first page has less to download and run.
const addresses = screen(() => import('./screens/Addresses').then((m) => m.AddressesScreen))
const bans = screen(() => import('./screens/Bans').then((m) => m.BansScreen))
const events = screen(() => import('./screens/Events').then((m) => m.EventsScreen))
const rules = screen(() => import('./screens/Rules').then((m) => m.RulesScreen))
const settings = screen(() => import('./screens/Settings').then((m) => m.SettingsScreen))
const AddressesScreen = addresses.Component
const BansScreen = bans.Component
const EventsScreen = events.Component
const RulesScreen = rules.Component
const SettingsScreen = settings.Component

const TITLES: Record<Screen, string> = {
  overview: 'Overview',
  addresses: 'Addresses',
  events: 'Events',
  bans: 'Bans',
  rules: 'Rules',
  settings: 'Settings',
}

/** The screens of grids: mounted once the first screen has its data, and then kept (see Kept), so that switching
 * to one shows its rows in the first frame, the first time too. */
const KEPT = ['addresses', 'bans', 'events'] as const satisfies Screen[]
type KeptScreen = (typeof KEPT)[number]

function isKept(screen: Screen): screen is KeptScreen {
  return (KEPT as readonly Screen[]).includes(screen)
}

export function App() {
  const route = useRoute()
  const ip = route.screen === 'addresses' ? route.params.get('ip') : null
  // The kept screens mounted so far: the one shown, then all of them once the first screen's data is in and the
  // browser has a moment, so that they don't hold it up.
  const [opened, setOpened] = useState<KeptScreen[]>([])
  if (isKept(route.screen) && !opened.includes(route.screen)) setOpened([...opened, route.screen])
  const client = useQueryClient()
  const first = useRef(route)
  useEffect(() => {
    let cancel: () => void = () => undefined
    let live = true
    // The first screen's data alone, then (once nothing it asked for is outstanding) every other screen's.
    void preloadOwn(client, first.current)
      .then(() => rpc.settled())
      .then(() => {
        if (!live) return
        void preloadAll(client)
        const all = () => {
          setOpened((o) => [...o, ...KEPT.filter((s) => !o.includes(s))])
          void rules.load()
          void settings.load()
        }
        if (typeof window.requestIdleCallback !== 'function') {
          const id = window.setTimeout(all, 200)
          cancel = () => {
            window.clearTimeout(id)
          }
        } else {
          const id = window.requestIdleCallback(all, { timeout: 1000 })
          cancel = () => {
            window.cancelIdleCallback(id)
          }
        }
      })
    return () => {
      live = false
      cancel()
    }
  }, [client])
  const kept = (screen: KeptScreen, content: ReactNode) =>
    opened.includes(screen) && (
      <Kept key={screen} shown={route.screen === screen}>
        <Suspense>{content}</Suspense>
      </Kept>
    )

  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [route.screen, ip])

  // The browser's tab says where it is: an address, or the screen.
  useEffect(() => {
    const where = route.screen === 'addresses' && ip !== null ? ip : TITLES[route.screen]
    document.title = `${where} · Barbican`
  }, [route.screen, ip])

  return (
    <Shell screen={route.screen}>
      {route.screen === 'overview' && <OverviewScreen />}
      {kept('addresses', <AddressesScreen ip={ip} tab={route.params.get('tab')} />)}
      {kept('events', <EventsScreen />)}
      {kept('bans', <BansScreen />)}
      <Suspense>
        {route.screen === 'rules' && <RulesScreen />}
        {route.screen === 'settings' && <SettingsScreen tab={route.params.get('tab')} />}
      </Suspense>
    </Shell>
  )
}
