import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'

import { rpc } from './api/rpc'
import { Kept } from './components/Kept'
import { Shell } from './components/Shell'
import { useRoute, type Screen } from './lib/router'
import { OverviewScreen } from './screens/Overview'

// The overview is in the first script; every other screen (the grids among them) loads after it, so that the
// first page has less to download and run.
const load = {
  addresses: () => import('./screens/Addresses'),
  bans: () => import('./screens/Bans'),
  events: () => import('./screens/Events'),
  rules: () => import('./screens/Rules'),
  settings: () => import('./screens/Settings'),
}
const AddressesScreen = lazy(() => load.addresses().then((m) => ({ default: m.AddressesScreen })))
const BansScreen = lazy(() => load.bans().then((m) => ({ default: m.BansScreen })))
const EventsScreen = lazy(() => load.events().then((m) => ({ default: m.EventsScreen })))
const RulesScreen = lazy(() => load.rules().then((m) => ({ default: m.RulesScreen })))
const SettingsScreen = lazy(() => load.settings().then((m) => ({ default: m.SettingsScreen })))

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
  useEffect(() => {
    let cancel: () => void = () => undefined
    let live = true
    void rpc.settled().then(() => {
      if (!live) return
      const all = () => {
        setOpened((o) => [...o, ...KEPT.filter((s) => !o.includes(s))])
        void load.rules()
        void load.settings()
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
  }, [])
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
