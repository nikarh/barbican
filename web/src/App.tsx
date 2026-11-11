import { useEffect, useState, type ReactNode } from 'react'

import { Kept } from './components/Kept'
import { Shell } from './components/Shell'
import { useRoute, type Screen } from './lib/router'
import { AddressesScreen } from './screens/Addresses'
import { BansScreen } from './screens/Bans'
import { EventsScreen } from './screens/Events'
import { OverviewScreen } from './screens/Overview'
import { RulesScreen } from './screens/Rules'
import { SettingsScreen } from './screens/Settings'

const TITLES: Record<Screen, string> = {
  overview: 'Overview',
  addresses: 'Addresses',
  events: 'Events',
  bans: 'Bans',
  rules: 'Rules',
  settings: 'Settings',
}

/** The screens of grids: mounted once the first screen is up, and then kept (see Kept), so that switching to one
 * shows its rows in the first frame, the first time too. */
const KEPT = ['addresses', 'bans', 'events'] as const satisfies Screen[]
type KeptScreen = (typeof KEPT)[number]

function isKept(screen: Screen): screen is KeptScreen {
  return (KEPT as readonly Screen[]).includes(screen)
}

export function App() {
  const route = useRoute()
  const ip = route.screen === 'addresses' ? route.params.get('ip') : null
  // The kept screens mounted so far: the one shown, then all of them once the browser has a moment.
  const [opened, setOpened] = useState<KeptScreen[]>([])
  if (isKept(route.screen) && !opened.includes(route.screen)) setOpened([...opened, route.screen])
  useEffect(() => {
    const all = () => {
      setOpened((o) => [...o, ...KEPT.filter((s) => !o.includes(s))])
    }
    if (typeof window.requestIdleCallback !== 'function') {
      const id = window.setTimeout(all, 500)
      return () => {
        window.clearTimeout(id)
      }
    }
    const id = window.requestIdleCallback(all, { timeout: 2000 })
    return () => {
      window.cancelIdleCallback(id)
    }
  }, [])
  const kept = (screen: KeptScreen, content: ReactNode) =>
    opened.includes(screen) && (
      <Kept key={screen} shown={route.screen === screen}>
        {content}
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
      {route.screen === 'rules' && <RulesScreen />}
      {route.screen === 'settings' && <SettingsScreen tab={route.params.get('tab')} />}
    </Shell>
  )
}
