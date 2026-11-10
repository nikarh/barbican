import { useEffect } from 'react'

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

export function App() {
  const route = useRoute()
  const ip = route.params.get('ip')

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
      {route.screen === 'addresses' && <AddressesScreen ip={ip} />}
      {route.screen === 'events' && <EventsScreen />}
      {route.screen === 'bans' && <BansScreen />}
      {route.screen === 'rules' && <RulesScreen />}
      {route.screen === 'settings' && <SettingsScreen tab={route.params.get('tab')} />}
    </Shell>
  )
}
