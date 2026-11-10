import { useEffect } from 'react'

import { Shell } from './components/Shell'
import { useRoute } from './lib/router'
import { AddressesScreen } from './screens/Addresses'
import { BansScreen } from './screens/Bans'
import { EventsScreen } from './screens/Events'
import { OverviewScreen } from './screens/Overview'
import { RulesScreen } from './screens/Rules'
import { SettingsScreen } from './screens/Settings'

export function App() {
  const route = useRoute()
  const ip = route.params.get('ip')

  useEffect(() => {
    window.scrollTo({ top: 0 })
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
