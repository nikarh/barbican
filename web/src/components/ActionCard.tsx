import type { CSSProperties, ReactNode } from 'react'

import classes from './ActionCard.module.css'

/**
 * A card of a list (a rule, a blocklist) with its buttons (`count` of them, action icons) in its top-right corner.
 * Only the lines beside the buttons make room for them; the rest of the content gets the card's full width, so a
 * narrow card (a phone) doesn't squeeze its text into a column between a switch and the buttons.
 */
export function ActionCard({
  actions,
  count,
  children,
}: {
  actions: ReactNode
  count: number
  children: ReactNode
}) {
  return (
    <div className={['panel', classes.card].join(' ')}>
      <div className={classes.body}>
        <div className={classes.space} style={{ '--actions': count } as CSSProperties} />
        {children}
      </div>
      <div className={classes.actions}>{actions}</div>
    </div>
  )
}
