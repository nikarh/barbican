import type { ReactNode } from 'react'

import { Shown, useShown } from '../lib/shown'
import classes from './Kept.module.css'

/**
 * A screen that stays mounted while another one shows, hidden: coming back to it shows it as it was in the very
 * first frame (its grid's rows, scroll position and filters), instead of a new grid that paints its frame, then its
 * header, then placeholder rows, then the rows. Its grids refresh their rows in place when it shows again.
 */
export function Kept({ shown, children }: { shown: boolean; children: ReactNode }) {
  const outer = useShown()
  return (
    <Shown value={outer && shown}>
      <div className={classes.kept} data-hidden={!shown || undefined} inert={!shown}>
        {children}
      </div>
    </Shown>
  )
}
