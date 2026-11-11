import { createContext, use } from 'react'

/** Whether what is inside is on screen: false inside a kept screen while another one shows (see Kept). */
export const Shown = createContext(true)

/** Whether what calls it is on screen. */
export function useShown(): boolean {
  return use(Shown)
}
