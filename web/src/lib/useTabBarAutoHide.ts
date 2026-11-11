import { useEffect, useState } from 'react'

/**
 * Firefox for Android moves bottom-pinned elements a frame late while its toolbar slides in or out
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=1797964), so a tab bar pinned there jumps on every scroll that moves
 * the toolbar. There, the tab bar leaves with the toolbar instead: hidden while scrolling down, back when scrolling up
 * or at the top. Other browsers keep it in place.
 */
const AFFECTED = /Android.*Firefox\//.test(navigator.userAgent)

/** Scrolling less than this (px) in one direction doesn't count, so small movements don't toggle the bar. */
const THRESHOLD = 12
/** The same for the finger, smaller: the toolbar starts to move with the first pixels, and the bar should too. */
const TOUCH_THRESHOLD = 4

/** Whether the tab bar should be hidden now. `screen` shows it again whenever the screen changes. */
export function useTabBarAutoHide(screen: string): boolean {
  // The screen it was hidden on: another screen shows it again.
  const [hiddenOn, setHiddenOn] = useState<string | null>(null)
  const hidden = hiddenOn === screen

  useEffect(() => {
    if (!AFFECTED) return
    const setHidden = (hide: boolean) => {
      setHiddenOn(hide ? screen : null)
    }
    let last = window.scrollY
    // How far the page has scrolled in the current direction: positive down, negative up.
    let travel = 0
    const onScroll = () => {
      const y = window.scrollY
      const delta = y - last
      last = y
      if (y <= 0) {
        travel = 0
        setHidden(false)
        return
      }
      if (Math.sign(delta) !== Math.sign(travel)) travel = 0
      travel += delta
      if (travel > THRESHOLD) setHidden(true)
      else if (travel < -THRESHOLD) setHidden(false)
    }
    // Firefox moves its toolbar as soon as the finger does, before the page scrolls (and so before any scroll event):
    // the finger is what tells early enough which way the toolbar goes.
    let touchY: number | null = null
    const onTouchStart = (e: TouchEvent) => {
      touchY = e.touches.length === 1 ? (e.touches[0]?.clientY ?? null) : null
    }
    const onTouchMove = (e: TouchEvent) => {
      const y = e.touches[0]?.clientY
      if (touchY === null || y === undefined) return
      // Only when the page can scroll at all; Firefox keeps its toolbar for pages that fit.
      const scrollable = document.documentElement.scrollHeight > window.innerHeight
      if (touchY - y > TOUCH_THRESHOLD && scrollable) setHidden(true)
      else if (y - touchY > TOUCH_THRESHOLD) setHidden(false)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('touchstart', onTouchStart, { passive: true })
    window.addEventListener('touchmove', onTouchMove, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('touchstart', onTouchStart)
      window.removeEventListener('touchmove', onTouchMove)
    }
  }, [screen])

  // For what floats above the tab bar, so it can follow it down.
  useEffect(() => {
    document.documentElement.toggleAttribute('data-tabbar-hidden', hidden)
  }, [hidden])

  return hidden
}
