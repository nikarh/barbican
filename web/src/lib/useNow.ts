import { useEffect, useState } from 'react'

/** The current time (ms), updated every `intervalMs`: render stays pure, and relative times stay current. */
export function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now())
    }, intervalMs)
    return () => {
      window.clearInterval(timer)
    }
  }, [intervalMs])
  return now
}
