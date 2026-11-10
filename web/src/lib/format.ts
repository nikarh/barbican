const regionNames = new Intl.DisplayNames(['en'], { type: 'region' })

/** The country's name, from its ISO code. */
export function countryName(code: string | null): string {
  if (code === null || code === '') return 'Unknown'
  try {
    return regionNames.of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}

/** The flag emoji of an ISO country code. */
export function flag(code: string | null): string {
  if (code?.length !== 2) return '·'
  const base = 0x1f1e6 - 'A'.charCodeAt(0)
  const upper = code.toUpperCase()
  return String.fromCodePoint(base + upper.charCodeAt(0), base + upper.charCodeAt(1))
}

export const CONTINENTS: { code: string; name: string }[] = [
  { code: 'AF', name: 'Africa' },
  { code: 'AN', name: 'Antarctica' },
  { code: 'AS', name: 'Asia' },
  { code: 'EU', name: 'Europe' },
  { code: 'NA', name: 'North America' },
  { code: 'OC', name: 'Oceania' },
  { code: 'SA', name: 'South America' },
]

/** Every ISO 3166-1 alpha-2 code the browser knows a name for. */
export const COUNTRIES: { code: string; name: string }[] = (() => {
  const out: { code: string; name: string }[] = []
  for (let a = 65; a <= 90; a += 1) {
    for (let b = 65; b <= 90; b += 1) {
      const code = String.fromCharCode(a, b)
      try {
        const name = regionNames.of(code)
        if (name !== undefined && name !== code && !name.includes('Unknown'))
          out.push({ code, name })
      } catch {
        // Not a region code.
      }
    }
  }
  return out.sort((x, y) => x.name.localeCompare(y.name))
})()

const DURATION_UNITS: [string, number][] = [
  ['y', 365 * 86_400],
  ['mo', 30 * 86_400],
  ['w', 7 * 86_400],
  ['d', 86_400],
  ['h', 3_600],
  ['min', 60],
  ['s', 1],
]

/** "90d", "1y", "1h 30m": a length, compactly (two units at most). */
export function formatLength(seconds: number): string {
  if (seconds <= 0) return '0s'
  const parts: string[] = []
  let rest = Math.round(seconds)
  for (const [unit, size] of DURATION_UNITS) {
    if (rest >= size && parts.length < 2) {
      const n = Math.floor(rest / size)
      parts.push(`${String(n)}${unit}`)
      rest -= n * size
    }
  }
  return parts.join(' ')
}

/** Reads what formatLength writes ("90d", "1h 30m", "2w"), or a number of seconds. */
export function parseLength(text: string): number | null {
  const trimmed = text.trim().toLowerCase()
  if (trimmed === '') return null
  if (/^\d+$/.test(trimmed)) return Number(trimmed)
  let total = 0
  const re = /(\d+(?:\.\d+)?)\s*(mo|min|y|w|d|h|m|s)/g
  let matched = ''
  for (const m of trimmed.matchAll(re)) {
    const unit = DURATION_UNITS.find(([u]) => u === (m[2] === 'm' ? 'min' : m[2]))
    if (unit === undefined || m[1] === undefined) return null
    total += Number(m[1]) * unit[1]
    matched += m[0]
  }
  if (matched.replace(/\s/g, '') !== trimmed.replace(/\s/g, '')) return null
  return total > 0 ? Math.round(total) : null
}

/** One unit, rounded to the nearest: "1y", "3d", "5h". */
export function approx(seconds: number): string {
  for (const [unit, size] of DURATION_UNITS) {
    if (seconds >= size * 0.95) return `${String(Math.round(seconds / size))}${unit}`
  }
  return `${String(Math.max(0, Math.round(seconds)))}s`
}

/** "3d ago", "just now". */
export function ago(unix: number | null, now: number = Date.now()): string {
  if (unix === null) return 'never'
  const seconds = Math.max(0, now / 1000 - unix)
  if (seconds < 45) return 'just now'
  return `${approx(seconds)} ago`
}

/** "in 3d", "until lifted", "ended". */
export function remaining(until: number | null, now: number = Date.now()): string {
  if (until === null) return 'until lifted'
  const seconds = until - now / 1000
  if (seconds <= 0) return 'ended'
  return `${approx(seconds)} left`
}

export function dateTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function day(unix: number): string {
  return new Date(unix * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function count(n: number): string {
  return n.toLocaleString()
}

export const KIND_LABELS = {
  http: 'HTTP',
  auth_failure: 'Failed login',
  auth_success: 'Login',
  invalid_user: 'Unknown user',
  probe: 'Probe',
} as const
