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

/** Codes the browser has names for that aren't countries of today (withdrawn ones, such as DD for East Germany,
 * named "Germany"; reserved ones; groupings): geolocation databases don't use them. */
const NOT_COUNTRIES = new Set(
  'AC AN BU CP CS DD DG DY EA EU EZ FX HV IC NH NT QO QU RH SU TA TP UK UN VD XA XB YD YU ZR'.split(
    ' ',
  ),
)

/** Every ISO 3166-1 alpha-2 code of a country of today that the browser knows a name for. */
export const COUNTRIES: { code: string; name: string }[] = (() => {
  const out: { code: string; name: string }[] = []
  for (let a = 65; a <= 90; a += 1) {
    for (let b = 65; b <= 90; b += 1) {
      const code = String.fromCharCode(a, b)
      if (NOT_COUNTRIES.has(code)) continue
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

const UNIT_NAMES: Record<string, [string, string]> = {
  y: ['year', 'years'],
  mo: ['month', 'months'],
  w: ['week', 'weeks'],
  d: ['day', 'days'],
  h: ['hour', 'hours'],
  min: ['minute', 'minutes'],
  s: ['second', 'seconds'],
}

/** "90 days", "1 year", "1 hour 30 minutes": a length in words (two units at most). */
export function lengthInWords(seconds: number): string {
  if (seconds <= 0) return '0 seconds'
  const parts: string[] = []
  let rest = Math.round(seconds)
  for (const [unit, size] of DURATION_UNITS) {
    if (rest >= size && parts.length < 2) {
      const n = Math.floor(rest / size)
      const [one, many] = UNIT_NAMES[unit] ?? [unit, unit]
      parts.push(`${String(n)} ${n === 1 ? one : many}`)
      rest -= n * size
    }
  }
  return parts.join(' ')
}

// Longer spellings first: "mo" before "m", "min" before "m".
const UNIT_PATTERN =
  /(\d+(?:\.\d+)?)\s*(years?|yrs?|y|months?|mo|weeks?|wk?|days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)/g

/** Reads what formatLength and lengthInWords write ("90d", "1h 30m", "2 weeks", "1 year 2 months"), or a number
 * of seconds. */
export function parseLength(text: string): number | null {
  const trimmed = text.trim().toLowerCase()
  if (trimmed === '') return null
  if (/^\d+$/.test(trimmed)) return Number(trimmed)
  let total = 0
  let matched = ''
  for (const m of trimmed.matchAll(UNIT_PATTERN)) {
    const name = m[2] ?? ''
    let key = name.charAt(0)
    if (name.startsWith('mo')) key = 'mo'
    else if (name.startsWith('m')) key = 'min'
    const unit = DURATION_UNITS.find(([u]) => u === key)
    if (unit === undefined || m[1] === undefined) return null
    total += Number(m[1]) * unit[1]
    matched += m[0]
  }
  if (matched.replace(/\s/g, '') !== trimmed.replace(/[\s,]|and/g, '')) return null
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

/** "in 3d", "now": how long until a time. */
export function fromNow(unix: number, now: number = Date.now()): string {
  const seconds = unix - now / 1000
  if (seconds < 45) return 'now'
  return `in ${approx(seconds)}`
}

/** "1 Nov 2026". */
export function date(unix: number): string {
  return new Date(unix * 1000).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/** "Nov 2026". */
export function month(unix: number): string {
  return new Date(unix * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short' })
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

const compactFormat = new Intl.NumberFormat(undefined, {
  notation: 'compact',
  maximumFractionDigits: 1,
})

/** "343M", "1.2K", "12": a big number, roughly. */
export function compact(n: number): string {
  return compactFormat.format(n)
}

/** "8.0%", "0.04%", "<0.01%": a share, with as many digits as it takes to not round to nothing. */
export function share(part: number, whole: number): string {
  if (whole <= 0 || part <= 0) return '0%'
  const pct = (part / whole) * 100
  if (pct < 0.01) return '<0.01%'
  if (pct < 1) return `${pct.toFixed(2)}%`
  if (pct < 10) return `${pct.toFixed(1)}%`
  return `${pct.toFixed(0)}%`
}

export const KIND_LABELS = {
  http: 'HTTP',
  auth_failure: 'Failed login',
  auth_success: 'Login',
  invalid_user: 'Unknown user',
  probe: 'Probe',
} as const
