import { useState } from 'react'

import { count, day } from '../lib/format'
import classes from './Bars.module.css'

export interface Bar {
  /** Unix time of the day. */
  day: number
  value: number
}

/** A single-series bar chart of days: the title names the series, so there is no legend. Thin bars with rounded
 * tops on a baseline, a 2px gap between them, and a tooltip per bar on hover (or tap). */
export function Bars({ title, bars, color }: { title: string; bars: Bar[]; color: string }) {
  const [hover, setHover] = useState<number | null>(null)
  const max = Math.max(1, ...bars.map((b) => b.value))
  const total = bars.reduce((sum, b) => sum + b.value, 0)
  const shown = hover === null ? null : bars[hover]
  const width = 100 / Math.max(1, bars.length)
  return (
    <figure className={classes.figure}>
      <figcaption className={classes.caption}>
        <span className="panel-title">{title}</span>
        <span className={classes.reading}>
          {shown ? (
            <>
              <strong className="num">{count(shown.value)}</strong> on {day(shown.day)}
            </>
          ) : (
            <>
              <strong className="num">{count(total)}</strong> in 30 days
            </>
          )}
        </span>
      </figcaption>
      <svg
        className={classes.plot}
        viewBox="0 0 100 40"
        preserveAspectRatio="none"
        role="img"
        aria-label={`${title}: ${count(total)} in 30 days, at most ${count(max)} a day`}
      >
        {bars.map((b, i) => {
          const h = b.value === 0 ? 0 : Math.max(0.8, (b.value / max) * 38)
          return (
            <g key={b.day}>
              {/* The hit target is the whole column, taller than the bar. */}
              <rect
                x={i * width}
                y={0}
                width={width}
                height={40}
                fill="transparent"
                onMouseEnter={() => {
                  setHover(i)
                }}
                onMouseLeave={() => {
                  setHover(null)
                }}
                onClick={() => {
                  setHover(i)
                }}
              />
              <rect
                className={classes.bar}
                x={i * width + 0.35}
                y={40 - h}
                width={Math.max(0.2, width - 0.7)}
                height={h}
                rx={0.6}
                fill={color}
                opacity={hover === null || hover === i ? 1 : 0.45}
                pointerEvents="none"
              />
            </g>
          )
        })}
      </svg>
      <div className={classes.axis}>
        <span>{bars[0] ? day(bars[0].day) : ''}</span>
        <span>today</span>
      </div>
    </figure>
  )
}
