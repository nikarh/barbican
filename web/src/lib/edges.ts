import type { EdgeStatus } from '../api/generated/model'

/** Packets an edge's firewall dropped, bans and lists together; `null` before its first report. */
export function edgeDropped(e: EdgeStatus): number | null {
  return e.report === null ? null : e.report.droppedBlocked + e.report.droppedListed
}
