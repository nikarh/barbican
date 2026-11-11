// Why the WebSocket fails. A browser doesn't tell a page why a WebSocket handshake failed, so after one does the UI
// asks over plain HTTP: `barbican ui-proxy` answers `api/proxy` itself (a ProxyStatus), and without the proxy (the
// agent serving the UI) that path is a 404 of the agent's.

import type { ProxyProblem, ProxyStatus } from './generated/model'

export type Problem =
  /** The UI proxy can't reach the agent's socket. */
  | { kind: 'proxy'; socket: string; problem: ProxyProblem }
  /** Plain HTTP reaches the agent (through the proxy or not), yet the WebSocket fails. */
  | { kind: 'answers' }
  /** Something in front of Barbican answered with an error status. */
  | { kind: 'gateway'; status: number }
  /** Something answered that isn't Barbican: a sign-in page, say. */
  | { kind: 'foreign' }
  /** Nothing answers at all. */
  | { kind: 'server' }

const TIMEOUT_MS = 5_000

function isProxyStatus(value: unknown): value is ProxyStatus {
  return typeof value === 'object' && value !== null && 'socket' in value && 'problem' in value
}

export async function diagnose(base: string): Promise<Problem> {
  let response: Response
  try {
    response = await fetch(`${base}api/proxy`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch {
    return { kind: 'server' }
  }
  // The agent's own 404: there is no proxy, and the agent answers.
  if (response.status === 404) return { kind: 'answers' }
  if (!response.ok) return { kind: 'gateway', status: response.status }
  const body: unknown = await response.json().catch(() => null)
  if (!isProxyStatus(body)) return { kind: 'foreign' }
  if (body.problem === null) return { kind: 'answers' }
  return { kind: 'proxy', socket: body.socket, problem: body.problem }
}
