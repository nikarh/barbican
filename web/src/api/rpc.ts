// The WebSocket RPC client. See crates/barbican/src/api.rs for the protocol.
//
// Calls made in the same tick go out together as one frame (a batch); each resolves on its own as the server answers
// it. Subscriptions are re-established after a reconnect.

import { diagnose, type Problem } from './diagnose'
import type {
  Activity,
  Ban,
  BlockCoverage,
  EdgeStatus,
  Entry,
  EventRow,
  Feed,
  GeoStatus,
  IpDetail,
  IpRow,
  Live,
  Meta,
  Overview,
  Page,
  Policy,
  Rule,
  Source,
} from './generated/model'
import type { Call, ErrorCode, ServerMessage } from './generated/rpc'

type Method = Call['method']

export type Params<M extends Method> =
  Extract<Call, { method: M }> extends { params: infer P } ? P : undefined

/** What each method resolves to. */
interface Results {
  'meta.get': Meta
  'overview.get': Overview
  'ips.list': Page<IpRow>
  'ip.get': IpDetail
  'ip.activity': Page<Activity>
  'events.list': Page<EventRow>
  'bans.list': Page<Ban>
  'ban.create': Ban
  'ban.lift': null
  'entries.list': Entry[]
  'entry.save': Entry
  'entry.delete': null
  'trust.remove': null
  'rules.list': Rule[]
  'rules.defaults': Rule[]
  'rule.save': Rule
  'rule.delete': null
  'rules.order': null
  'policy.get': Policy
  'policy.update': Policy
  'countries.coverage': BlockCoverage
  'geoip.status': GeoStatus
  'feeds.list': Feed[]
  'feeds.catalog': Source[]
  'feeds.apply': Feed[]
  'feed.save': Feed
  'feed.delete': null
  'feed.refresh': null
  'live.subscribe': Live[]
  'edges.list': EdgeStatus[]
  'edges.subscribe': null
  unsubscribe: null
}

/** The events of each subscription method. */
interface Events {
  'live.subscribe': Live
  'edges.subscribe': EdgeStatus[]
}

// Fails to compile when the server gains a method that isn't listed above.
type Exhaustive<T extends true> = T
export type ResultsCoverEveryMethod = Exhaustive<Method extends keyof Results ? true : false>

export type Result<M extends Method> = Results[M]

export class RpcError extends Error {
  readonly code: ErrorCode | 'disconnected'

  constructor(code: ErrorCode | 'disconnected', message: string) {
    super(message)
    this.name = 'RpcError'
    this.code = code
  }
}

export type ConnectionState = 'connecting' | 'open' | 'closed'

/** The connection, for the UI: whether it's open and, while it isn't, what's known about why. */
export interface Connection {
  state: ConnectionState
  /** Attempts that failed since the connection was last open. */
  failures: number
  /** When (ms) the next attempt starts, while closed. */
  retryAt: number | null
  /** When (ms) the connection was last open, while it isn't; `null` when it never was. */
  lostAt: number | null
  /** Why it fails, once known. */
  problem: Problem | null
  /** It has stayed down for a while ({@link GRACE_MS} in front of the user): time to say so. Until then the UI only
   * shows that it's connecting, as a phone drops the connection of a page in the background and the page reconnects
   * as soon as it is back in front. */
  down: boolean
}

interface Pending {
  resolve: (value: unknown) => void
  reject: (error: RpcError) => void
}

interface Subscription {
  call: Call
  /** The subscription's result, each time it is established (again, after a reconnect). */
  onResult: (result: unknown) => void
  onEvent: (event: unknown) => void
  onError: (error: RpcError) => void
}

const MAX_BACKOFF_MS = 10_000
/** How long the connection may be down, while the page is in front of the user, before the UI says so. */
export const GRACE_MS = 4_000

declare global {
  interface Window {
    /** The WebSocket index.html opens before the app's script has loaded; the client takes it over. */
    barbicanSocket?: WebSocket | undefined
  }
}

/** Asks the agent for its larger messages compressed (see crates/barbican/src/api.rs), where the browser can
 * inflate them. index.html opens its early socket with the same. */
export const PROTOCOLS = typeof DecompressionStream === 'function' ? ['barbican.deflate'] : []

async function inflate(data: Blob): Promise<string> {
  return new Response(data.stream().pipeThrough(new DecompressionStream('deflate'))).text()
}

/** The socket index.html opened for `url`, unless it already failed. Taken once. */
function takeEarlySocket(url: string): WebSocket | null {
  const socket = window.barbicanSocket
  window.barbicanSocket = undefined
  if (socket === undefined || socket.url !== url) return null
  return socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN
    ? socket
    : null
}

export class RpcClient {
  private socket: WebSocket | null = null
  private connection: Connection = {
    state: 'connecting',
    failures: 0,
    retryAt: null,
    lostAt: null,
    problem: null,
    down: false,
  }
  private retryTimer: number | null = null
  private graceTimer: number | null = null
  private diagnosis = 0
  private readonly listeners = new Set<() => void>()
  private readonly pending = new Map<string, Pending>()
  private readonly subscriptions = new Map<string, Subscription>()
  private queue: Record<string, unknown>[] = []
  private flushScheduled = false
  private nextId = 1
  private attempt = 0
  /** The page is going away (or into the back-forward cache): its socket was closed on purpose. */
  private leaving = false
  private readonly settledWaiters: (() => void)[] = []
  /** Messages in the order they came, compressed ones inflated in between. */
  private inbox: Promise<void> = Promise.resolve()
  private inflating = 0
  private readonly url: string
  private readonly diagnose: () => Promise<Problem>

  constructor(url: string, diagnose: () => Promise<Problem>) {
    this.url = url
    this.diagnose = diagnose
    this.connect(takeEarlySocket(url))
    // Back online, or back in front of the user: no need to wait out the backoff, and it's a fresh start.
    window.addEventListener('online', () => {
      this.attempt = 0
      this.retry()
    })
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible' || this.connection.state === 'open') return
      // What failed in the background (a phone drops the connection of a page that isn't shown) gets a grace period
      // of its own: the reconnection is usually done in a moment.
      this.attempt = 0
      this.stopGrace()
      if (this.connection.down) this.update({ down: false })
      this.startGrace()
      this.retry()
    })
    // A reload or leaving the page closes the socket with a proper close, at once: the agent and the proxies in
    // between let go of it now, instead of when they notice that the connection is gone.
    window.addEventListener('pagehide', () => {
      this.leaving = true
      if (this.retryTimer !== null) window.clearTimeout(this.retryTimer)
      this.retryTimer = null
      this.stopGrace()
      this.socket?.close(1000)
    })
    // Back from the back-forward cache.
    window.addEventListener('pageshow', (e) => {
      if (!e.persisted || !this.leaving) return
      this.leaving = false
      this.attempt = 0
      if (this.socket === null) this.connect()
    })
  }

  /** Resolves once connected with no call in flight: when what the screen asked for first has arrived. */
  settled(): Promise<void> {
    return new Promise((resolve) => {
      this.settledWaiters.push(resolve)
      this.checkSettled()
    })
  }

  private checkSettled(): void {
    if (this.connection.state !== 'open' || this.queue.length > 0) return
    for (const id of this.pending.keys()) {
      if (!this.subscriptions.has(id)) return
    }
    for (const resolve of this.settledWaiters.splice(0)) resolve()
  }

  // Connection state, for useSyncExternalStore.
  readonly subscribeState = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  readonly getConnection = (): Connection => this.connection

  private update(change: Partial<Connection>): void {
    this.connection = { ...this.connection, ...change }
    for (const listener of this.listeners) listener()
  }

  /** Counts the grace period down, unless it is already counting or over. It is over only while the page is in
   * front of the user: a page in the background is reconnecting as soon as it's back. */
  private startGrace(): void {
    if (this.graceTimer !== null || this.connection.down) return
    this.graceTimer = window.setTimeout(() => {
      this.graceTimer = null
      if (this.connection.state === 'open' || document.visibilityState !== 'visible') return
      this.update({ down: true })
    }, GRACE_MS)
  }

  private stopGrace(): void {
    if (this.graceTimer !== null) window.clearTimeout(this.graceTimer)
    this.graceTimer = null
  }

  /** Reconnects now instead of when the backoff ends, while closed. */
  readonly retry = (): void => {
    if (this.connection.state !== 'closed') return
    if (this.retryTimer !== null) window.clearTimeout(this.retryTimer)
    this.retryTimer = null
    void this.reconnect()
  }

  /** Opens a new WebSocket once plain HTTP shows the agent answers; until then asks again, backing off.
   *
   * A WebSocket that fails makes Firefox hold back the next ones to the same address, longer after each failure (up
   * to a minute) and in every tab: a page left open while the session expired would otherwise retry into 401s, and
   * the page opened after signing in again would wait seconds for its socket. Plain requests don't count. */
  private async reconnect(): Promise<void> {
    this.diagnosis += 1
    const diagnosis = this.diagnosis
    const problem = await this.diagnose()
    if (diagnosis !== this.diagnosis || this.leaving || this.connection.state !== 'closed') return
    if (problem.kind === 'answers') {
      this.connect()
      return
    }
    const delay = this.backoff()
    this.update({
      failures: this.connection.failures + 1,
      retryAt: Date.now() + delay,
      problem,
    })
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null
      void this.reconnect()
    }, delay)
  }

  private backoff(): number {
    const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.attempt)
    this.attempt += 1
    return delay
  }

  private connect(early: WebSocket | null = null): void {
    this.update({ state: 'connecting', retryAt: null })
    const socket = early ?? new WebSocket(this.url, PROTOCOLS)
    this.socket = socket

    const opened = () => {
      this.attempt = 0
      this.stopGrace()
      this.update({ state: 'open', failures: 0, lostAt: null, problem: null, down: false })
      // Resubscribe under the same ids, ahead of anything queued while offline.
      const queued = new Set(this.queue.map((r) => r.id))
      const resubscribe = [...this.subscriptions]
        .filter(([id]) => !queued.has(id))
        .map(([id, s]) => {
          this.pending.set(id, { resolve: s.onResult, reject: s.onError })
          return { id, ...s.call }
        })
      this.queue = [...resubscribe, ...this.queue]
      this.flush()
      this.checkSettled()
    }
    // The early socket may be open already: its open event has fired, before anyone listened.
    if (socket.readyState === WebSocket.OPEN) queueMicrotask(opened)
    else socket.addEventListener('open', opened)

    socket.addEventListener('message', (e: MessageEvent<unknown>) => {
      const data = e.data
      // Text right away, unless a compressed message before it is still being inflated: order is kept.
      if (typeof data === 'string' && this.inflating === 0) {
        this.receive(JSON.parse(data) as ServerMessage)
        return
      }
      if (typeof data !== 'string' && !(data instanceof Blob)) return
      this.inflating += 1
      this.inbox = this.inbox
        .then(async () => {
          const text = typeof data === 'string' ? data : await inflate(data)
          this.receive(JSON.parse(text) as ServerMessage)
        })
        .catch((error: unknown) => {
          console.error('A message from the agent could not be read', error)
        })
        .finally(() => {
          this.inflating -= 1
        })
    })

    socket.addEventListener('close', () => {
      if (this.socket !== socket) return
      this.socket = null
      if (this.leaving) return
      const delay = this.backoff()
      const { state, failures, lostAt } = this.connection
      this.update({
        state: 'closed',
        failures: failures + 1,
        retryAt: Date.now() + delay,
        lostAt: state === 'open' ? Date.now() : lostAt,
      })
      this.startGrace()
      this.diagnosis += 1
      const diagnosis = this.diagnosis
      void this.diagnose().then((problem) => {
        // Stale once a later one started, or the connection is back.
        if (diagnosis === this.diagnosis && this.connection.state !== 'open') {
          this.update({ problem })
        }
      })
      // Calls still queued were never sent: they go out once connected. Those sent are lost.
      const queued = new Set(this.queue.map((r) => r.id))
      for (const [id, p] of this.pending) {
        if (queued.has(id)) continue
        this.pending.delete(id)
        if (!this.subscriptions.has(id)) {
          p.reject(new RpcError('disconnected', 'The connection to the agent was lost'))
        }
      }
      this.retryTimer = window.setTimeout(() => {
        this.retryTimer = null
        void this.reconnect()
      }, delay)
    })
  }

  private receive(message: ServerMessage): void {
    switch (message.type) {
      case 'result': {
        const p = this.pending.get(message.id)
        this.pending.delete(message.id)
        p?.resolve(message.result)
        this.checkSettled()
        break
      }
      case 'error': {
        const error = new RpcError(message.error.code, message.error.message)
        if (message.id === null) {
          console.error('RPC error without an id', error)
          break
        }
        const p = this.pending.get(message.id)
        this.pending.delete(message.id)
        p?.reject(error)
        this.checkSettled()
        const s = this.subscriptions.get(message.id)
        if (s) {
          this.subscriptions.delete(message.id)
          s.onError(error)
        }
        break
      }
      case 'event':
        this.subscriptions.get(message.id)?.onEvent(message.event)
        break
    }
  }

  private send(request: Record<string, unknown>): void {
    this.queue.push(request)
    if (this.flushScheduled) return
    this.flushScheduled = true
    queueMicrotask(() => {
      this.flushScheduled = false
      this.flush()
    })
  }

  private flush(): void {
    if (this.queue.length === 0 || this.socket?.readyState !== WebSocket.OPEN) return
    const frame = this.queue.length === 1 ? this.queue[0] : this.queue
    this.queue = []
    this.socket.send(JSON.stringify(frame))
  }

  private id(): string {
    const id = `r${String(this.nextId)}`
    this.nextId += 1
    return id
  }

  /** Calls a method. Calls made in the same tick are sent as one batch. */
  call<M extends Method>(
    method: M,
    ...params: Params<M> extends undefined ? [] : [Params<M>]
  ): Promise<Result<M>> {
    const id = this.id()
    const call = params.length > 0 ? { method, params: params[0] } : { method }
    return new Promise<Result<M>>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject })
      this.send({ id, ...call })
    })
  }

  /** Subscribes to a stream of events; returns the unsubscribe function. `onResult` gets the call's result, again
   * after each reconnect. */
  subscribe<M extends keyof Events>(
    method: M,
    onEvent: (event: Events[M]) => void,
    onError: (error: RpcError) => void,
    onResult: (result: Result<M>) => void = () => undefined,
  ): () => void {
    const id = this.id()
    const call = { method } as Call
    const subscription: Subscription = {
      call,
      onResult: onResult as (result: unknown) => void,
      onEvent: onEvent as (event: unknown) => void,
      onError,
    }
    this.subscriptions.set(id, subscription)
    this.pending.set(id, { resolve: subscription.onResult, reject: onError })
    this.send({ id, ...call })
    return () => {
      if (!this.subscriptions.delete(id)) return
      this.pending.delete(id)
      if (this.connection.state === 'open') {
        void this.call('unsubscribe', { id }).catch(() => undefined)
      }
    }
  }
}

const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
// Relative to the page, so that the app also works under a path prefix behind a proxy.
const base = new URL('.', window.location.href).pathname
export const rpc = new RpcClient(`${protocol}//${window.location.host}${base}api/ws`, () =>
  diagnose(base),
)
