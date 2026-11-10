// The WebSocket RPC client. See crates/barbican/src/api.rs for the protocol.
//
// Calls made in the same tick go out together as one frame (a batch); each resolves on its own as the server answers
// it. Subscriptions are re-established after a reconnect.

import { diagnose, type Problem } from './diagnose'
import type {
  Activity,
  Ban,
  BlockCoverage,
  Entry,
  EventRow,
  Feed,
  FeedDef,
  GeoStatus,
  IpDetail,
  IpRow,
  Live,
  Meta,
  Overview,
  Page,
  Policy,
  Rule,
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
  'feeds.presets': FeedDef[]
  'feed.save': Feed
  'feed.delete': null
  'feed.refresh': null
  'live.subscribe': null
  unsubscribe: null
}

/** The events of each subscription method. */
interface Events {
  'live.subscribe': Live
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
}

interface Pending {
  resolve: (value: unknown) => void
  reject: (error: RpcError) => void
}

interface Subscription {
  call: Call
  onEvent: (event: unknown) => void
  onError: (error: RpcError) => void
}

const MAX_BACKOFF_MS = 10_000

export class RpcClient {
  private socket: WebSocket | null = null
  private connection: Connection = {
    state: 'connecting',
    failures: 0,
    retryAt: null,
    lostAt: null,
    problem: null,
  }
  private retryTimer: number | null = null
  private diagnosis = 0
  private readonly listeners = new Set<() => void>()
  private readonly pending = new Map<string, Pending>()
  private readonly subscriptions = new Map<string, Subscription>()
  private queue: Record<string, unknown>[] = []
  private flushScheduled = false
  private nextId = 1
  private attempt = 0
  private readonly url: string
  private readonly diagnose: () => Promise<Problem>

  constructor(url: string, diagnose: () => Promise<Problem>) {
    this.url = url
    this.diagnose = diagnose
    this.connect()
    // Back online, or back in front of the user: no need to wait out the backoff.
    window.addEventListener('online', this.retry)
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') this.retry()
    })
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

  /** Reconnects now instead of when the backoff ends, while closed. */
  readonly retry = (): void => {
    if (this.connection.state !== 'closed') return
    if (this.retryTimer !== null) window.clearTimeout(this.retryTimer)
    this.retryTimer = null
    this.connect()
  }

  private connect(): void {
    this.update({ state: 'connecting', retryAt: null })
    const socket = new WebSocket(this.url)
    this.socket = socket

    socket.addEventListener('open', () => {
      this.attempt = 0
      this.update({ state: 'open', failures: 0, lostAt: null, problem: null })
      // Resubscribe under the same ids, ahead of anything queued while offline.
      const queued = new Set(this.queue.map((r) => r.id))
      const resubscribe = [...this.subscriptions]
        .filter(([id]) => !queued.has(id))
        .map(([id, s]) => ({ id, ...s.call }))
      this.queue = [...resubscribe, ...this.queue]
      this.flush()
    })

    socket.addEventListener('message', (e: MessageEvent<unknown>) => {
      if (typeof e.data !== 'string') return
      this.receive(JSON.parse(e.data) as ServerMessage)
    })

    socket.addEventListener('close', () => {
      if (this.socket !== socket) return
      this.socket = null
      const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.attempt)
      this.attempt += 1
      const { state, failures, lostAt } = this.connection
      this.update({
        state: 'closed',
        failures: failures + 1,
        retryAt: Date.now() + delay,
        lostAt: state === 'open' ? Date.now() : lostAt,
      })
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
        this.connect()
      }, delay)
    })
  }

  private receive(message: ServerMessage): void {
    switch (message.type) {
      case 'result': {
        const p = this.pending.get(message.id)
        this.pending.delete(message.id)
        p?.resolve(message.result)
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

  /** Subscribes to a stream of events; returns the unsubscribe function. */
  subscribe<M extends keyof Events>(
    method: M,
    onEvent: (event: Events[M]) => void,
    onError: (error: RpcError) => void,
  ): () => void {
    const id = this.id()
    const call = { method } as Call
    this.subscriptions.set(id, {
      call,
      onEvent: onEvent as (event: unknown) => void,
      onError,
    })
    this.pending.set(id, { resolve: () => undefined, reject: onError })
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
