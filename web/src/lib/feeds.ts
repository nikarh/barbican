import type { Feed, FeedDef, Item, NetworkUse, Source, Use } from '../api/generated/model'
import { compact, count } from './format'

/** What a feed does with what it lists. */
export function feedUse(def: FeedDef): Use {
  if (!def.enabled) return 'off'
  if (def.block) return 'block'
  if (def.allow) return 'allow'
  return 'data'
}

/** A feed as `use_` makes it. */
export function withUse(def: FeedDef, use_: Use): FeedDef {
  return {
    ...def,
    enabled: use_ !== 'off',
    block: use_ === 'block',
    allow: use_ === 'allow',
  }
}

/** The catalog source and list a feed comes from: the one it was added from, or (added by hand, or before the
 * catalog) the one with its URL. */
export function catalogOf(def: FeedDef, catalog: Source[]): { source: Source; item: Item } | null {
  for (const source of catalog) {
    for (const item of source.items) {
      const added =
        def.catalog !== null && def.catalog.source === source.id && def.catalog.item === item.key
      const same =
        def.catalog === null && item.url === def.url && (item.select ?? null) === def.select
      if (added || same) return { source, item }
    }
  }
  return null
}

/** "1,234 prefixes", "742 networks", "208 user agents": what the list holds. */
export function entries(f: Feed): string {
  switch (f.def.content) {
    case 'networks':
      return `${count(f.count)} networks`
    case 'agents':
      return `${count(f.count)} user agents`
    case 'addresses':
      return `${count(f.count)} prefixes`
  }
}

/** "92K addresses", "2 /48 IPv6 networks": how much of the address space a list stands for. */
export function addresses(f: Feed): string {
  const parts: string[] = []
  if (f.extent.v4Addresses > 0) parts.push(`${compact(f.extent.v4Addresses)} IPv4 addresses`)
  if (f.extent.v6Networks > 0) parts.push(`${compact(f.extent.v6Networks)} IPv6 /48s`)
  return parts.join(' and ')
}

export const USE_LABELS: Record<Use, string> = {
  off: 'Off',
  block: 'Block',
  allow: 'Allow',
  data: 'Data',
}

/** What each use does, in a sentence. */
export const USE_EFFECTS: Record<Use, string> = {
  off: 'Not fetched, not used.',
  block:
    'Every address it lists is dropped, here and on the edges, like a blocked country. Bans and the allow list come first.',
  allow:
    'Every address it lists is never banned and is let through before any block, here and on the edges, like the allow list.',
  data: 'Nothing by itself: rules can ask whether an address (or a user agent) is in it, address pages show it, and the policy can give its addresses a ban length of their own.',
}

/** "3 blocked · 1 off": the networks of a list that do otherwise than the list. */
export function networksSummary(networks: NetworkUse[]): string {
  const n: Record<Use, number> = { off: 0, block: 0, allow: 0, data: 0 }
  for (const x of networks) n[x.use] += 1
  const words: Record<Use, string> = {
    block: 'blocked',
    allow: 'allowed',
    data: 'data',
    off: 'left out',
  }
  return (['block', 'allow', 'data', 'off'] as const)
    .filter((u) => n[u] > 0)
    .map((u) => `${String(n[u])} ${words[u]}`)
    .join(' · ')
}
