// Mirrors the Go structs bound by Wails. Kept hand-written rather than using
// the generated models so the shapes stay readable at the call sites.

export interface Listener {
    host: string
    port: number
}

export interface Transport {
    edge_ips: string[]
    edge_port: number
    edge_domain: string
    fake_sni: string
    mode: 'fast' | 'safe'
    auto: boolean
    spoof: boolean
    inject_delay_ms: number
    port_low: number
    port_high: number
}

export interface Pool {
    enabled: boolean
    size: number
    ttl_seconds: number
}

export interface Config {
    listener: Listener
    transport: Transport
    pool: Pool
    log: { level: string }
}

export interface Snapshot {
    running: boolean
    accepted: number
    active: number
    failed: number
    bytesUp: number
    bytesDown: number
    rateUp: number
    rateDown: number
    poolIdle: number
    poolHits: number
    poolMisses: number
    poolDiscarded: number
    injected: number
    confirmed: number
    spoofFail: number
    edge: string
    listener: string
}

export interface LogEntry {
    time: string
    message: string
}

export const emptySnapshot: Snapshot = {
    running: false,
    accepted: 0, active: 0, failed: 0,
    bytesUp: 0, bytesDown: 0, rateUp: 0, rateDown: 0,
    poolIdle: 0, poolHits: 0, poolMisses: 0, poolDiscarded: 0,
    injected: 0, confirmed: 0, spoofFail: 0,
    edge: '', listener: '',
}
