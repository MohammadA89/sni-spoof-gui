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

export interface Client {
    direct: boolean
    enabled: boolean
    socks_port: number
    http_port: number
    doh: string
}

export interface Config {
    listener: Listener
    transport: Transport
    pool: Pool
    log: { level: string }
    client: Client
}

// One row of the config list. It carries no UUID or password on purpose: this
// crosses into the webview, where it would end up in a devtools console or a
// screenshot.
export interface ProfileView {
    id: string
    name: string
    protocol: string
    endpoint: string
    security: string
    network: string
    sni: string
    active: boolean
    edgeOverride: boolean
    warnings: string[]
    usable: boolean
    problem?: string
}

export interface ImportResult {
    added: number
    existing: number
    failed: string[]
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

    clientMode: boolean
    socksAddr: string
    httpAddr: string
    profile: string
    // Dials the engine could not spoof - UDP and IPv6 - which is the number to
    // look at when traffic works but feels unprotected.
    passthru: number
    resolveFail: number
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
    clientMode: true, socksAddr: '', httpAddr: '', profile: '',
    passthru: 0, resolveFail: 0,
}

// Whether Windows is currently pointed at a proxy, and whether this app is the
// one that pointed it. The second half is what decides whether the toggle may
// safely put the previous setting back.
export interface SystemProxyState {
    enabled: boolean
    server: string
    ours: boolean
}

export const noSystemProxy: SystemProxyState = {enabled: false, server: '', ours: false}

export interface HealthResult {
    ok: boolean
    latencyMs: number
    exitIp: string
    error?: string
}

// The pair is what makes the test worth anything: a proxied request that
// succeeds proves only that something answered. It is the exit address
// differing from the direct one that proves traffic went through the server.
export interface ConnectionTest {
    proxied: HealthResult
    direct: HealthResult
    verdict: string
    working: boolean
    profile: string
}
