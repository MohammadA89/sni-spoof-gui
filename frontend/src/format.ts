const UNITS = ['B', 'KB', 'MB', 'GB', 'TB']

/** Formats a byte count for display, e.g. 1536 -> "1.5 KB". */
export function bytes(n: number): string {
    if (!isFinite(n) || n <= 0) return '0 B'
    let i = 0
    while (n >= 1024 && i < UNITS.length - 1) {
        n /= 1024
        i++
    }
    return `${i === 0 ? n.toFixed(0) : n.toFixed(1)} ${UNITS[i]}`
}

/** Formats a throughput in bytes per second. */
export function rate(bytesPerSecond: number): string {
    return `${bytes(bytesPerSecond)}/s`
}

/** Formats a plain count with thousands separators. */
export function count(n: number): string {
    return n.toLocaleString('en-US')
}
