interface Props {
    up: number[]
    down: number[]
}

/**
 * Two-series throughput chart.
 *
 * Both series share one vertical scale so the relative size of upload and
 * download stays honest; scaling them independently would make a trickle of
 * upload look like a flood next to a large download.
 */
export default function Sparkline({up, down}: Props) {
    const W = 600
    const H = 130
    const PAD = 6

    // A non-zero floor keeps an idle chart from drawing noise at full height.
    const peak = Math.max(1024, ...up, ...down)
    const points = Math.max(up.length, down.length, 2)

    const path = (series: number[]): string => {
        if (series.length === 0) return ''
        const step = (W - PAD * 2) / Math.max(points - 1, 1)
        return series
            .map((v, i) => {
                const x = PAD + i * step
                const y = H - PAD - (v / peak) * (H - PAD * 2)
                return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
            })
            .join(' ')
    }

    const area = (series: number[]): string => {
        const d = path(series)
        if (!d) return ''
        const step = (W - PAD * 2) / Math.max(points - 1, 1)
        const lastX = PAD + (series.length - 1) * step
        return `${d} L${lastX.toFixed(1)},${H - PAD} L${PAD},${H - PAD} Z`
    }

    return (
        <svg className="chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
            <defs>
                <linearGradient id="gUp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--up)" stopOpacity="0.28"/>
                    <stop offset="100%" stopColor="var(--up)" stopOpacity="0"/>
                </linearGradient>
                <linearGradient id="gDown" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--down)" stopOpacity="0.28"/>
                    <stop offset="100%" stopColor="var(--down)" stopOpacity="0"/>
                </linearGradient>
            </defs>

            {[0.25, 0.5, 0.75].map(f => (
                <line
                    key={f}
                    x1={PAD} x2={W - PAD}
                    y1={PAD + f * (H - PAD * 2)} y2={PAD + f * (H - PAD * 2)}
                    stroke="var(--border)" strokeWidth="1"
                />
            ))}

            <path d={area(down)} fill="url(#gDown)"/>
            <path d={area(up)} fill="url(#gUp)"/>
            <path d={path(down)} fill="none" stroke="var(--down)" strokeWidth="2"
                  vectorEffect="non-scaling-stroke" strokeLinejoin="round"/>
            <path d={path(up)} fill="none" stroke="var(--up)" strokeWidth="2"
                  vectorEffect="non-scaling-stroke" strokeLinejoin="round"/>
        </svg>
    )
}
