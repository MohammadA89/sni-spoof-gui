import {useEffect, useState} from 'react'
import {EventsOn} from '../../wailsjs/runtime/runtime'
import type {Snapshot} from '../types'
import type {Dict} from '../i18n'
import {bytes, count, rate} from '../format'
import Sparkline from '../components/Sparkline'

interface AutoStatus {
    active: boolean
    message: string
    done: number
    total: number
}

interface Props {
    t: Dict
    snap: Snapshot
    history: { up: number[]; down: number[] }
    busy: boolean
    error: string
    auto: boolean
    onToggle: () => void
    onToggleAuto: (on: boolean) => void
}

export default function Dashboard({t, snap, history, busy, error, auto, onToggle, onToggleAuto}: Props) {
    const [copied, setCopied] = useState(false)
    const [autoStatus, setAutoStatus] = useState<AutoStatus | null>(null)

    useEffect(() => {
        EventsOn('autoStatus', (s: AutoStatus) => setAutoStatus(s.active ? s : null))
    }, [])

    const copyAddr = async () => {
        try {
            await navigator.clipboard.writeText(snap.listener)
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
        } catch {
            // Clipboard can be unavailable in the webview; the address is
            // selectable on screen either way.
        }
    }

    const phase = autoStatus
        ? autoStatus.message === 'verifying candidates' ? t.phaseVerify : t.phaseLatency
        : ''
    const pct = autoStatus && autoStatus.total > 0
        ? Math.round((autoStatus.done / autoStatus.total) * 100)
        : 0

    const state = snap.running ? 'on' : busy ? 'busy' : 'off'

    return (
        <>
            {error && <div className="banner err">{t.errorPrefix}: {error}</div>}

            <section className={`hero ${state}`}>
                <button className={`power ${state}`} onClick={onToggle} disabled={busy}>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M12 3v9" strokeLinecap="round"/>
                        <path d="M6.3 6.3a8 8 0 1 0 11.4 0" strokeLinecap="round"/>
                    </svg>
                </button>

                <div className="hero-text">
                    <div className="hero-status">
                        {busy ? t.connecting : snap.running ? t.connected : t.disconnected}
                    </div>
                    <div className="hero-sub">
                        {busy && autoStatus
                            ? `${phase} — ${autoStatus.done}/${autoStatus.total}`
                            : snap.running
                                ? <>{t.edge}: <span className="num">{snap.edge}</span></>
                                : t.pressConnect}
                    </div>

                    {busy && autoStatus && (
                        <div className="progress hero-progress">
                            <div className="progress-bar" style={{width: `${pct}%`}}/>
                        </div>
                    )}

                    <label className="check auto-toggle">
                        <input type="checkbox" checked={auto} disabled={busy}
                               onChange={e => onToggleAuto(e.target.checked)}/>
                        <span>{t.autoMode}</span>
                        <span className="hint">— {t.autoModeHint}</span>
                    </label>
                </div>

                <div className="hero-addr">
                    <div className="card-label">{t.listenerAddr}</div>
                    <div className="addr-value">
                        <strong className="mono">{snap.listener}</strong>
                        <button className="mini-btn" onClick={copyAddr}>
                            {copied ? t.copied : t.copy}
                        </button>
                    </div>
                    <div className="hint">{t.listenerHint}</div>
                </div>
            </section>

            <div className="grid c4">
                <div className="card">
                    <div className="card-label">{t.download}</div>
                    <div className="card-value down num">{rate(snap.rateDown)}</div>
                    <div className="card-sub num">{bytes(snap.bytesDown)}</div>
                </div>
                <div className="card">
                    <div className="card-label">{t.upload}</div>
                    <div className="card-value up num">{rate(snap.rateUp)}</div>
                    <div className="card-sub num">{bytes(snap.bytesUp)}</div>
                </div>
                <div className="card">
                    <div className="card-label">{t.activeConns}</div>
                    <div className="card-value num">{count(snap.active)}</div>
                    <div className="card-sub">{t.totalAccepted}: {count(snap.accepted)}</div>
                </div>
                <div className="card">
                    <div className="card-label">{t.poolIdle}</div>
                    <div className="card-value num">{count(snap.poolIdle)}</div>
                    <div className="card-sub">{t.failedConns}: {count(snap.failed)}</div>
                </div>
            </div>

            <div className="panel">
                <div className="panel-head">
                    <span className="panel-title">{t.speed}</span>
                </div>
                <Sparkline up={history.up} down={history.down}/>
                <div className="legend">
                    <span><i className="swatch" style={{background: 'var(--down)'}}/>{t.download}</span>
                    <span><i className="swatch" style={{background: 'var(--up)'}}/>{t.upload}</span>
                </div>
            </div>

            <div className="grid c2">
                <div className="panel">
                    <div className="panel-head">
                        <span className="panel-title">{t.poolTitle}</span>
                    </div>
                    <div className="stat-row">
                        <div className="stat">
                            <span className="stat-label">{t.poolHits}</span>
                            <span className="stat-value num">{count(snap.poolHits)}</span>
                        </div>
                        <div className="stat">
                            <span className="stat-label">{t.poolMisses}</span>
                            <span className="stat-value num">{count(snap.poolMisses)}</span>
                        </div>
                        <div className="stat">
                            <span className="stat-label">{t.poolDiscarded}</span>
                            <span className="stat-value num">{count(snap.poolDiscarded)}</span>
                        </div>
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-head">
                        <span className="panel-title">{t.spoofTitle}</span>
                    </div>
                    <div className="stat-row">
                        <div className="stat">
                            <span className="stat-label">{t.injected}</span>
                            <span className="stat-value num">{count(snap.injected)}</span>
                        </div>
                        <div className="stat">
                            <span className="stat-label">{t.confirmed}</span>
                            <span className="stat-value num">{count(snap.confirmed)}</span>
                        </div>
                        <div className="stat">
                            <span className="stat-label">{t.spoofFailed}</span>
                            <span className="stat-value num">{count(snap.spoofFail)}</span>
                        </div>
                    </div>
                </div>
            </div>
        </>
    )
}
