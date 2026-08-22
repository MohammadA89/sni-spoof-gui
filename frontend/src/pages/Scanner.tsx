import {useEffect, useState} from 'react'
import {EventsOn} from '../../wailsjs/runtime/runtime'
import {
    ApplyEdgeIPs,
    ApplyFakeSNI,
    CancelScan,
    CheckDomain,
    ProbeSNIs,
    ScanIPs,
} from '../../wailsjs/go/main/App'
import type {Dict} from '../i18n'

interface IPResult {
    ip: string
    latencyMs: number
    tlsMs: number
    verified: boolean
    error?: string
}

interface SNIResult {
    sni: string
    successes: number
    attempts: number
    meanMs: number
    error?: string
}

interface DomainResult {
    domain: string
    edge: string
    served: boolean
    tlsMs: number
    protocol?: string
    error?: string
}

interface Progress {
    phase: string
    done: number
    total: number
}

type Tab = 'ip' | 'sni' | 'domain'

export default function Scanner({t}: { t: Dict }) {
    const [tab, setTab] = useState<Tab>('ip')
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState('')
    const [progress, setProgress] = useState<Progress | null>(null)

    const [sample, setSample] = useState(400)
    const [verify, setVerify] = useState(10)
    const [ips, setIps] = useState<IPResult[]>([])

    const [attempts, setAttempts] = useState(3)
    const [snis, setSnis] = useState<SNIResult[]>([])

    const [domain, setDomain] = useState('')
    const [domainResult, setDomainResult] = useState<DomainResult | null>(null)

    useEffect(() => {
        EventsOn('scanProgress', (p: Progress) => setProgress(p))
    }, [])

    const guard = async (fn: () => Promise<void>) => {
        setBusy(true)
        setError('')
        setProgress(null)
        try {
            await fn()
        } catch (e: any) {
            setError(String(e?.message ?? e))
        } finally {
            setBusy(false)
            setProgress(null)
        }
    }

    const runIPScan = () => guard(async () => {
        setIps(await ScanIPs(sample, verify) as IPResult[])
    })

    const runSNIProbe = () => guard(async () => {
        setSnis(await ProbeSNIs(attempts) as SNIResult[])
    })

    const runDomainCheck = () => guard(async () => {
        setDomainResult(await CheckDomain(domain.trim()) as DomainResult)
    })

    const applyIPs = () => guard(async () => {
        // Verified addresses first; an unverified one is only a guess.
        const chosen = ips.filter(r => r.verified).map(r => r.ip).slice(0, 8)
        await ApplyEdgeIPs(chosen.length > 0 ? chosen : ips.slice(0, 8).map(r => r.ip))
    })

    const applySNI = (sni: string) => guard(async () => {
        await ApplyFakeSNI(sni)
    })

    const verified = ips.filter(r => r.verified).length

    return (
        <>
            <h1 className="page-title">{t.navScanner}</h1>

            {error && <div className="banner err">{t.errorPrefix}: {error}</div>}

            <div className="tabs">
                <button className={`tab ${tab === 'ip' ? 'active' : ''}`} onClick={() => setTab('ip')}>{t.scanIPs}</button>
                <button className={`tab ${tab === 'sni' ? 'active' : ''}`} onClick={() => setTab('sni')}>{t.scanSNI}</button>
                <button className={`tab ${tab === 'domain' ? 'active' : ''}`} onClick={() => setTab('domain')}>{t.scanDomain}</button>
            </div>

            {busy && progress && (
                <div className="panel">
                    <div className="panel-head">
                        <span className="panel-title">{progress.phase === 'latency' ? t.phaseLatency : progress.phase === 'verify' ? t.phaseVerify : t.phaseSNI}</span>
                        <span className="panel-hint num">{progress.done} / {progress.total}</span>
                    </div>
                    <div className="progress">
                        <div className="progress-bar"
                             style={{width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%`}}/>
                    </div>
                </div>
            )}

            {tab === 'ip' && (
                <>
                    <div className="panel">
                        <div className="panel-head">
                            <span className="panel-title">{t.scanIPs}</span>
                            <span className="panel-hint">{t.scanIPsHint}</span>
                        </div>
                        <div className="row">
                            <div className="field">
                                <label>{t.sampleSize}</label>
                                <input type="number" className="num" value={sample} disabled={busy}
                                       onChange={e => setSample(Number(e.target.value))}/>
                            </div>
                            <div className="field">
                                <label>{t.verifyCount}</label>
                                <input type="number" className="num" value={verify} disabled={busy}
                                       onChange={e => setVerify(Number(e.target.value))}/>
                            </div>
                        </div>
                        <div className="actions">
                            <button className="btn primary" onClick={runIPScan} disabled={busy}>
                                {busy ? t.scanning : t.startScan}
                            </button>
                            {busy && <button className="btn" onClick={() => CancelScan()}>{t.cancel}</button>}
                            {ips.length > 0 && !busy && (
                                <button className="btn" onClick={applyIPs}>{t.applyBest}</button>
                            )}
                        </div>
                    </div>

                    {ips.length > 0 && (
                        <div className="panel">
                            <div className="panel-head">
                                <span className="panel-title">{t.results}</span>
                                <span className="panel-hint">{verified} {t.verifiedCount} / {ips.length}</span>
                            </div>
                            <table className="table">
                                <thead>
                                <tr>
                                    <th>{t.colIP}</th>
                                    <th>{t.colLatency}</th>
                                    <th>{t.colTLS}</th>
                                    <th>{t.colStatus}</th>
                                </tr>
                                </thead>
                                <tbody>
                                {ips.slice(0, 40).map(r => (
                                    <tr key={r.ip}>
                                        <td className="mono">{r.ip}</td>
                                        <td className="num">{r.latencyMs} ms</td>
                                        <td className="num">{r.tlsMs > 0 ? `${r.tlsMs} ms` : '—'}</td>
                                        <td>
                                            {r.verified
                                                ? <span className="tag ok">{t.verified}</span>
                                                : r.error
                                                    ? <span className="tag err" title={r.error}>{t.failed}</span>
                                                    : <span className="tag">{t.unverified}</span>}
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}

            {tab === 'sni' && (
                <>
                    <div className="panel">
                        <div className="panel-head">
                            <span className="panel-title">{t.scanSNI}</span>
                            <span className="panel-hint">{t.scanSNIHint}</span>
                        </div>
                        <div className="field" style={{maxWidth: 220}}>
                            <label>{t.attemptsEach}</label>
                            <input type="number" className="num" value={attempts} disabled={busy}
                                   onChange={e => setAttempts(Number(e.target.value))}/>
                        </div>
                        <div className="actions">
                            <button className="btn primary" onClick={runSNIProbe} disabled={busy}>
                                {busy ? t.scanning : t.startScan}
                            </button>
                            {busy && <button className="btn" onClick={() => CancelScan()}>{t.cancel}</button>}
                        </div>
                    </div>

                    {snis.length > 0 && (
                        <div className="panel">
                            <div className="panel-head"><span className="panel-title">{t.results}</span></div>
                            <table className="table">
                                <thead>
                                <tr>
                                    <th>{t.colSNI}</th>
                                    <th>{t.colSuccess}</th>
                                    <th>{t.colTLS}</th>
                                    <th></th>
                                </tr>
                                </thead>
                                <tbody>
                                {snis.map(r => (
                                    <tr key={r.sni}>
                                        <td className="mono">{r.sni}</td>
                                        <td className="num">{r.successes}/{r.attempts}</td>
                                        <td className="num">{r.meanMs > 0 ? `${r.meanMs} ms` : '—'}</td>
                                        <td>
                                            {r.successes === r.attempts && r.attempts > 0 ? (
                                                <button className="mini-btn" onClick={() => applySNI(r.sni)} disabled={busy}>
                                                    {t.use}
                                                </button>
                                            ) : (
                                                <span className="tag err" title={r.error}>{t.failed}</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}

            {tab === 'domain' && (
                <div className="panel">
                    <div className="panel-head">
                        <span className="panel-title">{t.scanDomain}</span>
                        <span className="panel-hint">{t.scanDomainHint}</span>
                    </div>
                    <div className="field">
                        <label>{t.domainLabel}</label>
                        <input type="text" className="mono" value={domain} placeholder="example.com"
                               disabled={busy}
                               onChange={e => setDomain(e.target.value)}
                               onKeyDown={e => { if (e.key === 'Enter' && !busy) runDomainCheck() }}/>
                        <div className="field-hint">{t.domainHint}</div>
                    </div>
                    <div className="actions">
                        <button className="btn primary" onClick={runDomainCheck} disabled={busy || !domain.trim()}>
                            {busy ? t.scanning : t.check}
                        </button>
                    </div>

                    {domainResult && (
                        <div className={`banner ${domainResult.served ? 'ok' : 'err'}`} style={{marginTop: 16}}>
                            {domainResult.served
                                ? `${domainResult.domain} — ${t.domainServed} (${domainResult.tlsMs} ms, ${domainResult.protocol})`
                                : `${domainResult.domain} — ${t.domainNotServed}: ${domainResult.error}`}
                        </div>
                    )}
                </div>
            )}
        </>
    )
}
