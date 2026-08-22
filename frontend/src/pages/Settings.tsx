import {useEffect, useState} from 'react'
import type {Config} from '../types'
import type {Dict} from '../i18n'

interface Props {
    t: Dict
    config: Config | null
    onSave: (c: Config) => Promise<string>
    onReset: () => Promise<Config>
    autostart: boolean
    onAutostart: (on: boolean) => void
}

export default function Settings({t, config, onSave, onReset, autostart, onAutostart}: Props) {
    const [draft, setDraft] = useState<Config | null>(config)
    const [error, setError] = useState('')
    const [ok, setOk] = useState('')

    // Adopt the config from the backend once it arrives, but never clobber
    // edits the user has already started making.
    useEffect(() => {
        if (config && !draft) setDraft(config)
    }, [config, draft])

    if (!draft) return <div className="empty">…</div>

    const patch = (fn: (c: Config) => void) => {
        const next: Config = JSON.parse(JSON.stringify(draft))
        fn(next)
        setDraft(next)
        setError('')
        setOk('')
    }

    const save = async () => {
        const err = await onSave(draft)
        if (err) {
            setError(err)
            setOk('')
        } else {
            setError('')
            setOk(t.saved)
            setTimeout(() => setOk(''), 2500)
        }
    }

    const reset = async () => {
        setDraft(await onReset())
        setError('')
        setOk('')
    }

    // Numeric inputs are kept as numbers; an empty box becomes 0 and is caught
    // by backend validation rather than silently becoming NaN.
    const num = (v: string) => (v === '' ? 0 : Number(v))

    return (
        <>
            <h1 className="page-title">{t.navSettings}</h1>

            {error && <div className="banner err">{t.errorPrefix}: {error}</div>}
            {ok && <div className="banner ok">{ok} — {t.restartNeeded}</div>}

            <div className="panel">
                <div className="panel-head"><span className="panel-title">{t.settingsListener}</span></div>
                <div className="row">
                    <div className="field">
                        <label>{t.host}</label>
                        <input type="text" value={draft.listener.host}
                               onChange={e => patch(c => { c.listener.host = e.target.value })}/>
                    </div>
                    <div className="field">
                        <label>{t.port}</label>
                        <input type="number" className="num" value={draft.listener.port}
                               onChange={e => patch(c => { c.listener.port = num(e.target.value) })}/>
                    </div>
                </div>
            </div>

            <div className="panel">
                <div className="panel-head"><span className="panel-title">{t.settingsTransport}</span></div>

                <div className="field">
                    <label>{t.edgeIPs}</label>
                    <textarea className="mono" value={draft.transport.edge_ips.join('\n')}
                              onChange={e => patch(c => {
                                  c.transport.edge_ips = e.target.value
                                      .split('\n')
                                      .map(s => s.trim())
                                      .filter(Boolean)
                              })}/>
                    <div className="field-hint">{t.edgeIPsHint}</div>
                </div>

                <div className="row">
                    <div className="field">
                        <label>{t.edgePort}</label>
                        <input type="number" className="num" value={draft.transport.edge_port}
                               onChange={e => patch(c => { c.transport.edge_port = num(e.target.value) })}/>
                    </div>
                    <div className="field">
                        <label>{t.fakeSNI}</label>
                        <input type="text" className="mono" value={draft.transport.fake_sni}
                               onChange={e => patch(c => { c.transport.fake_sni = e.target.value })}/>
                    </div>
                </div>
                <div className="field-hint" style={{marginTop: -8, marginBottom: 14}}>{t.fakeSNIHint}</div>

                <div className="field">
                    <label className="check">
                        <input type="checkbox" checked={draft.transport.auto}
                               onChange={e => patch(c => { c.transport.auto = e.target.checked })}/>
                        {t.autoMode}
                    </label>
                    <div className="field-hint">{t.autoModeHint}</div>
                </div>

                <div className="field">
                    <label className="check">
                        <input type="checkbox" checked={draft.transport.spoof}
                               onChange={e => patch(c => { c.transport.spoof = e.target.checked })}/>
                        {t.spoofOn}
                    </label>
                    <div className="field-hint">{t.spoofHint}</div>
                </div>

                <div className="field">
                    <label>{t.mode}</label>
                    <select value={draft.transport.mode} disabled={!draft.transport.spoof}
                            onChange={e => patch(c => { c.transport.mode = e.target.value as 'fast' | 'safe' })}>
                        <option value="fast">{t.modeFast}</option>
                        <option value="safe">{t.modeSafe}</option>
                    </select>
                </div>

                <div className="row">
                    <div className="field">
                        <label>{t.injectDelay}</label>
                        <input type="number" className="num" value={draft.transport.inject_delay_ms}
                               onChange={e => patch(c => { c.transport.inject_delay_ms = num(e.target.value) })}/>
                        <div className="field-hint">{t.injectDelayHint}</div>
                    </div>
                    <div className="field">
                        <label>{t.portRange}</label>
                        <div className="row">
                            <input type="number" className="num" value={draft.transport.port_low}
                                   onChange={e => patch(c => { c.transport.port_low = num(e.target.value) })}/>
                            <input type="number" className="num" value={draft.transport.port_high}
                                   onChange={e => patch(c => { c.transport.port_high = num(e.target.value) })}/>
                        </div>
                    </div>
                </div>
            </div>

            <div className="panel">
                <div className="panel-head">
                    <span className="panel-title">{t.settingsPool}</span>
                    <span className="panel-hint">{t.poolHint}</span>
                </div>

                <div className="field">
                    <label className="check">
                        <input type="checkbox" checked={draft.pool.enabled}
                               onChange={e => patch(c => { c.pool.enabled = e.target.checked })}/>
                        {t.poolEnabled}
                    </label>
                </div>

                <div className="row">
                    <div className="field">
                        <label>{t.poolSize}</label>
                        <input type="number" className="num" value={draft.pool.size}
                               disabled={!draft.pool.enabled}
                               onChange={e => patch(c => { c.pool.size = num(e.target.value) })}/>
                    </div>
                    <div className="field">
                        <label>{t.poolTTL}</label>
                        <input type="number" className="num" value={draft.pool.ttl_seconds}
                               disabled={!draft.pool.enabled}
                               onChange={e => patch(c => { c.pool.ttl_seconds = num(e.target.value) })}/>
                        <div className="field-hint">{t.poolTTLHint}</div>
                    </div>
                </div>
            </div>

            <div className="panel">
                <div className="panel-head"><span className="panel-title">{t.settingsSystem}</span></div>
                <div className="field">
                    <label className="check">
                        <input type="checkbox" checked={autostart}
                               onChange={e => onAutostart(e.target.checked)}/>
                        {t.autostart}
                    </label>
                    <div className="field-hint">{t.autostartHint}</div>
                </div>
                <div className="field-hint">{t.trayHint}</div>
            </div>

            <div className="actions">
                <button className="btn primary" onClick={save}>{t.save}</button>
                <button className="btn" onClick={reset}>{t.reset}</button>
            </div>
        </>
    )
}
