import {useCallback, useEffect, useState} from 'react'
import {
    ActiveProfileJSON,
    DeleteProfile,
    ImportConfigs,
    ListProfiles,
    RenameProfile,
    SelectProfile,
    SetEdgeOverride,
} from '../../wailsjs/go/main/App'
import type {Dict} from '../i18n'
import type {ImportResult, ProfileView} from '../types'

interface Props {
    t: Dict
    onChanged: () => void
}

export default function Configs({t, onChanged}: Props) {
    const [list, setList] = useState<ProfileView[]>([])
    const [text, setText] = useState('')
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState('')
    const [result, setResult] = useState<ImportResult | null>(null)
    const [json, setJson] = useState('')

    const refresh = useCallback(async () => {
        try {
            setList((await ListProfiles()) as ProfileView[])
        } catch (e: any) {
            setError(String(e?.message ?? e))
        }
    }, [])

    useEffect(() => {
        refresh()
    }, [refresh])

    const doImport = async () => {
        setBusy(true)
        setError('')
        setResult(null)
        try {
            const r = (await ImportConfigs(text)) as ImportResult
            setResult(r)
            // Only clear the box on a clean import: if some lines failed, the
            // user needs to still see what they pasted.
            if (r.failed.length === 0) setText('')
            await refresh()
            onChanged()
        } catch (e: any) {
            setError(String(e?.message ?? e))
        } finally {
            setBusy(false)
        }
    }

    const act = async (fn: () => Promise<unknown>) => {
        setError('')
        try {
            await fn()
            await refresh()
            onChanged()
        } catch (e: any) {
            setError(String(e?.message ?? e))
        }
    }

    const showJSON = async () => {
        if (json) {
            setJson('')
            return
        }
        try {
            setJson(await ActiveProfileJSON())
        } catch (e: any) {
            setError(String(e?.message ?? e))
        }
    }

    return (
        <>
            {error && <div className="banner err">{t.errorPrefix}: {error}</div>}

            <div className="panel">
                <div className="panel-head">
                    <span className="panel-title">{t.configsTitle}</span>
                </div>
                <p className="hint">{t.configsHint}</p>

                <textarea
                    className="paste-box mono"
                    rows={4}
                    dir="ltr"
                    spellCheck={false}
                    placeholder={t.importPlaceholder}
                    value={text}
                    onChange={e => setText(e.target.value)}
                />
                <div className="row">
                    <button className="btn primary" onClick={doImport} disabled={busy || !text.trim()}>
                        {busy ? t.importing : t.importBtn}
                    </button>
                    {result && (
                        <span className="hint">
                            {result.added} {t.importedN}
                            {result.existing > 0 && ` · ${result.existing} ${t.existingN}`}
                            {result.failed.length > 0 && ` · ${result.failed.length} ${t.failedN}`}
                        </span>
                    )}
                </div>

                {result && result.failed.length > 0 && (
                    <ul className="fail-list">
                        {result.failed.map((f, i) => <li key={i}>{f}</li>)}
                    </ul>
                )}
            </div>

            {list.length === 0 ? (
                <div className="panel empty">
                    <div className="empty-title">{t.noConfigs}</div>
                    <div className="hint">{t.noConfigsHint}</div>
                </div>
            ) : (
                <div className="cfg-list">
                    {list.map(p => (
                        <div key={p.id} className={`cfg ${p.active ? 'active' : ''} ${p.usable ? '' : 'broken'}`}>
                            <div className="cfg-main">
                                <div className="cfg-name">
                                    {p.name}
                                    {p.active && <span className="tag on">{t.selected}</span>}
                                    {!p.usable && <span className="tag err">{t.cfgUnusable}</span>}
                                </div>
                                <div className="cfg-meta mono">
                                    {p.protocol} · {p.endpoint}
                                    {p.security && p.security !== 'none' && ` · ${p.security}`}
                                    {p.network && ` / ${p.network}`}
                                    {p.sni && ` · ${p.sni}`}
                                </div>

                                {p.problem && <div className="cfg-problem">{p.problem}</div>}

                                {p.warnings.length > 0 && (
                                    <details className="cfg-warn">
                                        <summary>{t.cfgWarnings} ({p.warnings.length})</summary>
                                        <ul>
                                            {p.warnings.map((w, i) => <li key={i}>{w}</li>)}
                                        </ul>
                                    </details>
                                )}

                                <label className="check">
                                    <input
                                        type="checkbox"
                                        checked={p.edgeOverride}
                                        onChange={e => act(() => SetEdgeOverride(p.id, e.target.checked))}
                                    />
                                    <span>{t.edgeOverride}</span>
                                    <span className="hint">— {t.edgeOverrideHint}</span>
                                </label>
                            </div>

                            <div className="cfg-actions">
                                {!p.active && (
                                    <button className="mini-btn" disabled={!p.usable}
                                            onClick={() => act(() => SelectProfile(p.id))}>
                                        {t.selectBtn}
                                    </button>
                                )}
                                <button className="mini-btn" onClick={() => {
                                    const name = window.prompt(t.renameBtn, p.name)
                                    if (name !== null) act(() => RenameProfile(p.id, name))
                                }}>
                                    {t.renameBtn}
                                </button>
                                <button className="mini-btn danger" onClick={() => {
                                    if (window.confirm(t.confirmDelete)) act(() => DeleteProfile(p.id))
                                }}>
                                    {t.deleteBtn}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {list.some(p => p.active) && (
                <div className="panel">
                    <div className="panel-head">
                        <span className="panel-title">xray JSON</span>
                        <button className="mini-btn" onClick={showJSON}>
                            {json ? t.hideJSON : t.showJSON}
                        </button>
                    </div>
                    {json && (
                        <>
                            <p className="banner warn">{t.jsonSecret}</p>
                            <pre className="json-box mono" dir="ltr">{json}</pre>
                            <button className="mini-btn" onClick={() => navigator.clipboard?.writeText(json)}>
                                {t.copyJSON}
                            </button>
                        </>
                    )}
                </div>
            )}
        </>
    )
}
