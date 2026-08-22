import {useCallback, useEffect, useRef, useState} from 'react'
import {EventsOn} from '../wailsjs/runtime/runtime'
import {
    ClearLogs,
    DefaultConfig,
    GetAutostart,
    SetAutostart,
    GetConfig,
    GetLogs,
    GetSnapshot,
    SaveConfig,
    Start,
    Stop,
} from '../wailsjs/go/main/App'

import {dict, type Lang} from './i18n'
import {emptySnapshot, type Config, type LogEntry, type Snapshot} from './types'
import Dashboard from './pages/Dashboard'
import Settings from './pages/Settings'
import Scanner from './pages/Scanner'
import Logs from './pages/Logs'
import About from './pages/About'

type Page = 'dashboard' | 'settings' | 'scanner' | 'logs' | 'about'
type Theme = 'dark' | 'light'

// Roughly a minute of history at the backend's half-second push interval.
const HISTORY_POINTS = 120

export default function App() {
    const [page, setPage] = useState<Page>('dashboard')
    const [lang, setLang] = useState<Lang>('fa')
    const [theme, setTheme] = useState<Theme>('dark')

    const [snap, setSnap] = useState<Snapshot>(emptySnapshot)
    const [config, setConfig] = useState<Config | null>(null)
    const [logs, setLogs] = useState<LogEntry[]>([])
    const [autostart, setAutostart] = useState(false)
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState('')

    const [history, setHistory] = useState<{ up: number[]; down: number[] }>({
        up: new Array(HISTORY_POINTS).fill(0),
        down: new Array(HISTORY_POINTS).fill(0),
    })

    const t = dict(lang)

    // The document element carries both direction and theme, so plain CSS can
    // mirror the layout and swap palettes without any component knowing.
    useEffect(() => {
        document.documentElement.lang = lang
        document.documentElement.dir = t.dir
        document.documentElement.dataset.theme = theme
    }, [lang, theme, t.dir])

    // Subscribe once. Wails delivers snapshots on a timer from the backend
    // rather than the frontend polling, which keeps the two in step.
    const mounted = useRef(false)
    useEffect(() => {
        if (mounted.current) return
        mounted.current = true

        GetSnapshot().then(s => setSnap(s as Snapshot)).catch(() => {})
        GetConfig().then(c => setConfig(c as Config)).catch(() => {})
        GetLogs().then(l => setLogs(l as LogEntry[])).catch(() => {})
        GetAutostart().then(setAutostart).catch(() => {})

        EventsOn('stats', (s: Snapshot) => {
            setSnap(s)
            setHistory(h => ({
                up: [...h.up.slice(1), s.rateUp],
                down: [...h.down.slice(1), s.rateDown],
            }))
        })
        EventsOn('log', (entry: LogEntry) => {
            setLogs(prev => (prev.length >= 500 ? [...prev.slice(1), entry] : [...prev, entry]))
        })
    }, [])

    const toggle = useCallback(async () => {
        setBusy(true)
        setError('')
        try {
            if (snap.running) {
                await Stop()
                setSnap(s => ({...s, running: false}))
            } else {
                await Start()
                const s = await GetSnapshot()
                setSnap(s as Snapshot)
            }
        } catch (e: any) {
            const msg = String(e?.message ?? e)
            // The most common first-run failure by far is missing elevation,
            // and the raw driver error does not say what to do about it.
            setError(/administrator|privilege/i.test(msg) ? `${msg} — ${t.adminNeeded}` : msg)
        } finally {
            setBusy(false)
        }
    }, [snap.running, t.adminNeeded])

    const saveConfig = useCallback(async (c: Config): Promise<string> => {
        try {
            await SaveConfig(c as any)
            setConfig(c)
            return ''
        } catch (e: any) {
            return String(e?.message ?? e)
        }
    }, [])

    const resetConfig = useCallback(async (): Promise<Config> => {
        const c = (await DefaultConfig()) as Config
        return c
    }, [])

    const toggleAuto = useCallback(async (on: boolean) => {
        if (!config) return
        const next: Config = {...config, transport: {...config.transport, auto: on}}
        await saveConfig(next)
    }, [config, saveConfig])

    const toggleAutostart = useCallback(async (on: boolean) => {
        try {
            await SetAutostart(on)
            setAutostart(on)
        } catch {
            // The backend logs the reason; leave the toggle where it was.
        }
    }, [])

    const clearLogs = useCallback(async () => {
        await ClearLogs()
        setLogs([])
    }, [])

    const NAV: Array<[Page, string]> = [
        ['dashboard', t.navDashboard],
        ['settings', t.navSettings],
        ['scanner', t.navScanner],
        ['logs', t.navLogs],
        ['about', t.navAbout],
    ]

    return (
        <div className="app">
            <aside className="sidebar">
                <div className="brand">
                    <span className={`brand-dot ${snap.running ? 'on' : ''}`}/>
                    <span className="brand-name">{t.appName}</span>
                </div>

                {NAV.map(([id, label]) => (
                    <button
                        key={id}
                        className={`nav-item ${page === id ? 'active' : ''}`}
                        onClick={() => setPage(id)}
                    >
                        {label}
                    </button>
                ))}

                <div className="sidebar-foot">
                    <button className="chip" onClick={() => setLang(lang === 'fa' ? 'en' : 'fa')}>
                        {lang === 'fa' ? 'EN' : 'فا'}
                    </button>
                    <button className="chip" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
                        {theme === 'dark' ? '☀' : '☾'}
                    </button>
                </div>
            </aside>

            <main className="main">
                {page === 'dashboard' && (
                    <Dashboard t={t} snap={snap} history={history} busy={busy} error={error}
                               auto={config?.transport.auto ?? true}
                               onToggle={toggle} onToggleAuto={toggleAuto}/>
                )}
                {page === 'settings' && (
                    <Settings t={t} config={config} onSave={saveConfig} onReset={resetConfig}
                              autostart={autostart} onAutostart={toggleAutostart}/>
                )}
                {page === 'scanner' && <Scanner t={t}/>}
                {page === 'logs' && <Logs t={t} logs={logs} onClear={clearLogs}/>}
                {page === 'about' && <About t={t}/>}
            </main>
        </div>
    )
}
