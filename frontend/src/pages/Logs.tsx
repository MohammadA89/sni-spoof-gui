import {useEffect, useRef} from 'react'
import type {LogEntry} from '../types'
import type {Dict} from '../i18n'

interface Props {
    t: Dict
    logs: LogEntry[]
    onClear: () => void
}

export default function Logs({t, logs, onClear}: Props) {
    const endRef = useRef<HTMLDivElement>(null)
    const viewRef = useRef<HTMLDivElement>(null)

    // Follow the tail only while the user is already at the bottom, so reading
    // back through history is not yanked away by every new line.
    useEffect(() => {
        const view = viewRef.current
        if (!view) return
        const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 60
        if (atBottom) endRef.current?.scrollIntoView({block: 'end'})
    }, [logs])

    return (
        <>
            <h1 className="page-title">{t.navLogs}</h1>
            <div className="actions" style={{marginBottom: 12}}>
                <button className="btn" onClick={onClear}>{t.clearLogs}</button>
            </div>
            <div className="log-view" ref={viewRef}>
                {logs.length === 0 && <div className="empty">{t.noLogs}</div>}
                {logs.map((l, i) => (
                    <div className="log-line" key={i}>
                        <span className="log-time">{l.time}</span>
                        <span>{l.message}</span>
                    </div>
                ))}
                <div ref={endRef}/>
            </div>
        </>
    )
}
