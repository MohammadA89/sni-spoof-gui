import type {Dict} from '../i18n'
import {BrowserOpenURL} from '../../wailsjs/runtime/runtime'

const UPSTREAM = 'https://github.com/patterniha/SNI-Spoofing'

export default function About({t}: { t: Dict }) {
    return (
        <div className="about">
            <h1 className="page-title">{t.navAbout}</h1>

            <div className="panel">
                <div className="panel-head"><span className="panel-title">{t.aboutWhat}</span></div>
                <p>{t.aboutWhatBody}</p>
                <p><strong>{t.aboutNotVPN}</strong></p>
            </div>

            <div className="panel">
                <p>
                    {t.aboutCredit}{' '}
                    <a href={UPSTREAM} onClick={e => {
                        // Keep the link out of the webview itself; open it in
                        // the user's real browser.
                        e.preventDefault()
                        BrowserOpenURL(UPSTREAM)
                    }}>patterniha/SNI-Spoofing</a>
                    {' — '}{t.aboutLicense}
                </p>
            </div>
        </div>
    )
}
