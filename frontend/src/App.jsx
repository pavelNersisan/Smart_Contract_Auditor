import { useCallback, useEffect, useState } from 'react'
import ContractUpload from './components/ContractUpload.jsx'
import VulnerabilityReport from './components/VulnerabilityReport.jsx'

// All requests are relative: in production FastAPI serves this bundle and the
// API from the same origin, and in dev Vite proxies them to the backend.
const API = {
  audit: '/audit',
  health: '/health',
  detectors: '/detectors',
}

export default function App() {
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [health, setHealth] = useState(null)

  useEffect(() => {
    fetch(API.health)
      .then((r) => (r.ok ? r.json() : null))
      .then(setHealth)
      .catch(() => setHealth(null))
  }, [])

  const runAudit = useCallback(async ({ filename, source }) => {
    setBusy(true)
    setError('')
    setResult(null)
    try {
      const response = await fetch(API.audit, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, filename, run_external_tools: true }),
      })
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}))
        throw new Error(detail.detail || `HTTP ${response.status}`)
      }
      setResult(await response.json())
    } catch (err) {
      setError(err.message || 'Audit request failed')
    } finally {
      setBusy(false)
    }
  }, [])

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>Smart Contract Auditor</h1>
          <p className="tagline">
            Static analysis for Solidity — reentrancy, access control, arithmetic,
            external calls and hygiene, with a 1–100 risk score.
          </p>
        </div>
        <div className="engine-status">
          {health ? (
            <>
              <span className={`dot ${health.solc ? 'ok' : 'warn'}`} />
              <div>
                <strong>{health.solc ? 'Compiler ready' : 'No compiler'}</strong>
                <small>{health.solc_version} · {health.detectors} checks</small>
              </div>
            </>
          ) : (
            <>
              <span className="dot warn" />
              <div>
                <strong>API unreachable</strong>
                <small>is the backend running?</small>
              </div>
            </>
          )}
        </div>
      </header>

      <main className="app-main">
        <ContractUpload onSubmit={runAudit} busy={busy} />
        {error && <div className="alert error">{error}</div>}
        {busy && <div className="alert info">Analysing…</div>}
        {result && <VulnerabilityReport result={result} />}
      </main>

      <footer className="app-footer">
        Static analysis cannot prove the absence of bugs. Treat every report as a
        prioritised starting point, not a guarantee.
      </footer>
    </div>
  )
}
