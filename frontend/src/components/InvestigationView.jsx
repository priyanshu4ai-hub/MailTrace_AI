import { useEffect, useRef, useState, createContext, useContext } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { DEMO_CASES } from '../data/demoCases'
import { OverviewTab } from './tabs/OverviewTab'
import { InvestigationTab } from './tabs/InvestigationTab'
import { EvidenceTab } from './tabs/EvidenceTab'
import { IndicatorsTab } from './tabs/IndicatorsTab'
import { TimelineTab } from './tabs/TimelineTab'
import { ReportsTab } from './tabs/ReportsTab'

const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

/* ── Theme Context ─────────────────────────────────────────── */
const ThemeCtx = createContext()
function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('mt-theme')
      if (saved) return saved === 'dark'
      return true
    }
    return true
  })
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    document.documentElement.classList.toggle('light', !dark)
    localStorage.setItem('mt-theme', dark ? 'dark' : 'light')
  }, [dark])
  return <ThemeCtx.Provider value={{ dark, toggle: () => setDark(d => !d) }}>{children}</ThemeCtx.Provider>
}

/* ── Node colors ───────────────────────────────────────────── */
const NODE_COLORS = {
  email: '#0ea5e9', sender: '#ef4444', recipient: '#10b981',
  relay_ip: '#f59e0b', authentication: '#8b5cf6', threat_assessment: '#f97316',
}

/* ── Navigation Items ──────────────────────────────────────── */
const NAV = [
  { label: 'Overview', icon: GridIcon },
  { label: 'Investigation', icon: SearchIcon },
  { label: 'Evidence', icon: FileIcon },
  { label: 'Indicators', icon: AlertIcon },
  { label: 'Timeline', icon: ClockIcon },
  { label: 'Reports', icon: DocIcon },
]

/* ══════════════════════════════════════════════════════════════
   SIDEBAR COMPONENT
   ══════════════════════════════════════════════════════════════ */
function Sidebar({ activeTab, onSelectTab }) {
  const { dark } = useContext(ThemeCtx)
  return (
    <aside className="hidden lg:flex flex-col w-[210px] flex-shrink-0 border-r transition-colors duration-200"
      style={{ background: 'var(--sidebar-bg)', borderColor: 'var(--border)' }}>
      {/* Brand */}
      <div className="px-5 py-5 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shadow-sm" style={{ background: 'var(--accent)' }}>
            <ShieldIcon className="w-4 h-4 text-white" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-primary)' }}>MailTrace AI</p>
            <p className="text-[10px] tracking-wider uppercase font-semibold" style={{ color: 'var(--sidebar-text)' }}>Email Forensics</p>
          </div>
        </div>
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {NAV.map(({ label, icon: Icon }) => {
          const isActive = activeTab === label
          return (
            <button
              key={label}
              onClick={() => onSelectTab(label)}
              className="w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs transition-all duration-200"
              style={{
                color: isActive ? 'var(--sidebar-active)' : 'var(--sidebar-text)',
                background: isActive ? 'var(--accent-muted)' : 'transparent',
                fontWeight: isActive ? '600' : '500',
              }}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </button>
          )
        })}
      </nav>

      {/* Analyst profile */}
      <div className="px-4 py-4 border-t flex items-center gap-3" style={{ borderColor: 'var(--border)' }}>
        <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white shadow-sm" style={{ background: 'var(--accent)' }}>
          AD
        </div>
        <div>
          <p className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>Analyst</p>
          <p className="text-[10px] flex items-center gap-1.5 font-medium" style={{ color: 'var(--sidebar-text)' }}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />Online (SIH26106)
          </p>
        </div>
      </div>
    </aside>
  )
}

/* ══════════════════════════════════════════════════════════════
   TOP BAR COMPONENT
   ══════════════════════════════════════════════════════════════ */
function TopBar({
  caseId,
  status,
  threatLevel,
  confidence,
  onFile,
  file,
  loading,
  isDemo,
  demoCaseKey,
  onSelectDemoCase,
  onExportReport,
}) {
  const { dark, toggle } = useContext(ThemeCtx)
  const [showCaseDropdown, setShowCaseDropdown] = useState(false)
  const dropdownRef = useRef(null)

  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setShowCaseDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const threatColor = threatLevel === 'High' ? 'text-red-500' : threatLevel === 'Medium' ? 'text-amber-500' : 'text-emerald-500'

  return (
    <header className="flex-shrink-0 flex items-center justify-between px-6 py-3 border-b no-print transition-colors duration-200"
      style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
      {/* Case metadata */}
      <div className="flex items-center gap-6 sm:gap-8">
        <MetaItem label="Case ID" value={caseId} mono />
        <MetaItem label="Status">
          <span className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${loading ? 'bg-amber-500 animate-pulse' : 'bg-emerald-500'}`} />
            <span className="text-xs sm:text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{status}</span>
          </span>
        </MetaItem>
        <MetaItem label="Threat Level">
          <span className={`text-xs sm:text-sm font-bold uppercase ${threatColor}`}>
            {threatLevel}
          </span>
        </MetaItem>
        <MetaItem label="Confidence" value={`${confidence}%`} />
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Upload Button */}
        <label
          className="flex items-center gap-2 px-3.5 py-1.5 sm:px-4 sm:py-2 rounded-lg text-xs sm:text-sm font-semibold text-white transition-all duration-200 hover:opacity-90 shadow-sm"
          style={{ background: 'var(--accent)', cursor: 'pointer' }}
        >
          <UploadIcon className="w-4 h-4" />
          <span>{loading ? 'Analyzing…' : file ? file.name : 'Upload .EML'}</span>
          <input className="sr-only" type="file" accept=".eml,.txt,message/rfc822,text/plain" onChange={onFile} disabled={loading} />
        </label>

        {/* Demo Case Switcher Dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setShowCaseDropdown(!showCaseDropdown)}
            className="flex items-center gap-1.5 px-3 py-1.5 sm:py-2 rounded-lg text-xs sm:text-sm font-medium border transition-colors"
            style={{
              borderColor: 'var(--border-strong)',
              color: isDemo ? 'var(--accent)' : 'var(--text-secondary)',
              background: 'var(--bg-raised)',
            }}
          >
            <span>{isDemo ? (demoCaseKey === 'phishing' ? 'Scenario: Phishing MFA' : demoCaseKey === 'bec' ? 'Scenario: BEC Fraud' : 'Scenario: Clean Standup') : 'Custom Upload'}</span>
            <ChevronDownIcon className="w-3.5 h-3.5 opacity-70" />
          </button>

          {showCaseDropdown && (
            <div
              className="absolute right-0 mt-1 w-72 rounded-xl shadow-xl border p-1.5 z-50 animate-fade-in"
              style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
            >
              <p className="text-[10px] uppercase font-bold px-3 py-1.5" style={{ color: 'var(--text-muted)' }}>
                Select Investigation Scenario
              </p>
              {[
                { key: 'phishing', label: '1. Phishing: M365 MFA Token Harvester', sub: 'Critical 94% • SPF/DMARC Fail • Russian Relay' },
                { key: 'bec', label: '2. BEC: CEO M&A Wire Fraud ($142k)', sub: 'Critical 96% • Lookalike Domain • Hetzner' },
                { key: 'safe', label: '3. Clean: Internal Standup Notes', sub: 'Verified Clean 98% • Full DKIM/DMARC Pass' },
              ].map(c => (
                <button
                  key={c.key}
                  onClick={() => {
                    onSelectDemoCase(c.key)
                    setShowCaseDropdown(false)
                  }}
                  className="w-full text-left px-3 py-2 rounded-lg text-xs transition-colors hover:bg-slate-500/10"
                  style={{
                    background: demoCaseKey === c.key && isDemo ? 'var(--accent-muted)' : 'transparent',
                    color: demoCaseKey === c.key && isDemo ? 'var(--accent)' : 'var(--text-primary)',
                  }}
                >
                  <p className="font-semibold">{c.label}</p>
                  <p className="text-[10px] opacity-75 mt-0.5" style={{ color: 'var(--text-muted)' }}>{c.sub}</p>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Export Report Action Button */}
        <button
          onClick={onExportReport}
          className="hidden md:flex items-center gap-1.5 px-3 py-1.5 sm:py-2 rounded-lg text-xs sm:text-sm font-medium border transition-colors hover:bg-slate-500/10"
          style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)', color: 'var(--text-primary)' }}
        >
          <DocIcon className="w-3.5 h-3.5 text-sky-500" />
          <span>Export Report</span>
        </button>

        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="p-2 rounded-lg border transition-colors duration-200 hover:opacity-80 flex items-center justify-center"
          style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)', color: 'var(--text-primary)' }}
          aria-label="Toggle theme"
          title={dark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {dark ? <SunIcon className="w-4 h-4 text-amber-400" /> : <MoonIcon className="w-4 h-4 text-sky-600" />}
        </button>
      </div>
    </header>
  )
}

function MetaItem({ label, value, mono, children }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider font-semibold mb-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
      {children || <p className={`text-xs sm:text-sm font-bold ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-primary)' }}>{value}</p>}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════
   MAIN INVESTIGATION ROOT COMPONENT
   ══════════════════════════════════════════════════════════════ */
function InvestigationView() {
  const [activeTab, setActiveTab] = useState('Overview')
  const [demoCaseKey, setDemoCaseKey] = useState('phishing')
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(DEMO_CASES.phishing)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [isDemo, setIsDemo] = useState(true)

  async function investigate(f) {
    if (!f) return
    setError(''); setLoading(true); setIsDemo(false)
    try {
      const body = new FormData()
      body.append('file', f)
      const res = await fetch(`${API_URL}/api/v1/investigate`, { method: 'POST', body })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.detail || 'Investigation request failed.')
      setResult(data)
    } catch (e) {
      setError(e.message || 'Cannot reach the analysis API.')
    } finally {
      setLoading(false)
    }
  }

  const onFile = (e) => {
    const f = e.target.files?.[0]
    setFile(f)
    if (f) investigate(f)
  }

  const handleSelectDemoCase = (key) => {
    if (DEMO_CASES[key]) {
      setDemoCaseKey(key)
      setResult(DEMO_CASES[key])
      setIsDemo(true)
      setFile(null)
      setError('')
    }
  }

  const t = result?.threat_analysis
  const cls = t?.classification ?? 'Unknown'
  const level = (t?.confidence_score >= 80 || cls === 'Phishing' || cls === 'BEC') ? 'High' : t?.confidence_score >= 50 ? 'Medium' : 'Low'
  const caseId = isDemo ? (DEMO_CASES[demoCaseKey]?.id || 'INC-2026-08491') : `INC-${Date.now().toString(36).toUpperCase()}`

  return (
    <ThemeProvider>
      <div className="h-screen flex overflow-hidden" style={{ background: 'var(--bg-base)', color: 'var(--text-primary)' }}>
        {/* Persistent Sidebar */}
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <TopBar
            caseId={caseId}
            status={loading ? 'Processing…' : 'Completed'}
            threatLevel={level}
            confidence={t?.confidence_score ?? 0}
            onFile={onFile}
            file={file}
            loading={loading}
            isDemo={isDemo}
            demoCaseKey={demoCaseKey}
            onSelectDemoCase={handleSelectDemoCase}
            onExportReport={() => setActiveTab('Reports')}
          />

          {/* Tab Navigation for Mobile / Tablet */}
          <div className="lg:hidden flex overflow-x-auto scrollbar-thin px-4 py-2 border-b gap-2"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            {NAV.map(({ label, icon: Icon }) => (
              <button
                key={label}
                onClick={() => setActiveTab(label)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors"
                style={{
                  background: activeTab === label ? 'var(--accent)' : 'var(--bg-raised)',
                  color: activeTab === label ? '#ffffff' : 'var(--text-secondary)',
                }}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{label}</span>
              </button>
            ))}
          </div>

          {/* Active Tab View */}
          <main className="flex-1 overflow-y-auto scrollbar-thin p-4 sm:p-6 space-y-5">
            {error && (
              <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-xs sm:text-sm animate-fade-in font-medium"
                style={{ background: 'var(--danger-muted)', color: 'var(--danger)', border: '1px solid var(--danger)' }}>
                <AlertIcon className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {isDemo && activeTab === 'Overview' && (
              <div className="flex items-center justify-between px-4 py-2.5 rounded-xl text-xs font-medium animate-fade-in border"
                style={{ background: 'var(--accent-muted)', borderColor: 'var(--accent)', color: 'var(--accent)' }}>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse" />
                  <span>Viewing Scenario: <strong>{DEMO_CASES[demoCaseKey]?.name}</strong>. Upload an .eml file at any time to run live AI triage.</span>
                </div>
                <button onClick={() => setActiveTab('Investigation')} className="underline text-[11px] font-bold">
                  Explore Analysis →
                </button>
              </div>
            )}

            {activeTab === 'Overview' && (
              <OverviewTab
                result={result}
                t={t}
                cls={cls}
                GraphCanvas={GraphCanvas}
                onSwitchTab={setActiveTab}
              />
            )}

            {activeTab === 'Investigation' && (
              <InvestigationTab
                result={result}
                t={t}
                GraphCanvas={GraphCanvas}
              />
            )}

            {activeTab === 'Evidence' && (
              <EvidenceTab
                result={result}
              />
            )}

            {activeTab === 'Indicators' && (
              <IndicatorsTab
                result={result}
                t={t}
              />
            )}

            {activeTab === 'Timeline' && (
              <TimelineTab
                result={result}
                t={t}
              />
            )}

            {activeTab === 'Reports' && (
              <ReportsTab
                result={result}
                t={t}
                caseId={caseId}
              />
            )}
          </main>
        </div>
      </div>
    </ThemeProvider>
  )
}

/* ══════════════════════════════════════════════════════════════
   GRAPH CANVAS REUSABLE COMPONENT
   ══════════════════════════════════════════════════════════════ */
function GraphCanvas({ graph, geoHops, onNodeClick }) {
  const ref = useRef(null)
  const [dim, setDim] = useState({ w: 0, h: 0 })
  const { dark } = useContext(ThemeCtx)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new ResizeObserver(([e]) => setDim({ w: e.contentRect.width, h: e.contentRect.height }))
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  const labelColor = dark ? '#e2e8f0' : '#1e293b'
  const bgRect = dark ? 'rgba(15, 23, 42, 0.88)' : 'rgba(255, 255, 255, 0.92)'

  return (
    <div className="absolute inset-0" ref={ref}>
      {dim.w > 0 && dim.h > 0 && (
        <ForceGraph2D
          graphData={graph}
          width={dim.w}
          height={dim.h}
          backgroundColor="transparent"
          nodeLabel={(n) => `${n.name} (${n.type})`}
          nodeRelSize={6}
          linkColor={() => dark ? 'rgba(56,189,248,0.25)' : 'rgba(14,165,233,0.3)'}
          linkWidth={1.2}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={() => dark ? '#38bdf8' : '#0ea5e9'}
          linkDirectionalParticleSpeed={0.004}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          linkLabel={(l) => l.relation.replace(/_/g, ' ')}
          cooldownTicks={90}
          onNodeClick={(node) => onNodeClick && onNodeClick(node)}
          nodeCanvasObject={(node, ctx, scale) => {
            const color = NODE_COLORS[node.type] || '#64748b'
            const r = 5.5

            // Outer soft halo
            ctx.beginPath()
            ctx.arc(node.x, node.y, r + 2.5, 0, Math.PI * 2)
            ctx.fillStyle = color + '22'
            ctx.fill()

            // Core node
            ctx.beginPath()
            ctx.arc(node.x, node.y, r, 0, Math.PI * 2)
            ctx.fillStyle = color
            ctx.fill()

            // Label pill
            const fs = Math.max(10 / scale, 3.2)
            ctx.font = `500 ${fs}px Inter, sans-serif`
            const tw = ctx.measureText(node.name || node.id).width
            ctx.fillStyle = bgRect
            ctx.fillRect(node.x - tw / 2 - 3, node.y + r + 2, tw + 6, fs + 4)
            ctx.textAlign = 'center'
            ctx.textBaseline = 'top'
            ctx.fillStyle = labelColor
            ctx.fillText(node.name || node.id, node.x, node.y + r + 4)
          }}
        />
      )}

      {/* Legend bar */}
      <div className="absolute bottom-0 inset-x-0 flex flex-wrap items-center gap-3 sm:gap-4 px-3 py-2 border-t text-[10px]"
        style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', opacity: 0.95 }}>
        {Object.entries(NODE_COLORS).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1.5 font-medium" style={{ color: 'var(--text-muted)' }}>
            <span className="w-2 h-2 rounded-full" style={{ background: c }} />
            {t.replace(/_/g, ' ')}
          </span>
        ))}
      </div>
    </div>
  )
}

/* ── Inline SVG Icons ───────────────────────────────────────── */
function ShieldIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> }
function GridIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg> }
function SearchIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> }
function FileIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> }
function AlertIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg> }
function ClockIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> }
function DocIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> }
function UploadIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg> }
function SunIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg> }
function MoonIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg> }
function ChevronDownIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg> }

export default InvestigationView
