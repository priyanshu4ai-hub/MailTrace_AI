import React, { useEffect, useState } from 'react'

const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

/* ── Event-type display metadata ─────────────────────────────────────── */
const EVENT_META = {
  CASE_CREATED:                { label: 'Case Created',              icon: '📁', category: 'CASE_MGMT' },
  CASE_UPDATED:                { label: 'Case Updated',              icon: '✏️',  category: 'CASE_MGMT' },
  EMAIL_UPLOADED:              { label: 'Email Uploaded',            icon: '📤', category: 'INGEST' },
  EMAIL_PARSED:                { label: 'Email Parsed',              icon: '📧', category: 'PARSER' },
  AUTH_ANALYSIS_COMPLETED:     { label: 'Authentication Analysis',   icon: '🔐', category: 'AUTH_ENGINE' },
  PHISHING_ANALYSIS_COMPLETED: { label: 'Phishing Analysis',        icon: '🎣', category: 'PHISHING_ENGINE' },
  IOC_EXTRACTION_COMPLETED:    { label: 'IOC Extraction',            icon: '🔍', category: 'EXTRACTION' },
  GEOINT_COMPLETED:            { label: 'GeoIP Intelligence',        icon: '🌍', category: 'GEO_OSINT' },
  GEOINT_UNAVAILABLE:          { label: 'GeoIP Intelligence',        icon: '🌍', category: 'GEO_OSINT' },
  AI_ANALYSIS_COMPLETED:       { label: 'AI Investigation',          icon: '🤖', category: 'AI_ENGINE' },
  AI_ANALYSIS_SKIPPED:         { label: 'AI Investigation',          icon: '🤖', category: 'AI_ENGINE' },
  ATTACK_GRAPH_GENERATED:      { label: 'Attack Graph',              icon: '🕸️', category: 'GRAPH_ENGINE' },
  EVIDENCE_HASH_GENERATED:     { label: 'Evidence Hash Sealed',      icon: '🔒', category: 'CRYPTOGRAPHY' },
  INVESTIGATION_COMPLETED:     { label: 'Investigation Completed',   icon: '✅', category: 'SUMMARY' },
  ANALYST_NOTE_ADDED:          { label: 'Analyst Note Added',        icon: '📝', category: 'CASE_MGMT' },
  REPORT_GENERATED:            { label: 'Report Generated',          icon: '📊', category: 'REPORTING' },
}

function getEventStatus(eventType) {
  if (eventType === 'GEOINT_UNAVAILABLE') return 'UNAVAILABLE'
  if (eventType === 'AI_ANALYSIS_SKIPPED') return 'SKIPPED'
  if (eventType.endsWith('_FAILED')) return 'FAILED'
  if (eventType === 'CASE_CREATED' || eventType === 'CASE_UPDATED') return 'LOGGED'
  if (eventType === 'ANALYST_NOTE_ADDED') return 'LOGGED'
  if (eventType === 'EMAIL_UPLOADED') return 'COMPLETED'
  if (eventType === 'EVIDENCE_HASH_GENERATED') return 'SEALED'
  return 'COMPLETED'
}

function StatusBadge({ status }) {
  const styles = {
    COMPLETED:   'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    SEALED:      'text-sky-400 bg-sky-500/10 border-sky-500/30',
    SKIPPED:     'text-amber-400 bg-amber-500/10 border-amber-500/30',
    UNAVAILABLE: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    FAILED:      'text-red-500 bg-red-500/10 border-red-500/30',
    LOGGED:      'text-indigo-400 bg-indigo-500/10 border-indigo-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${styles[status] || styles.COMPLETED}`}>
      {status}
    </span>
  )
}

function formatTs(iso) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  } catch { return iso }
}

function parseMeta(raw) {
  if (!raw) return {}
  try { return JSON.parse(raw) } catch { return {} }
}

/* ── Live Timeline (case-linked, database-backed) ─────────────── */
function LiveTimeline({ caseId }) {
  const [timeline, setTimeline] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)

  const fetchTimeline = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_URL}/api/v1/cases/${caseId}/timeline`)
      if (!res.ok) throw new Error(`API returned ${res.status}`)
      const data = await res.json()
      setTimeline(data)
      if (data.events?.length && !selected) {
        setSelected(data.events[data.events.length - 1])
      }
    } catch (err) {
      setError(err.message || 'Failed to load timeline from server.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (caseId) fetchTimeline()
  }, [caseId])

  if (loading) return (
    <div className="flex items-center gap-3 p-8 animate-pulse text-xs text-gray-500">
      <span className="w-3 h-3 rounded-full bg-sky-500 animate-ping" />
      Loading forensic timeline from database...
    </div>
  )

  if (error) return (
    <div className="p-4 rounded-xl text-xs text-red-400 bg-red-500/10 border border-red-500/20">
      ⚠ {error}
    </div>
  )

  if (!timeline || timeline.events.length === 0) return (
    <div className="p-12 text-center space-y-2">
      <p className="text-2xl">🔍</p>
      <p className="text-xs font-semibold text-gray-400">No investigation events yet.</p>
      <p className="text-[10px] text-gray-500">Upload an .eml file to this case to begin forensic triage.</p>
    </div>
  )

  const currentEvent = selected || timeline.events[timeline.events.length - 1]

  return (
    <div className="grid xl:grid-cols-12 gap-5">
      {/* Vertical Timeline List */}
      <section className="xl:col-span-7 rounded-xl overflow-hidden"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>

        <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            Pipeline Execution Steps ({timeline.total_events} Events)
          </span>
          <div className="flex items-center gap-2">
            {timeline.total_duration_ms !== null && timeline.total_duration_ms !== undefined && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-500 font-bold border border-emerald-500/20">
                Δ {timeline.total_duration_ms}ms total
              </span>
            )}
            <button onClick={fetchTimeline} className="text-[10px] px-2 py-0.5 rounded border text-gray-400 hover:text-gray-300 transition-colors"
              style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
              ↻
            </button>
          </div>
        </div>

        <div className="relative p-4 space-y-0">
          {timeline.events.map((evt, idx) => {
            const meta = EVENT_META[evt.event_type] || { label: evt.event_type, icon: '📌', category: 'OTHER' }
            const evtStatus = getEventStatus(evt.event_type)
            const parsed = parseMeta(evt.event_metadata)
            const durationMs = parsed.duration_ms
            const isSelected = selected?.id === evt.id
            const isLast = idx === timeline.events.length - 1

            return (
              <div key={evt.id} className="relative flex gap-3">
                {/* Vertical connector line */}
                {!isLast && (
                  <div className="absolute left-[14px] top-7 bottom-0 w-px bg-gradient-to-b from-sky-500/30 to-transparent z-0" />
                )}

                {/* Icon circle */}
                <div className={`relative z-10 w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-[13px] transition-all
                  ${isSelected ? 'ring-2 ring-sky-500' : ''}`}
                  style={{ background: isSelected ? 'var(--accent)' : 'var(--bg-raised)', border: '1px solid var(--border)' }}>
                  {meta.icon}
                </div>

                {/* Event content */}
                <div
                  onClick={() => setSelected(evt)}
                  className={`flex-1 mb-3 pb-3 rounded-xl border cursor-pointer transition-all p-3
                    ${isSelected ? 'ring-1 ring-sky-500/60' : 'hover:bg-slate-500/5'}`}
                  style={{ background: isSelected ? 'var(--bg-raised)' : 'transparent', borderColor: isSelected ? 'var(--border)' : 'transparent' }}>

                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold" style={{ color: 'var(--text-primary)' }}>
                          {meta.label}
                        </span>
                        <span className="text-[9px] font-mono uppercase tracking-wider text-sky-500 font-semibold">
                          {meta.category}
                        </span>
                      </div>
                      <p className="text-[10px] mt-0.5 line-clamp-2" style={{ color: 'var(--text-secondary)' }}>
                        {evt.description}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-1 flex-shrink-0">
                      <StatusBadge status={evtStatus} />
                      <span className="font-mono text-[9px] text-gray-500">{formatTs(evt.timestamp)}</span>
                      {durationMs !== undefined && (
                        <span className="font-mono text-[9px] text-gray-500">Δ {durationMs}ms</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* Event Detail Inspector */}
      {currentEvent && (() => {
        const meta = EVENT_META[currentEvent.event_type] || { label: currentEvent.event_type, icon: '📌', category: 'OTHER' }
        const evtStatus = getEventStatus(currentEvent.event_type)
        const parsed = parseMeta(currentEvent.event_metadata)

        return (
          <section className="xl:col-span-5 rounded-xl p-5 flex flex-col space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>

            <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                Stage Forensic Telemetry
              </h3>
              <span className="text-[10px] font-mono text-sky-500">{meta.icon} {meta.category}</span>
            </div>

            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Stage Name</p>
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{meta.label}</h4>
                <StatusBadge status={evtStatus} />
              </div>
            </div>

            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Execution Summary</p>
              <p className="text-xs leading-relaxed p-3 rounded-lg" style={{ background: 'var(--bg-raised)', color: 'var(--text-secondary)' }}>
                {currentEvent.description}
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Timestamp</p>
              <span className="font-mono text-xs text-sky-400">{currentEvent.timestamp}</span>
            </div>

            {Object.keys(parsed).length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-2">Captured Artifact Metadata</p>
                <dl className="space-y-1.5 text-xs">
                  {Object.entries(parsed).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between p-2 rounded border"
                      style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                      <dt className="text-gray-500 font-medium capitalize">{k.replace(/_/g, ' ')}</dt>
                      <dd className="font-mono text-[11px] font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}
          </section>
        )
      })()}
    </div>
  )
}

/* ── Static / Demo Timeline (no case linked) ─────────────────── */
function StaticTimeline({ result, t }) {
  const [activeStep, setActiveStep] = useState(0)

  const auth = result?.authentication || {}
  const geoHops = result?.geo_hops || result?.geoHops || []

  const pipelineStages = [
    {
      title: 'Email Ingest & RFC 822 Validation',
      time: '—',
      duration: '—',
      status: 'COMPLETED',
      category: 'PARSER',
      icon: '📧',
      description: 'The .eml message stream was read, size-checked against the 5 MB policy limit, and parsed into canonical envelope and header objects.',
      metadata: {
        'Message-ID': result?.email?.message_id || '<unknown>',
        'URL Count': `${result?.email?.urls?.length || 0}`,
        'Link Mismatches': `${result?.email?.link_mismatches?.length || 0}`,
      },
    },
    {
      title: 'SPF, DKIM & DMARC Authentication Audit',
      time: '—',
      duration: '—',
      status: (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass') ? 'COMPLETED' : 'FLAGGED',
      category: 'AUTH_ENGINE',
      icon: '🔐',
      description: `Evaluated RFC 7208 SPF records, RFC 6376 DKIM signatures, and RFC 7489 DMARC policy. SPF=${auth.spf}, DKIM=${auth.dkim}, DMARC=${auth.dmarc}.`,
      metadata: {
        'SPF Verification': auth.spf?.toUpperCase() || 'NONE',
        'DKIM Signature': auth.dkim?.toUpperCase() || 'NONE',
        'DMARC Alignment': auth.dmarc?.toUpperCase() || 'NONE',
      },
    },
    {
      title: 'Network Hop & GeoIP OSINT Resolution',
      time: '—',
      duration: '—',
      status: geoHops.length > 0 ? 'COMPLETED' : 'UNAVAILABLE',
      category: 'GEO_OSINT',
      icon: '🌍',
      description: geoHops.length > 0
        ? `Resolved ${geoHops.length} relay hop(s). First relay: ${geoHops[0]?.ip || '—'} (${geoHops[0]?.country || '—'}).`
        : 'No relay hops resolved. GeoIP service may be unavailable or email has no Received headers.',
      metadata: {
        'Relay IP': geoHops[0]?.ip || '—',
        'Location': `${geoHops[0]?.city || '—'}, ${geoHops[0]?.country || '—'}`,
        'Hop Count': `${geoHops.length}`,
      },
    },
    {
      title: 'Threat Intelligence & AI Analysis',
      time: '—',
      duration: '—',
      status: t?.confidence_score >= 70 ? 'FLAGGED' : 'COMPLETED',
      category: 'AI_ENGINE',
      icon: '🤖',
      description: `Threat detection engine classified email as ${t?.classification || '—'} with ${t?.confidence_score || 0}% confidence. MITRE: ${t?.mitre_attack_mapping || '—'}.`,
      metadata: {
        'Classification': t?.classification || '—',
        'Confidence Score': `${t?.confidence_score || 0}%`,
        'MITRE Mapping': t?.mitre_attack_mapping || '—',
      },
    },
    {
      title: 'Evidence Canonicalization & SHA-256 Hash Seal',
      time: '—',
      duration: '—',
      status: 'SEALED',
      category: 'CRYPTOGRAPHY',
      icon: '🔒',
      description: 'Tamper-evident SHA-256 cryptographic digest computed across canonicalized forensic observables for chain-of-custody integrity.',
      metadata: {
        'Evidence Hash': (result?.evidence_hash || 'not computed').slice(0, 32) + '...',
        'Chain of Custody': result?.evidence_hash ? 'VERIFIED IMMUTABLE' : 'PENDING',
      },
    },
  ]

  const current = pipelineStages[activeStep]

  return (
    <div className="grid xl:grid-cols-12 gap-5">
      <section className="xl:col-span-7 rounded-xl overflow-hidden p-5 space-y-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2"
          style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
          Demo Pipeline Execution ({pipelineStages.length} Milestones)
        </h3>
        <div className="space-y-2">
          {pipelineStages.map((stage, idx) => {
            const isSelected = activeStep === idx
            const statusColor = stage.status === 'FLAGGED'
              ? 'text-red-500 bg-red-500/10 border-red-500/30'
              : stage.status === 'SEALED'
                ? 'text-sky-500 bg-sky-500/10 border-sky-500/30'
                : stage.status === 'UNAVAILABLE'
                  ? 'text-orange-400 bg-orange-500/10 border-orange-500/30'
                  : 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30'

            return (
              <div key={idx} onClick={() => setActiveStep(idx)}
                className={`p-3 rounded-xl border transition-all cursor-pointer text-xs flex items-center justify-between gap-2 ${isSelected ? 'ring-2 ring-sky-500/50' : 'hover:bg-slate-500/5'}`}
                style={{ background: isSelected ? 'var(--bg-raised)' : 'var(--bg-surface)', borderColor: 'var(--border)' }}>
                <div className="flex items-center gap-3">
                  <span className="text-sm">{stage.icon}</span>
                  <div>
                    <h4 className="font-bold" style={{ color: 'var(--text-primary)' }}>{stage.title}</h4>
                    <span className="text-[9px] uppercase tracking-wider text-sky-500 font-semibold">{stage.category}</span>
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase border flex-shrink-0 ${statusColor}`}>
                  {stage.status}
                </span>
              </div>
            )
          })}
        </div>
      </section>

      <section className="xl:col-span-5 rounded-xl p-5 space-y-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
          <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>Stage Forensic Telemetry</h3>
          <span className="text-[10px] font-mono text-sky-500">{current.icon} Step #{activeStep + 1}</span>
        </div>
        <div className="space-y-4 text-xs">
          <div>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Milestone Name</p>
            <h4 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{current.title}</h4>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Execution Summary</p>
            <p className="leading-relaxed p-3 rounded-lg" style={{ background: 'var(--bg-raised)', color: 'var(--text-secondary)' }}>{current.description}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-2">Captured Artifact Metadata</p>
            <dl className="space-y-1.5">
              {Object.entries(current.metadata).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between p-2 rounded border"
                  style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                  <dt className="text-gray-500 font-medium">{k}</dt>
                  <dd className="font-mono text-[11px] font-semibold" style={{ color: 'var(--text-primary)' }}>{v}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>
    </div>
  )
}

/* ── Main export ──────────────────────────────────────────────── */
export function TimelineTab({ result, t, activeCaseId }) {
  const hasCaseId = Boolean(activeCaseId)

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header bar */}
      <section className="rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            Forensic Investigation Timeline
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {hasCaseId
              ? 'Real forensic events persisted to SQLite, retrieved live from the database.'
              : 'Demo mode — create a case and upload an .eml to see real persisted events.'}
          </p>
        </div>
        {hasCaseId && (
          <span className="text-[10px] font-mono px-2 py-1 rounded bg-sky-500/10 text-sky-500 font-bold border border-sky-500/20 whitespace-nowrap">
            CASE LINKED
          </span>
        )}
      </section>

      {/* Render the appropriate timeline */}
      {hasCaseId
        ? <LiveTimeline caseId={activeCaseId} />
        : <StaticTimeline result={result} t={t} />
      }
    </div>
  )
}
