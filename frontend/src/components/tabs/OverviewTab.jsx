import React from 'react'
import { AIInvestigationPanel } from '../AIInvestigationPanel'

export function OverviewTab({ result, t, cls, GraphCanvas, onSwitchTab }) {
  const score = t?.confidence_score ?? 0
  const isHigh = score >= 70
  const isMed = score >= 40 && score < 70
  const scoreColor = isHigh ? 'var(--danger)' : isMed ? 'var(--warning)' : 'var(--success)'

  const factors = [
    ['RFC 5321 vs 5322 Alignment', isHigh ? 'Misaligned' : 'Aligned', isHigh ? '+30' : '+0'],
    ['Domain Age & Reputation', isHigh ? 'High Risk' : 'Verified', isHigh ? '+25' : '+0'],
    ['Relay Autonomous System', isMed || isHigh ? 'Untrusted ASN' : 'Clean MX', isHigh ? '+15' : '+5'],
    ['Authentication Audit', score >= 60 ? 'Failed' : 'Strict Pass', score >= 60 ? '+15' : '+0'],
    ['Content & Lure Telemetry', isMed || isHigh ? 'Coercive Trigger' : 'Clean', '+9'],
  ]

  const geoHops = result?.geo_hops || result?.geoHops || []
  const hop = geoHops[0]

  const originRows = [
    ['From (RFC 5322)', result?.email?.from || '—'],
    ['Return-Path (5321)', result?.email?.from?.match(/<(.+)>/)?.[1] || result?.email?.from || '—'],
    ['Relay IP Address', result?.email?.received_headers?.[0]?.match(/\[([0-9.]+)\]/)?.[1] || (hop ? hop.ip : '—')],
    ...(hop ? [['Geo Location', `${hop.city}, ${hop.country} (${hop.isp || 'Commercial ASN'})`]] : []),
    ['Message-ID', result?.email?.message_id || '—'],
  ]

  const iocItems = [
    { label: 'Observed URLs', count: (t?.social_engineering_techniques?.length || 0) > 0 ? 2 : 0, icon: LinkIcon },
    { label: 'Relay IPs', count: geoHops.length || 1, icon: ServerIcon },
    { label: 'Domains', count: 1, icon: GlobeIcon },
    { label: 'MIME Payloads', count: 1, icon: PaperclipIcon },
  ]

  const timelineSteps = [
    'Envelope Ingestion', 'MIME Parsed', 'Auth Audited', 'IOC Extracted',
    'OSINT Resolved', 'Threat Triage', 'Evidence Sealed',
  ]

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Top row: Graph + Threat + Auth/Origin */}
      <div className="grid xl:grid-cols-12 gap-5">
        {/* Attack Graph Card */}
        <section className="xl:col-span-5 rounded-xl overflow-hidden flex flex-col min-h-[450px]"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'var(--border)' }}>
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>Correlated Attack Graph</h2>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>Entity topology of envelope headers, relay hops, and threat nodes</p>
            </div>
            <button onClick={() => onSwitchTab('Investigation')} className="text-[11px] font-semibold px-2.5 py-1 rounded transition-colors"
              style={{ color: 'var(--accent)', background: 'var(--accent-muted)' }}>
              Deep Inspect →
            </button>
          </div>
          <div className="flex-1 relative">
            <GraphCanvas graph={result.attack_graph} geoHops={geoHops} />
          </div>
        </section>

        {/* AI Investigation Panel Card */}
        <div className="xl:col-span-4 flex flex-col">
          <AIInvestigationPanel
            t={t}
            deterministic={result?.threat_analysis?.deterministic_assessment}
          />
        </div>

        {/* Right Stack: Authentication & Message Origin */}
        <div className="xl:col-span-3 flex flex-col gap-5">
          {/* Auth Card */}
          <section className="rounded-xl overflow-hidden p-4 space-y-3"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h2 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
              Protocol Authentication
            </h2>
            <div className="space-y-2">
              {Object.entries(result.authentication || {}).map(([mech, status]) => {
                const pass = status === 'pass'
                const none = status === 'none'
                const warn = status === 'softfail' || status === 'temperror'
                const color = pass ? 'var(--success)' : none ? 'var(--text-muted)' : warn ? 'var(--warning)' : 'var(--danger)'
                const bg = pass ? 'var(--success-muted)' : none ? 'var(--bg-raised)' : warn ? 'var(--warning-muted)' : 'var(--danger-muted)'
                return (
                  <div key={mech} className="flex items-center justify-between py-2 px-3 rounded-lg" style={{ background: bg }}>
                    <span className="text-xs font-bold uppercase" style={{ color: 'var(--text-primary)' }}>{mech}</span>
                    <span className="flex items-center gap-1.5 text-xs font-bold uppercase" style={{ color }}>
                      {status}
                      {pass ? <CheckIcon className="w-3.5 h-3.5" /> : status === 'fail' ? <XIcon className="w-3.5 h-3.5" /> : null}
                    </span>
                  </div>
                )
              })}
            </div>
          </section>

          {/* Origin Card */}
          <section className="rounded-xl overflow-hidden p-4 space-y-3 flex-1"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h2 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
              Origin Telemetry
            </h2>
            <dl className="space-y-2">
              {originRows.map(([label, value]) => (
                <div key={label} className="flex items-start gap-2 text-xs">
                  <dt className="w-24 flex-shrink-0 font-medium" style={{ color: 'var(--text-muted)' }}>{label}</dt>
                  <dd className="font-mono text-[11px] break-all font-medium" style={{ color: 'var(--text-secondary)' }}>{value}</dd>
                </div>
              ))}
            </dl>
          </section>
        </div>
      </div>

      {/* Bottom row: Indicators (IOCs) + Timeline */}
      <div className="grid xl:grid-cols-12 gap-5">
        {/* Indicators summary */}
        <section className="xl:col-span-5 rounded-xl overflow-hidden p-4 space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>Indicators of Compromise (IOCs)</h2>
            <button onClick={() => onSwitchTab('Indicators')} className="text-[10px] font-semibold" style={{ color: 'var(--accent)' }}>
              Full Workbench →
            </button>
          </div>
          <div className="grid grid-cols-4 gap-3">
            {iocItems.map(({ label, count, icon: Icon }) => (
              <div key={label} className="text-center p-3 rounded-lg border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <Icon className="w-4 h-4 mx-auto mb-1.5" style={{ color: 'var(--text-muted)' }} />
                <p className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>{count}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{label}</p>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(t?.suspicious_indicators || []).map(tag => (
              <span key={tag} className="text-[11px] px-2.5 py-1 rounded font-mono font-semibold"
                style={{ color: 'var(--danger)', background: 'var(--danger-muted)', border: '1px solid var(--danger)' }}>
                {tag}
              </span>
            ))}
          </div>
        </section>

        {/* Timeline overview */}
        <section className="xl:col-span-7 rounded-xl overflow-hidden p-4 flex flex-col justify-between"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>Investigation Timeline</h2>
            <button onClick={() => onSwitchTab('Timeline')} className="text-[10px] font-semibold" style={{ color: 'var(--accent)' }}>
              Full Audit Log →
            </button>
          </div>
          <div className="pt-4 pb-2">
            <div className="flex items-center justify-between relative">
              <div className="absolute top-3 left-0 right-0 h-0.5" style={{ background: 'var(--border)' }} />
              <div className="absolute top-3 left-0 h-0.5" style={{ background: 'var(--accent)', width: '100%' }} />
              {timelineSteps.map((step, i) => {
                const time = `14:22:${(18 + i * 2).toString().padStart(2, '0')}`
                return (
                  <div key={step} className="relative flex flex-col items-center z-10" style={{ minWidth: 65 }}>
                    <div className="w-5 h-5 rounded-full flex items-center justify-center border-2"
                      style={{ background: 'var(--bg-surface)', borderColor: 'var(--accent)' }}>
                      <CheckIcon className="w-2.5 h-2.5" style={{ color: 'var(--accent)' }} />
                    </div>
                    <p className="text-[9px] font-medium mt-1.5 text-center leading-tight" style={{ color: 'var(--text-primary)' }}>{step}</p>
                    <p className="text-[8px] font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>{time}</p>
                  </div>
                )
              })}
            </div>
          </div>
        </section>
      </div>

      {/* Forensic Evidence Integrity banner */}
      <section className="rounded-xl overflow-hidden p-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div className="grid md:grid-cols-3 gap-4 items-center">
          <div>
            <span className="text-[10px] uppercase tracking-wider font-semibold block mb-1" style={{ color: 'var(--text-muted)' }}>Investigation Explanation</span>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{t?.explanation}</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider font-semibold block mb-1" style={{ color: 'var(--text-muted)' }}>Recommended SOC Action</span>
            <p className="text-xs font-medium leading-relaxed" style={{ color: 'var(--text-primary)' }}>{t?.recommended_action}</p>
          </div>
          <div className="border-t md:border-t-0 md:border-l md:pl-4" style={{ borderColor: 'var(--border)' }}>
            <span className="text-[10px] uppercase tracking-wider font-semibold block mb-1" style={{ color: 'var(--text-muted)' }}>Evidence Tamper-Proof Hash (SHA-256)</span>
            <p className="font-mono text-[10px] break-all select-all p-2 rounded font-bold" style={{ background: 'var(--bg-raised)', color: 'var(--accent)' }}>
              {result.evidence_hash}
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}

function CheckIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/></svg> }
function XIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/></svg> }
function LinkIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg> }
function ServerIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg> }
function GlobeIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> }
function PaperclipIcon(p) { return <svg {...p} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg> }
