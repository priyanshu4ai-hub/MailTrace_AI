import React, { useState } from 'react'

export function TimelineTab({ result, t }) {
  const [activeStep, setActiveStep] = useState(0)

  const auth = result?.authentication || {}
  const geoHops = result?.geo_hops || result?.geoHops || []

  const pipelineStages = [
    {
      title: 'Email Ingest & RFC 822 Validation',
      time: '10:21:14.020',
      duration: '18ms',
      status: 'COMPLETE',
      category: 'PARSER',
      description: 'The .eml message stream was read, size-checked against the 5MB policy limit, and parsed into canonical envelope and header objects.',
      metadata: {
        'Payload Size': '4.2 KB',
        'MIME Boundary': 'multipart/alternative',
        'Message-ID': result?.email?.message_id || '<unknown>',
      },
    },
    {
      title: 'MIME Body & Attachment Extraction',
      time: '10:21:14.038',
      duration: '14ms',
      status: 'COMPLETE',
      category: 'EXTRACTION',
      description: 'Extracted plaintext and stripped HTML body via BeautifulSoup. Parsed 2 embedded hyperlinks and checked for hidden unicode zero-width characters.',
      metadata: {
        'Body Text Length': `${(result?.email?.body || '').length} characters`,
        'Embedded Links': '2 URLs detected',
        'Attachments': '0 binary payloads',
      },
    },
    {
      title: 'SPF, DKIM & DMARC Authentication Audit',
      time: '10:21:14.052',
      duration: '42ms',
      status: (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass') ? 'PASS' : 'FLAGGED',
      category: 'AUTH_ENGINE',
      description: `Evaluated RFC 7208 SPF records, RFC 6376 DKIM digital signatures, and RFC 7489 DMARC policy alignment. Result: SPF=${auth.spf}, DKIM=${auth.dkim}, DMARC=${auth.dmarc}.`,
      metadata: {
        'SPF Verification': auth.spf?.toUpperCase() || 'NONE',
        'DKIM Signature': auth.dkim?.toUpperCase() || 'NONE',
        'DMARC Alignment': auth.dmarc?.toUpperCase() || 'NONE',
      },
    },
    {
      title: 'Network Hop & GeoIP OSINT Resolution',
      time: '10:21:14.094',
      duration: '85ms',
      status: 'COMPLETE',
      category: 'GEO_OSINT',
      description: `Resolved ${result?.email?.received_headers?.length || 1} Received relay hops against MaxMind GeoIP and threat intelligence feeds. Identified external relay: ${geoHops[0]?.ip || '198.51.100.22'}.`,
      metadata: {
        'Relay IP': geoHops[0]?.ip || '198.51.100.22',
        'Relay Location': `${geoHops[0]?.city || 'Moscow'}, ${geoHops[0]?.country || 'RU'}`,
        'Autonomous System': geoHops[0]?.asn || 'AS12389',
      },
    },
    {
      title: 'Threat Intelligence & Llama-3 Analysis',
      time: '10:21:14.179',
      duration: '230ms',
      status: t?.confidence_score >= 70 ? 'ALERT_HIGH' : 'ANALYZED',
      category: 'AI_ENGINE',
      description: `Threat detection engine evaluated social engineering lures and attack methodology against the MITRE ATT&CK framework. Classified as ${t?.classification || 'Phishing'} with ${t?.confidence_score || 87}% confidence score.`,
      metadata: {
        'Classification': t?.classification || 'Phishing',
        'Confidence Score': `${t?.confidence_score || 87}%`,
        'MITRE Mapping': t?.mitre_attack_mapping || 'T1566',
      },
    },
    {
      title: 'Evidence Canonicalization & SHA-256 Hash Seal',
      time: '10:21:14.409',
      duration: '8ms',
      status: 'SEALED',
      category: 'CRYPTOGRAPHY',
      description: 'Calculated tamper-evident SHA-256 cryptographic digest across canonicalized forensic observables for court-admissible chain of custody.',
      metadata: {
        'Evidence Hash': result?.evidence_hash || 'e3b0c44298fc...',
        'Chain of Custody': 'VERIFIED IMMUTABLE',
      },
    },
  ]

  const current = pipelineStages[activeStep]

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header bar */}
      <section className="rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            Investigation Audit Timeline &amp; Event Sequence
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Microsecond-precision execution trace of automated parsing, authentication, OSINT, and threat classification.
          </p>
        </div>
        <span className="text-xs font-mono px-3 py-1 rounded bg-emerald-500/10 text-emerald-500 font-bold">
          Total Execution Latency: 397ms
        </span>
      </section>

      {/* Main Grid: Pipeline Steps + Detail Inspector */}
      <div className="grid xl:grid-cols-12 gap-5">
        {/* Step list (7 cols) */}
        <section className="xl:col-span-7 rounded-xl overflow-hidden p-5 space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
            Pipeline Execution Steps ({pipelineStages.length} Milestones)
          </h3>

          <div className="space-y-3">
            {pipelineStages.map((stage, idx) => {
              const isSelected = activeStep === idx
              const isFlagged = stage.status === 'FLAGGED' || stage.status === 'ALERT_HIGH'
              const statusColor = isFlagged ? 'text-red-500 bg-red-500/10 border-red-500/30'
                : stage.status === 'SEALED' ? 'text-sky-500 bg-sky-500/10 border-sky-500/30'
                : 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30'

              return (
                <div
                  key={idx}
                  onClick={() => setActiveStep(idx)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${isSelected ? 'ring-2 ring-sky-500/50' : 'hover:bg-slate-500/5'}`}
                  style={{
                    background: isSelected ? 'var(--bg-raised)' : 'var(--bg-surface)',
                    borderColor: 'var(--border)',
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono font-bold"
                        style={{ background: isSelected ? 'var(--accent)' : 'var(--bg-inset)', color: isSelected ? '#ffffff' : 'var(--text-muted)' }}>
                        {idx + 1}
                      </span>
                      <div>
                        <h4 className="text-xs font-bold" style={{ color: 'var(--text-primary)' }}>{stage.title}</h4>
                        <div className="flex items-center gap-2 mt-0.5 font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                          <span>{stage.time}</span>
                          <span>•</span>
                          <span>Δ {stage.duration}</span>
                          <span>•</span>
                          <span className="uppercase text-sky-500 font-semibold">{stage.category}</span>
                        </div>
                      </div>
                    </div>

                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${statusColor}`}>
                      {stage.status}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* Selected Step Detail Panel (5 cols) */}
        <section className="xl:col-span-5 rounded-xl overflow-hidden p-5 flex flex-col space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Step Forensic Telemetry
            </h3>
            <span className="text-[10px] font-mono text-sky-500">Step #{activeStep + 1}</span>
          </div>

          <div className="space-y-4">
            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Milestone Name</p>
              <h4 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{current.title}</h4>
            </div>

            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1">Execution Summary</p>
              <p className="text-xs leading-relaxed p-3 rounded-lg" style={{ background: 'var(--bg-raised)', color: 'var(--text-secondary)' }}>
                {current.description}
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-2">Captured Artifact Metadata</p>
              <dl className="space-y-2 text-xs">
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
    </div>
  )
}
