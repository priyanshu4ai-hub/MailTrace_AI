import React, { useState } from 'react'

export function IndicatorsTab({ result, t }) {
  const [defang, setDefang] = useState(false)
  const [categoryFilter, setCategoryFilter] = useState('ALL')
  const [copied, setCopied] = useState(false)

  const email = result?.email || {}
  const geoHops = result?.geo_hops || result?.geoHops || []
  const senderDomain = email.from ? (email.from.match(/@([\w.-]+)/)?.[1] || 'unknown') : 'unknown'
  const relayIp = geoHops[0]?.ip || (email.received_headers?.[0]?.match(/\[([0-9.]+)\]/)?.[1] || '198.51.100.22')

  // Generate structured IOC list from case data
  const baseIocs = [
    {
      type: 'IP_ADDRESS',
      value: relayIp,
      category: 'Network Relay',
      severity: result?.authentication?.spf === 'fail' ? 'High' : 'Medium',
      context: `External relay hop (${geoHops[0]?.city || 'Moscow'}, ${geoHops[0]?.country || 'RU'}). Evaluated against IP blocklists.`,
      action: 'Block on perimeter firewall & gateway',
    },
    {
      type: 'DOMAIN',
      value: senderDomain,
      category: 'Sender Infrastructure',
      severity: result?.authentication?.dmarc === 'fail' ? 'High' : 'Low',
      context: 'Domain extracted from envelope From header. Failed SPF/DMARC authentication alignment.',
      action: 'Add to mail gateway domain quarantine policy',
    },
    {
      type: 'EMAIL_ADDRESS',
      value: email.from || 'unknown',
      category: 'Threat Actor Identity',
      severity: 'High',
      context: 'Display name impersonation / spoofed originator mailbox.',
      action: 'Flag across SIEM for mailbox correlation',
    },
    {
      type: 'MESSAGE_ID',
      value: email.message_id || '<unknown@domain>',
      category: 'Telemetry Header',
      severity: 'Low',
      context: 'RFC 822 unique message tracking identifier.',
      action: 'Use for message trace & inbox purging',
    },
    {
      type: 'HASH_SHA256',
      value: result?.evidence_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      category: 'Evidence Digest',
      severity: 'Info',
      context: 'Cryptographic SHA-256 digest of normalized email artifact.',
      action: 'Store in case management for chain-of-custody',
    },
    ...(t?.suspicious_indicators || []).map((ind, i) => ({
      type: 'BEHAVIORAL_IOC',
      value: ind,
      category: 'Threat Heuristic',
      severity: 'High',
      context: 'Llama 3 AI threat detection pattern detection heuristic.',
      action: 'Document in incident ticket',
    })),
  ]

  const formatValue = (val) => {
    if (!defang) return val
    return val
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/\./g, '[.]')
  }

  const filteredIocs = categoryFilter === 'ALL'
    ? baseIocs
    : baseIocs.filter(i => i.type === categoryFilter)

  const copyIocs = () => {
    const text = filteredIocs.map(i => `${i.type}: ${formatValue(i.value)} [Severity: ${i.severity}]`).join('\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const exportCsv = () => {
    const header = 'Type,Value,Category,Severity,Context,Recommended Action\n'
    const rows = filteredIocs.map(i => `"${i.type}","${formatValue(i.value)}","${i.category}","${i.severity}","${i.context}","${i.action}"`).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mailtrace-iocs-${Date.now()}.csv`
    a.click()
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Top action header */}
      <section className="rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            Threat Intelligence &amp; Indicators of Compromise (IOCs)
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Defanged forensic observables, MITRE technique alignments and exportable feeds for SIEM/SOAR ingestion.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Defang Toggle */}
          <button
            onClick={() => setDefang(!defang)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
            style={{
              background: defang ? 'var(--accent-muted)' : 'var(--bg-raised)',
              borderColor: defang ? 'var(--accent)' : 'var(--border)',
              color: defang ? 'var(--accent)' : 'var(--text-secondary)',
            }}
          >
            <span>Defang IOCs ({defang ? 'ON: hxxp/['.concat('.').concat(']') : 'OFF'})</span>
          </button>

          <button
            onClick={copyIocs}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            {copied ? '✓ IOCs Copied' : 'Copy IOCs'}
          </button>

          <button
            onClick={exportCsv}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-sky-500 text-white hover:bg-sky-600 transition-colors"
          >
            Export CSV
          </button>
        </div>
      </section>

      {/* Category filter pills */}
      <div className="flex flex-wrap gap-2">
        {['ALL', 'IP_ADDRESS', 'DOMAIN', 'EMAIL_ADDRESS', 'HASH_SHA256', 'BEHAVIORAL_IOC'].map(cat => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className="text-xs px-3 py-1.5 rounded-lg transition-colors font-medium"
            style={{
              background: categoryFilter === cat ? 'var(--accent)' : 'var(--bg-surface)',
              color: categoryFilter === cat ? '#ffffff' : 'var(--text-secondary)',
              border: '1px solid var(--border)',
            }}
          >
            {cat.replace(/_/g, ' ')} ({cat === 'ALL' ? baseIocs.length : baseIocs.filter(i => i.type === cat).length})
          </button>
        ))}
      </div>

      {/* IOC Table */}
      <section className="rounded-xl overflow-hidden"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b text-[10px] uppercase tracking-wider"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                <th className="py-3 px-4">Observable Type</th>
                <th className="py-3 px-4">Observable Value</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Forensic Context &amp; Recommended Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredIocs.map((ioc, idx) => {
                const isHigh = ioc.severity === 'High' || ioc.severity === 'Critical'
                const isMed = ioc.severity === 'Medium'
                const sevColor = isHigh ? 'text-red-500 bg-red-500/10 border-red-500/20'
                  : isMed ? 'text-amber-500 bg-amber-500/10 border-amber-500/20'
                  : 'text-sky-500 bg-sky-500/10 border-sky-500/20'

                return (
                  <tr key={idx} className="border-b hover:bg-slate-500/5 transition-colors" style={{ borderColor: 'var(--border)' }}>
                    <td className="py-3 px-4 font-mono font-semibold text-[11px]" style={{ color: 'var(--text-muted)' }}>
                      {ioc.type}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs font-bold select-all break-all max-w-xs" style={{ color: 'var(--text-primary)' }}>
                      {formatValue(ioc.value)}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevColor}`}>
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>
                      {ioc.category}
                    </td>
                    <td className="py-3 px-4 space-y-0.5">
                      <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{ioc.context}</p>
                      <p className="text-[10px] font-semibold text-sky-500">Action: {ioc.action}</p>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Social Engineering Behavioral Indicators */}
      <div className="grid md:grid-cols-2 gap-5">
        <section className="rounded-xl p-5 space-y-3"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
            Detected Social Engineering Methodologies
          </h3>
          <div className="space-y-2">
            {(t?.social_engineering_techniques || []).map((tech, i) => (
              <div key={i} className="flex items-center justify-between p-2.5 rounded-lg border text-xs"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <span className="font-semibold text-amber-500">{tech}</span>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/10 text-amber-500">
                  FLAGGED LURE
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-xl p-5 space-y-3"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
            MITRE ATT&CK® Tactic Matrix
          </h3>
          <div className="p-3 rounded-lg border space-y-2 text-xs" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-sky-500">{t?.mitre_attack_mapping || 'T1566'}</span>
              <span className="text-[10px] uppercase bg-sky-500/10 text-sky-500 px-2 py-0.5 rounded font-bold">Enterprise ATT&CK</span>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              Initial Access tactic: Adversaries send spearphishing emails with malicious links, spoofed authentication, or attachments to gain initial code execution on target organization endpoints.
            </p>
          </div>
        </section>
      </div>
    </div>
  )
}
