import React, { useState } from 'react'

export function IndicatorsTab({ result, t }) {
  const [defang, setDefang] = useState(false)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [copied, setCopied] = useState(false)

  const email = result?.email || {}
  const geoHops = result?.geo_hops || result?.geoHops || []
  const threatIntel = result?.threat_intelligence || []

  // If threat_intelligence is available from API, use it; otherwise build default base IOC list
  const senderDomain = email.from ? (email.from.match(/@([\w.-]+)/)?.[1] || 'unknown') : 'unknown'
  const relayIp = geoHops[0]?.ip || (email.received_headers?.[0]?.match(/\[([0-9.]+)\]/)?.[1] || '198.51.100.22')

  const iocList = threatIntel.length > 0
    ? threatIntel.map((item, idx) => ({
        id: idx,
        type: item.type.toUpperCase(),
        value: item.indicator,
        status: (item.status || 'unknown').toLowerCase(),
        confidence: item.confidence ?? 0,
        source: item.source || 'Local Analysis',
        reputation: item.reputation || item.status || 'Unknown',
        country: item.country || null,
        asn: item.asn || null,
        isp: item.isp || null,
        categories: item.categories || [],
        reasons: item.reasons?.length ? item.reasons : ['No malicious heuristics flagged.'],
        checked_at: item.checked_at || 'Just now',
      }))
    : [
        {
          id: 0,
          type: 'IP',
          value: relayIp,
          status: result?.authentication?.spf === 'fail' ? 'suspicious' : 'unknown',
          confidence: result?.authentication?.spf === 'fail' ? 75 : 40,
          source: 'Local Analysis',
          reputation: result?.authentication?.spf === 'fail' ? 'Suspicious Relay' : 'Observed Relay',
          country: geoHops[0]?.country || null,
          asn: geoHops[0]?.asn || null,
          isp: geoHops[0]?.isp || null,
          categories: ['relay_ip'],
          reasons: [`Relay hop in ${geoHops[0]?.city || 'Unknown'}, ${geoHops[0]?.country || 'Unknown'}`],
          checked_at: 'Just now',
        },
        {
          id: 1,
          type: 'DOMAIN',
          value: senderDomain,
          status: result?.authentication?.dmarc === 'fail' ? 'suspicious' : 'benign',
          confidence: 70,
          source: 'Local Analysis',
          reputation: result?.authentication?.dmarc === 'fail' ? 'Auth Misaligned' : 'Aligned',
          country: null,
          asn: null,
          isp: null,
          categories: ['sender_domain'],
          reasons: ['Sender identity envelope domain'],
          checked_at: 'Just now',
        },
        ...(email.urls || []).map((u, i) => ({
          id: 2 + i,
          type: 'URL',
          value: u,
          status: 'suspicious',
          confidence: 85,
          source: 'Local Analysis',
          reputation: 'Suspicious Lure',
          country: null,
          asn: null,
          isp: null,
          categories: ['embedded_link'],
          reasons: ['Embedded link extracted from message body'],
          checked_at: 'Just now',
        })),
      ]

  const formatValue = (val) => {
    if (!defang || !val) return val
    return val
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/\./g, '[.]')
  }

  // Filter IOCs
  const filteredIocs = iocList.filter(item => {
    const matchStatus = statusFilter === 'ALL' || item.status.toUpperCase() === statusFilter.toUpperCase()
    const matchType = typeFilter === 'ALL' || item.type.toUpperCase() === typeFilter.toUpperCase()
    return matchStatus && matchType
  })

  // Count summaries
  const totalCount = iocList.length
  const malCount = iocList.filter(i => i.status === 'malicious').length
  const suspCount = iocList.filter(i => i.status === 'suspicious').length
  const benCount = iocList.filter(i => i.status === 'benign').length
  const unkCount = iocList.filter(i => i.status === 'unknown' || i.status === 'unavailable').length

  const copyIocs = () => {
    const text = filteredIocs.map(i => `[${i.type}] ${formatValue(i.value)} | Status: ${i.status.toUpperCase()} (${i.confidence}%) | Source: ${i.source}`).join('\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const exportCsv = () => {
    const header = 'Type,Indicator,Status,Confidence,Source,Country,ASN,ISP,Reasons,CheckedAt\n'
    const rows = filteredIocs.map(i =>
      `"${i.type}","${formatValue(i.value)}","${i.status}","${i.confidence}%","${i.source}","${i.country || ''}","${i.asn || ''}","${i.isp || ''}","${i.reasons.join('; ')}","${i.checked_at}"`
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mailtrace-threat-intel-${Date.now()}.csv`
    a.click()
  }

  const getStatusBadge = (st) => {
    const s = (st || 'unknown').toLowerCase()
    if (s === 'malicious') {
      return <span className="px-2.5 py-1 rounded text-[10px] font-black uppercase text-red-500 bg-red-500/10 border border-red-500/30">MALICIOUS</span>
    }
    if (s === 'suspicious') {
      return <span className="px-2.5 py-1 rounded text-[10px] font-black uppercase text-amber-500 bg-amber-500/10 border border-amber-500/30">SUSPICIOUS</span>
    }
    if (s === 'benign') {
      return <span className="px-2.5 py-1 rounded text-[10px] font-black uppercase text-emerald-500 bg-emerald-500/10 border border-emerald-500/30">BENIGN</span>
    }
    return <span className="px-2.5 py-1 rounded text-[10px] font-black uppercase text-slate-400 bg-slate-500/10 border border-slate-500/20">UNKNOWN</span>
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Top action header */}
      <section
        className="rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base" role="img" aria-label="Shield">🛡️</span>
            <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Threat Intelligence &amp; IOC Observables
            </h2>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Normalized observables enriched with local heuristics, reputation status, and infrastructure intelligence.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Defang Toggle */}
          <button
            onClick={() => setDefang(!defang)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors"
            style={{
              background: defang ? 'var(--accent-muted)' : 'var(--bg-raised)',
              borderColor: defang ? 'var(--accent)' : 'var(--border)',
              color: defang ? 'var(--accent)' : 'var(--text-secondary)',
            }}
          >
            <span>Defang IOCs: {defang ? 'ON (hxxp/[.])' : 'OFF'}</span>
          </button>

          <button
            onClick={copyIocs}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            {copied ? '✓ IOCs Copied' : 'Copy IOCs'}
          </button>

          <button
            onClick={exportCsv}
            className="px-3.5 py-1.5 rounded-lg text-xs font-bold bg-sky-500 text-white hover:bg-sky-600 shadow-sm transition-colors"
          >
            Export CSV
          </button>
        </div>
      </section>

      {/* Intelligence Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl border" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase font-semibold tracking-wider" style={{ color: 'var(--text-muted)' }}>Observables</p>
          <p className="text-xl font-bold font-mono mt-0.5" style={{ color: 'var(--text-primary)' }}>{totalCount}</p>
        </div>
        <div className="p-3.5 rounded-xl border" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase font-semibold tracking-wider text-red-500">Malicious</p>
          <p className="text-xl font-bold font-mono text-red-500 mt-0.5">{malCount}</p>
        </div>
        <div className="p-3.5 rounded-xl border" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase font-semibold tracking-wider text-amber-500">Suspicious</p>
          <p className="text-xl font-bold font-mono text-amber-500 mt-0.5">{suspCount}</p>
        </div>
        <div className="p-3.5 rounded-xl border" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase font-semibold tracking-wider text-emerald-500">Benign</p>
          <p className="text-xl font-bold font-mono text-emerald-500 mt-0.5">{benCount}</p>
        </div>
        <div className="p-3.5 rounded-xl border col-span-2 sm:col-span-1" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">Unrated / Unknown</p>
          <p className="text-xl font-bold font-mono text-slate-400 mt-0.5">{unkCount}</p>
        </div>
      </div>

      {/* Status filter pills */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          <span className="text-xs font-semibold py-1" style={{ color: 'var(--text-muted)' }}>Status:</span>
          {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN'].map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className="text-xs px-3 py-1.5 rounded-lg transition-colors font-semibold"
              style={{
                background: statusFilter === st ? 'var(--accent)' : 'var(--bg-surface)',
                color: statusFilter === st ? '#ffffff' : 'var(--text-secondary)',
                border: '1px solid var(--border)',
              }}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-2">
          <span className="text-xs font-semibold py-1" style={{ color: 'var(--text-muted)' }}>Type:</span>
          {['ALL', 'URL', 'DOMAIN', 'IP', 'EMAIL'].map(tp => (
            <button
              key={tp}
              onClick={() => setTypeFilter(tp)}
              className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-semibold"
              style={{
                background: typeFilter === tp ? 'var(--bg-raised)' : 'transparent',
                color: typeFilter === tp ? 'var(--text-primary)' : 'var(--text-muted)',
                border: '1px solid var(--border)',
              }}
            >
              {tp}
            </button>
          ))}
        </div>
      </div>

      {/* Enriched Threat Intelligence Cards */}
      <div className="grid grid-cols-1 gap-4">
        {filteredIocs.map((ioc) => (
          <div
            key={ioc.id}
            className="rounded-xl p-4 border space-y-3 transition-all hover:border-sky-500/40"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}
          >
            {/* Top Bar: Value + Status + Confidence + Source */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3" style={{ borderColor: 'var(--border)' }}>
              <div className="flex items-center gap-2 min-w-0 max-w-full">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-800 text-sky-400 border border-slate-700">
                  {ioc.type}
                </span>
                <span className="font-mono text-xs sm:text-sm font-bold truncate select-all" style={{ color: 'var(--text-primary)' }}>
                  {formatValue(ioc.value)}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <span className="text-[10px] block uppercase font-semibold" style={{ color: 'var(--text-muted)' }}>Confidence</span>
                  <span className="font-mono text-xs font-bold text-sky-400">{ioc.confidence}%</span>
                </div>
                {getStatusBadge(ioc.status)}
              </div>
            </div>

            {/* Middle Grid: Findings + Infrastructure */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 text-xs">
              {/* Evidence & Reasons */}
              <div className="md:col-span-7 space-y-1.5">
                <p className="text-[10px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-muted)' }}>
                  Threat Intelligence Findings
                </p>
                <ul className="space-y-1">
                  {ioc.reasons.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 p-1.5 rounded" style={{ background: 'var(--bg-raised)' }}>
                      <span className="text-amber-500 font-bold text-xs mt-0.5 flex-shrink-0">•</span>
                      <span className="leading-tight font-medium" style={{ color: 'var(--text-secondary)' }}>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Infrastructure Context */}
              <div className="md:col-span-5 space-y-1.5 border-t md:border-t-0 md:border-l md:pl-4 pt-2 md:pt-0" style={{ borderColor: 'var(--border)' }}>
                <p className="text-[10px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-muted)' }}>
                  Infrastructure Telemetry
                </p>
                <dl className="space-y-1">
                  <div className="flex justify-between">
                    <dt className="text-gray-500 text-[11px]">Intel Source:</dt>
                    <dd className="font-semibold text-[11px] text-sky-400">{ioc.source}</dd>
                  </div>
                  {ioc.country && (
                    <div className="flex justify-between">
                      <dt className="text-gray-500 text-[11px]">Geo Location:</dt>
                      <dd className="font-medium text-[11px]" style={{ color: 'var(--text-secondary)' }}>{ioc.country}</dd>
                    </div>
                  )}
                  {ioc.asn && (
                    <div className="flex justify-between">
                      <dt className="text-gray-500 text-[11px]">Autonomous System:</dt>
                      <dd className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{ioc.asn}</dd>
                    </div>
                  )}
                  {ioc.isp && (
                    <div className="flex justify-between">
                      <dt className="text-gray-500 text-[11px]">ISP / Operator:</dt>
                      <dd className="text-[11px] truncate max-w-[150px]" style={{ color: 'var(--text-secondary)' }}>{ioc.isp}</dd>
                    </div>
                  )}
                  <div className="flex justify-between pt-1 border-t" style={{ borderColor: 'var(--border)' }}>
                    <dt className="text-gray-500 text-[10px]">Checked At:</dt>
                    <dd className="text-[10px] font-mono text-gray-500">{ioc.checked_at}</dd>
                  </div>
                </dl>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
