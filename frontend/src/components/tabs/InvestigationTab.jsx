import React, { useState } from 'react'
import { AIInvestigationPanel } from '../AIInvestigationPanel'

export function InvestigationTab({ result, t, GraphCanvas }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [filterType, setFilterType] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [searchTerm, setSearchTerm] = useState('')
  const [viewMode, setViewMode] = useState('ENTITY') // 'ENTITY' | 'AI_PANEL'

  const nodes = result?.attack_graph?.nodes || []
  const links = result?.attack_graph?.links || []
  const geoHops = result?.geo_hops || result?.geoHops || []

  const activeNode = selectedNode || nodes[0] || null

  const filteredNodes = nodes.filter(n => {
    const sTerm = (searchTerm || '').trim().toLowerCase()
    const matchesSearch = !sTerm ||
      (n.name || '').toLowerCase().includes(sTerm) ||
      (n.id || '').toLowerCase().includes(sTerm) ||
      (n.type || '').toLowerCase().includes(sTerm) ||
      (n.status || '').toLowerCase().includes(sTerm) ||
      (n.ip || '').toLowerCase().includes(sTerm)

    const matchesType = filterType === 'ALL' || (n.type || '').toLowerCase() === filterType.toLowerCase()
    const nodeStatus = (n.status || 'unknown').toLowerCase()
    const matchesStatus = statusFilter === 'ALL' || nodeStatus === statusFilter.toLowerCase()

    return matchesSearch && matchesType && matchesStatus
  })

  const getStatusBadge = (st) => {
    const s = (st || 'unknown').toLowerCase()
    if (s === 'malicious') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase text-red-500 bg-red-500/10 border border-red-500/30">MALICIOUS</span>
    }
    if (s === 'suspicious') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase text-amber-500 bg-amber-500/10 border border-amber-500/30">SUSPICIOUS</span>
    }
    if (s === 'benign') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase text-emerald-500 bg-emerald-500/10 border border-emerald-500/30">BENIGN</span>
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase text-slate-400 bg-slate-500/10 border border-slate-500/20">UNKNOWN</span>
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header bar for investigation workbench with Search & Dual Filters */}
      <div className="flex flex-col gap-3 p-4 rounded-xl"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base" role="img" aria-label="Graph">🕸️</span>
              <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                Forensic Attack &amp; Infrastructure Graph
              </h2>
            </div>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Sequential MTA relay propagation chain, domain infrastructure links &amp; threat intelligence severity mapping.
            </p>
          </div>

          {/* Search Box */}
          <div className="relative min-w-[240px]">
            <input
              type="text"
              placeholder="Search graph (IP, domain, sender, keyword)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full text-xs px-3 py-1.5 rounded-lg border focus:outline-none focus:border-sky-500"
              style={{
                background: 'var(--bg-raised)',
                borderColor: 'var(--border)',
                color: 'var(--text-primary)',
              }}
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-white"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Filter Controls Row */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
          {/* Entity Type Filter */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold" style={{ color: 'var(--text-muted)' }}>Entity Type:</span>
            {['ALL', 'SENDER', 'RECIPIENT', 'RELAY_IP', 'DOMAIN', 'URL', 'AUTHENTICATION', 'THREAT_ASSESSMENT'].map(ft => (
              <button
                key={ft}
                onClick={() => setFilterType(ft)}
                className="text-[10px] px-2 py-0.5 rounded transition-colors font-medium"
                style={{
                  background: filterType === ft ? 'var(--accent)' : 'var(--bg-raised)',
                  color: filterType === ft ? '#ffffff' : 'var(--text-secondary)',
                  border: '1px solid var(--border)',
                }}
              >
                {ft.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          {/* Threat Status Filter */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold" style={{ color: 'var(--text-muted)' }}>Threat Status:</span>
            {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN'].map(st => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className="text-[10px] px-2 py-0.5 rounded transition-colors font-bold"
                style={{
                  background: statusFilter === st ? 'var(--accent)' : 'var(--bg-raised)',
                  color: statusFilter === st ? '#ffffff' : 'var(--text-secondary)',
                  border: '1px solid var(--border)',
                }}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Grid: Full Graph + Entity Inspector */}
      <div className="grid xl:grid-cols-12 gap-5 min-h-[540px]">
        {/* Graph Canvas Section */}
        <section className="xl:col-span-8 rounded-xl overflow-hidden flex flex-col relative min-h-[500px]"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between px-4 py-2 border-b z-10"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Interactive Topology ({nodes.length} Nodes, {links.length} Relations)
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)' }}>
              Click any node in graph or list to inspect
            </span>
          </div>

          <div className="flex-1 relative min-h-[460px]">
            <GraphCanvas
              graph={result.attack_graph}
              geoHops={geoHops}
              onNodeClick={(n) => setSelectedNode(n)}
              filterType={filterType}
              statusFilter={statusFilter}
              searchTerm={searchTerm}
              selectedNode={activeNode}
            />
          </div>
        </section>

        {/* Node Inspector Panel */}
        <section className="xl:col-span-4 rounded-xl overflow-hidden flex flex-col p-4 space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-1.5 bg-slate-800/40 p-0.5 rounded-lg border" style={{ borderColor: 'var(--border)' }}>
              <button
                onClick={() => setViewMode('ENTITY')}
                className={`text-[10px] font-bold px-2 py-1 rounded transition-colors ${viewMode === 'ENTITY' ? 'bg-sky-500 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Entity Inspector
              </button>
              <button
                onClick={() => setViewMode('AI_PANEL')}
                className={`text-[10px] font-bold px-2 py-1 rounded transition-colors ${viewMode === 'AI_PANEL' ? 'bg-sky-500 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                🤖 AI Panel
              </button>
            </div>
            {viewMode === 'ENTITY' && activeNode && (
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded"
                style={{ background: 'var(--accent-muted)', color: 'var(--accent)' }}>
                {activeNode.type}
              </span>
            )}
          </div>

          {viewMode === 'AI_PANEL' ? (
            <div className="overflow-y-auto max-h-[600px] scrollbar-thin">
              <AIInvestigationPanel t={t} deterministic={result?.threat_analysis?.deterministic_assessment} />
            </div>
          ) : activeNode ? (
            <div className="space-y-4 text-xs overflow-y-auto max-h-[600px] scrollbar-thin pr-1">
              {/* Entity Header & Identifier */}
              <div>
                <p className="text-[10px] uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Entity Identifier</p>
                <p className="font-mono text-xs font-bold break-all p-2 rounded" style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)' }}>
                  {activeNode.name || activeNode.id}
                </p>
              </div>

              {/* Threat Intelligence Status Box */}
              <div className="p-3 rounded-lg border space-y-2" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-gray-500">Threat Status</span>
                  {getStatusBadge(activeNode.status)}
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-500 text-[11px]">Triage Confidence:</span>
                  <span className="font-mono font-bold text-sky-400">{activeNode.confidence ?? activeNode.confidence_score ?? 0}%</span>
                </div>
                {activeNode.source && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-500 text-[11px]">Intel Source:</span>
                    <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{activeNode.source}</span>
                  </div>
                )}
              </div>

              {/* Findings / Reasons if available */}
              {activeNode.reasons && activeNode.reasons.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-[10px] uppercase font-bold tracking-wider" style={{ color: 'var(--text-muted)' }}>
                    Threat Evidence &amp; Findings
                  </p>
                  <ul className="space-y-1">
                    {activeNode.reasons.map((r, i) => (
                      <li key={i} className="flex items-start gap-1.5 p-1.5 rounded" style={{ background: 'var(--bg-raised)' }}>
                        <span className="text-amber-500 font-bold">•</span>
                        <span className="text-[11px] leading-tight" style={{ color: 'var(--text-secondary)' }}>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* OSINT / Geo metadata if IP */}
              {activeNode.type === 'relay_ip' && (
                <div className="p-3 rounded-lg space-y-2 border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                  <p className="text-[10px] uppercase font-semibold tracking-wider text-amber-500">OSINT &amp; GeoIP Telemetry</p>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-gray-500 block text-[10px]">Country</span>
                      <span className="font-semibold">{activeNode.country || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">City</span>
                      <span className="font-semibold">{activeNode.city || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">ISP / Org</span>
                      <span className="font-mono text-[11px] truncate block">{activeNode.isp || 'Commercial ISP'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">Autonomous System</span>
                      <span className="font-mono text-[11px] font-bold text-primary">{activeNode.asn || 'AS-UNKNOWN'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Threat Assessment Details */}
              {activeNode.type === 'threat_assessment' && (
                <div className="p-3 rounded-lg space-y-2 border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                  <p className="text-[10px] uppercase font-semibold tracking-wider text-amber-500">AI Threat Classification</p>
                  <div className="space-y-1 text-xs">
                    <p><b className="text-gray-400">Threat Type:</b> {activeNode.threat_type || 'Unknown'}</p>
                    <p><b className="text-gray-400">Technical Risk:</b> {activeNode.deterministic_risk ? `${activeNode.deterministic_risk}/100` : 'N/A'}</p>
                    <p className="text-[11px] text-gray-300 mt-1">{activeNode.summary || 'Assessment available.'}</p>
                  </div>
                </div>
              )}

              {/* Connected relationships */}
              <div>
                <p className="text-[10px] uppercase font-semibold tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>
                  Connected Relationships
                </p>
                <div className="space-y-1.5 max-h-36 overflow-y-auto scrollbar-thin">
                  {links.filter(l => {
                    const srcId = typeof l.source === 'object' ? l.source.id : l.source
                    const tgtId = typeof l.target === 'object' ? l.target.id : l.target
                    return srcId === activeNode.id || tgtId === activeNode.id
                  }).map((link, idx) => {
                    const srcId = typeof link.source === 'object' ? link.source.id : link.source
                    const tgtId = typeof link.target === 'object' ? link.target.id : link.target
                    return (
                      <div key={idx} className="flex items-center justify-between p-2 rounded text-[11px]" style={{ background: 'var(--bg-raised)' }}>
                        <span className="font-mono truncate max-w-[120px]" style={{ color: 'var(--text-muted)' }}>{srcId}</span>
                        <span className="font-bold text-[9px] uppercase px-1.5 py-0.5 rounded text-sky-500 bg-sky-500/10">
                          {link.relation}
                        </span>
                        <span className="font-mono truncate max-w-[120px]" style={{ color: 'var(--text-secondary)' }}>{tgtId}</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Quick action / Forensic Context */}
              <div className="pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <p className="text-[10px] text-gray-500">Forensic Context:</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                  {activeNode.type === 'sender' && 'Sender identity extracted from envelope From header. Cross-checked with SPF records.'}
                  {activeNode.type === 'recipient' && 'Target mailbox recipient designated in message delivery headers.'}
                  {activeNode.type === 'domain' && 'Domain infrastructure node correlated with sender envelope or embedded link hosting.'}
                  {activeNode.type === 'url' && 'Embedded hyperlinked destination extracted from email payload.'}
                  {activeNode.type === 'relay_ip' && 'External SMTP relay detected in Received trace. Evaluated against reputation blocklists.'}
                  {activeNode.type === 'authentication' && 'Cryptographic and domain policy authentication telemetry (SPF/DKIM/DMARC).'}
                  {activeNode.type === 'threat_assessment' && 'Llama-3 threat engine heuristic assessment classification node.'}
                  {activeNode.type === 'email' && 'Central email message artifact envelope node.'}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-500">Select an entity to view properties.</p>
          )}

          {/* Quick Entity Switcher List */}
          <div className="border-t pt-3 flex-1 flex flex-col min-h-0" style={{ borderColor: 'var(--border)' }}>
            <p className="text-[10px] uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Artifact Nodes ({filteredNodes.length})
            </p>
            <div className="space-y-1 overflow-y-auto scrollbar-thin flex-1 max-h-36">
              {filteredNodes.map(n => (
                <button
                  key={n.id}
                  onClick={() => setSelectedNode(n)}
                  className="w-full text-left px-2.5 py-1.5 rounded text-xs flex items-center justify-between transition-colors"
                  style={{
                    background: activeNode?.id === n.id ? 'var(--accent-muted)' : 'var(--bg-raised)',
                    color: activeNode?.id === n.id ? 'var(--accent)' : 'var(--text-primary)',
                  }}
                >
                  <span className="truncate max-w-[180px] font-mono text-[11px]">{n.name || n.id}</span>
                  <span className="text-[9px] uppercase font-semibold opacity-70">{n.type}</span>
                </button>
              ))}
            </div>
          </div>
        </section>
      </div>

      {/* Network Hop Route Tracer */}
      <section className="rounded-xl overflow-hidden p-4 space-y-3"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
          Sequential Network Hop-by-Hop Route Trace ({result?.email?.received_headers?.length || 0} Hops)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b text-[10px] uppercase tracking-wider" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                <th className="py-2 px-3">Hop #</th>
                <th className="py-2 px-3">Relay IP</th>
                <th className="py-2 px-3">Geo Location</th>
                <th className="py-2 px-3">ISP / ASN</th>
                <th className="py-2 px-3">Raw Received Trace Snippet</th>
              </tr>
            </thead>
            <tbody>
              {(result?.email?.received_headers || []).map((header, idx) => {
                const ipMatch = header.match(/\[([0-9.]+)\]/)
                const ip = ipMatch ? ipMatch[1] : 'Internal / Unknown'
                const hopData = geoHops.find(h => h.ip === ip) || {}
                return (
                  <tr
                    key={idx}
                    onClick={() => {
                      const matchedNode = nodes.find(n => n.ip === ip || n.id === `ip:${ip}`)
                      if (matchedNode) setSelectedNode(matchedNode)
                    }}
                    className="border-b hover:bg-slate-500/10 cursor-pointer transition-colors"
                    style={{ borderColor: 'var(--border)' }}
                  >
                    <td className="py-2.5 px-3 font-mono font-bold text-sky-500">#{idx + 1}</td>
                    <td className="py-2.5 px-3 font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{ip}</td>
                    <td className="py-2.5 px-3">
                      {hopData.city ? (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-slate-500/10 font-medium">
                          {hopData.city}, {hopData.country}
                        </span>
                      ) : (
                        <span className="text-gray-500 text-[11px]">Direct / LAN</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                      {hopData.isp || hopData.asn || 'Corporate Gateway'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[10px] text-gray-500 truncate max-w-xs">{header}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
