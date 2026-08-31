import React, { useState } from 'react'

export function InvestigationTab({ result, t, GraphCanvas }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [filterType, setFilterType] = useState('ALL')

  const nodes = result?.attack_graph?.nodes || []
  const links = result?.attack_graph?.links || []
  const geoHops = result?.geo_hops || result?.geoHops || []

  const activeNode = selectedNode || nodes[0] || null

  const filteredNodes = filterType === 'ALL'
    ? nodes
    : nodes.filter(n => n.type.toLowerCase() === filterType.toLowerCase())

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header bar for investigation workbench */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            Deep Investigation Workbench
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Interactive node forensics, infrastructure hop graph &amp; threat cluster correlation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Filter Entities:</span>
          {['ALL', 'SENDER', 'RECIPIENT', 'RELAY_IP', 'AUTHENTICATION'].map(ft => (
            <button
              key={ft}
              onClick={() => setFilterType(ft)}
              className="text-[11px] px-2.5 py-1 rounded transition-colors font-medium"
              style={{
                background: filterType === ft ? 'var(--accent)' : 'var(--bg-raised)',
                color: filterType === ft ? '#ffffff' : 'var(--text-secondary)',
                border: '1px solid var(--border)',
              }}
            >
              {ft.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Full Graph + Entity Inspector */}
      <div className="grid xl:grid-cols-12 gap-5 min-h-[520px]">
        {/* Graph Canvas */}
        <section className="xl:col-span-8 rounded-xl overflow-hidden flex flex-col relative min-h-[500px]"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b z-10"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Interactive Attack Graph ({nodes.length} Nodes, {links.length} Relations)
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)' }}>
              Click any node in graph or list to inspect
            </span>
          </div>

          <div className="flex-1 relative">
            <GraphCanvas graph={result.attack_graph} geoHops={geoHops} onNodeClick={(n) => setSelectedNode(n)} />
          </div>
        </section>

        {/* Node Inspector Panel */}
        <section className="xl:col-span-4 rounded-xl overflow-hidden flex flex-col p-4 space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Entity Inspector
            </h3>
            {activeNode && (
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded"
                style={{ background: 'var(--accent-muted)', color: 'var(--accent)' }}>
                {activeNode.type}
              </span>
            )}
          </div>

          {activeNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <p className="text-[10px] uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Entity Identifier</p>
                <p className="font-mono text-xs font-bold break-all p-2 rounded" style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)' }}>
                  {activeNode.name || activeNode.id}
                </p>
              </div>

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

              {/* Quick action */}
              <div className="pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <p className="text-[10px] text-gray-500">Forensic Context:</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                  {activeNode.type === 'sender' && 'Sender identity extracted from envelope From header. Cross-checked with SPF records.'}
                  {activeNode.type === 'recipient' && 'Target mailbox recipient designated in message delivery headers.'}
                  {activeNode.type === 'relay_ip' && 'External SMTP relay detected in Received trace. Evaluated against reputation blocklists.'}
                  {activeNode.type === 'authentication' && 'Cryptographic and domain policy authentication telemetry (SPF/DKIM/DMARC).'}
                  {activeNode.type === 'threat_assessment' && 'Llama-3 threat engine heuristic assessment classification node.'}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-500">Select an entity to view properties.</p>
          )}

          {/* Quick Entity Switcher List */}
          <div className="border-t pt-3 flex-1 flex flex-col min-h-0" style={{ borderColor: 'var(--border)' }}>
            <p className="text-[10px] uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>All Artifact Nodes</p>
            <div className="space-y-1 overflow-y-auto scrollbar-thin flex-1 max-h-40">
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
          Network Hop-by-Hop Route Trace ({result?.email?.received_headers?.length || 0} Hops)
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
                  <tr key={idx} className="border-b hover:bg-slate-500/5 transition-colors" style={{ borderColor: 'var(--border)' }}>
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
