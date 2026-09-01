import React, { useState, useEffect } from 'react'

const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

export function CampaignsTab({ activeCase, onSelectCaseForInvestigation, GraphCanvas }) {
  const [campaigns, setCampaigns] = useState([])
  const [metrics, setMetrics] = useState({
    total_campaigns: 0,
    high_confidence_count: 0,
    total_emails_correlated: 0,
    total_shared_iocs: 0,
  })
  const [selectedCampaignId, setSelectedCampaignId] = useState(null)
  const [campaignDetail, setCampaignDetail] = useState(null)
  const [loading, setLoading] = useState(false)
  const [detecting, setDetecting] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')
  const [filterType, setFilterType] = useState('ALL')

  useEffect(() => {
    fetchCampaigns()
  }, [activeCase])

  async function fetchCampaigns() {
    setLoading(true)
    setError('')
    try {
      const url = activeCase?.id
        ? `${API_URL}/api/v1/cases/${activeCase.id}/campaigns`
        : `${API_URL}/api/v1/campaigns`
      const res = await fetch(url)
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to fetch campaigns')

      setCampaigns(data.campaigns || [])
      setMetrics({
        total_campaigns: data.total_campaigns || 0,
        high_confidence_count: data.high_confidence_count || 0,
        total_emails_correlated: data.total_emails_correlated || 0,
        total_shared_iocs: data.total_shared_iocs || 0,
      })

      if (data.campaigns && data.campaigns.length > 0) {
        const firstId = data.campaigns[0].campaign_id
        setSelectedCampaignId(firstId)
        fetchCampaignDetail(firstId)
      } else {
        setSelectedCampaignId(null)
        setCampaignDetail(null)
      }
    } catch (e) {
      setError(e.message || 'Error loading campaigns')
    } finally {
      setLoading(false)
    }
  }

  async function fetchCampaignDetail(campId) {
    try {
      const res = await fetch(`${API_URL}/api/v1/campaigns/${campId}`)
      const data = await res.json()
      if (res.ok) {
        setCampaignDetail(data)
      }
    } catch (e) {
      console.error('Error fetching campaign detail:', e)
    }
  }

  async function handleRunDetection() {
    setDetecting(true)
    setError('')
    setSuccessMsg('')
    try {
      const url = activeCase?.id
        ? `${API_URL}/api/v1/cases/${activeCase.id}/campaigns/detect`
        : `${API_URL}/api/v1/campaigns/detect`
      const res = await fetch(url, { method: 'POST' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Campaign detection failed')

      setSuccessMsg(data.message || 'Campaign detection complete!')
      await fetchCampaigns()
    } catch (e) {
      setError(e.message || 'Failed to execute campaign detection')
    } finally {
      setDetecting(false)
    }
  }

  const filteredCampaigns = campaigns.filter(c => {
    if (filterType === 'ALL') return true
    if (filterType === 'HIGH_CONF') return c.confidence >= 85
    return c.threat_type.toLowerCase().includes(filterType.toLowerCase())
  })

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base" role="img" aria-label="Campaign">🎯</span>
            <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Campaign Detection &amp; Multi-Email Correlation
            </h2>
            {activeCase && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                Case #{activeCase.case_number}
              </span>
            )}
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Correlates shared infrastructure, malicious domains, payload URLs &amp; sender patterns across multiple email artifacts.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRunDetection}
            disabled={detecting}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white transition-all shadow-sm disabled:opacity-50"
            style={{ background: 'var(--accent)' }}
          >
            {detecting ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Correlating IOCs...
              </>
            ) : (
              <>
                <span>⚡</span>
                Run Campaign Detection
              </>
            )}
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="p-3 rounded-lg text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/20">
          ⚠️ {error}
        </div>
      )}
      {successMsg && (
        <div className="p-3 rounded-lg text-xs font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
          ✓ {successMsg}
        </div>
      )}

      {/* Metric Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border flex flex-col justify-between"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <span className="text-[10px] uppercase font-bold tracking-wider" style={{ color: 'var(--text-muted)' }}>
            Detected Campaigns
          </span>
          <p className="text-2xl font-black mt-2 font-mono" style={{ color: 'var(--text-primary)' }}>
            {metrics.total_campaigns}
          </p>
          <span className="text-[10px] text-gray-500 mt-1">Cross-email threat clusters</span>
        </div>

        <div className="p-4 rounded-xl border flex flex-col justify-between"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <span className="text-[10px] uppercase font-bold tracking-wider text-red-400">
            High Confidence (≥85%)
          </span>
          <p className="text-2xl font-black mt-2 font-mono text-red-500">
            {metrics.high_confidence_count}
          </p>
          <span className="text-[10px] text-gray-500 mt-1">Strong infrastructure overlap</span>
        </div>

        <div className="p-4 rounded-xl border flex flex-col justify-between"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <span className="text-[10px] uppercase font-bold tracking-wider text-sky-400">
            Correlated Emails
          </span>
          <p className="text-2xl font-black mt-2 font-mono text-sky-500">
            {metrics.total_emails_correlated}
          </p>
          <span className="text-[10px] text-gray-500 mt-1">Linked email artifacts</span>
        </div>

        <div className="p-4 rounded-xl border flex flex-col justify-between"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <span className="text-[10px] uppercase font-bold tracking-wider text-amber-400">
            Shared IOCs
          </span>
          <p className="text-2xl font-black mt-2 font-mono text-amber-500">
            {metrics.total_shared_iocs}
          </p>
          <span className="text-[10px] text-gray-500 mt-1">Shared domains, URLs &amp; IPs</span>
        </div>
      </div>

      {/* Main Content Grid: Campaign List + Detailed Profile */}
      <div className="grid xl:grid-cols-12 gap-5 min-h-[580px]">
        {/* Left Column: Campaigns List */}
        <section className="xl:col-span-5 rounded-xl overflow-hidden flex flex-col border"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <div className="p-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Campaign Clusters ({filteredCampaigns.length})
            </span>
            <div className="flex items-center gap-1">
              {['ALL', 'HIGH_CONF', 'PHISH', 'BEC'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilterType(f)}
                  className="text-[10px] px-2 py-0.5 rounded font-medium transition-colors"
                  style={{
                    background: filterType === f ? 'var(--accent)' : 'var(--bg-raised)',
                    color: filterType === f ? '#ffffff' : 'var(--text-secondary)',
                    border: '1px solid var(--border)',
                  }}
                >
                  {f === 'HIGH_CONF' ? 'High Conf' : f}
                </button>
              ))}
            </div>
          </div>

          <div className="p-3 space-y-3 flex-1 overflow-y-auto max-h-[680px] scrollbar-thin">
            {loading ? (
              <div className="p-8 text-center text-xs text-gray-500">Loading campaigns...</div>
            ) : filteredCampaigns.length === 0 ? (
              <div className="p-8 text-center space-y-3">
                <p className="text-xs text-gray-400">No campaigns detected yet.</p>
                <p className="text-[11px] text-gray-500">
                  Click <strong>Run Campaign Detection</strong> to correlate existing email artifacts.
                </p>
              </div>
            ) : (
              filteredCampaigns.map(c => {
                const isSelected = selectedCampaignId === c.campaign_id
                return (
                  <div
                    key={c.id || c.campaign_id}
                    onClick={() => {
                      setSelectedCampaignId(c.campaign_id)
                      fetchCampaignDetail(c.campaign_id)
                    }}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${isSelected ? 'ring-2 ring-sky-500 shadow-md' : 'hover:bg-slate-500/5'}`}
                    style={{
                      background: isSelected ? 'var(--bg-raised)' : 'var(--bg-surface)',
                      borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                    }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-[10px] font-mono font-bold text-sky-400">
                          {c.campaign_id}
                        </span>
                        <h4 className="text-xs font-bold mt-0.5" style={{ color: 'var(--text-primary)' }}>
                          {c.name}
                        </h4>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${c.confidence >= 85 ? 'bg-red-500/10 text-red-500 border border-red-500/30' : 'bg-amber-500/10 text-amber-500 border border-amber-500/30'}`}>
                        {c.confidence}% CONF
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 mt-3 pt-2.5 border-t text-center text-[10px]" style={{ borderColor: 'var(--border)' }}>
                      <div>
                        <span className="text-gray-500 block">Emails</span>
                        <span className="font-mono font-bold" style={{ color: 'var(--text-primary)' }}>{c.email_count}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Shared IOCs</span>
                        <span className="font-mono font-bold text-amber-500">{c.shared_ioc_count}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Threat Type</span>
                        <span className="font-semibold truncate block" style={{ color: 'var(--text-secondary)' }}>{c.threat_type}</span>
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </section>

        {/* Right Column: Detailed Campaign Inspector */}
        <section className="xl:col-span-7 rounded-xl overflow-hidden flex flex-col border"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          {campaignDetail ? (
            <div className="p-5 space-y-5 overflow-y-auto max-h-[750px] scrollbar-thin">
              {/* Campaign Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b"
                style={{ borderColor: 'var(--border)' }}>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-black uppercase px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                      {campaignDetail.campaign_id}
                    </span>
                    <span className="text-[10px] uppercase font-bold text-gray-500">Status: {campaignDetail.status}</span>
                  </div>
                  <h3 className="text-base font-bold mt-1" style={{ color: 'var(--text-primary)' }}>
                    {campaignDetail.name}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <div className="text-right">
                    <span className="text-[10px] uppercase text-gray-500 block font-semibold">Campaign Confidence</span>
                    <span className="text-lg font-black font-mono text-red-500">{campaignDetail.confidence}%</span>
                  </div>
                </div>
              </div>

              {/* AI & SOC Summary */}
              {campaignDetail.ai_summary && (
                <div className="p-3.5 rounded-xl border space-y-1.5"
                  style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-sky-400">
                    <span>🤖</span> AI Threat Narrative &amp; SOC Summary
                  </div>
                  <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                    {campaignDetail.ai_summary}
                  </p>
                </div>
              )}

              {/* Why Grouped? (Correlation Evidence Breakdown) */}
              {campaignDetail.reasons && campaignDetail.reasons.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                    Why This Is A Campaign (Correlation Evidence)
                  </h4>
                  <div className="grid sm:grid-cols-2 gap-2">
                    {campaignDetail.reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg border text-xs"
                        style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                        <span className="text-emerald-500 font-bold">✓</span>
                        <span className="text-[11px] leading-tight" style={{ color: 'var(--text-secondary)' }}>{r}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Converging Campaign Attack Graph */}
              {campaignDetail.attack_graph?.nodes?.length > 0 && GraphCanvas && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                    Campaign Attack &amp; Infrastructure Graph
                  </h4>
                  <div className="h-[300px] rounded-xl overflow-hidden relative border"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                    <GraphCanvas graph={campaignDetail.attack_graph} />
                  </div>
                </div>
              )}

              {/* Correlated Email Members */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                  Correlated Email Artifacts ({campaignDetail.emails?.length || 0})
                </h4>
                <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border)' }}>
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b text-[10px] uppercase font-bold text-gray-500" style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
                        <th className="py-2 px-3">Subject</th>
                        <th className="py-2 px-3">Sender</th>
                        <th className="py-2 px-3">Risk</th>
                        <th className="py-2 px-3">Threat</th>
                        <th className="py-2 px-3">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(campaignDetail.emails || []).map((m, idx) => (
                        <tr key={idx} className="border-b hover:bg-slate-500/5 transition-colors" style={{ borderColor: 'var(--border)' }}>
                          <td className="py-2.5 px-3 font-medium max-w-xs truncate" style={{ color: 'var(--text-primary)' }}>
                            {m.subject || 'No Subject'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                            {m.sender}
                          </td>
                          <td className="py-2.5 px-3 font-mono font-bold text-red-500">
                            {m.risk_score}/100
                          </td>
                          <td className="py-2.5 px-3 font-semibold text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                            {m.threat_type}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400">
                              Artifact #{m.artifact_id}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Shared Indicators Table */}
              {campaignDetail.shared_indicators && campaignDetail.shared_indicators.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                    Shared Threat Indicators ({campaignDetail.shared_indicators.length})
                  </h4>
                  <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border)' }}>
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b text-[10px] uppercase font-bold text-gray-500" style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
                          <th className="py-2 px-3">Indicator</th>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Emails Seen</th>
                          <th className="py-2 px-3">Threat Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {campaignDetail.shared_indicators.map((ind, idx) => (
                          <tr key={idx} className="border-b hover:bg-slate-500/5 transition-colors" style={{ borderColor: 'var(--border)' }}>
                            <td className="py-2.5 px-3 font-mono font-semibold max-w-xs truncate" style={{ color: 'var(--text-primary)' }}>
                              {ind.indicator}
                            </td>
                            <td className="py-2.5 px-3 uppercase text-[10px] font-bold text-gray-400">
                              {ind.type}
                            </td>
                            <td className="py-2.5 px-3 font-mono font-bold text-sky-400">
                              {ind.emails_count} emails
                            </td>
                            <td className="py-2.5 px-3">
                              <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase text-red-500 bg-red-500/10 border border-red-500/30">
                                {ind.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* SOC Defensive Recommendations */}
              {campaignDetail.recommendations && campaignDetail.recommendations.length > 0 && (
                <div className="space-y-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-500">
                    Defensive Actions &amp; SOC Recommendations
                  </h4>
                  <ul className="space-y-1.5">
                    {campaignDetail.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 p-2.5 rounded-lg border text-xs"
                        style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                        <span className="text-sky-400 font-bold">🛡️</span>
                        <span style={{ color: 'var(--text-secondary)' }}>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-gray-500">
              Select a campaign cluster from the left panel to inspect detailed telemetry.
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
