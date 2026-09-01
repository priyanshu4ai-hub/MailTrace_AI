import React, { useState, useEffect } from 'react'

const STATUS_COLORS = {
  RECOMMENDED: { bg: 'rgba(59,130,246,0.12)', text: '#60a5fa', border: 'rgba(59,130,246,0.25)' },
  PENDING_APPROVAL: { bg: 'rgba(251,191,36,0.12)', text: '#fbbf24', border: 'rgba(251,191,36,0.25)' },
  APPROVED: { bg: 'rgba(16,185,129,0.12)', text: '#34d399', border: 'rgba(16,185,129,0.25)' },
  EXECUTING: { bg: 'rgba(139,92,246,0.12)', text: '#a78bfa', border: 'rgba(139,92,246,0.25)' },
  EXECUTED: { bg: 'rgba(16,185,129,0.12)', text: '#10b981', border: 'rgba(16,185,129,0.25)' },
  REJECTED: { bg: 'rgba(239,68,68,0.12)', text: '#f87171', border: 'rgba(239,68,68,0.25)' },
  FAILED: { bg: 'rgba(239,68,68,0.12)', text: '#ef4444', border: 'rgba(239,68,68,0.25)' },
  CANCELLED: { bg: 'rgba(100,116,139,0.12)', text: '#94a3b8', border: 'rgba(100,116,139,0.25)' },
}

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

const ACTION_ICONS = {
  BLOCK_DOMAIN: '🌐',
  BLOCK_IP: '🛡️',
  BLOCK_URL: '🔗',
  SEARCH_MAILBOX: '📧',
  ISOLATE_ARTIFACT: '🔒',
  FLAG_USER: '🚩',
  RESET_CREDENTIAL_RECOMMENDATION: '🔑',
}

export function ResponseTab({ result, activeCase }) {
  const [actions, setActions] = useState([])
  const [metrics, setMetrics] = useState({})
  const [generating, setGenerating] = useState(false)
  const [selectedAction, setSelectedAction] = useState(null)
  const [showExecuteConfirm, setShowExecuteConfirm] = useState(null)
  const [showRejectModal, setShowRejectModal] = useState(null)
  const [rejectReason, setRejectReason] = useState('')

  const numericCaseId = activeCase?.id || null

  const loadResponses = async () => {
    if (!numericCaseId) return
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/responses`)
      if (res.ok) {
        const data = await res.json()
        setActions(data.actions || [])
        setMetrics({
          total: data.total_actions,
          recommended: data.recommended_count,
          pending: data.pending_approval_count,
          approved: data.approved_count,
          executed: data.executed_count,
          rejected: data.rejected_count,
        })
      }
    } catch (err) {
      console.error('Failed to load responses:', err)
    }
  }

  useEffect(() => { if (numericCaseId) loadResponses() }, [numericCaseId])

  const handleGenerateRecommendations = async () => {
    if (!numericCaseId) return
    setGenerating(true)
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/responses/recommend`, { method: 'POST' })
      if (res.ok) await loadResponses()
    } catch (err) {
      console.error('Failed to generate recommendations:', err)
    } finally {
      setGenerating(false)
    }
  }

  const handleApprove = async (responseId) => {
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/responses/${responseId}/approve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
      if (res.ok) await loadResponses()
    } catch (err) { console.error(err) }
  }

  const handleReject = async (responseId) => {
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/responses/${responseId}/reject`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: rejectReason || 'Action rejected by SOC analyst.' }) })
      if (res.ok) { setShowRejectModal(null); setRejectReason(''); await loadResponses() }
    } catch (err) { console.error(err) }
  }

  const handleExecute = async (responseId) => {
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/responses/${responseId}/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
      if (res.ok) { setShowExecuteConfirm(null); await loadResponses() }
    } catch (err) { console.error(err) }
  }

  const metricCards = [
    { label: 'Total', value: metrics.total || 0, color: '#60a5fa' },
    { label: 'Recommended', value: metrics.recommended || 0, color: '#60a5fa' },
    { label: 'Approved', value: metrics.approved || 0, color: '#34d399' },
    { label: 'Executed', value: metrics.executed || 0, color: '#10b981' },
    { label: 'Rejected', value: metrics.rejected || 0, color: '#f87171' },
  ]

  return (
    <div className="space-y-5 animate-fade-in max-w-5xl mx-auto">
      {/* Header */}
      <section className="rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 no-print"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Incident Response Console
            </h2>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Controlled SOC automation with analyst approval gates. All actions execute in SIMULATION mode.
          </p>
        </div>

        <button
          onClick={handleGenerateRecommendations}
          disabled={generating || !numericCaseId}
          className="px-4 py-2 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-600 text-white transition-all shadow-sm flex items-center gap-2 disabled:opacity-50"
        >
          <span>⚡</span>
          <span>{generating ? 'Analyzing Findings...' : 'Generate Recommendations'}</span>
        </button>
      </section>

      {/* Metrics Overview */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {metricCards.map(mc => (
          <div key={mc.label} className="p-3 rounded-xl border text-center"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <span className="text-[10px] uppercase font-semibold text-gray-500 block">{mc.label}</span>
            <span className="text-xl font-bold font-mono" style={{ color: mc.color }}>{mc.value}</span>
          </div>
        ))}
      </div>

      {/* Simulation Disclaimer */}
      {actions.length > 0 && (
        <div className="p-3 rounded-lg border text-xs bg-amber-500/5 border-amber-500/20 flex items-center gap-2">
          <span className="text-amber-400 font-bold text-sm">⚠</span>
          <span className="text-amber-300/80 font-medium">
            SIMULATION MODE — No production firewalls, DNS providers, mailboxes, or identity systems will be modified. All responses are controlled simulations for SOC workflow demonstration.
          </span>
        </div>
      )}

      {/* Actions List */}
      {actions.length === 0 ? (
        <div className="p-8 rounded-xl border text-center" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
          <p className="text-sm text-gray-400 font-medium">No response actions generated yet.</p>
          <p className="text-xs text-gray-500 mt-1">Click "Generate Recommendations" to analyze case findings and create targeted response actions.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {actions.map(action => {
            const sc = STATUS_COLORS[action.status] || STATUS_COLORS.RECOMMENDED
            const sevColor = SEVERITY_COLORS[action.severity] || '#94a3b8'
            const icon = ACTION_ICONS[action.action_type] || '🔧'

            return (
              <div key={action.response_id}
                className="rounded-xl border p-4 transition-all hover:border-sky-500/30 cursor-pointer"
                style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                onClick={() => setSelectedAction(selectedAction?.response_id === action.response_id ? null : action)}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3 flex-1 min-w-0">
                    <span className="text-xl mt-0.5">{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-bold text-sky-400">{action.response_id}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase border"
                          style={{ background: sc.bg, color: sc.text, borderColor: sc.border }}>
                          {action.status}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                          style={{ background: `${sevColor}15`, color: sevColor }}>
                          {action.severity}
                        </span>
                      </div>
                      <p className="text-xs font-semibold text-gray-200 mt-1">{action.action_type.replace(/_/g, ' ')}</p>
                      <p className="text-xs font-mono text-gray-400 truncate mt-0.5" title={action.target}>{action.target}</p>
                      <p className="text-[11px] text-gray-500 mt-1 line-clamp-2">{action.reason}</p>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col items-end gap-1.5 flex-shrink-0" onClick={e => e.stopPropagation()}>
                    {(action.status === 'RECOMMENDED' || action.status === 'PENDING_APPROVAL') && (
                      <>
                        <button onClick={() => handleApprove(action.response_id)}
                          className="px-3 py-1 rounded-lg text-[11px] font-semibold bg-emerald-500 hover:bg-emerald-600 text-white transition-all">
                          ✓ Approve
                        </button>
                        <button onClick={() => { setShowRejectModal(action); setRejectReason('') }}
                          className="px-3 py-1 rounded-lg text-[11px] font-medium border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-all">
                          ✕ Reject
                        </button>
                      </>
                    )}
                    {action.status === 'APPROVED' && (
                      <button onClick={() => setShowExecuteConfirm(action)}
                        className="px-3 py-1.5 rounded-lg text-[11px] font-semibold bg-purple-500 hover:bg-purple-600 text-white transition-all flex items-center gap-1">
                        <span>▶</span> Execute
                      </button>
                    )}
                    {action.status === 'EXECUTED' && (
                      <span className="px-2 py-1 rounded-lg text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                        {action.result}
                      </span>
                    )}
                  </div>
                </div>

                {/* Expanded Detail */}
                {selectedAction?.response_id === action.response_id && (
                  <div className="mt-4 pt-4 border-t space-y-3 text-xs" style={{ borderColor: 'var(--border)' }}>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      {[
                        ['Response ID', action.response_id],
                        ['Action Type', action.action_type],
                        ['Target', action.target],
                        ['Severity', action.severity.toUpperCase()],
                        ['Execution Mode', action.execution_mode],
                        ['Result', action.result || 'Pending'],
                        ['Requested By', action.requested_by],
                        ['Approved By', action.approved_by || '—'],
                        ['Source', action.source],
                        ['Created At', action.created_at ? new Date(action.created_at).toLocaleString() : '—'],
                        ['Approved At', action.approved_at ? new Date(action.approved_at).toLocaleString() : '—'],
                        ['Executed At', action.executed_at ? new Date(action.executed_at).toLocaleString() : '—'],
                      ].map(([label, value]) => (
                        <div key={label}>
                          <span className="text-[10px] uppercase font-semibold text-gray-500 block">{label}</span>
                          <span className="text-gray-200 font-mono font-bold text-[11px] break-all">{value}</span>
                        </div>
                      ))}
                    </div>

                    {action.evidence && action.evidence.length > 0 && (
                      <div>
                        <span className="text-[10px] uppercase font-semibold text-gray-500 block mb-1">Supporting Evidence</span>
                        <div className="flex flex-wrap gap-1.5">
                          {action.evidence.map((ev, i) => (
                            <span key={i} className="px-2 py-0.5 rounded text-[10px] font-medium bg-sky-500/10 text-sky-300 border border-sky-500/20">
                              {ev}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {action.result_message && (
                      <div className="p-3 rounded-lg border bg-slate-900/40" style={{ borderColor: 'var(--border)' }}>
                        <span className="text-[10px] uppercase font-semibold text-gray-500 block mb-1">Execution Log</span>
                        <p className="text-[11px] text-emerald-400 font-mono">{action.result_message}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Execute Confirmation Modal */}
      {showExecuteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fade-in no-print">
          <div className="rounded-2xl p-6 max-w-md w-full space-y-4 border shadow-2xl"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-amber-400 uppercase tracking-wider">⚠ Confirm Execution</h3>
              <button onClick={() => setShowExecuteConfirm(null)} className="text-gray-400 hover:text-white text-lg font-bold">✕</button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="p-3 rounded-lg border bg-amber-500/5 border-amber-500/20 text-amber-300/80 font-medium text-center">
                SIMULATION MODE — NO PRODUCTION SYSTEM WILL BE MODIFIED
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-[10px] uppercase text-gray-500 block">Action</span>
                  <span className="text-gray-200 font-bold">{showExecuteConfirm.action_type.replace(/_/g, ' ')}</span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-gray-500 block">Target</span>
                  <span className="text-sky-400 font-mono font-bold break-all">{showExecuteConfirm.target}</span>
                </div>
              </div>
              <div>
                <span className="text-[10px] uppercase text-gray-500 block">Reason</span>
                <span className="text-gray-300">{showExecuteConfirm.reason}</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
              <button onClick={() => setShowExecuteConfirm(null)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white">
                Cancel
              </button>
              <button onClick={() => handleExecute(showExecuteConfirm.response_id)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-purple-500 hover:bg-purple-600 text-white transition-all">
                ▶ Execute in Simulation Mode
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fade-in no-print">
          <div className="rounded-2xl p-6 max-w-md w-full space-y-4 border shadow-2xl"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-red-400 uppercase tracking-wider">Reject Response Action</h3>
              <button onClick={() => setShowRejectModal(null)} className="text-gray-400 hover:text-white text-lg font-bold">✕</button>
            </div>

            <div className="text-xs space-y-2">
              <p className="text-gray-300">Rejecting <span className="font-bold text-sky-400">{showRejectModal.response_id}</span> ({showRejectModal.action_type})</p>
              <textarea
                value={rejectReason}
                onChange={e => setRejectReason(e.target.value)}
                rows={2}
                placeholder="Reason for rejection..."
                className="w-full p-2.5 rounded-lg border text-xs focus:outline-none focus:border-red-500"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
              <button onClick={() => setShowRejectModal(null)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white">
                Cancel
              </button>
              <button onClick={() => handleReject(showRejectModal.response_id)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-red-500 hover:bg-red-600 text-white transition-all">
                Reject Action
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
