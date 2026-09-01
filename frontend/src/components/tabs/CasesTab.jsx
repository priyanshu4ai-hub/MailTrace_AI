import React, { useEffect, useState } from 'react'

const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

export function CasesTab({ onSelectCaseForInvestigation }) {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showNewModal, setShowNewModal] = useState(false)
  const [selectedCase, setSelectedCase] = useState(null)
  const [noteText, setNoteText] = useState('')
  const [postingNote, setPostingNote] = useState(false)

  // New Case form state
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')
  const [newThreatType, setNewThreatType] = useState('phishing')
  const [creating, setCreating] = useState(false)

  const fetchCases = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_URL}/api/v1/cases`)
      if (!res.ok) throw new Error('Failed to load cases.')
      const data = await res.json()
      setCases(data)
      if (selectedCase) {
        const updated = data.find(c => c.id === selectedCase.id)
        if (updated) setSelectedCase(updated)
      }
    } catch (err) {
      setError(err.message || 'Cannot fetch cases from backend API.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCases()
  }, [])

  const handleCreateCase = async (e) => {
    e.preventDefault()
    if (!newTitle.trim()) return
    setCreating(true)
    try {
      const res = await fetch(`${API_URL}/api/v1/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle.trim(),
          description: newDesc.trim(),
          severity: newSeverity,
          threat_type: newThreatType,
        }),
      })
      if (!res.ok) throw new Error('Could not create case.')
      const created = await res.json()
      setCases([created, ...cases])
      setShowNewModal(false)
      setNewTitle('')
      setNewDesc('')
      setSelectedCase(created)
    } catch (err) {
      alert(err.message || 'Error creating case')
    } finally {
      setCreating(false)
    }
  }

  const handleAddNote = async () => {
    if (!selectedCase || !noteText.trim()) return
    setPostingNote(true)
    try {
      const res = await fetch(`${API_URL}/api/v1/cases/${selectedCase.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteText.trim() }),
      })
      if (!res.ok) throw new Error('Failed to add analyst note.')
      setNoteText('')
      fetchCases()
    } catch (err) {
      alert(err.message || 'Error adding note')
    } finally {
      setPostingNote(false)
    }
  }

  const handleStatusChange = async (newStatus) => {
    if (!selectedCase) return
    try {
      const res = await fetch(`${API_URL}/api/v1/cases/${selectedCase.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      })
      if (!res.ok) throw new Error('Failed to update status.')
      const updated = await res.json()
      setSelectedCase(updated)
      fetchCases()
    } catch (err) {
      alert(err.message || 'Error updating status')
    }
  }

  const formatDate = (isoStr) => {
    if (!isoStr) return '—'
    try {
      const d = new Date(isoStr)
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    } catch {
      return isoStr
    }
  }

  const getSevBadge = (sev) => {
    const s = (sev || 'medium').toLowerCase()
    if (s === 'critical' || s === 'high') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-red-500 bg-red-500/10 border border-red-500/20">{s}</span>
    }
    if (s === 'medium') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-amber-500 bg-amber-500/10 border border-amber-500/20">{s}</span>
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-emerald-500 bg-emerald-500/10 border border-emerald-500/20">{s}</span>
  }

  const getStatusBadge = (st) => {
    const s = (st || 'open').toLowerCase()
    if (s === 'open') return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-sky-500 bg-sky-500/10">OPEN</span>
    if (s === 'in_progress') return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-amber-500 bg-amber-500/10">IN PROGRESS</span>
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-gray-400 bg-gray-500/10">CLOSED</span>
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Action Header */}
      <section className="rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            DFIR Incident Case Management
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Persistent SQLite database repository tracking incident cases, email artifacts, forensic results, and timeline audits.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchCases}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            ↻ Refresh
          </button>
          <button
            onClick={() => setShowNewModal(true)}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white shadow-sm transition-all"
            style={{ background: 'var(--accent)' }}
          >
            + New Case
          </button>
        </div>
      </section>

      {error && (
        <div className="p-3 rounded-xl text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-500">
          {error}
        </div>
      )}

      {/* Main Grid: Cases Table (Left) + Selected Case Detail (Right) */}
      <div className="grid xl:grid-cols-12 gap-5">
        {/* Cases List */}
        <section className={`${selectedCase ? 'xl:col-span-7' : 'xl:col-span-12'} rounded-xl overflow-hidden flex flex-col`}
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="p-3.5 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Active Incident Cases ({cases.length})
            </span>
            <span className="text-[10px] text-gray-500">Click any row to inspect case file</span>
          </div>

          {loading ? (
            <div className="p-8 text-center text-xs text-gray-500 animate-pulse">Loading database records...</div>
          ) : cases.length === 0 ? (
            <div className="p-12 text-center space-y-3">
              <p className="text-xs text-gray-400">No cases found in database.</p>
              <button
                onClick={() => setShowNewModal(true)}
                className="text-xs font-semibold text-sky-500 underline"
              >
                Create your first case →
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-wider"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                    <th className="py-2.5 px-3">Case Number</th>
                    <th className="py-2.5 px-3">Title</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Threat Type</th>
                    <th className="py-2.5 px-3">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((c) => {
                    const isSelected = selectedCase?.id === c.id
                    return (
                      <tr
                        key={c.id}
                        onClick={() => setSelectedCase(c)}
                        className={`border-b cursor-pointer transition-colors ${isSelected ? 'bg-sky-500/10' : 'hover:bg-slate-500/5'}`}
                        style={{ borderColor: 'var(--border)' }}
                      >
                        <td className="py-2.5 px-3 font-mono font-bold text-sky-500 text-[11px] whitespace-nowrap">
                          {c.case_number}
                        </td>
                        <td className="py-2.5 px-3 font-semibold break-words max-w-[200px]" style={{ color: 'var(--text-primary)' }}>
                          {c.title}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">{getSevBadge(c.severity)}</td>
                        <td className="py-2.5 px-3 whitespace-nowrap">{getStatusBadge(c.status)}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] uppercase text-gray-400 whitespace-nowrap">
                          {c.threat_type}
                        </td>
                        <td className="py-2.5 px-3 text-[10px] text-gray-500 whitespace-nowrap">
                          {formatDate(c.updated_at)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Selected Case Detail Inspector */}
        {selectedCase && (
          <section className="xl:col-span-5 rounded-xl p-5 space-y-5 flex flex-col justify-between"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-start justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-sky-500">{selectedCase.case_number}</span>
                    {getStatusBadge(selectedCase.status)}
                    {getSevBadge(selectedCase.severity)}
                  </div>
                  <h3 className="text-base font-bold mt-1" style={{ color: 'var(--text-primary)' }}>{selectedCase.title}</h3>
                </div>
                <button
                  onClick={() => setSelectedCase(null)}
                  className="text-gray-500 hover:text-gray-300 text-xs px-2 py-1"
                >
                  ✕ Close
                </button>
              </div>

              {/* Status Update Actions */}
              <div className="flex items-center justify-between text-xs p-2.5 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <span className="text-gray-500 font-medium">Status Workflow:</span>
                <div className="flex gap-1.5">
                  {['open', 'in_progress', 'closed'].map((st) => (
                    <button
                      key={st}
                      onClick={() => handleStatusChange(st)}
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors ${selectedCase.status === st ? 'bg-sky-500 text-white' : 'bg-slate-500/10 text-gray-400 hover:bg-slate-500/20'}`}
                    >
                      {st.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>

              {/* Open Investigation Action */}
              <div className="p-3.5 rounded-xl border bg-sky-500/5 border-sky-500/20 flex items-center justify-between">
                <div>
                  <p className="text-xs font-bold text-sky-500">Open Investigation for {selectedCase.case_number}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5">Attach a live .EML file or view forensic results under this case.</p>
                </div>
                <button
                  onClick={() => onSelectCaseForInvestigation && onSelectCaseForInvestigation(selectedCase)}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-bold bg-sky-500 text-white hover:bg-sky-600 transition-colors shadow-sm whitespace-nowrap"
                >
                  Investigate →
                </button>
              </div>

              {/* Description */}
              {selectedCase.description && (
                <div>
                  <p className="text-[10px] uppercase font-bold text-gray-500 tracking-wider mb-1">Description</p>
                  <p className="text-xs p-3 rounded-lg leading-relaxed" style={{ background: 'var(--bg-raised)', color: 'var(--text-secondary)' }}>
                    {selectedCase.description}
                  </p>
                </div>
              )}

              {/* Attached Email Artifacts */}
              <div>
                <p className="text-[10px] uppercase font-bold text-gray-500 tracking-wider mb-1.5">
                  Attached Email Artifacts ({selectedCase.email_artifacts?.length || 0})
                </p>
                {selectedCase.email_artifacts?.length === 0 ? (
                  <p className="text-xs text-gray-500 italic p-2">No email artifacts attached yet.</p>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto scrollbar-thin">
                    {selectedCase.email_artifacts?.map((art) => (
                      <div key={art.id} className="p-2.5 rounded-lg border text-xs flex items-center justify-between"
                        style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                        <div>
                          <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>{art.filename}</p>
                          <p className="text-[10px] font-mono text-gray-500 truncate max-w-xs">{art.subject || 'No Subject'}</p>
                        </div>
                        <span className="font-mono text-[9px] text-sky-500 font-bold bg-sky-500/10 px-1.5 py-0.5 rounded">
                          SHA: {art.sha256?.slice(0, 8)}...
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Timeline Audit Log */}
              <div>
                <p className="text-[10px] uppercase font-bold text-gray-500 tracking-wider mb-1.5">
                  Case Timeline History ({selectedCase.timeline_events?.length || 0})
                </p>
                <div className="space-y-1.5 max-h-40 overflow-y-auto scrollbar-thin">
                  {selectedCase.timeline_events?.map((evt) => (
                    <div key={evt.id} className="p-2 rounded text-xs flex items-start justify-between border"
                      style={{ background: 'var(--bg-inset)', borderColor: 'var(--border)' }}>
                      <div>
                        <span className="text-[9px] font-mono font-bold uppercase text-sky-500 block">{evt.event_type}</span>
                        <p className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{evt.description}</p>
                      </div>
                      <span className="text-[9px] font-mono text-gray-500 whitespace-nowrap ml-2">{formatDate(evt.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Notes */}
              <div>
                <p className="text-[10px] uppercase font-bold text-gray-500 tracking-wider mb-1.5">Analyst Notes</p>
                <div className="space-y-2 mb-2 max-h-32 overflow-y-auto scrollbar-thin">
                  {selectedCase.analyst_notes?.map((n) => (
                    <div key={n.id} className="p-2.5 rounded-lg border text-xs" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                      <p style={{ color: 'var(--text-primary)' }}>{n.note}</p>
                      <p className="text-[9px] text-gray-500 mt-1 font-mono">{formatDate(n.created_at)}</p>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    placeholder="Add an analyst note to this case..."
                    className="flex-1 text-xs px-3 py-2 rounded-lg border focus:outline-none focus:border-sky-500"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                  />
                  <button
                    onClick={handleAddNote}
                    disabled={postingNote || !noteText.trim()}
                    className="px-3 py-2 text-xs font-semibold bg-sky-500 text-white rounded-lg hover:bg-sky-600 disabled:opacity-50 transition-colors"
                  >
                    Post Note
                  </button>
                </div>
              </div>
            </div>
          </section>
        )}
      </div>

      {/* New Case Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="w-full max-w-lg rounded-2xl border p-6 space-y-5 shadow-2xl"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}>
            <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
              <h3 className="text-base font-bold">Create New Incident Case</h3>
              <button onClick={() => setShowNewModal(false)} className="text-gray-500 hover:text-gray-300">✕</button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-4 text-xs">
              <div>
                <label className="block text-gray-400 font-semibold mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. M365 Spearphishing Token Harvester Campaign"
                  className="w-full text-xs p-2.5 rounded-lg border focus:outline-none focus:border-sky-500"
                  style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                />
              </div>

              <div>
                <label className="block text-gray-400 font-semibold mb-1">Description</label>
                <textarea
                  rows={3}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Brief summary of initial triage observations or reported email incident..."
                  className="w-full text-xs p-2.5 rounded-lg border focus:outline-none focus:border-sky-500"
                  style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-gray-400 font-semibold mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full text-xs p-2.5 rounded-lg border focus:outline-none focus:border-sky-500"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-400 font-semibold mb-1">Threat Type</label>
                  <select
                    value={newThreatType}
                    onChange={(e) => setNewThreatType(e.target.value)}
                    className="w-full text-xs p-2.5 rounded-lg border focus:outline-none focus:border-sky-500"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                  >
                    <option value="phishing">Phishing</option>
                    <option value="bec">BEC Wire Fraud</option>
                    <option value="impersonation">Brand Impersonation</option>
                    <option value="spam">Spam / Low Risk</option>
                    <option value="safe">Safe / Clean</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium border"
                  style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)', color: 'var(--text-secondary)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !newTitle.trim()}
                  className="px-5 py-2 rounded-lg text-xs font-semibold bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 transition-colors shadow-sm"
                >
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
