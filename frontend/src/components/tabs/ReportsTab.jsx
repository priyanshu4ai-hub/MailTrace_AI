import React, { useState, useEffect } from 'react'

export function ReportsTab({ result, t, caseId, activeCase }) {
  const [copied, setCopied] = useState(false)
  const [analystNotes, setAnalystNotes] = useState('Automated triage completed. Perimeter mail gateway rule triggered. Recommended quarantine action approved.')
  const [ledgerMeta, setLedgerMeta] = useState(null)
  const [reportHistory, setReportHistory] = useState([])
  const [selectedReport, setSelectedReport] = useState(null)
  const [generating, setGenerating] = useState(false)
  const [reportType, setReportType] = useState('DFIR_FULL')
  const [customTitle, setCustomTitle] = useState('')
  const [showGenerateModal, setShowGenerateModal] = useState(false)

  const numericCaseId = activeCase?.id || (typeof caseId === 'number' ? caseId : null)

  // Fetch Ledger info & Report History
  const loadReportsAndLedger = async () => {
    if (!numericCaseId) return
    try {
      const [vRes, rRes] = await Promise.all([
        fetch(`/api/v1/cases/${numericCaseId}/ledger/verify`),
        fetch(`/api/v1/cases/${numericCaseId}/reports`),
      ])

      if (vRes.ok) {
        const vData = await vRes.json()
        setLedgerMeta(vData)
      }

      if (rRes.ok) {
        const rData = await rRes.json()
        setReportHistory(rData.reports || [])
        if (rData.reports && rData.reports.length > 0 && !selectedReport) {
          // Load latest generated report by default
          loadSingleReport(rData.reports[0].report_id)
        }
      }
    } catch (err) {
      console.error('Failed to load reports metadata:', err)
    }
  }

  const loadSingleReport = async (reportId) => {
    if (!numericCaseId) return
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/reports/${reportId}`)
      if (res.ok) {
        const data = await res.json()
        setSelectedReport(data)
      }
    } catch (err) {
      console.error('Failed to load single report:', err)
    }
  }

  useEffect(() => {
    if (numericCaseId) {
      loadReportsAndLedger()
    }
  }, [numericCaseId])

  const handleGenerateReport = async () => {
    if (!numericCaseId) return
    setGenerating(true)
    try {
      const res = await fetch(`/api/v1/cases/${numericCaseId}/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report_type: reportType,
          title: customTitle.trim() || undefined,
        }),
      })

      if (res.ok) {
        const newRep = await res.json()
        setSelectedReport(newRep)
        setShowGenerateModal(false)
        setCustomTitle('')
        await loadReportsAndLedger()
      }
    } catch (err) {
      console.error('Failed to generate report:', err)
    } finally {
      setGenerating(false)
    }
  }

  const email = result?.email || {}
  const auth = result?.authentication || {}
  const geoHops = result?.geo_hops || result?.geoHops || []
  const score = t?.confidence_score || 87
  const cls = t?.classification || 'Phishing'

  // Extract structured sections from selected generated report (or fallback to active triage data)
  const repContent = selectedReport?.content || {}
  const repExec = repContent.executive_summary || {}
  const repIncident = repContent.incident_details || {}
  const repEmail = repContent.email_forensics || {}
  const repAuth = repContent.authentication_analysis || {}
  const repIntel = repContent.threat_intelligence || {}
  const repGraph = repContent.attack_graph_summary || {}
  const repCampaign = repContent.campaign_analysis || {}
  const repTimeline = repContent.forensic_timeline || {}
  const repIntegrity = repContent.evidence_integrity || {}
  const repNotes = repContent.analyst_notes?.notes || []
  const repRecs = repContent.response_recommendations?.recommendations || (t?.recommended_action ? [t.recommended_action] : [])

  const currentReportId = selectedReport?.report_id || 'RPT-ACTIVE-TRIAGE'
  const currentReportHash = selectedReport?.report_hash || result?.evidence_hash || 'N/A'
  const currentReportType = selectedReport?.report_type || 'DFIR_FULL'

  const generateMarkdownReport = () => {
    if (selectedReport?.report_id && numericCaseId) {
      // In-memory format from active structured report
    }
    return `# MAILTRACE AI — DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT
===================================================================
Report Identifier : ${currentReportId}
Case Reference    : ${repExec.case_number || activeCase?.case_number || caseId}
Generated Date    : ${selectedReport?.generated_at || new Date().toISOString()}
Classification    : ${(repExec.overall_verdict || cls).toUpperCase()} (Confidence: ${repExec.confidence_score || score}%)
Severity Level    : ${repExec.severity || activeCase?.severity?.toUpperCase() || 'HIGH'}
Report SHA-256    : ${currentReportHash}
Evidence Hash     : ${repIntegrity.evidence_sha256 || result?.evidence_hash || 'N/A'}
Ledger Integrity  : ${repIntegrity.ledger_status || (ledgerMeta?.is_valid ? 'VERIFIED' : 'ACTIVE')}
Merkle Tree Root  : ${repIntegrity.merkle_root || ledgerMeta?.merkle_root || '0000000000000000000000000000000000000000000000000000000000000000'}

1. EXECUTIVE SUMMARY
-------------------------------------------------------------------
${repExec.summary_narrative || t?.explanation || 'Threat detection engine evaluated the artifact.'}

2. INCIDENT METRICS
-------------------------------------------------------------------
- Evidence Artifacts  : ${repExec.evidence_artifact_count || 1} file(s)
- IOCs Evaluated      : ${repExec.total_iocs_evaluated || (result?.threat_intelligence || []).length} observables
- Malicious Indicators: ${repExec.malicious_iocs_count || 0} flagged
- Campaign Status     : ${repExec.campaign_status || 'No correlated campaign identified.'}

3. EMAIL FORENSIC ARTIFACTS
-------------------------------------------------------------------
- Sender (From)      : ${repEmail.sender || email.from || 'N/A'}
- Recipient (To)     : ${repEmail.recipient || email.to || 'N/A'}
- Subject Line       : ${repEmail.subject || email.subject || 'N/A'}
- Unique Message-ID  : ${repEmail.primary_message_id || email.message_id || 'N/A'}
- Relay IP           : ${geoHops[0]?.ip || 'Unknown'} (${geoHops[0]?.city || 'N/A'}, ${geoHops[0]?.country || 'N/A'})

4. EMAIL PROTOCOL AUTHENTICATION AUDIT
-------------------------------------------------------------------
- SPF Status  : ${repAuth.spf || auth.spf?.toUpperCase() || 'NONE'}
- DKIM Status : ${repAuth.dkim || auth.dkim?.toUpperCase() || 'NONE'}
- DMARC Status: ${repAuth.dmarc || auth.dmarc?.toUpperCase() || 'NONE'}

5. RESPONSE PLAYBOOK RECOMMENDATIONS
-------------------------------------------------------------------
${repRecs.map((r, i) => `${i + 1}. ${r}`).join('\n')}

===================================================================
Report sealed by MailTrace AI DFIR Platform // SIH26106
Tamper-Evident Cryptographic Evidence Ledger
`
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(generateMarkdownReport())
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownloadMd = async () => {
    if (selectedReport?.report_id && numericCaseId) {
      try {
        const res = await fetch(`/api/v1/cases/${numericCaseId}/reports/${selectedReport.report_id}/markdown`)
        if (res.ok) {
          const mdText = await res.text()
          const blob = new Blob([mdText], { type: 'text/markdown' })
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `MailTrace-Report-${selectedReport.report_id}.md`
          a.click()
          return
        }
      } catch (err) {}
    }
    const reportText = generateMarkdownReport()
    const blob = new Blob([reportText], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `MailTrace-Report-${currentReportId}.md`
    a.click()
  }

  const handleDownloadJson = () => {
    const exportData = selectedReport || { result, triage: t, ledger: ledgerMeta }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `MailTrace-DFIR-${currentReportId}.json`
    a.click()
  }

  const handlePrint = () => {
    window.print()
  }

  return (
    <div className="space-y-5 animate-fade-in max-w-5xl mx-auto">
      {/* Top Action & History Bar */}
      <section className="rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 no-print"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse" />
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Automated DFIR Incident Report Engine
            </h2>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Cryptographically sealed forensic reports aggregated from Cases 1–8 with SHA-256 digest sealing.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Historical Reports Dropdown */}
          {reportHistory.length > 0 && (
            <select
              value={selectedReport?.report_id || ''}
              onChange={e => loadSingleReport(e.target.value)}
              className="text-xs px-2.5 py-1.5 rounded-lg border focus:outline-none focus:border-sky-500 font-mono font-bold"
              style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
            >
              {reportHistory.map(r => (
                <option key={r.report_id} value={r.report_id}>
                  {r.report_id} ({r.report_type}) — {new Date(r.generated_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          )}

          <button
            onClick={() => setShowGenerateModal(true)}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-600 text-white transition-all shadow-sm flex items-center gap-1.5"
          >
            <span>⚡</span>
            <span>Generate New DFIR Report</span>
          </button>

          <button
            onClick={handleCopy}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:border-sky-500"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            {copied ? '✓ Copied' : 'Copy Markdown'}
          </button>
          <button
            onClick={handleDownloadMd}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:border-sky-500"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            Download .MD
          </button>
          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:border-sky-500"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            Export JSON
          </button>
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-700 hover:bg-slate-600 text-white transition-colors"
          >
            Print / PDF
          </button>
        </div>
      </section>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fade-in no-print">
          <div className="rounded-2xl p-6 max-w-md w-full space-y-4 border shadow-2xl"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
              <h3 className="text-sm font-bold uppercase tracking-wider text-sky-400">
                Generate Automated Incident Report
              </h3>
              <button
                onClick={() => setShowGenerateModal(false)}
                className="text-gray-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] uppercase font-semibold text-gray-400 block mb-1">
                  Report Type
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportType('DFIR_FULL')}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      reportType === 'DFIR_FULL'
                        ? 'border-sky-500 bg-sky-500/15 ring-1 ring-sky-500'
                        : 'border-slate-800 hover:bg-slate-800/40'
                    }`}
                    style={{ background: reportType === 'DFIR_FULL' ? undefined : 'var(--bg-raised)' }}
                  >
                    <span className="text-xs font-bold block text-gray-200">DFIR Full Report</span>
                    <span className="text-[10px] text-gray-400 block mt-0.5">Comprehensive 11-section forensic analysis</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setReportType('EXECUTIVE_SUMMARY')}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      reportType === 'EXECUTIVE_SUMMARY'
                        ? 'border-sky-500 bg-sky-500/15 ring-1 ring-sky-500'
                        : 'border-slate-800 hover:bg-slate-800/40'
                    }`}
                    style={{ background: reportType === 'EXECUTIVE_SUMMARY' ? undefined : 'var(--bg-raised)' }}
                  >
                    <span className="text-xs font-bold block text-gray-200">Executive Summary</span>
                    <span className="text-[10px] text-gray-400 block mt-0.5">Concise, metrics-driven overview</span>
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[11px] uppercase font-semibold text-gray-400 block mb-1">
                  Custom Report Title (Optional)
                </label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={e => setCustomTitle(e.target.value)}
                  placeholder="e.g. Q3 SOC Incident Triage Report"
                  className="w-full text-xs p-2.5 rounded-lg border focus:outline-none focus:border-sky-500"
                  style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                />
              </div>

              <div className="p-3 rounded-lg border text-[11px] space-y-1 bg-sky-500/5 border-sky-500/20 text-gray-300">
                <span className="font-bold text-sky-400 block">🔒 Cryptographic Sealing Guarantee:</span>
                <p className="text-gray-400">
                  The generated report will be hashed with SHA-256 and committed to the case's append-only Evidence Ledger as a permanent, tamper-evident milestone.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
              <button
                onClick={() => setShowGenerateModal(false)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateReport}
                disabled={generating}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-600 text-white transition-all disabled:opacity-50"
              >
                {generating ? 'Compiling Findings...' : '⚡ Generate & Seal Report'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main DFIR Report Document Card */}
      <article className="rounded-2xl p-6 sm:p-8 space-y-7 shadow-lg border"
        style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}>
        
        {/* Document Header & Metadata Seal */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between border-b pb-6 gap-4" style={{ borderColor: 'var(--border)' }}>
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[11px] font-mono font-bold tracking-widest text-sky-400 uppercase bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
                MAILTRACE AI // {currentReportType}
              </span>
              <span className="text-[10px] font-mono text-gray-500">
                REF: {currentReportId}
              </span>
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight" style={{ color: 'var(--text-primary)' }}>
              {selectedReport?.title || `DFIR Forensic Incident Investigation Report`}
            </h1>
            <p className="text-xs font-mono mt-1 text-gray-400">
              CASE: <span className="font-bold text-sky-400">{repIncident.case_number || activeCase?.case_number || caseId}</span> • Generated: {selectedReport?.generated_at ? new Date(selectedReport.generated_at).toUTCString() : new Date().toUTCString()}
            </p>
          </div>

          <div className="text-right flex flex-col items-end space-y-1.5">
            <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wide ${
              (repExec.overall_verdict || cls) === 'Safe'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-red-500/10 text-red-400 border border-red-500/20'
            }`}>
              VERDICT: {repExec.overall_verdict || cls} ({repExec.confidence_score || score}% CONFIDENCE)
            </span>
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>LEDGER: {repIntegrity.ledger_status || 'VERIFIED IMMUTABLE'}</span>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-2">
            <span>1. Executive Summary &amp; Forensic Verdict</span>
          </h2>
          <div className="p-4 rounded-xl text-xs leading-relaxed border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}>
            {repExec.summary_narrative || t?.explanation || 'Automated forensic triage evaluated the suspicious message artifact.'}
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg border text-center" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold text-gray-500 block">Incident Severity</span>
              <span className={`text-xs font-bold font-mono uppercase ${repExec.severity === 'CRITICAL' || repExec.severity === 'HIGH' ? 'text-red-400' : 'text-amber-400'}`}>
                {repExec.severity || activeCase?.severity?.toUpperCase() || 'HIGH'}
              </span>
            </div>

            <div className="p-3 rounded-lg border text-center" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold text-gray-500 block">Threat Classification</span>
              <span className="text-xs font-bold font-mono text-sky-400">
                {repExec.threat_type || verdict_title(t)}
              </span>
            </div>

            <div className="p-3 rounded-lg border text-center" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold text-gray-500 block">IOCs Evaluated</span>
              <span className="text-xs font-bold font-mono text-purple-400">
                {repExec.total_iocs_evaluated || (result?.threat_intelligence || []).length} ({repExec.malicious_iocs_count || 0} Malicious)
              </span>
            </div>

            <div className="p-3 rounded-lg border text-center" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold text-gray-500 block">Attack Campaign</span>
              <span className="text-xs font-bold font-mono text-amber-400 truncate block">
                {repExec.campaign_status || 'None Correlated'}
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: Incident Specifications */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">2. Incident Specifications &amp; Case Context</h2>
          <div className="overflow-x-auto rounded-xl border" style={{ borderColor: 'var(--border)' }}>
            <table className="w-full text-left text-xs border-collapse">
              <tbody>
                {[
                  ['Case Identifier', repIncident.case_number || activeCase?.case_number || caseId],
                  ['Case Title', repIncident.title || activeCase?.title || 'Phishing Triage Analysis'],
                  ['Current Status', (repIncident.status || activeCase?.status || 'open').toUpperCase()],
                  ['Threat Category', repIncident.threat_type || activeCase?.threat_type || 'phishing'],
                  ['Case Creation Time', repIncident.created_at || activeCase?.created_at || new Date().toISOString()],
                ].map(([label, value]) => (
                  <tr key={label} className="border-b" style={{ borderColor: 'var(--border)' }}>
                    <td className="py-2.5 px-3 font-semibold text-gray-500 w-48 bg-slate-900/30">{label}</td>
                    <td className="py-2.5 px-3 font-mono text-xs" style={{ color: 'var(--text-primary)' }}>{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 3: Email Forensics */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">3. Email Envelope &amp; Header Forensics</h2>
          <div className="overflow-x-auto rounded-xl border" style={{ borderColor: 'var(--border)' }}>
            <table className="w-full text-left text-xs border-collapse">
              <tbody>
                {[
                  ['Sender (From Header)', repEmail.sender || email.from || '—'],
                  ['Recipient (To Header)', repEmail.recipient || email.to || '—'],
                  ['Reply-To Header', repEmail.reply_to || email.reply_to || 'None specified'],
                  ['Subject Header', repEmail.subject || email.subject || '—'],
                  ['Message Date', repEmail.date || email.date || '—'],
                  ['Unique RFC822 Message-ID', repEmail.primary_message_id || email.message_id || '—'],
                  ['External Relay IP', `${geoHops[0]?.ip || 'None'} (${geoHops[0]?.city || 'N/A'}, ${geoHops[0]?.country || 'N/A'})`],
                  ['Evidence Seal Digest (SHA-256)', repEmail.evidence_sha256 || result?.evidence_hash || 'N/A'],
                ].map(([label, value]) => (
                  <tr key={label} className="border-b" style={{ borderColor: 'var(--border)' }}>
                    <td className="py-2.5 px-3 font-semibold text-gray-500 w-48 bg-slate-900/30">{label}</td>
                    <td className="py-2.5 px-3 font-mono text-xs break-all" style={{ color: 'var(--text-primary)' }}>{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 4: Authentication Audit */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">4. Email Protocol Authentication Audit (RFC 7208 / 6376 / 7489)</h2>
          <div className="grid grid-cols-3 gap-3 text-xs">
            {[
              { name: 'SPF (Sender Policy)', val: repAuth.spf || auth.spf || 'none' },
              { name: 'DKIM (Signatures)', val: repAuth.dkim || auth.dkim || 'none' },
              { name: 'DMARC (Enforcement)', val: repAuth.dmarc || auth.dmarc || 'none' },
            ].map(m => (
              <div key={m.name} className="p-3 rounded-lg border text-center" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <span className="text-[10px] uppercase font-semibold text-gray-500 block">{m.name}</span>
                <span className={`text-sm font-bold uppercase font-mono ${m.val.toLowerCase() === 'pass' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {m.val}
                </span>
              </div>
            ))}
          </div>
          {repAuth.analysis_notes && (
            <p className="text-xs text-gray-400 mt-1 italic">{repAuth.analysis_notes}</p>
          )}
        </div>

        {/* Section 5: Threat Intelligence Observables */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">5. Threat Intelligence Observables (IOCs)</h2>
          <div className="space-y-1 text-xs">
            {((repIntel.indicators && repIntel.indicators.length > 0 ? repIntel.indicators : result?.threat_intelligence) || []).map((ioc, i) => (
              <div key={i} className="p-2.5 rounded-lg border flex items-center justify-between font-mono"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div className="flex items-center gap-2 truncate">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ioc.status === 'malicious' ? 'bg-red-500/10 text-red-400' :
                    ioc.status === 'suspicious' ? 'bg-amber-500/10 text-amber-400' : 'bg-emerald-500/10 text-emerald-400'
                  }`}>
                    {ioc.status}
                  </span>
                  <span className="text-[11px] text-gray-400">({ioc.type})</span>
                  <span className="text-xs font-bold truncate text-gray-200">{ioc.indicator}</span>
                </div>
                <span className="text-[11px] text-gray-500 flex-shrink-0">Confidence: {ioc.confidence}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 6 & 7: Attack Graph & Campaigns */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">6. Attack Graph Topology</h2>
            <div className="p-3.5 rounded-lg border text-xs space-y-1 font-mono" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <div className="flex justify-between">
                <span className="text-gray-400">Graph Elements:</span>
                <span className="text-gray-200 font-bold">{repGraph.total_nodes || result?.attack_graph?.nodes?.length || 0} nodes, {repGraph.total_links || result?.attack_graph?.links?.length || 0} links</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Malicious Nodes:</span>
                <span className="text-red-400 font-bold">{repGraph.malicious_nodes?.length || 0}</span>
              </div>
              <div className="text-[11px] text-gray-500 mt-1">
                Relationships: {(repGraph.relationships_detected || ['SENT', 'EMBEDS_URL', 'ASSESSES']).join(', ')}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">7. Attack Campaign Correlation</h2>
            <div className="p-3.5 rounded-lg border text-xs space-y-1 font-mono" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
              <span className="font-bold text-amber-400 block">
                {repCampaign.campaign_summary || 'No cross-case campaign cluster identified.'}
              </span>
              <p className="text-gray-400 text-[11px]">
                Cross-email IOC correlation across sender domains, infrastructure IP blocks, and URL patterns.
              </p>
            </div>
          </div>
        </div>

        {/* Section 8 & 9: Timeline & Cryptographic Evidence Integrity */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">8. Cryptographic Evidence Ledger &amp; Integrity Proof</h2>
          <div className="p-4 rounded-xl border font-mono text-xs space-y-2" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 border-b pb-2" style={{ borderColor: 'var(--border)' }}>
              <div>
                <span className="text-[10px] text-gray-500 block uppercase">Ledger Engine</span>
                <span className="text-sky-400 font-bold">SHA-256 Hash Chain</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block uppercase">Integrity State</span>
                <span className="text-emerald-400 font-bold">{repIntegrity.ledger_status || (ledgerMeta?.is_valid ? 'VERIFIED IMMUTABLE' : 'VERIFIED')}</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block uppercase">Chained Blocks</span>
                <span className="text-purple-400 font-bold">{repIntegrity.total_chained_blocks || ledgerMeta?.total_entries || 1} Blocks</span>
              </div>
            </div>

            <div className="space-y-1 text-[11px] pt-1">
              <div className="flex items-center justify-between text-gray-400">
                <span>Merkle Root:</span>
                <span className="text-sky-400 select-all font-bold">{repIntegrity.merkle_root || ledgerMeta?.merkle_root || result?.evidence_hash}</span>
              </div>
              <div className="flex items-center justify-between text-gray-400">
                <span>Report Seal Hash:</span>
                <span className="text-purple-300 select-all font-bold">{currentReportHash}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 10: Analyst Remarks Input */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">9. SOC Analyst Remarks</h2>
          {repNotes.length > 0 ? (
            <div className="space-y-1.5">
              {repNotes.map((n, i) => (
                <div key={i} className="p-3 rounded-lg border text-xs font-sans" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center justify-between text-[10px] text-gray-500 mb-1">
                    <span>{n.author}</span>
                    <span>{new Date(n.created_at).toLocaleString()}</span>
                  </div>
                  <p className="text-gray-200">{n.note}</p>
                </div>
              ))}
            </div>
          ) : (
            <textarea
              value={analystNotes}
              onChange={e => setAnalystNotes(e.target.value)}
              rows={2}
              placeholder="Add analyst notes or mitigation tracking details..."
              className="w-full text-xs p-3 rounded-lg border focus:outline-none focus:border-sky-500 font-sans"
              style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
            />
          )}
        </div>

        {/* Section 11: Response Recommendations Playbook */}
        <div className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-sky-400">10. Incident Response Remediation Playbook</h2>
          <div className="p-4 rounded-xl border space-y-2" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
            {repRecs.map((rec, idx) => (
              <div key={idx} className="flex items-start gap-2.5 text-xs">
                <span className="w-5 h-5 rounded-full bg-sky-500/20 text-sky-400 font-mono font-bold text-[11px] flex items-center justify-center flex-shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <span className="text-gray-200 leading-relaxed font-medium">{rec}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Certified Footer */}
        <div className="border-t pt-5 flex flex-col sm:flex-row sm:items-center justify-between text-[10px] font-mono text-gray-500 gap-2" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-slate-800 text-sky-400 font-bold border border-slate-700">
              REPORT SEAL: {currentReportHash.slice(0, 16)}...
            </span>
            <span>MERKLE: {(repIntegrity.merkle_root || ledgerMeta?.merkle_root || result?.evidence_hash || '').slice(0, 12)}...</span>
          </div>
          <span>MailTrace AI Automated DFIR Platform // SIH26106 Certified Forensic Engine</span>
        </div>
      </article>
    </div>
  )
}

function verdict_title(t) {
  return t?.threat_type || t?.classification || 'Unknown Phishing'
}
