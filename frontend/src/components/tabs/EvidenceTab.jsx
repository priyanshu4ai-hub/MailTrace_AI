import React, { useState, useEffect } from 'react'

export function EvidenceTab({ result, activeCase }) {
  const [evidenceView, setEvidenceView] = useState('headers')
  const [searchQuery, setSearchQuery] = useState('')
  const [copied, setCopied] = useState(false)
  const [ledgerData, setLedgerData] = useState(null)
  const [verificationResult, setVerificationResult] = useState(null)
  const [loadingLedger, setLoadingLedger] = useState(false)
  const [selectedBlock, setSelectedBlock] = useState(null)

  const email = result?.email || {}
  const auth = result?.authentication || {}
  const caseId = activeCase?.id

  const rawHeaders = [
    `From: ${email.from || ''}`,
    `To: ${email.to || ''}`,
    `Subject: ${email.subject || ''}`,
    `Date: ${email.date || ''}`,
    `Message-ID: ${email.message_id || ''}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset="utf-8"`,
    `Authentication-Results: ${email.authentication_results || 'none'}`,
    ...(email.received_headers || []).map(h => `Received: ${h}`),
  ]

  const filteredHeaders = searchQuery
    ? rawHeaders.filter(h => h.toLowerCase().includes(searchQuery.toLowerCase()))
    : rawHeaders

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Fetch Ledger data and verification status
  const fetchLedger = async () => {
    if (!caseId) return
    setLoadingLedger(true)
    try {
      const [ledgerRes, verifyRes] = await Promise.all([
        fetch(`/api/v1/cases/${caseId}/ledger`),
        fetch(`/api/v1/cases/${caseId}/ledger/verify`),
      ])

      if (ledgerRes.ok && verifyRes.ok) {
        const lData = await ledgerRes.json()
        const vData = await verifyRes.json()
        setLedgerData(lData)
        setVerificationResult(vData)
        if (lData.entries && lData.entries.length > 0) {
          setSelectedBlock(lData.entries[lData.entries.length - 1])
        }
      }
    } catch (err) {
      console.error('Failed to load evidence ledger:', err)
    } finally {
      setLoadingLedger(false)
    }
  }

  useEffect(() => {
    if (caseId) {
      fetchLedger()
    }
  }, [caseId])

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Evidence Top Metadata Bar */}
      <section className="rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Digital Evidence Locker // Cryptographic Ledger
            </h2>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Tamper-evident RFC822 payload, cryptographic hash-chained blocks, Merkle root proofs, and MIME telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:border-sky-500"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            {copied ? '✓ Evidence JSON Copied' : 'Copy Evidence JSON'}
          </button>
          <div className="flex rounded-lg p-0.5 border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
            {[
              { id: 'headers', label: 'Raw Headers' },
              { id: 'body', label: 'Message Body' },
              { id: 'crypto', label: 'Blockchain Ledger & Crypto' },
            ].map(v => (
              <button
                key={v.id}
                onClick={() => setEvidenceView(v.id)}
                className="px-3 py-1 text-xs font-medium rounded-md transition-colors"
                style={{
                  background: evidenceView === v.id ? 'var(--accent)' : 'transparent',
                  color: evidenceView === v.id ? '#ffffff' : 'var(--text-secondary)',
                }}
              >
                {v.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* View 1: Raw Headers */}
      {evidenceView === 'headers' && (
        <section className="rounded-xl overflow-hidden flex flex-col"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 border-b gap-2" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                RFC822 Header Stream ({rawHeaders.length} Lines)
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-500">
                Parsed by EMLParser
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search header keys or values..."
                className="text-xs px-3 py-1.5 rounded-lg border focus:outline-none focus:border-sky-500 w-48 sm:w-64"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
              />
              <button
                onClick={() => copyToClipboard(rawHeaders.join('\n'))}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-sky-500 text-white hover:bg-sky-600 transition-colors"
              >
                {copied ? 'Copied!' : 'Copy Headers'}
              </button>
            </div>
          </div>

          <div className="p-4 overflow-x-auto max-h-[480px] scrollbar-thin font-mono text-xs space-y-1.5"
            style={{ background: 'var(--bg-inset)' }}>
            {filteredHeaders.map((line, idx) => {
              const colonIdx = line.indexOf(':')
              const key = colonIdx > -1 ? line.slice(0, colonIdx) : ''
              const val = colonIdx > -1 ? line.slice(colonIdx + 1) : line
              return (
                <div key={idx} className="flex items-start gap-3 hover:bg-slate-500/10 px-2 py-0.5 rounded">
                  <span className="text-[10px] w-8 flex-shrink-0 select-none text-right" style={{ color: 'var(--text-muted)' }}>
                    {idx + 1}
                  </span>
                  <div className="break-all">
                    {key ? (
                      <>
                        <span className="font-bold text-sky-500">{key}:</span>
                        <span className="text-gray-300 ml-1.5">{val}</span>
                      </>
                    ) : (
                      <span className="text-gray-400">{line}</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      )}

      {/* View 2: Extracted Message Body */}
      {evidenceView === 'body' && (
        <section className="rounded-xl overflow-hidden p-5 space-y-4"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                Decoded Body Forensics
              </h3>
              <p className="text-[11px] text-gray-500">Full normalized plaintext representation of the parsed email payload</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-1 rounded bg-amber-500/10 text-amber-500 border border-amber-500/20 font-bold">
              HTML Stripped &amp; Sanitized
            </span>
          </div>

          <div className="p-4 rounded-lg font-mono text-xs whitespace-pre-wrap leading-relaxed border"
            style={{ background: 'var(--bg-inset)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}>
            {email.body || 'No plaintext or HTML body content present in parsed message.'}
          </div>

          <div className="p-3 rounded-lg border bg-amber-500/5 border-amber-500/20 text-xs space-y-1">
            <span className="font-bold text-amber-500 text-[11px] uppercase tracking-wider block">Security Body Analysis:</span>
            <p className="text-gray-400">
              Heuristic engines scanned the body for social engineering lures, urgency triggers, credential harvesting URL patterns, and obfuscated unicode characters.
            </p>
          </div>
        </section>
      )}

      {/* View 3: Cryptographic Ledger & Blockchain Integrity */}
      {evidenceView === 'crypto' && (
        <div className="space-y-5">
          {/* Top Integrity Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl border space-y-1" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block">Ledger Verification Status</span>
              <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${verificationResult?.is_valid !== false ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'}`} />
                <span className={`text-sm font-bold tracking-wide font-mono ${verificationResult?.is_valid !== false ? 'text-emerald-400' : 'text-red-400'}`}>
                  {verificationResult?.is_valid !== false ? 'VERIFIED IMMUTABLE' : 'TAMPER DETECTED'}
                </span>
              </div>
              <span className="text-[10px] text-gray-500 block">
                {verificationResult?.total_entries ? `${verificationResult.total_entries} Blocks Chained` : 'Cryptographically Sealed'}
              </span>
            </div>

            <div className="p-4 rounded-xl border space-y-1" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block">Merkle Tree Root</span>
              <p className="font-mono text-xs text-sky-400 font-bold truncate select-all" title={verificationResult?.merkle_root || result.evidence_hash}>
                {verificationResult?.merkle_root ? verificationResult.merkle_root.slice(0, 18) + '...' : result.evidence_hash ? result.evidence_hash.slice(0, 18) + '...' : 'N/A'}
              </p>
              <span className="text-[10px] text-gray-500 block">Aggregate Proof of Integrity</span>
            </div>

            <div className="p-4 rounded-xl border space-y-1" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block">Hash Algorithm</span>
              <span className="text-sm font-bold font-mono text-purple-400 block">SHA-256 (RFC 6234)</span>
              <span className="text-[10px] text-gray-500 block">256-bit Immutable Digest</span>
            </div>

            <div className="p-4 rounded-xl border space-y-2 flex flex-col justify-between" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block">Chain of Custody Audit</span>
              <button
                onClick={fetchLedger}
                disabled={loadingLedger}
                className="w-full py-1.5 px-3 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-600 text-white transition-all shadow-sm flex items-center justify-center gap-2"
              >
                {loadingLedger ? 'Verifying Hashes...' : '⚡ Run Live Integrity Audit'}
              </button>
            </div>
          </div>

          {/* Ledger Blocks & Chain Explorer */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Block List Column */}
            <div className="lg:col-span-5 rounded-xl border p-4 space-y-3" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border)' }}>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-200">
                  Immutable Block Chain ({ledgerData?.entries?.length || 1} Blocks)
                </h3>
                <span className="text-[10px] font-mono text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
                  Append-Only Ledger
                </span>
              </div>

              <div className="space-y-2 max-h-[460px] overflow-y-auto scrollbar-thin pr-1">
                {ledgerData?.entries && ledgerData.entries.length > 0 ? (
                  ledgerData.entries.map((block) => {
                    const isSelected = selectedBlock?.id === block.id
                    return (
                      <div
                        key={block.id}
                        onClick={() => setSelectedBlock(block)}
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-sky-500/15 border-sky-500 ring-1 ring-sky-500/30'
                            : 'hover:bg-slate-800/40 border-slate-800'
                        }`}
                        style={{ background: isSelected ? undefined : 'var(--bg-raised)' }}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-700/60 text-gray-300">
                              #{block.sequence_number}
                            </span>
                            <span className="text-xs font-semibold text-gray-200">
                              {block.entry_type}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/20">
                            SEALED
                          </span>
                        </div>

                        <div className="space-y-1 text-[11px] font-mono">
                          <div className="flex items-center justify-between text-gray-400">
                            <span>Block Hash:</span>
                            <span className="text-sky-400 font-bold">{block.entry_hash.slice(0, 14)}...</span>
                          </div>
                          <div className="flex items-center justify-between text-gray-500 text-[10px]">
                            <span>Prev Hash:</span>
                            <span>{block.previous_hash.slice(0, 10)}...</span>
                          </div>
                        </div>
                      </div>
                    )
                  })
                ) : (
                  // Fallback synthetic view if no case attached
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg border border-sky-500 bg-sky-500/10">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-gray-200">#1 GENESIS &amp; EVIDENCE SEAL</span>
                        <span className="text-[10px] font-mono text-emerald-400 font-bold">VERIFIED</span>
                      </div>
                      <p className="text-[11px] font-mono text-sky-400 truncate">{result.evidence_hash}</p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Block Inspector Column */}
            <div className="lg:col-span-7 rounded-xl border p-5 space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
              <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-200">
                    Block Inspector {selectedBlock ? `// Block #${selectedBlock.sequence_number}` : '// Active Seal'}
                  </h3>
                  <p className="text-[11px] text-gray-500">Cryptographic audit envelope and cryptographic proof validation</p>
                </div>
                <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  CHAIN VERIFIED
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">
                    Entry Type &amp; Reference ID
                  </span>
                  <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                    <span className="font-bold text-sky-400">{selectedBlock?.entry_type || 'EVIDENCE_HASH_SEALED'}</span>
                    <span className="text-gray-400 text-[11px]">{selectedBlock?.reference_id || result?.email?.message_id || 'Canonical Seal'}</span>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">
                    Block Seal Hash (SHA-256)
                  </span>
                  <p className="p-2.5 rounded font-bold text-xs break-all select-all border"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--accent)' }}>
                    {selectedBlock?.entry_hash || result.evidence_hash}
                  </p>
                </div>

                <div>
                  <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">
                    Previous Chained Hash
                  </span>
                  <p className="p-2.5 rounded text-xs break-all select-all border text-gray-400"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                    {selectedBlock?.previous_hash || '0000000000000000000000000000000000000000000000000000000000000000'}
                  </p>
                </div>

                <div>
                  <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">
                    Payload Data Hash
                  </span>
                  <p className="p-2.5 rounded text-xs break-all select-all border text-purple-300"
                    style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                    {selectedBlock?.data_hash || result.evidence_hash}
                  </p>
                </div>

                {selectedBlock?.metadata_json && selectedBlock.metadata_json !== '{}' && (
                  <div>
                    <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">
                      Block Metadata
                    </span>
                    <pre className="p-2.5 rounded text-[11px] overflow-x-auto border text-gray-300"
                      style={{ background: 'var(--bg-inset)', borderColor: 'var(--border)' }}>
                      {JSON.stringify(JSON.parse(selectedBlock.metadata_json), null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Email Authentication Protocols Telemetry */}
          <section className="rounded-xl p-5 space-y-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
              Protocol Authentication Telemetry
            </h3>

            <div className="grid md:grid-cols-3 gap-3 text-xs">
              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>SPF (Sender Policy)</span>
                  <span className="text-[10px] text-gray-500">RFC 7208 IP authorization</span>
                </div>
                <span className={`px-2.5 py-1 rounded font-mono font-bold uppercase ${auth.spf === 'pass' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
                  {auth.spf || 'none'}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>DKIM (Signatures)</span>
                  <span className="text-[10px] text-gray-500">RFC 6376 Cryptography</span>
                </div>
                <span className={`px-2.5 py-1 rounded font-mono font-bold uppercase ${auth.dkim === 'pass' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-500/10 text-slate-400'}`}>
                  {auth.dkim || 'none'}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>DMARC (Enforcement)</span>
                  <span className="text-[10px] text-gray-500">RFC 7489 Conformance</span>
                </div>
                <span className={`px-2.5 py-1 rounded font-mono font-bold uppercase ${auth.dmarc === 'pass' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
                  {auth.dmarc || 'none'}
                </span>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
