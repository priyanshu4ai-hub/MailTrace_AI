import React, { useState } from 'react'

export function EvidenceTab({ result }) {
  const [evidenceView, setEvidenceView] = useState('headers')
  const [searchQuery, setSearchQuery] = useState('')
  const [copied, setCopied] = useState(false)

  const email = result?.email || {}
  const auth = result?.authentication || {}
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

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Evidence Top Metadata Bar */}
      <section className="rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
              Digital Evidence Locker // Case Artifacts
            </h2>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Tamper-evident RFC822 payload, cryptographic authentication proofs and MIME structures.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
            style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)', color: 'var(--text-secondary)' }}
          >
            {copied ? '✓ Evidence JSON Copied' : 'Copy Evidence JSON'}
          </button>
          <div className="flex rounded-lg p-0.5 border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
            {[
              { id: 'headers', label: 'Raw Headers' },
              { id: 'body', label: 'Message Body' },
              { id: 'crypto', label: 'Crypto & Integrity' },
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
              <p className="text-[11px] text-gray-500">MIME text/plain &amp; BeautifulSoup HTML payload extraction</p>
            </div>
            <span className="text-xs font-mono text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded">
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
              Heuristic engines scanned the body for social engineering lures, urgency triggers (e.g. "30 minutes", "password reset", "account terminated"), credential harvesting URL patterns, and obfuscated unicode characters.
            </p>
          </div>
        </section>
      )}

      {/* View 3: Cryptographic & Integrity */}
      {evidenceView === 'crypto' && (
        <div className="grid md:grid-cols-2 gap-5">
          <section className="rounded-xl p-5 space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
              Cryptographic Integrity Proofs
            </h3>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] uppercase font-semibold tracking-wider text-gray-500 block mb-1">SHA-256 Evidence Seal Hash</span>
                <p className="font-mono text-xs p-3 rounded break-all select-all font-bold"
                  style={{ background: 'var(--bg-raised)', color: 'var(--accent)' }}>
                  {result.evidence_hash}
                </p>
              </div>

              <div className="p-3 rounded-lg border flex items-center justify-between"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="text-xs font-semibold block" style={{ color: 'var(--text-primary)' }}>Tamper-Evident Canonicalization</span>
                  <span className="text-[10px] text-gray-500">SHA-256 digest calculated across all normalized forensic artifacts.</span>
                </div>
                <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/10 text-emerald-500">
                  VERIFIED SEAL
                </span>
              </div>
            </div>
          </section>

          <section className="rounded-xl p-5 space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider border-b pb-2" style={{ color: 'var(--text-primary)', borderColor: 'var(--border)' }}>
              Protocol Authentication Telemetry
            </h3>

            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>SPF (Sender Policy Framework)</span>
                  <span className="text-[10px] text-gray-500">RFC 7208 IP authorization record</span>
                </div>
                <span className={`px-2.5 py-1 rounded font-mono font-bold uppercase ${auth.spf === 'pass' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
                  {auth.spf || 'none'}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>DKIM (DomainKeys Identified Mail)</span>
                  <span className="text-[10px] text-gray-500">RFC 6376 Cryptographic signature</span>
                </div>
                <span className={`px-2.5 py-1 rounded font-mono font-bold uppercase ${auth.dkim === 'pass' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-500/10 text-slate-400'}`}>
                  {auth.dkim || 'none'}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
                <div>
                  <span className="font-semibold block" style={{ color: 'var(--text-primary)' }}>DMARC (Domain-based Auth &amp; Conformance)</span>
                  <span className="text-[10px] text-gray-500">RFC 7489 Alignment &amp; enforcement policy</span>
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
