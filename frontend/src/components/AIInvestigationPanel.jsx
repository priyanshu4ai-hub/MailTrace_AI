import React from 'react'

export function AIInvestigationPanel({ t, deterministic, loading }) {
  if (loading) {
    return (
      <div
        className="rounded-xl p-5 space-y-4 animate-pulse"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
      >
        <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border)' }}>
          <div className="h-4 w-36 bg-slate-700/30 rounded" />
          <div className="h-4 w-20 bg-slate-700/30 rounded" />
        </div>
        <div className="space-y-3">
          <div className="h-6 w-3/4 bg-slate-700/30 rounded" />
          <div className="h-16 w-full bg-slate-700/30 rounded" />
        </div>
      </div>
    )
  }

  const threatType = t?.threat_type || t?.classification || 'Unknown'
  const aiUsed = Boolean(t?.ai_used)
  const aiConfidence = t?.confidence ?? t?.confidence_score ?? 0

  // Deterministic risk score (technical engine)
  const detAssessment = deterministic || t?.deterministic_assessment
  const detScore = detAssessment?.risk_score ?? (t?.confidence_score ?? 0)
  const detRiskLevel = (detAssessment?.risk_level || (detScore >= 80 ? 'critical' : detScore >= 50 ? 'high' : detScore >= 20 ? 'medium' : 'safe')).toUpperCase()

  const reasons = t?.reasons?.length
    ? t.reasons
    : t?.suspicious_indicators?.length
    ? t.suspicious_indicators
    : ['No anomalous indicators detected.']

  const attackTechniques = t?.attack_techniques?.length
    ? t.attack_techniques
    : t?.mitre_attack_mapping
    ? [{ id: t.mitre_attack_mapping, name: 'Phishing Pattern', reason: 'Derived from message forensic telemetry' }]
    : []

  const recommendations = t?.recommendations?.length
    ? t.recommendations
    : t?.recommended_action
    ? [t.recommended_action]
    : ['Review message context before taking action.']

  const conclusion = t?.analyst_conclusion || t?.explanation || t?.summary || 'Threat investigation evaluated the artifact.'

  const isCritical = detRiskLevel === 'CRITICAL' || detScore >= 80 || threatType === 'Credential Phishing' || threatType === 'Business Email Compromise'
  const isHigh = detRiskLevel === 'HIGH' || (detScore >= 50 && detScore < 80)
  const isMed = detRiskLevel === 'MEDIUM' || (detScore >= 20 && detScore < 50)
  const badgeColor = isCritical ? 'var(--danger)' : isHigh ? '#f97316' : isMed ? 'var(--warning)' : 'var(--success)'
  const badgeBg = isCritical ? 'var(--danger-muted)' : isHigh ? 'rgba(249, 115, 22, 0.15)' : isMed ? 'var(--warning-muted)' : 'var(--success-muted)'

  return (
    <section
      className="rounded-xl overflow-hidden flex flex-col space-y-4 p-5 shadow-sm transition-all"
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
      }}
    >
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-2">
          <span className="text-base" role="img" aria-label="AI Bot">🤖</span>
          <h2 className="text-xs sm:text-sm font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
            AI Investigation Panel
          </h2>
        </div>
        <div className="flex items-center gap-2">
          {aiUsed ? (
            <span
              className="flex items-center gap-1.5 text-[10px] font-bold uppercase px-2.5 py-1 rounded-full"
              style={{ background: 'var(--accent-muted)', color: 'var(--accent)', border: '1px solid var(--accent)' }}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
              AI Enriched
            </span>
          ) : (
            <span
              className="flex items-center gap-1.5 text-[10px] font-bold uppercase px-2.5 py-1 rounded-full"
              style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
              title="Groq LLM enrichment was skipped or not configured. Active analysis is using deterministic rules."
            >
              <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
              AI Unavailable (Deterministic Fallback)
            </span>
          )}
        </div>
      </div>

      {/* Threat Classification & Dual Scores */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl border" style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}>
        {/* Threat Type */}
        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-muted)' }}>
            Threat Classification
          </p>
          <p className="text-sm sm:text-base font-bold truncate" style={{ color: 'var(--text-primary)' }}>
            {threatType}
          </p>
          <span
            className="inline-block text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded"
            style={{ color: badgeColor, background: badgeBg }}
          >
            {detRiskLevel} RISK
          </span>
        </div>

        {/* AI Confidence */}
        <div className="space-y-1 border-t sm:border-t-0 sm:border-l sm:pl-3 pt-2 sm:pt-0" style={{ borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-muted)' }}>
            AI Confidence
          </p>
          <div className="flex items-baseline gap-1">
            <span className="text-xl sm:text-2xl font-black font-mono" style={{ color: 'var(--accent)' }}>
              {aiConfidence}%
            </span>
          </div>
          <p className="text-[9px] leading-tight" style={{ color: 'var(--text-muted)' }}>
            {aiUsed ? 'Model certainty in classification' : 'Heuristic certainty estimate'}
          </p>
        </div>

        {/* Deterministic Risk Score */}
        <div className="space-y-1 border-t sm:border-t-0 sm:border-l sm:pl-3 pt-2 sm:pt-0" style={{ borderColor: 'var(--border)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-muted)' }}>
            Deterministic Risk
          </p>
          <div className="flex items-baseline gap-1">
            <span className="text-xl sm:text-2xl font-black font-mono" style={{ color: badgeColor }}>
              {detScore}
            </span>
            <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <p className="text-[9px] leading-tight" style={{ color: 'var(--text-muted)' }}>
            Calculated technical risk engine
          </p>
        </div>
      </div>

      {/* WHY THIS IS SUSPICIOUS (Evidence-based reasons) */}
      <div className="space-y-2">
        <h3 className="text-[11px] uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: 'var(--text-primary)' }}>
          <span className="text-amber-500 font-bold">⚡</span>
          Why This Is Suspicious
        </h3>
        <ul className="space-y-1.5">
          {reasons.map((reason, idx) => (
            <li
              key={idx}
              className="text-xs flex items-start gap-2 p-2 rounded-lg transition-colors"
              style={{ background: 'var(--bg-raised)' }}
            >
              <span className="text-emerald-500 font-bold text-xs mt-0.5 flex-shrink-0">✓</span>
              <span className="leading-snug font-medium" style={{ color: 'var(--text-secondary)' }}>
                {reason}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {/* MITRE ATT&CK Mapping */}
      {attackTechniques.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-[11px] uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: 'var(--text-primary)' }}>
            <span className="text-sky-400 font-bold">🛡️</span>
            MITRE ATT&CK® Techniques
          </h3>
          <div className="space-y-2">
            {attackTechniques.map((tech, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg border text-xs space-y-1"
                style={{ background: 'var(--bg-raised)', borderColor: 'var(--border)' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded text-sky-400 bg-sky-500/10 border border-sky-500/20">
                    {tech.id}
                  </span>
                  <span className="font-semibold text-xs truncate" style={{ color: 'var(--text-primary)' }}>
                    {tech.name}
                  </span>
                </div>
                {tech.reason && (
                  <p className="text-[11px] leading-relaxed mt-1" style={{ color: 'var(--text-secondary)' }}>
                    <strong className="text-gray-400 font-medium">Evidence:</strong> {tech.reason}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* RECOMMENDED ACTIONS */}
      <div className="space-y-2">
        <h3 className="text-[11px] uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: 'var(--text-primary)' }}>
          <span className="text-red-400 font-bold">🎯</span>
          Recommended Actions
        </h3>
        <ul className="space-y-1.5">
          {recommendations.map((rec, idx) => (
            <li
              key={idx}
              className="text-xs flex items-start gap-2 p-2 rounded-lg"
              style={{ background: 'var(--bg-raised)' }}
            >
              <span className="text-red-400 font-bold flex-shrink-0">•</span>
              <span className="font-medium leading-snug" style={{ color: 'var(--text-primary)' }}>
                {rec}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {/* ANALYST CONCLUSION */}
      <div className="space-y-1.5 border-t pt-3" style={{ borderColor: 'var(--border)' }}>
        <h3 className="text-[11px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-muted)' }}>
          Analyst Conclusion
        </h3>
        <blockquote
          className="p-3 rounded-xl border text-xs leading-relaxed font-medium italic"
          style={{
            background: 'var(--bg-raised)',
            borderColor: 'var(--border)',
            color: 'var(--text-secondary)',
          }}
        >
          &ldquo;{conclusion}&rdquo;
        </blockquote>
      </div>
    </section>
  )
}
