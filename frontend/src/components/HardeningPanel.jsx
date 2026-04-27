import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { dashboardAPI } from '../utils/api'
import toast from 'react-hot-toast'

const stagger = (i) => ({ initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.04, duration: 0.22 } })

const GRADE_COLORS = {
  'A+': '#3fb950', A: '#3fb950', B: '#58a6ff', C: '#d29922', D: '#f0883e', F: '#f85149',
}
const GRADE_BG = {
  'A+': '#3fb95022', A: '#3fb95022', B: '#58a6ff22', C: '#d2992222', D: '#f0883e22', F: '#f8514922',
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR = { critical: 'var(--danger)', high: 'var(--warning)', medium: 'var(--accent)', low: 'var(--text-3)', info: 'var(--text-3)' }

const CATEGORY_ICONS = {
  ssh: '🔐', firewall: '🛡', kernel: '⚙', suid: '⚠', sudo: '👤',
  users: '👥', services: '🌐', permissions: '🔒',
}

export default function HardeningPanel() {
  const [summary, setSummary] = useState(null)
  const [report, setReport]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [auditing, setAuditing] = useState(false)
  const [activeCategory, setActiveCategory] = useState('all')
  const [showPassed, setShowPassed] = useState(false)
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => { load(); const t = setInterval(load, 120000); return () => clearInterval(t) }, [])

  const load = async () => {
    try {
      const [sRes, rRes] = await Promise.all([
        dashboardAPI.get('/hardening/summary'),
        dashboardAPI.get('/hardening/report'),
      ])
      setSummary(sRes.data)
      if (rRes.data?.score !== undefined) setReport(rRes.data)
    } catch {} finally { setLoading(false) }
  }

  const handleAudit = async () => {
    setAuditing(true)
    try { await dashboardAPI.post('/hardening/audit'); await load() } catch {}
    setAuditing(false)
  }

  // Called by FindingRow after a successful auto-fix.
  // Optimistically mark the finding as passed so it disappears immediately
  // (the backend report only updates after the next full audit).
  const handleAutoFixed = useCallback((fixedCheckId) => {
    setReport(prev => {
      if (!prev?.findings) return prev
      const updatedFindings = prev.findings.map(f =>
        f.check_id === fixedCheckId ? { ...f, passed: true } : f
      )
      return { ...prev, findings: updatedFindings }
    })
    // Trigger a fresh audit in the background so the server state catches up
    setTimeout(load, 3000)
  }, [])

  const allFindings = report?.findings || []
  const categories = ['all', ...new Set(allFindings.map(f => f.category))]

  const filtered = allFindings.filter(f => {
    const catOk = activeCategory === 'all' || f.category === activeCategory
    const passOk = showPassed || !f.passed
    return catOk && passOk
  }).sort((a, b) => {
    const sOrder = (s) => SEV_ORDER.indexOf(s)
    if (a.passed !== b.passed) return a.passed ? 1 : -1
    return sOrder(a.severity) - sOrder(b.severity)
  })

  if (loading) return (
    <div style={{ padding: 24 }}>
      <div className="skeleton" style={{ height: 40, marginBottom: 12, borderRadius: 8 }} />
      <div className="skeleton" style={{ height: 300, borderRadius: 8 }} />
    </div>
  )

  const grade = summary?.grade || '—'
  const score = summary?.score ?? 0
  const gradeColor = GRADE_COLORS[grade] || 'var(--text-3)'
  const gradeBg = GRADE_BG[grade] || 'transparent'

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Security Hardening Advisor</h2>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 3 }}>
            AI-powered system configuration audit across {summary?.total_checks ?? 0} checks
          </p>
        </div>
        <button className="btn btn-ghost" onClick={handleAudit} disabled={auditing} style={{ fontSize: 13 }}>
          {auditing ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 12, height: 12, border: '2px solid var(--border-md)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} />
              Auditing…
            </span>
          ) : '↻ Run Audit'}
        </button>
      </div>

      {/* Score + category breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, marginBottom: 12 }}>

        {/* Grade card */}
        <motion.div {...stagger(0)} className="card" style={{ padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{
            width: 88, height: 88, borderRadius: '50%',
            border: `4px solid ${gradeColor}`,
            background: gradeBg,
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            marginBottom: 16,
          }}>
            <span style={{ fontSize: 32, fontWeight: 900, color: gradeColor, lineHeight: 1 }}>{grade}</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-1)', fontFamily: 'var(--font-mono)' }}>{score}<span style={{ fontSize: 14, color: 'var(--text-3)' }}>/100</span></div>
          <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>Hardening Score</div>

          <div className="divider" style={{ margin: '16px 0', width: '100%' }} />

          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <ScoreLine label="Checks Passed" value={`${summary?.passed_checks ?? 0} / ${summary?.total_checks ?? 0}`} color="var(--success)" />
            <ScoreLine label="Critical Failures" value={summary?.critical_failures ?? 0} color="var(--danger)" />
          </div>

          {summary?.audit_time_iso && (
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 12, textAlign: 'center' }}>
              Last audit: {new Date(summary.audit_time_iso).toLocaleTimeString()}
            </div>
          )}
        </motion.div>

        {/* AI Summary + Recommendations */}
        <motion.div {...stagger(1)} className="card" style={{ padding: 20 }}>
          <div className="section-title">AI Security Assessment</div>
          {summary?.ai_summary ? (
            <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.65, marginBottom: 16 }}>
              {summary.ai_summary}
            </p>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--text-3)' }}>No audit data yet. Run an audit to get AI recommendations.</p>
          )}

          {(summary?.top_recommendations || []).length > 0 && (
            <>
              <div className="section-title">Top Recommendations</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {summary.top_recommendations.map((rec, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-surface)', border: '1px solid var(--border)',
                  }}>
                    <span style={{ fontSize: 16, flexShrink: 0 }}>
                      {rec.startsWith('[CRITICAL]') ? '🔴' : rec.startsWith('[HIGH]') ? '🟠' : rec.startsWith('[MEDIUM]') ? '🟡' : '🔵'}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.55 }}>{rec}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </motion.div>
      </div>

      {/* Category tabs */}
      <motion.div {...stagger(2)} className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {categories.map(cat => {
              const catData = summary?.by_category?.[cat] || {}
              const icon = CATEGORY_ICONS[cat] || ''
              return (
                <button key={cat} onClick={() => setActiveCategory(cat)}
                  className="btn btn-ghost"
                  style={{
                    fontSize: 11, padding: '4px 10px',
                    background: activeCategory === cat ? 'var(--accent)' : 'transparent',
                    color: activeCategory === cat ? '#fff' : 'var(--text-3)',
                    borderColor: activeCategory === cat ? 'var(--accent)' : 'var(--border)',
                  }}>
                  {icon} {cat.charAt(0).toUpperCase() + cat.slice(1)}
                  {cat !== 'all' && catData.failed > 0 && (
                    <span style={{ marginLeft: 4, padding: '1px 5px', borderRadius: 99, background: 'var(--danger)', color: '#fff', fontSize: 9 }}>
                      {catData.failed}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12, color: 'var(--text-3)' }}>
            <input type="checkbox" checked={showPassed} onChange={e => setShowPassed(e.target.checked)} />
            Show passed
          </label>
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <div style={{ fontSize: 28 }}>✓</div>
            <p style={{ color: 'var(--success)', fontWeight: 600 }}>All checks passed in this category</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {filtered.map((finding, i) => (
              <FindingRow key={finding.check_id || i} finding={finding}
                expanded={expandedId === finding.check_id}
                onClick={() => setExpandedId(expandedId === finding.check_id ? null : finding.check_id)}
                onAutoFixed={handleAutoFixed} />
            ))}
          </div>
        )}
      </motion.div>
    </div>
  )
}

function FindingRow({ finding, expanded, onClick, onAutoFixed }) {
  const color = SEV_COLOR[finding.severity] || 'var(--text-3)'
  const [fixing, setFixing] = useState(false)

  const handleAutoFix = async (e) => {
    e.stopPropagation()
    if (!window.confirm(`Apply automatic fix for "${finding.title}"?\n\nCommand: ${finding.fix_command}\n\nThis will modify system configuration.`)) return
    setFixing(true)
    try {
      await dashboardAPI.post('/hardening/autofix', { check_id: finding.check_id })
      toast.success(`Fix applied: ${finding.title}`)
      if (onAutoFixed) onAutoFixed(finding.check_id)
    } catch (err) {
      const msg = err?.response?.data?.detail || 'Auto-fix failed'
      toast.error(msg)
    } finally {
      setFixing(false)
    }
  }

  return (
    <div onClick={onClick} style={{
      borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
      background: expanded ? 'var(--bg-surface)' : 'transparent',
      cursor: 'pointer', overflow: 'hidden',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
        {/* Pass/fail indicator */}
        <span style={{
          width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
          background: finding.passed ? 'var(--success)22' : color + '22',
          color: finding.passed ? 'var(--success)' : color,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 13, fontWeight: 900,
        }}>{finding.passed ? '✓' : '✗'}</span>

        {/* Title */}
        <span style={{ flex: 1, fontSize: 14, color: 'var(--text-1)', fontWeight: finding.passed ? 400 : 600 }}>
          {finding.title}
        </span>

        {/* Severity badge — fixed-width column, left-aligned so every badge
            starts at the same X regardless of label length */}
        <span style={{ flexShrink: 0, width: 82, display: 'flex', alignItems: 'center', justifyContent: 'flex-start' }}>
          {!finding.passed && (
            <span className={`badge badge-${finding.severity}`}>
              {finding.severity}
            </span>
          )}
        </span>

        {/* Category tag */}
        <span style={{
          flexShrink: 0, fontSize: 12, color: 'var(--text-2)',
          padding: '3px 8px', borderRadius: 5,
          background: 'var(--bg-surface)', border: '1px solid var(--border-md)',
          lineHeight: '20px', fontWeight: 500,
        }}>
          {CATEGORY_ICONS[finding.category] || ''} {finding.category}
        </span>

        <span style={{ fontSize: 13, color: 'var(--text-3)', flexShrink: 0 }}>{expanded ? '▲' : '▼'}</span>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}>
            <div style={{ padding: '12px 16px 16px', borderTop: '1px solid var(--border)' }}>
              <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 14, lineHeight: 1.65 }}>
                {finding.description}
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>Current Value</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: finding.passed ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {finding.current_value}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>Recommended</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--success)', fontWeight: 600 }}>
                    {finding.recommended_value}
                  </div>
                </div>
              </div>
              {!finding.passed && finding.fix_command && (
                <div>
                  <div style={{
                    padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg)', border: '1px solid var(--border)',
                    fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent)',
                    lineHeight: 1.6, marginBottom: 10,
                  }}>
                    <div style={{ color: 'var(--text-3)', fontSize: 12, marginBottom: 4 }}>Fix command:</div>
                    {finding.fix_command}
                  </div>
                  <button
                    onClick={handleAutoFix}
                    disabled={fixing}
                    className="btn btn-success btn-sm"
                    style={{ fontSize: 12 }}>
                    {fixing
                      ? <><span style={{ width: 11, height: 11, border: '2px solid rgba(63,185,80,0.3)', borderTopColor: 'var(--success)', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} /> Applying…</>
                      : '⚡ Auto Fix'}
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function ScoreLine({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>{value}</span>
    </div>
  )
}
