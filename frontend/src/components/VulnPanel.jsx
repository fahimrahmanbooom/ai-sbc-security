import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { dashboardAPI } from '../utils/api'

const stagger = (i) => ({ initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.04, duration: 0.22 } })

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
const SEVERITY_COLORS = {
  critical: 'var(--danger)',
  high: 'var(--warning)',
  medium: 'var(--accent)',
  low: 'var(--text-3)',
}

function GradeBar({ label, count, max, color }) {
  const pct = max > 0 ? (count / max) * 100 : 0
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</span>
        <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>{count}</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

export default function VulnPanel() {
  const [summary, setSummary]   = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading]   = useState(true)
  const [scanning, setScanning] = useState(false)
  const [filter, setFilter]     = useState('all')
  const [expanded, setExpanded] = useState(null)

  useEffect(() => { load(); const t = setInterval(load, 60000); return () => clearInterval(t) }, [])

  const load = async () => {
    try {
      const [sRes, fRes] = await Promise.all([
        dashboardAPI.get('/vulns/summary'),
        dashboardAPI.get('/vulns/findings?limit=100'),
      ])
      setSummary(sRes.data)
      setFindings(fRes.data.findings || [])
    } catch {} finally { setLoading(false) }
  }

  const handleScan = async () => {
    setScanning(true)
    try { await dashboardAPI.post('/vulns/scan'); await load() } catch {}
    setScanning(false)
  }

  const filteredFindings = filter === 'all'
    ? findings
    : findings.filter(f => f.ai_priority_label === filter)

  if (loading) return <div style={{ padding: 24 }}><div className="skeleton" style={{ height: 40, marginBottom: 12, borderRadius: 8 }} /><div className="skeleton" style={{ height: 300, borderRadius: 8 }} /></div>

  const bySev = summary?.by_severity || {}
  const maxCount = Math.max(...Object.values(bySev), 1)
  const totalVulns = summary?.vulnerabilities_found ?? 0
  const riskLevel = (
    (bySev.critical || 0) > 0 ? 'critical'
    : (bySev.high || 0) > 0 ? 'high'
    : (bySev.medium || 0) > 0 ? 'medium'
    : 'low'
  )

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Vulnerability Scanner</h2>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 3 }}>
            AI-prioritized CVE analysis for installed packages
          </p>
        </div>
        <button className="btn btn-ghost" onClick={handleScan} disabled={scanning} style={{ fontSize: 13 }}>
          {scanning ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 12, height: 12, border: '2px solid var(--border-md)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} />
              Scanning…
            </span>
          ) : '↻ Scan Now'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: 12, marginBottom: 12 }}>

        {/* Severity breakdown */}
        <motion.div {...stagger(0)} className="card" style={{ padding: 20 }}>
          <div className="section-title">By Severity</div>

          {/* Risk indicator */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20,
            padding: '10px 12px', borderRadius: 'var(--radius-sm)',
            background: SEVERITY_COLORS[riskLevel] + '18',
            border: `1px solid ${SEVERITY_COLORS[riskLevel]}44`,
          }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: SEVERITY_COLORS[riskLevel], flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Overall Risk</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: SEVERITY_COLORS[riskLevel], textTransform: 'uppercase' }}>
                {riskLevel}
              </div>
            </div>
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-1)', fontFamily: 'var(--font-mono)' }}>{totalVulns}</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>total CVEs</div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {SEVERITY_ORDER.map(sev => (
              <GradeBar key={sev} label={sev} count={bySev[sev] || 0} max={maxCount} color={SEVERITY_COLORS[sev]} />
            ))}
          </div>

          <div className="divider" style={{ margin: '16px 0' }} />
          <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
            Packages scanned: <strong style={{ color: 'var(--text-2)' }}>{summary?.packages_scanned ?? 0}</strong>
          </div>
          {summary?.scan_time_iso && (
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>
              Last scan: {new Date(summary.scan_time_iso).toLocaleTimeString()}
            </div>
          )}
        </motion.div>

        {/* Top findings preview */}
        <motion.div {...stagger(1)} className="card" style={{ padding: 20 }}>
          <div className="section-title">Top Vulnerabilities</div>
          {(summary?.top_findings || []).length === 0 ? (
            <div className="empty-state"><div style={{ fontSize: 24 }}>✓</div><p style={{ color: 'var(--success)' }}>No known CVEs found</p></div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(summary?.top_findings || []).map((f, i) => (
                <div key={i} style={{
                  padding: '10px 12px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--bg-surface)', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'flex-start', gap: 12,
                }}>
                  {/* Score badge */}
                  <div style={{
                    minWidth: 36, height: 36, borderRadius: 'var(--radius-sm)',
                    background: SEVERITY_COLORS[f.label] + '22',
                    border: `1px solid ${SEVERITY_COLORS[f.label]}44`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexDirection: 'column',
                  }}>
                    <span style={{ fontSize: 13, fontWeight: 800, color: SEVERITY_COLORS[f.label], fontFamily: 'var(--font-mono)', lineHeight: 1 }}>{f.ai_priority?.toFixed(1)}</span>
                    <span style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase' }}>risk</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                      <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: SEVERITY_COLORS[f.label] }}>{f.cve_id}</span>
                      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{f.package} {f.version}</span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.description}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Full findings table */}
      <motion.div {...stagger(2)} className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div className="section-title" style={{ marginBottom: 0 }}>All Findings</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {['all', ...SEVERITY_ORDER].map(sev => (
              <button key={sev} onClick={() => setFilter(sev)}
                className="btn btn-ghost"
                style={{
                  fontSize: 11, padding: '4px 10px',
                  background: filter === sev ? (SEVERITY_COLORS[sev] || 'var(--accent)') : 'transparent',
                  color: filter === sev ? '#fff' : 'var(--text-3)',
                  borderColor: filter === sev ? (SEVERITY_COLORS[sev] || 'var(--accent)') : 'var(--border)',
                }}>
                {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)} {sev !== 'all' ? `(${bySev[sev] || 0})` : ''}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <div style={{ fontSize: 24 }}>✓</div>
            <p style={{ color: 'var(--success)', fontWeight: 600 }}>No {filter !== 'all' ? filter : ''} vulnerabilities found</p>
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Package</th>
                <th>Version</th>
                <th style={{ textAlign: 'right' }}>AI Score</th>
                <th>Priority</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.slice(0, 50).map((f, i) => {
                const color = SEVERITY_COLORS[f.ai_priority_label] || 'var(--text-3)'
                const cve = f.cve || {}
                const pkg = f.package || {}
                return (
                  <tr key={i} onClick={() => setExpanded(expanded === i ? null : i)}
                    style={{ cursor: 'pointer', background: expanded === i ? 'var(--bg-surface)' : 'transparent' }}>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color, fontWeight: 700 }}>
                        {cve.cve_id || '—'}
                      </span>
                    </td>
                    <td style={{ fontWeight: 500, color: 'var(--text-1)' }}>{pkg.name || '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{pkg.version || '—'}</td>
                    <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color, fontWeight: 700 }}>
                      {f.ai_priority_score?.toFixed(1)}
                    </td>
                    <td><span className={`badge badge-${f.ai_priority_label}`}>{f.ai_priority_label}</span></td>
                    <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12, color: 'var(--text-2)' }}>
                      {cve.description?.slice(0, 80)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </motion.div>
    </div>
  )
}
