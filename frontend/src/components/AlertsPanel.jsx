import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { dashboardAPI } from '../utils/api'
import toast from 'react-hot-toast'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [showResolved, setShowResolved] = useState(false)

  useEffect(() => { load() }, [showResolved])

  const load = async () => {
    try {
      const { data } = await dashboardAPI.alerts({ limit: 200, resolved: showResolved ? undefined : false })
      setAlerts(data.alerts || [])
    } catch {}
    setLoading(false)
  }

  const acknowledge = async (id) => {
    await dashboardAPI.acknowledgeAlert(id)
    toast.success('Alert acknowledged')
    load()
  }

  const resolve = async (id) => {
    await dashboardAPI.resolveAlert(id)
    toast.success('Alert resolved')
    load()
  }

  const filtered = filter === 'all' ? alerts : alerts.filter(a => a.severity === filter)
  const counts = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = alerts.filter(a => a.severity === sev).length
    return acc
  }, {})

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 8 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Alerts</h2>
          <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 3 }}>
            {alerts.length} alert{alerts.length !== 1 ? 's' : ''} · real-time threat log
          </p>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13, color: 'var(--text-3)' }}>
          <input type="checkbox" checked={showResolved} onChange={e => setShowResolved(e.target.checked)} />
          Show resolved
        </label>
      </div>

      {/* Severity filter pills */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 20, flexWrap: 'wrap' }}>
        {['all', ...SEV_ORDER].map(sev => {
          const isActive = sev === filter
          const sevForBadge = sev === 'all' ? 'info' : sev
          return (
            <button key={sev} onClick={() => setFilter(sev)}
              className={isActive ? `badge badge-${sevForBadge}` : 'btn btn-ghost'}
              style={{
                fontSize: 12, padding: '4px 12px', cursor: 'pointer',
                ...(isActive ? {} : { color: 'var(--text-3)' }),
              }}>
              {sev.toUpperCase()}
              {sev !== 'all' && counts[sev] > 0 && (
                <span style={{ marginLeft: 5, opacity: 0.8, fontWeight: 700 }}>{counts[sev]}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Alerts list */}
      {loading ? (
        <div className="empty-state" style={{ padding: '48px 0' }}>
          <p style={{ color: 'var(--text-3)' }}>Loading alerts…</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-state" style={{ padding: '48px 0' }}>
          <div style={{ fontSize: 28 }}>✓</div>
          <p style={{ color: 'var(--success)', fontWeight: 600 }}>No alerts in this filter</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <AnimatePresence>
            {filtered.map((alert, i) => (
              <motion.div key={alert.id}
                initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 16 }}
                transition={{ delay: i * 0.02 }}
                className="card"
                style={{
                  padding: 16,
                  ...(alert.severity === 'critical' ? {
                    borderColor: 'rgba(248,81,73,0.3)',
                    background: 'rgba(248,81,73,0.04)',
                  } : {}),
                }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <ThreatScoreRing score={alert.threat_score} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                      <span className={`badge badge-${alert.severity}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span style={{
                        fontSize: 12, padding: '2px 8px', borderRadius: 6,
                        background: 'var(--bg-surface)', border: '1px solid var(--border)',
                        color: 'var(--text-3)',
                      }}>
                        {alert.category}
                      </span>
                      {alert.source_ip && (
                        <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent)' }}>
                          {alert.source_ip}
                          {alert.geo_country && ` · ${alert.geo_country}`}
                        </span>
                      )}
                    </div>
                    <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>
                      {alert.title}
                    </p>
                    <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.55 }}>
                      {alert.description?.slice(0, 150)}
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
                      {new Date(alert.timestamp).toLocaleString()}
                    </p>
                  </div>
                  {!alert.resolved && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flexShrink: 0 }}>
                      {!alert.acknowledged && (
                        <button onClick={() => acknowledge(alert.id)}
                          className="btn btn-ghost btn-sm"
                          style={{ fontSize: 12, color: '#d29922', borderColor: 'rgba(210,153,34,0.35)' }}>
                          ACK
                        </button>
                      )}
                      <button onClick={() => resolve(alert.id)}
                        className="btn btn-success btn-sm"
                        style={{ fontSize: 12 }}>
                        CLOSE
                      </button>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}

function ThreatScoreRing({ score }) {
  const norm = Math.min(10, score || 0) / 10
  const color = norm > 0.7 ? 'var(--danger)' : norm > 0.4 ? 'var(--warning)' : 'var(--success)'
  const hexColor = norm > 0.7 ? '#f85149' : norm > 0.4 ? '#f0883e' : '#3fb950'
  const r = 14, circ = 2 * Math.PI * r
  return (
    <div style={{ flexShrink: 0, width: 40, height: 40, position: 'relative',
      display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width="40" height="40" style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx="20" cy="20" r={r} fill="none" stroke="var(--border-md)" strokeWidth="2.5" />
        <circle cx="20" cy="20" r={r} fill="none" stroke={hexColor} strokeWidth="2.5"
                strokeDasharray={`${norm * circ} ${circ}`}
                style={{ transition: 'stroke-dasharray 1s ease' }} />
      </svg>
      <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)', color, position: 'relative' }}>
        {(score || 0).toFixed(0)}
      </span>
    </div>
  )
}
