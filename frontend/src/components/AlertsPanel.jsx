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
    <motion.div className="p-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="font-display text-lg tracking-widest" style={{ color: 'var(--accent-cyan)' }}>ALERTS</h1>
          <p className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {alerts.length} alerts • real-time threat log
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs font-mono cursor-pointer"
               style={{ color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={showResolved} onChange={e => setShowResolved(e.target.checked)}
                 className="accent-cyan-400" />
          Show resolved
        </label>
      </div>

      {/* Severity filter pills */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {['all', ...SEV_ORDER].map(sev => (
          <motion.button key={sev} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
            onClick={() => setFilter(sev)}
            className={`px-3 py-1 rounded-full text-xs font-mono tracking-wide transition-all ${sev === filter ? `badge-${sev === 'all' ? 'info' : sev}` : ''}`}
            style={sev !== filter ? { background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)', border: '1px solid var(--border-subtle)' } : {}}>
            {sev.toUpperCase()}
            {sev !== 'all' && counts[sev] > 0 && (
              <span className="ml-1.5 opacity-70">{counts[sev]}</span>
            )}
          </motion.button>
        ))}
      </div>

      {/* Alerts list */}
      {loading ? (
        <div className="text-center py-12 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
          LOADING ALERTS...
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12">
          <p className="font-display text-2xl mb-2" style={{ color: 'var(--accent-cyan)' }}>CLEAR</p>
          <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>No alerts in this filter</p>
        </div>
      ) : (
        <div className="space-y-2">
          <AnimatePresence>
            {filtered.map((alert, i) => (
              <motion.div key={alert.id}
                initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}
                transition={{ delay: i * 0.02 }}
                className={`rounded-xl p-4 ${alert.severity === 'critical' ? 'card-critical' : 'card-glow'}`}
                style={{ background: 'var(--bg-card)' }}>
                <div className="flex items-start gap-3">
                  <ThreatScoreRing score={alert.threat_score} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`badge-${alert.severity} text-xs px-2 py-0.5 rounded font-mono`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="text-xs font-mono px-2 py-0.5 rounded"
                            style={{ background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)' }}>
                        {alert.category}
                      </span>
                      {alert.source_ip && (
                        <span className="text-xs font-mono" style={{ color: 'var(--accent-cyan)' }}>
                          {alert.source_ip}
                          {alert.geo_country && ` · ${alert.geo_country}`}
                        </span>
                      )}
                    </div>
                    <p className="text-sm font-mono mb-1" style={{ color: 'var(--text-primary)' }}>
                      {alert.title}
                    </p>
                    <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      {alert.description?.slice(0, 150)}
                    </p>
                    <p className="text-xs mt-1 font-mono" style={{ color: 'var(--text-muted)' }}>
                      {new Date(alert.timestamp).toLocaleString()}
                    </p>
                  </div>
                  {!alert.resolved && (
                    <div className="flex flex-col gap-1.5 flex-shrink-0">
                      {!alert.acknowledged && (
                        <button onClick={() => acknowledge(alert.id)}
                          className="text-xs px-2 py-1 rounded font-mono transition-all"
                          style={{ background: 'rgba(255,215,0,0.1)', color: '#ffd700', border: '1px solid rgba(255,215,0,0.2)' }}>
                          ACK
                        </button>
                      )}
                      <button onClick={() => resolve(alert.id)}
                        className="text-xs px-2 py-1 rounded font-mono transition-all"
                        style={{ background: 'rgba(0,255,179,0.08)', color: '#00ffb3', border: '1px solid rgba(0,255,179,0.2)' }}>
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
    </motion.div>
  )
}

function ThreatScoreRing({ score }) {
  const norm = Math.min(10, score) / 10
  const color = norm > 0.7 ? '#ff3d5a' : norm > 0.4 ? '#ffd700' : '#00ffb3'
  const r = 14, circ = 2 * Math.PI * r
  return (
    <div className="flex-shrink-0 w-10 h-10 relative flex items-center justify-center">
      <svg width="40" height="40" className="-rotate-90">
        <circle cx="20" cy="20" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="2.5" />
        <circle cx="20" cy="20" r={r} fill="none" stroke={color} strokeWidth="2.5"
                strokeDasharray={`${norm * circ} ${circ}`}
                style={{ transition: 'stroke-dasharray 1s ease', filter: `drop-shadow(0 0 4px ${color})` }} />
      </svg>
      <span className="absolute font-mono font-bold text-xs" style={{ color }}>
        {score?.toFixed(0)}
      </span>
    </div>
  )
}
