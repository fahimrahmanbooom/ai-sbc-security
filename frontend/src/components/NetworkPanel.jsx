import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { dashboardAPI, formatBytesPerSec } from '../utils/api'

export default function NetworkPanel({ liveMetrics }) {
  const [connections, setConnections] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    load()
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [])

  const load = async () => {
    try {
      const { data } = await dashboardAPI.connections()
      setConnections(data.connections || [])
    } catch {}
    setLoading(false)
  }

  const established = connections.filter(c => c.status === 'ESTABLISHED')
  const listening = connections.filter(c => c.status === 'LISTEN')
  const suspicious = connections.filter(c => c.is_suspicious)

  return (
    <motion.div className="p-6 space-y-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div>
        <h1 className="font-display text-lg tracking-widest" style={{ color: 'var(--accent-cyan)' }}>NETWORK</h1>
        <p className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Live connection monitoring & traffic analysis
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'TOTAL', value: connections.length, color: 'var(--accent-cyan)' },
          { label: 'ESTABLISHED', value: established.length, color: '#0077ff' },
          { label: 'LISTENING', value: listening.length, color: '#7c3aed' },
          { label: 'SUSPICIOUS', value: suspicious.length, color: suspicious.length > 0 ? '#ff3d5a' : '#00ffb3' },
        ].map((stat, i) => (
          <motion.div key={stat.label}
            initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }}
            className="card-glow rounded-xl p-4 text-center" style={{ background: 'var(--bg-card)' }}>
            <p className="text-xs font-mono tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>
              {stat.label}
            </p>
            <p className="font-display text-3xl font-bold" style={{ color: stat.color }}>
              {stat.value}
            </p>
          </motion.div>
        ))}
      </div>

      {/* Bandwidth */}
      <div className="grid grid-cols-2 gap-4">
        <div className="card-glow rounded-xl p-4" style={{ background: 'var(--bg-card)' }}>
          <p className="text-xs font-mono tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>↓ INBOUND</p>
          <p className="font-display text-xl" style={{ color: '#00ffb3' }}>
            {formatBytesPerSec(liveMetrics.net_bytes_recv_rate || 0)}
          </p>
        </div>
        <div className="card-glow rounded-xl p-4" style={{ background: 'var(--bg-card)' }}>
          <p className="text-xs font-mono tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>↑ OUTBOUND</p>
          <p className="font-display text-xl" style={{ color: '#ff6b35' }}>
            {formatBytesPerSec(liveMetrics.net_bytes_sent_rate || 0)}
          </p>
        </div>
      </div>

      {/* Suspicious connections highlight */}
      {suspicious.length > 0 && (
        <motion.div className="card-critical rounded-xl p-4" style={{ background: 'rgba(255,61,90,0.05)' }}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <h3 className="text-xs font-mono tracking-widest mb-3 flex items-center gap-2"
              style={{ color: '#ff3d5a' }}>
            <span className="animate-pulse-red w-2 h-2 rounded-full inline-block" style={{ background: '#ff3d5a' }} />
            SUSPICIOUS CONNECTIONS DETECTED
          </h3>
          <div className="space-y-2">
            {suspicious.slice(0, 5).map((c, i) => (
              <div key={i} className="flex items-center gap-3 text-xs font-mono"
                   style={{ color: 'var(--text-secondary)' }}>
                <span style={{ color: '#ff3d5a' }}>{c.remote_ip}</span>
                <span>→ port {c.remote_port}</span>
                <span className="ml-auto">{c.type} · {c.status}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Connection table */}
      <div className="card-glow rounded-2xl p-5" style={{ background: 'var(--bg-card)' }}>
        <h3 className="text-xs font-mono tracking-widest mb-4" style={{ color: 'var(--text-muted)' }}>
          ACTIVE CONNECTIONS ({established.length})
        </h3>
        {loading ? (
          <p className="text-xs font-mono text-center py-4" style={{ color: 'var(--text-muted)' }}>SCANNING...</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-subtle)' }}>
                  <th className="text-left py-2 pr-4">LOCAL</th>
                  <th className="text-left py-2 pr-4">REMOTE</th>
                  <th className="text-left py-2 pr-4">STATUS</th>
                  <th className="text-left py-2 pr-4">PROTO</th>
                  <th className="text-right py-2">FLAG</th>
                </tr>
              </thead>
              <tbody>
                {connections.slice(0, 30).map((c, i) => (
                  <tr key={i}
                      style={{
                        color: c.is_suspicious ? '#ff3d5a' : 'var(--text-secondary)',
                        borderBottom: '1px solid rgba(255,255,255,0.02)'
                      }}>
                    <td className="py-1 pr-4 truncate max-w-32">{c.local_addr || '—'}</td>
                    <td className="py-1 pr-4 truncate max-w-32">{c.remote_addr || '—'}</td>
                    <td className="py-1 pr-4">
                      <span style={{ color: c.status === 'ESTABLISHED' ? '#00ffb3' : c.status === 'LISTEN' ? '#7c3aed' : 'var(--text-muted)' }}>
                        {c.status}
                      </span>
                    </td>
                    <td className="py-1 pr-4">{c.type}</td>
                    <td className="py-1 text-right">
                      {c.is_suspicious && <span style={{ color: '#ff3d5a' }}>⚠ SUSPICIOUS</span>}
                      {c.service && !c.is_suspicious && <span style={{ color: 'var(--text-muted)' }}>{c.service}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </motion.div>
  )
}
