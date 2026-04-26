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
  const listening    = connections.filter(c => c.status === 'LISTEN')
  const suspicious   = connections.filter(c => c.is_suspicious)

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Network</h2>
        <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 3 }}>
          Live connection monitoring &amp; traffic analysis
        </p>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 12 }}>
        {[
          { label: 'Total', value: connections.length, color: 'var(--accent)' },
          { label: 'Established', value: established.length, color: '#58a6ff' },
          { label: 'Listening', value: listening.length, color: '#a78bfa' },
          { label: 'Suspicious', value: suspicious.length, color: suspicious.length > 0 ? 'var(--danger)' : 'var(--success)' },
        ].map((stat, i) => (
          <motion.div key={stat.label} className="card"
            style={{ padding: 20, textAlign: 'center' }}
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
              {stat.label}
            </div>
            <div style={{ fontSize: 30, fontWeight: 800, color: stat.color, fontFamily: 'var(--font-mono)' }}>
              {stat.value}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Bandwidth */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <motion.div className="card" style={{ padding: 20 }}
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            ↓ Inbound
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--success)', fontFamily: 'var(--font-mono)' }}>
            {formatBytesPerSec(liveMetrics?.net_bytes_recv_rate || 0)}
          </div>
        </motion.div>
        <motion.div className="card" style={{ padding: 20 }}
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            ↑ Outbound
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
            {formatBytesPerSec(liveMetrics?.net_bytes_sent_rate || 0)}
          </div>
        </motion.div>
      </div>

      {/* Suspicious connections highlight */}
      {suspicious.length > 0 && (
        <motion.div className="card" style={{
            padding: 16, marginBottom: 12,
            borderColor: 'rgba(248,81,73,0.3)', background: 'rgba(248,81,73,0.04)',
          }}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <span className="dot dot-red" style={{ animation: 'pulse-dot 1s infinite' }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--danger)', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
              SUSPICIOUS CONNECTIONS DETECTED
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {suspicious.slice(0, 5).map((c, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--danger)', fontWeight: 600 }}>{c.remote_ip}</span>
                <span style={{ color: 'var(--text-3)' }}>→ port {c.remote_port}</span>
                <span style={{ marginLeft: 'auto', color: 'var(--text-3)' }}>{c.type} · {c.status}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Connection table */}
      <motion.div className="card" style={{ padding: 20 }}
        initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>
          Active Connections ({established.length})
        </div>
        {loading ? (
          <p style={{ fontSize: 13, color: 'var(--text-3)', textAlign: 'center', padding: '16px 0', fontFamily: 'var(--font-mono)' }}>
            Scanning…
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', fontSize: 13, fontFamily: 'var(--font-mono)', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Local', 'Remote', 'Status', 'Proto', 'Flag'].map((h, i) => (
                    <th key={h} style={{
                      textAlign: i === 4 ? 'right' : 'left',
                      padding: '6px 12px 8px 0',
                      fontSize: 11, fontWeight: 600, color: 'var(--text-3)',
                      textTransform: 'uppercase', letterSpacing: '0.05em',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {connections.slice(0, 30).map((c, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px 8px 0', color: 'var(--text-2)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.local_addr || '—'}
                    </td>
                    <td style={{ padding: '8px 12px 8px 0', color: c.is_suspicious ? 'var(--danger)' : 'var(--text-2)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.remote_addr || '—'}
                    </td>
                    <td style={{ padding: '8px 12px 8px 0' }}>
                      <span style={{
                        color: c.status === 'ESTABLISHED' ? 'var(--success)'
                             : c.status === 'LISTEN'       ? '#a78bfa'
                             : 'var(--text-3)',
                      }}>
                        {c.status}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px 8px 0', color: 'var(--text-3)' }}>{c.type}</td>
                    <td style={{ padding: '8px 0', textAlign: 'right' }}>
                      {c.is_suspicious
                        ? <span style={{ color: 'var(--danger)', fontWeight: 600 }}>⚠ SUSP</span>
                        : c.service
                          ? <span style={{ color: 'var(--text-3)' }}>{c.service}</span>
                          : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>
    </div>
  )
}
