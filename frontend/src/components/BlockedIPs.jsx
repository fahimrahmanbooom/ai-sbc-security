import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { dashboardAPI } from '../utils/api'
import toast from 'react-hot-toast'

export default function BlockedIPs() {
  const [ips, setIps]         = useState([])
  const [newIP, setNewIP]     = useState('')
  const [newReason, setNewReason] = useState('')
  const [loading, setLoading] = useState(true)
  const [adding, setAdding]   = useState(false)

  useEffect(() => { load() }, [])

  const load = async () => {
    try {
      const { data } = await dashboardAPI.blockedIPs()
      setIps(data.blocked_ips || [])
    } catch {}
    setLoading(false)
  }

  const handleBlock = async (e) => {
    e.preventDefault()
    if (!newIP.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
      toast.error('Invalid IP address format'); return
    }
    setAdding(true)
    try {
      await dashboardAPI.blockIP(newIP, newReason || 'Manual block')
      toast.success(`${newIP} blocked`)
      setNewIP(''); setNewReason('')
      load()
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to block IP')
    }
    setAdding(false)
  }

  const handleUnblock = async (id, ip) => {
    try {
      await dashboardAPI.unblockIP(id)
      toast.success(`${ip} unblocked`)
      load()
    } catch {
      toast.error('Failed to unblock IP')
    }
  }

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Blocked IPs</h2>
        <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 3 }}>
          {ips.length} IP{ips.length !== 1 ? 's' : ''} in blocklist — firewall entries
        </p>
      </div>

      {/* Add IP form */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card" style={{ padding: 20, marginBottom: 16 }}>
        <div className="section-title">Block New IP</div>
        <form onSubmit={handleBlock} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <input
            value={newIP}
            onChange={e => setNewIP(e.target.value)}
            placeholder="192.168.1.100"
            className="input"
            style={{ flex: '1 1 160px' }}
          />
          <input
            value={newReason}
            onChange={e => setNewReason(e.target.value)}
            placeholder="Reason (optional)"
            className="input"
            style={{ flex: '2 1 220px' }}
          />
          <button type="submit" disabled={adding} className="btn btn-danger"
            style={{ flexShrink: 0, fontSize: 14 }}>
            {adding ? 'Blocking…' : '⊗ Block IP'}
          </button>
        </form>
      </motion.div>

      {/* IP table */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }} className="card" style={{ padding: 20 }}>
        {loading ? (
          <div className="empty-state" style={{ padding: '32px 0' }}>
            <p style={{ color: 'var(--text-3)' }}>Loading…</p>
          </div>
        ) : ips.length === 0 ? (
          <div className="empty-state" style={{ padding: '32px 0' }}>
            <div style={{ fontSize: 28 }}>✓</div>
            <p style={{ color: 'var(--success)', fontWeight: 600 }}>No blocked IPs</p>
            <p style={{ fontSize: 13, color: 'var(--text-3)' }}>Block an IP above to add it to the firewall</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {/* Header row */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '160px 1fr 110px 80px 80px',
              gap: 12, padding: '4px 12px',
            }}>
              {['IP Address', 'Reason', 'Blocked At', 'Source', ''].map(h => (
                <span key={h} style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)',
                  textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</span>
              ))}
            </div>
            <AnimatePresence>
              {ips.map((ip, i) => (
                <motion.div key={ip.id}
                  initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 8 }} transition={{ delay: i * 0.03 }}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '160px 1fr 110px 80px 80px',
                    gap: 12, padding: '10px 12px', alignItems: 'center',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--danger-muted)',
                    border: '1px solid rgba(248,81,73,0.15)',
                  }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14,
                    fontWeight: 700, color: 'var(--danger)' }}>
                    {ip.ip_address}
                  </span>
                  <span style={{ fontSize: 13, color: 'var(--text-2)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ip.reason}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                    {new Date(ip.blocked_at).toLocaleDateString()}
                  </span>
                  <span className={`badge ${ip.auto_blocked ? 'badge-high' : 'badge-info'}`}>
                    {ip.auto_blocked ? 'Auto' : 'Manual'}
                  </span>
                  <button onClick={() => handleUnblock(ip.id, ip.ip_address)}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: 12, color: 'var(--text-3)' }}
                    onMouseEnter={e => e.currentTarget.style.color = 'var(--success)'}
                    onMouseLeave={e => e.currentTarget.style.color = 'var(--text-3)'}>
                    Unblock
                  </button>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </motion.div>
    </div>
  )
}
