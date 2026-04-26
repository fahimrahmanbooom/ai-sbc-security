import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { dashboardAPI } from '../utils/api'
import toast from 'react-hot-toast'

export default function BlockedIPs() {
  const [ips, setIps] = useState([])
  const [newIP, setNewIP] = useState('')
  const [newReason, setNewReason] = useState('')
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)

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
      toast.error('Invalid IP address format')
      return
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
    <motion.div className="p-6 space-y-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div>
        <h1 className="font-display text-lg tracking-widest" style={{ color: 'var(--accent-cyan)' }}>BLOCKED IPs</h1>
        <p className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
          {ips.length} IPs in blocklist • manage firewall entries
        </p>
      </div>

      {/* Add IP form */}
      <div className="card-glow rounded-2xl p-5" style={{ background: 'var(--bg-card)' }}>
        <h3 className="text-xs font-mono tracking-widest mb-4" style={{ color: 'var(--text-muted)' }}>
          BLOCK NEW IP
        </h3>
        <form onSubmit={handleBlock} className="flex gap-3 flex-wrap">
          <input value={newIP} onChange={e => setNewIP(e.target.value)}
            placeholder="192.168.1.100"
            className="flex-1 min-w-32 px-3 py-2 rounded-lg font-mono text-sm outline-none"
            style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}
            onFocus={e => e.target.style.borderColor = 'rgba(255,61,90,0.5)'}
            onBlur={e => e.target.style.borderColor = 'var(--border-subtle)'} />
          <input value={newReason} onChange={e => setNewReason(e.target.value)}
            placeholder="Reason (optional)"
            className="flex-1 min-w-48 px-3 py-2 rounded-lg font-mono text-sm outline-none"
            style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}
            onFocus={e => e.target.style.borderColor = 'rgba(255,61,90,0.5)'}
            onBlur={e => e.target.style.borderColor = 'var(--border-subtle)'} />
          <motion.button type="submit" disabled={adding}
            whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
            className="px-5 py-2 rounded-lg font-mono text-sm font-bold"
            style={{ background: 'rgba(255,61,90,0.15)', color: '#ff3d5a', border: '1px solid rgba(255,61,90,0.3)' }}>
            {adding ? 'BLOCKING...' : '⊗ BLOCK'}
          </motion.button>
        </form>
      </div>

      {/* IP table */}
      <div className="card-glow rounded-2xl p-5" style={{ background: 'var(--bg-card)' }}>
        {loading ? (
          <p className="text-xs font-mono text-center py-8" style={{ color: 'var(--text-muted)' }}>LOADING...</p>
        ) : ips.length === 0 ? (
          <p className="text-xs font-mono text-center py-8" style={{ color: 'var(--text-muted)' }}>No blocked IPs</p>
        ) : (
          <div className="space-y-2">
            <AnimatePresence>
              {ips.map((ip, i) => (
                <motion.div key={ip.id}
                  initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }} transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-3 p-3 rounded-lg"
                  style={{ background: 'rgba(255,61,90,0.04)', border: '1px solid rgba(255,61,90,0.1)' }}>
                  <span className="font-mono font-bold text-sm flex-1" style={{ color: '#ff3d5a' }}>
                    {ip.ip_address}
                  </span>
                  <span className="text-xs flex-1" style={{ color: 'var(--text-secondary)' }}>
                    {ip.reason}
                  </span>
                  <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                    {new Date(ip.blocked_at).toLocaleDateString()}
                  </span>
                  <span className="text-xs px-1.5 py-0.5 rounded font-mono"
                        style={{ background: ip.auto_blocked ? 'rgba(255,107,53,0.12)' : 'rgba(0,255,179,0.08)',
                                 color: ip.auto_blocked ? '#ff6b35' : '#00ffb3' }}>
                    {ip.auto_blocked ? 'AUTO' : 'MANUAL'}
                  </span>
                  <button onClick={() => handleUnblock(ip.id, ip.ip_address)}
                    className="text-xs px-2 py-1 rounded font-mono transition-all"
                    style={{ color: 'var(--text-muted)' }}
                    onMouseEnter={e => { e.target.style.color = '#00ffb3'; e.target.style.background = 'rgba(0,255,179,0.08)' }}
                    onMouseLeave={e => { e.target.style.color = 'var(--text-muted)'; e.target.style.background = '' }}>
                    UNBLOCK
                  </button>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>
    </motion.div>
  )
}
