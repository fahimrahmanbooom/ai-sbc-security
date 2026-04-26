import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { dashboardAPI } from '../utils/api'

const stagger = (i) => ({ initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.04, duration: 0.22 } })

const SEV_COLOR = { critical: 'var(--danger)', high: 'var(--warning)', medium: 'var(--accent)', low: 'var(--text-3)', info: 'var(--text-3)' }
const ML_COLOR  = { malicious: 'var(--danger)', suspicious: 'var(--warning)', benign: 'var(--success)', unknown: 'var(--text-3)' }

export default function FIMPanel() {
  const [status, setStatus]   = useState(null)
  const [events, setEvents]   = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [baselining, setBaselining] = useState(false)
  const [filter, setFilter]   = useState('all')  // all | malicious | suspicious
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t) }, [])

  const load = async () => {
    try {
      const [sRes, eRes] = await Promise.all([
        dashboardAPI.get('/fim/status'),
        dashboardAPI.get('/fim/events?limit=100'),
      ])
      setStatus(sRes.data)
      setEvents(eRes.data.events || [])
    } catch {} finally { setLoading(false) }
  }

  const handleScan = async () => {
    setScanning(true)
    try { await dashboardAPI.post('/fim/scan'); await load() } catch {}
    setScanning(false)
  }

  const handleRebaseline = async () => {
    if (!window.confirm('Re-establish baseline from current system state? Only do this on a verified clean system.')) return
    setBaselining(true)
    try { await dashboardAPI.post('/fim/rebaseline'); await load() } catch {}
    setBaselining(false)
  }

  const filtered = filter === 'all' ? events
    : events.filter(e => filter === 'flagged' ? e.ml_label !== 'benign' : e.ml_label === filter)

  if (loading) return <div style={{ padding: 24 }}><div className="skeleton" style={{ height: 40, borderRadius: 8, marginBottom: 12 }} /><div className="skeleton" style={{ height: 200, borderRadius: 8 }} /></div>

  const stats = status || {}
  const baseline = stats.baseline || {}

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>File Integrity Monitor</h2>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 3 }}>
            SHA256 baseline + AI-powered change classification
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={handleScan} disabled={scanning} style={{ fontSize: 13 }}>
            {scanning ? 'Scanning…' : '↻ Scan Now'}
          </button>
          <button className="btn btn-ghost" onClick={handleRebaseline} disabled={baselining}
            style={{ fontSize: 13, color: 'var(--warning)', borderColor: 'var(--warning)' }}>
            {baselining ? 'Working…' : '⚡ Rebaseline'}
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Files Watched',    value: (stats.total_files_watched ?? 0).toLocaleString(), color: 'var(--accent)' },
          { label: 'Total Events',     value: (stats.total_events ?? 0).toLocaleString(),        color: 'var(--text-1)' },
          { label: 'Events in Memory', value: (stats.events_in_memory ?? 0).toLocaleString(),    color: 'var(--text-1)' },
          { label: 'Baseline Files',   value: (baseline.total_files ?? 0).toLocaleString(),      color: 'var(--success)' },
        ].map((card, i) => (
          <motion.div key={card.label} {...stagger(i)} className="card" style={{ padding: '14px 16px' }}>
            <div className="metric-label" style={{ marginBottom: 6 }}>{card.label}</div>
            <div className="metric-value" style={{ color: card.color, fontSize: 22 }}>{card.value}</div>
          </motion.div>
        ))}
      </div>

      {/* Status bar */}
      <motion.div {...stagger(4)} className="card" style={{ padding: '12px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: stats.baseline_established ? 'var(--success)' : 'var(--warning)', display: 'inline-block' }} />
          <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
            {stats.baseline_established ? 'Baseline established' : 'Establishing baseline…'}
          </span>
        </div>
        {stats.last_scan && (
          <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
            Last scan: {new Date(stats.last_scan).toLocaleTimeString()}
          </div>
        )}
        <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-3)' }}>
          Auto-scan every 5 minutes
        </div>
      </motion.div>

      {/* Events table */}
      <motion.div {...stagger(5)} className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div className="section-title" style={{ marginBottom: 0 }}>Change Events</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {['all', 'flagged', 'suspicious', 'malicious'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`btn btn-ghost`}
                style={{
                  fontSize: 11, padding: '4px 10px',
                  background: filter === f ? 'var(--accent)' : 'transparent',
                  color: filter === f ? '#fff' : 'var(--text-3)',
                  borderColor: filter === f ? 'var(--accent)' : 'var(--border)',
                }}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state" style={{ padding: '32px 0' }}>
            <div style={{ fontSize: 28 }}>✓</div>
            <p style={{ color: 'var(--success)', fontWeight: 600 }}>
              {filter === 'all' ? 'No file changes detected' : `No ${filter} changes`}
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {filtered.slice(0, 60).map((ev, i) => (
              <EventRow key={i} ev={ev} expanded={expandedId === i}
                onClick={() => setExpandedId(expandedId === i ? null : i)} />
            ))}
          </div>
        )}
      </motion.div>

      {/* Baseline breakdown */}
      {baseline.by_directory && (
        <motion.div {...stagger(6)} className="card" style={{ padding: 20, marginTop: 12 }}>
          <div className="section-title">Baseline Coverage</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8 }}>
            {Object.entries(baseline.by_directory).slice(0, 12).map(([dir, count]) => (
              <div key={dir} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 12px', background: 'var(--bg-surface)',
                borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
              }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)', fontFamily: 'var(--font-mono)' }}>{dir}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-1)', fontFamily: 'var(--font-mono)' }}>{count}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}

function EventRow({ ev, expanded, onClick }) {
  const sevColor = SEV_COLOR[ev.severity] || 'var(--text-3)'
  const mlColor  = ML_COLOR[ev.ml_label] || 'var(--text-3)'
  const typeIcon = ev.event_type === 'modified' ? '✎' : ev.event_type === 'deleted' ? '✕' : ev.event_type === 'added' ? '+' : '⚠'

  return (
    <div onClick={onClick} style={{
      borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
      background: expanded ? 'var(--bg-surface)' : 'transparent',
      cursor: 'pointer', overflow: 'hidden',
      transition: 'background 0.15s',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}>
        {/* Type icon */}
        <span style={{
          width: 22, height: 22, borderRadius: '50%',
          background: sevColor + '22', color: sevColor,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 13, fontWeight: 700, flexShrink: 0,
        }}>{typeIcon}</span>

        {/* Path */}
        <span style={{
          flex: 1, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-1)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{ev.path}</span>

        {/* Badges */}
        <span className={`badge badge-${ev.severity}`} style={{ fontSize: 10 }}>{ev.severity}</span>
        <span style={{ fontSize: 11, color: mlColor, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
          {ev.ml_label}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 4, fontFamily: 'var(--font-mono)' }}>
          {new Date(ev.timestamp * 1000).toLocaleTimeString()}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{expanded ? '▲' : '▼'}</span>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}>
            <div style={{
              padding: '10px 12px 12px',
              borderTop: '1px solid var(--border)',
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12,
            }}>
              <Detail label="Event Type"   value={ev.event_type} />
              <Detail label="ML Score"     value={`${(ev.ml_score * 100).toFixed(0)}%`} />
              {ev.old_hash && <Detail label="Old Hash"   value={ev.old_hash?.slice(0, 16) + '…'} mono />}
              {ev.new_hash && <Detail label="New Hash"   value={ev.new_hash?.slice(0, 16) + '…'} mono />}
              {ev.old_meta?.size !== undefined && <Detail label="Old Size" value={`${ev.old_meta.size} bytes`} />}
              {ev.new_meta?.size !== undefined && <Detail label="New Size" value={`${ev.new_meta.size} bytes`} />}
              {ev.old_meta?.mode && <Detail label="Old Mode" value={ev.old_meta.mode} mono />}
              {ev.new_meta?.mode && <Detail label="New Mode" value={ev.new_meta.mode} mono />}
              {ev.description && (
                <div style={{ gridColumn: '1 / -1' }}>
                  <Detail label="Description" value={ev.description} />
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Detail({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
      <div style={{ fontSize: 12, color: 'var(--text-1)', fontFamily: mono ? 'var(--font-mono)' : 'inherit' }}>{value}</div>
    </div>
  )
}
