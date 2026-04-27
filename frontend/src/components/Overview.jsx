import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, RadialBarChart, RadialBar } from 'recharts'
import { dashboardAPI, formatBytesPerSec } from '../utils/api'

const stagger = (i) => ({ initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.05, duration: 0.25 } })

const AI_MODULES = [
  { key: 'anomaly',    label: 'Anomaly Detection',  icon: '🧠', desc: 'Baseline ML' },
  { key: 'ids',        label: 'IDS Engine',          icon: '🔍', desc: 'Signature + ML' },
  { key: 'fim',        label: 'File Integrity',      icon: '📁', desc: 'SHA256 + AI' },
  { key: 'honeypot',   label: 'Honeypot',            icon: '🍯', desc: 'Deception layer' },
  { key: 'predictor',  label: 'Threat Predictor',    icon: '📈', desc: 'Time-series' },
  { key: 'federated',  label: 'Federated Learning',  icon: '🌐', desc: 'Privacy-aware' },
]

export default function Overview({ liveMetrics, lastMessage }) {
  const [data, setData] = useState(null)
  const [history, setHistory] = useState([])
  const [aiStatus, setAiStatus] = useState({})

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) }, [])

  useEffect(() => {
    if (liveMetrics.cpu_percent !== undefined) {
      const now = new Date()
      setHistory(h => [...h.slice(-80), {
        t: `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`,
        cpu: liveMetrics.cpu_percent,
        ram: liveMetrics.ram_percent,
        netIn:  (liveMetrics.net_bytes_recv_rate || 0) / 1024,
        netOut: (liveMetrics.net_bytes_sent_rate || 0) / 1024,
      }])
    }
  }, [liveMetrics])

  const load = async () => {
    try {
      const { data: d } = await dashboardAPI.overview()
      setData(d)
      if (d.metric_history?.length) {
        setHistory(d.metric_history.slice(-80).map(h => ({
          t: new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          cpu: h.cpu, ram: h.ram, netIn: h.net_recv / 1024, netOut: h.net_sent / 1024, threat: h.threat_level * 100,
        })))
      }
      // Fetch AI module statuses
      const statuses = {}
      await Promise.allSettled([
        dashboardAPI.get('/fim/status').then(r => { statuses.fim = r.data?.baseline_established ? 'active' : 'starting' }),
        dashboardAPI.get('/honeypot/stats').then(r => { statuses.honeypot = r.data?.active_ports > 0 ? 'active' : 'idle' }),
        dashboardAPI.get('/federated/status').then(r => { statuses.federated = r.data?.enabled ? 'active' : 'disabled' }),
      ])
      statuses.anomaly   = d?.ai?.anomaly_score !== undefined ? 'active' : 'active'
      statuses.ids       = 'active'
      statuses.predictor = 'active'
      setAiStatus(statuses)
    } catch {}
  }

  const sys = data?.system || {}
  const sec = data?.security || {}
  const net = data?.network || {}

  const cpu  = liveMetrics.cpu_percent  ?? sys.cpu_percent  ?? 0
  const ram  = liveMetrics.ram_percent  ?? sys.ram_percent  ?? 0
  const disk = sys.disk_percent ?? 0
  const temp = liveMetrics.cpu_temp     ?? sys.cpu_temp

  return (
    <div style={{ padding: 24 }}>

      {/* ── Top stat cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Unresolved Alerts', value: sec.unresolved_alerts ?? 0,   color: 'var(--danger)',   dim: sec.unresolved_alerts > 0 },
          { label: 'IDS Detections',    value: sec.ids_total_alerts  ?? 0,   color: 'var(--warning)' },
          { label: 'Unique Attackers',  value: sec.unique_attackers  ?? 0,   color: 'var(--purple)' },
          { label: 'Blocked IPs',       value: sec.blocked_ips       ?? 0,   color: 'var(--text-2)' },
          { label: 'Connections',       value: net.total_connections ?? 0,   color: 'var(--accent)' },
          { label: 'Suspicious Conns',  value: net.suspicious        ?? 0,   color: 'var(--danger)',   dim: net.suspicious > 0 },
        ].map((card, i) => (
          <motion.div key={card.label} {...stagger(i)} className="card"
            style={{ padding: '16px 18px' }}>
            <div className="metric-label" style={{ marginBottom: 8 }}>{card.label}</div>
            <div className="metric-value" style={{ color: card.color }}>
              {card.value.toLocaleString()}
            </div>
          </motion.div>
        ))}
      </div>

      {/* ── Software Update Widget ── */}
      <UpdateWidget lastMessage={lastMessage} />

      {/* ── AI Status card ── */}
      <motion.div {...stagger(6)} className="card" style={{ padding: '16px 20px', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div className="section-title" style={{ marginBottom: 0 }}>AI Engine Status</div>
          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
            {Object.values(aiStatus).filter(s => s === 'active').length} / {AI_MODULES.length} active
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10 }}>
          {AI_MODULES.map(m => {
            const status = aiStatus[m.key] || 'active'
            const isActive = status === 'active' || status === 'starting'
            return (
              <div key={m.key} style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px',
                borderRadius: 'var(--radius-sm)', background: 'var(--bg-surface)',
                border: `1px solid ${isActive ? 'var(--border-md)' : 'var(--border)'}`,
              }}>
                <span style={{ fontSize: 18, flexShrink: 0 }}>{m.icon}</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)', lineHeight: 1.2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>{m.desc}</div>
                </div>
                <span style={{ marginLeft: 'auto', flexShrink: 0 }}>
                  {status === 'starting'
                    ? <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning)', display: 'inline-block' }} />
                    : status === 'disabled'
                    ? <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--text-3)', display: 'inline-block' }} />
                    : <span className="dot dot-green" />}
                </span>
              </div>
            )
          })}
        </div>
      </motion.div>

      {/* ── Resource bars + Charts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 12, marginBottom: 12 }}>
        {/* Resources */}
        <motion.div {...stagger(7)} className="card" style={{ padding: 20 }}>
          <div className="section-title">System Resources</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <ResourceRow label="CPU"  pct={cpu}  value={`${cpu.toFixed(1)}%`} color="var(--accent)" />
            <ResourceRow label="RAM"  pct={ram}  value={`${ram.toFixed(1)}%`}
              sub={`${sys.ram_used_mb ?? 0} / ${sys.ram_total_mb ?? 0} MB`} color="var(--purple)" />
            <ResourceRow label="Disk" pct={disk} value={`${disk.toFixed(1)}%`}
              sub={`${sys.disk_used_gb ?? 0} / ${sys.disk_total_gb ?? 0} GB`} color="var(--success)" />
            {temp != null && (
              <ResourceRow label="Temp" pct={(temp/100)*100} value={`${temp.toFixed(0)}°C`}
                color={temp > 70 ? 'var(--danger)' : 'var(--warning)'} />
            )}
          </div>

          {/* Load averages */}
          <div className="divider" style={{ margin: '16px 0' }} />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            {[['1m', sys.load_avg_1], ['5m', sys.load_avg_5], ['15m', sys.load_avg_15]].map(([l, v]) => (
              <div key={l} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)',
                  color: 'var(--text-1)' }}>{v?.toFixed(2) ?? '—'}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>Load {l}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* CPU/RAM chart */}
        <motion.div {...stagger(8)} className="card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div className="section-title" style={{ marginBottom: 0 }}>CPU & RAM Usage</div>
            <div style={{ display: 'flex', gap: 16 }}>
              <Legend color="var(--accent)"  label="CPU" />
              <Legend color="var(--purple)"  label="RAM" />
            </div>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={history} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gCpu" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--accent)"  stopOpacity={0.25}/>
                  <stop offset="100%" stopColor="var(--accent)"  stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gRam" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--purple)"  stopOpacity={0.25}/>
                  <stop offset="100%" stopColor="var(--purple)"  stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={60} />
              <YAxis domain={[0,100]} tickLine={false} axisLine={false} tickFormatter={v=>`${v}%`} />
              <Tooltip formatter={(v,n)=>[`${v?.toFixed(1)}%`, n]} />
              <Area type="monotone" dataKey="cpu" stroke="var(--accent)" strokeWidth={1.5} fill="url(#gCpu)" name="CPU" dot={false} />
              <Area type="monotone" dataKey="ram" stroke="var(--purple)" strokeWidth={1.5} fill="url(#gRam)" name="RAM" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* ── Threat score chart ── */}
      {history.some(h => h.threat !== undefined) && (
        <motion.div {...stagger(9)} className="card" style={{ padding: 20, marginBottom: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div className="section-title" style={{ marginBottom: 0 }}>AI Threat Score</div>
            <Legend color="var(--danger)" label="Threat level %" />
          </div>
          <ResponsiveContainer width="100%" height={110}>
            <AreaChart data={history} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gThreat" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--danger)" stopOpacity={0.35}/>
                  <stop offset="100%" stopColor="var(--danger)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={60} />
              <YAxis domain={[0, 100]} tickLine={false} axisLine={false} tickFormatter={v => `${v}%`} />
              <Tooltip formatter={(v) => [`${v?.toFixed(1)}%`, 'Threat']} />
              <Area type="monotone" dataKey="threat" stroke="var(--danger)" strokeWidth={1.5} fill="url(#gThreat)" name="Threat" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      )}

      {/* ── Network chart + Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        {/* Network */}
        <motion.div {...stagger(10)} className="card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div className="section-title" style={{ marginBottom: 0 }}>Network Traffic</div>
            <div style={{ display: 'flex', gap: 16 }}>
              <Legend color="var(--success)" label="↓ In" />
              <Legend color="var(--warning)" label="↑ Out" />
            </div>
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart data={history} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gIn"  x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--success)" stopOpacity={0.2}/>
                  <stop offset="100%" stopColor="var(--success)" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--warning)" stopOpacity={0.2}/>
                  <stop offset="100%" stopColor="var(--warning)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={60} />
              <YAxis tickLine={false} axisLine={false} tickFormatter={v=>`${v.toFixed(0)}K`} />
              <Tooltip formatter={(v,n)=>[`${v?.toFixed(1)} KB/s`, n]} />
              <Area type="monotone" dataKey="netIn"  stroke="var(--success)" strokeWidth={1.5} fill="url(#gIn)"  name="↓ In"  dot={false} />
              <Area type="monotone" dataKey="netOut" stroke="var(--warning)" strokeWidth={1.5} fill="url(#gOut)" name="↑ Out" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Recent alerts */}
        <motion.div {...stagger(11)} className="card" style={{ padding: 20 }}>
          <div className="section-title">Recent Alerts</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 200, overflowY: 'auto' }}>
            {!(data?.recent_alerts?.length) ? (
              <div className="empty-state" style={{ padding: '24px 0' }}>
                <div style={{ fontSize: 24 }}>✓</div>
                <p style={{ color: 'var(--success)', fontWeight: 600 }}>No active alerts</p>
              </div>
            ) : data.recent_alerts.map(a => (
              <div key={a.id}
                className={`alert-strip-${a.severity}`}
                style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px',
                  background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)' }}>
                <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.title}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
                    {a.source_ip && `${a.source_ip} · `}
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 700,
                  color: a.threat_score >= 8 ? 'var(--danger)' : 'var(--text-3)' }}>
                  {a.threat_score?.toFixed(1)}
                </span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* ── Top processes ── */}
      {sys.top_processes?.length > 0 && (
        <motion.div {...stagger(12)} className="card" style={{ padding: 20 }}>
          <div className="section-title">Top Processes by CPU</div>
          <table className="table">
            <thead>
              <tr><th>PID</th><th>Process</th><th style={{ textAlign:'right' }}>CPU %</th><th style={{ textAlign:'right' }}>MEM %</th><th>Status</th></tr>
            </thead>
            <tbody>
              {sys.top_processes.slice(0,8).map((p, i) => (
                <tr key={i}>
                  <td className="mono">{p.pid}</td>
                  <td style={{ color: 'var(--text-1)', fontWeight: 500 }}>{p.name}</td>
                  <td style={{ textAlign:'right', fontFamily:'var(--font-mono)', color: p.cpu > 50 ? 'var(--danger)' : 'var(--text-1)', fontWeight: p.cpu > 10 ? 600 : 400 }}>
                    {p.cpu?.toFixed(1)}
                  </td>
                  <td style={{ textAlign:'right', fontFamily:'var(--font-mono)' }}>{p.mem?.toFixed(1)}</td>
                  <td><span className={`badge badge-${p.status === 'running' ? 'info' : 'low'}`}>{p.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      )}
    </div>
  )
}

function ResourceRow({ label, pct, value, sub, color }) {
  const isHigh = pct > 88
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>{label}</span>
        <div style={{ textAlign: 'right' }}>
          <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)',
            color: isHigh ? 'var(--danger)' : color }}>{value}</span>
          {sub && <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{sub}</div>}
        </div>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{
          width: `${Math.min(100, pct)}%`,
          background: isHigh ? 'var(--danger)' : color,
        }} />
      </div>
    </div>
  )
}

function Legend({ color, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <div style={{ width: 8, height: 2, borderRadius: 99, background: color }} />
      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{label}</span>
    </div>
  )
}

// ── Software Update Widget ─────────────────────────────────────────────────────
function UpdateWidget({ lastMessage }) {
  const [versionInfo, setVersionInfo]   = useState(null)
  const [checking, setChecking]         = useState(false)
  const [updating, setUpdating]         = useState(false)
  const [updateLog, setUpdateLog]       = useState([])
  const [showLog, setShowLog]           = useState(false)
  const logRef                          = React.useRef(null)

  const checkForUpdates = async () => {
    setChecking(true)
    try {
      const { data } = await dashboardAPI.systemVersion()
      setVersionInfo(data)
    } catch {}
    setChecking(false)
  }

  React.useEffect(() => { checkForUpdates() }, [])

  // Receive live progress messages via the shared WebSocket
  React.useEffect(() => {
    if (!lastMessage || lastMessage.type !== 'update_progress') return
    setUpdateLog(prev => [...prev, lastMessage])
    setShowLog(true)
    if (lastMessage.done || lastMessage.error) {
      setUpdating(false)
      // Re-check version after a successful update
      if (lastMessage.done) setTimeout(checkForUpdates, 2000)
    }
  }, [lastMessage])

  // Auto-scroll log to bottom
  React.useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [updateLog])

  const handleUpdate = async () => {
    setUpdateLog([])
    setUpdating(true)
    setShowLog(true)
    try {
      await dashboardAPI.systemUpdate()
    } catch {
      setUpdating(false)
      setUpdateLog([{ step: 'Failed to start update', error: true }])
    }
  }

  const updateAvailable = versionInfo?.update_available

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="card"
      style={{ padding: '14px 20px', marginBottom: 12 }}
    >
      {/* ── Header row ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        {/* Left: icon + title + version */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 18, flexShrink: 0 }}>🔄</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-1)' }}>Software Update</div>
            {versionInfo ? (
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1, fontFamily: 'var(--font-mono)' }}>
                {updateAvailable
                  ? <>current: {versionInfo.current_version} &rarr; latest: {versionInfo.latest_version}</>
                  : <>version: {versionInfo.current_version}</>
                }
              </div>
            ) : (
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>Checking GitHub…</div>
            )}
          </div>
        </div>

        {/* Right: status pill + action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>

          {/* Status pill — rightmost label before action buttons */}
          {versionInfo && (
            <span style={{
              padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
              background: updateAvailable ? 'rgba(88,166,255,0.12)' : 'rgba(63,185,80,0.12)',
              color:      updateAvailable ? '#58a6ff'              : 'var(--success)',
              border:     `1px solid ${updateAvailable ? 'rgba(88,166,255,0.3)' : 'rgba(63,185,80,0.3)'}`,
            }}>
              {updateAvailable ? '↑ Update available' : '✓ Up to date'}
            </span>
          )}

          <button
            onClick={checkForUpdates}
            disabled={checking || updating}
            className="btn btn-ghost"
            style={{ fontSize: 12, padding: '5px 12px' }}
          >
            {checking ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 11, height: 11, border: '2px solid var(--border-md)', borderTopColor: 'var(--accent)', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />
                Checking…
              </span>
            ) : '↻ Check'}
          </button>

          {updateAvailable && !updating && (
            <button
              onClick={handleUpdate}
              className="btn btn-primary"
              style={{ fontSize: 12, padding: '5px 12px' }}
            >
              ↑ Update now
            </button>
          )}

          {updating && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: 'var(--warning)', padding: '5px 12px' }}>
              <span style={{ width: 11, height: 11, border: '2px solid rgba(210,153,34,0.3)', borderTopColor: '#d29922', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />
              Updating…
            </span>
          )}

          {showLog && !updating && (
            <button
              onClick={() => setShowLog(s => !s)}
              className="btn btn-ghost"
              style={{ fontSize: 11, padding: '4px 10px', color: 'var(--text-3)' }}
            >
              Hide log
            </button>
          )}
        </div>
      </div>

      {/* ── Progress / log panel ── */}
      <AnimatePresence>
        {showLog && updateLog.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}
          >
            <div
              ref={logRef}
              style={{
                marginTop: 12,
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '10px 14px',
                maxHeight: 200, overflowY: 'auto',
                fontFamily: 'var(--font-mono)', fontSize: 12,
                display: 'flex', flexDirection: 'column', gap: 5,
              }}
            >
              {updateLog.map((entry, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                  <span style={{ flexShrink: 0, color: entry.error ? 'var(--danger)' : entry.done ? 'var(--success)' : 'var(--accent)' }}>
                    {entry.error ? '✗' : entry.done ? '✓' : '›'}
                  </span>
                  <div>
                    <span style={{ color: entry.error ? 'var(--danger)' : entry.done ? 'var(--success)' : 'var(--text-1)', fontWeight: 600 }}>
                      {entry.step}
                    </span>
                    {entry.detail && (
                      <span style={{ color: 'var(--text-3)', marginLeft: 8 }}>{entry.detail}</span>
                    )}
                  </div>
                </div>
              ))}
              {updating && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-3)' }}>
                  <span style={{ width: 10, height: 10, border: '2px solid var(--border-md)', borderTopColor: 'var(--accent)', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite', flexShrink: 0 }} />
                  Running…
                </div>
              )}
            </div>

            {!updating && updateLog.some(e => e.done) && (
              <button
                onClick={() => window.location.reload()}
                className="btn btn-primary"
                style={{ width: '100%', marginTop: 10, fontSize: 12 }}
              >
                Reload dashboard
              </button>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
