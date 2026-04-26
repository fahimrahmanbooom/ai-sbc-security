import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { dashboardAPI, formatBytesPerSec } from '../utils/api'

const stagger = (i) => ({ initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.05, duration: 0.25 } })

export default function Overview({ liveMetrics, lastMessage }) {
  const [data, setData] = useState(null)
  const [history, setHistory] = useState([])

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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
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

      {/* ── Resource bars + Charts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 12, marginBottom: 12 }}>
        {/* Resources */}
        <motion.div {...stagger(6)} className="card" style={{ padding: 20 }}>
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
        <motion.div {...stagger(7)} className="card" style={{ padding: 20 }}>
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

      {/* ── Network chart + Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        {/* Network */}
        <motion.div {...stagger(8)} className="card" style={{ padding: 20 }}>
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
        <motion.div {...stagger(9)} className="card" style={{ padding: 20 }}>
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
        <motion.div {...stagger(10)} className="card" style={{ padding: 20 }}>
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
