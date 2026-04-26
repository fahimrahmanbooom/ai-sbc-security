import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { dashboardAPI } from '../utils/api'

const stagger = (i) => ({ initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.04, duration: 0.22 } })

const LABEL_COLOR = {
  credential_brute_force: 'var(--danger)',
  exploit_attempt:        'var(--warning)',
  recon:                  'var(--accent)',
  port_scan:              'var(--text-2)',
  other:                  'var(--text-3)',
}
const LABEL_NICE = {
  credential_brute_force: 'Brute Force',
  exploit_attempt:        'Exploit Attempt',
  recon:                  'Reconnaissance',
  port_scan:              'Port Scan',
  other:                  'Other',
}

export default function HoneypotPanel() {
  const [stats, setStats]       = useState(null)
  const [probes, setProbes]     = useState([])
  const [clusters, setClusters] = useState([])
  const [attackers, setAttackers] = useState([])
  const [loading, setLoading]   = useState(true)
  const [activeTab, setActiveTab] = useState('activity')  // activity | clusters | attackers

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  const load = async () => {
    try {
      const [sRes, pRes, cRes, aRes] = await Promise.all([
        dashboardAPI.honeypotStats(),
        dashboardAPI.honeypotProbes(60),
        dashboardAPI.honeypotClusters(),
        dashboardAPI.honeypotAttackers(15),
      ])
      setStats(sRes.data)
      setProbes(pRes.data.probes || [])
      setClusters(cRes.data.clusters || [])
      setAttackers(aRes.data.attackers || [])
    } catch {} finally { setLoading(false) }
  }

  if (loading) return (
    <div style={{ padding: 24 }}>
      <div className="skeleton" style={{ height: 40, marginBottom: 12, borderRadius: 8 }} />
      <div className="skeleton" style={{ height: 280, borderRadius: 8 }} />
    </div>
  )

  const s = stats || {}

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>AI Honeypot</h2>
        <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 3 }}>
          Low-interaction deception system — {s.active_ports ?? 0} ports listening
        </p>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 16 }}>
        {[
          { label: 'Total Probes',    value: (s.total_probes ?? 0).toLocaleString(),  color: 'var(--accent)' },
          { label: 'Unique IPs',      value: (s.unique_ips ?? 0).toLocaleString(),    color: 'var(--warning)' },
          { label: 'Attack Clusters', value: (s.clusters ?? 0).toLocaleString(),      color: 'var(--purple)' },
          { label: 'Active Ports',    value: (s.active_ports ?? 0).toLocaleString(),  color: 'var(--success)' },
        ].map((card, i) => (
          <motion.div key={card.label} {...stagger(i)} className="card" style={{ padding: '14px 16px' }}>
            <div className="metric-label" style={{ marginBottom: 6 }}>{card.label}</div>
            <div className="metric-value" style={{ color: card.color, fontSize: 22 }}>{card.value}</div>
          </motion.div>
        ))}
      </div>

      {/* Service breakdown */}
      {s.by_service && Object.keys(s.by_service).length > 0 && (
        <motion.div {...stagger(4)} className="card" style={{ padding: 16, marginBottom: 12 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Probes by Service</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {Object.entries(s.by_service).sort((a, b) => b[1] - a[1]).map(([svc, count]) => (
              <div key={svc} style={{
                padding: '6px 12px', borderRadius: 99,
                background: 'var(--bg-surface)', border: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-2)' }}>{svc.replace('fake-', '')}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{count}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Main tabs */}
      <motion.div {...stagger(5)} className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', gap: 4, marginBottom: 16, padding: 4, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', width: 'fit-content', border: '1px solid var(--border)' }}>
          {[
            { id: 'activity', label: `Activity (${probes.length})` },
            { id: 'clusters', label: `Clusters (${clusters.length})` },
            { id: 'attackers', label: `Top Attackers (${attackers.length})` },
          ].map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              style={{
                padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 500,
                border: 'none', cursor: 'pointer', transition: 'all 0.15s',
                background: activeTab === t.id ? 'var(--bg-card)' : 'transparent',
                color: activeTab === t.id ? 'var(--text-1)' : 'var(--text-3)',
              }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Activity tab */}
        {activeTab === 'activity' && (
          probes.length === 0 ? (
            <div className="empty-state" style={{ padding: '32px 0' }}>
              <div style={{ fontSize: 28 }}>🍯</div>
              <p style={{ color: 'var(--text-3)' }}>No probes captured yet</p>
              <p style={{ fontSize: 12, color: 'var(--text-3)' }}>The honeypot is listening for connections</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Target Port</th>
                  <th>Service</th>
                  <th>Attack Type</th>
                  <th style={{ textAlign: 'right' }}>Threat</th>
                </tr>
              </thead>
              <tbody>
                {[...probes].reverse().slice(0, 40).map((p, i) => {
                  const color = LABEL_COLOR[p.threat_label] || 'var(--text-3)'
                  return (
                    <tr key={i}>
                      <td style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-3)' }}>
                        {new Date(p.timestamp * 1000).toLocaleTimeString()}
                      </td>
                      <td className="mono" style={{ fontWeight: 600 }}>{p.src_ip}</td>
                      <td className="mono">{p.honeypot_port}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{p.service?.replace('fake-', '')}</td>
                      <td>
                        <span style={{ fontSize: 12, fontWeight: 600, color }}>
                          {LABEL_NICE[p.threat_label] || p.threat_label}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontSize: 12,
                        color: p.threat_score >= 0.7 ? 'var(--danger)' : p.threat_score >= 0.4 ? 'var(--warning)' : 'var(--text-3)',
                        fontWeight: 700 }}>
                        {(p.threat_score * 10).toFixed(1)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )
        )}

        {/* Clusters tab */}
        {activeTab === 'clusters' && (
          clusters.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 0' }}>
              <p style={{ color: 'var(--text-3)' }}>No attack clusters identified yet</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {clusters.map((c, i) => {
                const color = LABEL_COLOR[c.label] || 'var(--text-3)'
                return (
                  <div key={c.cluster_id} style={{
                    padding: '14px 16px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-surface)', border: `1px solid ${color}33`,
                    display: 'flex', alignItems: 'flex-start', gap: 14,
                  }}>
                    <div style={{
                      minWidth: 44, textAlign: 'center', padding: '6px 4px',
                      borderRadius: 'var(--radius-sm)', background: color + '18',
                    }}>
                      <div style={{ fontSize: 18, fontWeight: 800, color, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>{c.probe_count}</div>
                      <div style={{ fontSize: 9, color: 'var(--text-3)' }}>probes</div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color, marginBottom: 4 }}>
                        {LABEL_NICE[c.label] || c.label}
                        <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-3)', fontWeight: 400 }}>
                          Cluster #{c.cluster_id}
                        </span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 6 }}>{c.description}</div>
                      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                        <Meta label="IPs" value={c.unique_ips} />
                        <Meta label="Ports" value={c.top_ports?.join(', ') || '—'} />
                        <Meta label="First seen" value={new Date(c.first_seen * 1000).toLocaleString()} />
                        <Meta label="Last seen" value={new Date(c.last_seen * 1000).toLocaleString()} />
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )
        )}

        {/* Top Attackers tab */}
        {activeTab === 'attackers' && (
          attackers.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 0' }}>
              <p style={{ color: 'var(--text-3)' }}>No attackers tracked yet</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>IP Address</th>
                  <th style={{ textAlign: 'right' }}>Probes</th>
                  <th>Services Targeted</th>
                  <th style={{ textAlign: 'right' }}>Max Threat</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {attackers.map((a, i) => (
                  <tr key={a.ip}>
                    <td className="mono" style={{ color: 'var(--text-3)' }}>{i + 1}</td>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--text-1)' }}>{a.ip}</td>
                    <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent)' }}>
                      {a.probe_count}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)' }}>
                      {a.services_targeted?.map(s => s.replace('fake-', '')).join(', ')}
                    </td>
                    <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)',
                      color: a.max_threat_score >= 0.7 ? 'var(--danger)' : 'var(--warning)',
                      fontWeight: 700, fontSize: 12 }}>
                      {(a.max_threat_score * 10).toFixed(1)}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                      {a.last_seen_iso ? new Date(a.last_seen_iso).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </motion.div>
    </div>
  )
}

function Meta({ label, value }) {
  return (
    <div>
      <span style={{ fontSize: 10, color: 'var(--text-3)', marginRight: 4 }}>{label}:</span>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-2)', fontFamily: 'var(--font-mono)' }}>{value}</span>
    </div>
  )
}
