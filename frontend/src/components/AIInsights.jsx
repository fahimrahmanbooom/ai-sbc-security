import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { dashboardAPI } from '../utils/api'

export default function AIInsights() {
  const [forecast, setForecast] = useState(null)
  const [insights, setInsights] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [tab, setTab] = useState('forecast')
  const [lastRefresh, setLastRefresh] = useState(null)

  const load = (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    Promise.all([
      dashboardAPI.forecast(),
      dashboardAPI.insights(),
    ]).then(([f, i]) => {
      setForecast(f.data)
      setInsights(i.data)
      setLastRefresh(new Date())
    }).catch(() => {}).finally(() => {
      setLoading(false)
      setRefreshing(false)
    })
  }

  useEffect(() => { load() }, [])

  if (loading) return (
    <div style={{ padding: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', height: 260 }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{
          width: 40, height: 40, border: '3px solid var(--border-md)',
          borderTopColor: 'var(--accent)', borderRadius: '50%',
          animation: 'spin 0.8s linear infinite', margin: '0 auto 12px',
        }} />
        <p style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>AI MODELS PROCESSING…</p>
      </div>
    </div>
  )

  const riskColor = (r) => ({
    critical: 'var(--danger)', high: 'var(--warning)',
    medium: '#d29922', low: 'var(--success)',
  }[r] || 'var(--success)')

  return (
    <motion.div style={{ padding: 24 }} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>AI Insights</h2>
          <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 3 }}>
            Machine learning analysis &amp; predictive threat forecasting
            {lastRefresh && (
              <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                · updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <button onClick={() => load(true)} disabled={refreshing}
          className="btn btn-ghost"
          style={{ fontSize: 12, padding: '5px 12px', flexShrink: 0 }}>
          {refreshing ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 10, height: 10, border: '2px solid var(--border-md)', borderTopColor: 'var(--accent)', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />
              Refreshing…
            </span>
          ) : '↻ Refresh'}
        </button>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex', gap: 4, padding: 4, borderRadius: 10,
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        marginBottom: 20, width: 'fit-content',
      }}>
        {['forecast', 'log_insights', 'ids_alerts'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{
              padding: '6px 14px', borderRadius: 7, fontSize: 12, fontWeight: 600,
              fontFamily: 'var(--font-mono)', cursor: 'pointer', border: 'none',
              background: tab === t ? 'var(--accent)' : 'transparent',
              color: tab === t ? '#fff' : 'var(--text-3)',
              transition: 'all 0.15s',
            }}>
            {t.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      {/* ── Forecast tab ── */}
      {tab === 'forecast' && forecast && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Summary card */}
          <motion.div className="card" style={{ padding: 20 }}
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
              <div>
                <div className="section-title" style={{ marginBottom: 6 }}>24-HOUR THREAT FORECAST</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 22, fontWeight: 800, color: riskColor(forecast.overall_risk) }}>
                    {forecast.overall_risk?.toUpperCase()}
                  </span>
                  <span style={{
                    fontSize: 11, fontWeight: 600, padding: '3px 8px', borderRadius: 99,
                    background: 'var(--bg-surface)', border: '1px solid var(--border-md)',
                    color: 'var(--text-2)', fontFamily: 'var(--font-mono)',
                  }}>
                    {forecast.trend?.toUpperCase()} TREND
                  </span>
                </div>
                <p style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 8, lineHeight: 1.6 }}>
                  {forecast.summary}
                </p>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div className="section-title" style={{ marginBottom: 4 }}>PEAK AT</div>
                <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
                  {forecast.peak_threat_hour?.toString().padStart(2, '0')}:00
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                  score: {(forecast.peak_threat_score * 100)?.toFixed(0)}%
                </div>
              </div>
            </div>

            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={forecast.hourly_predictions}>
                <defs>
                  <linearGradient id="forecastGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.35}/>
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="hour" tickFormatter={h => `${h.toString().padStart(2,'0')}h`}
                       tick={{ fontSize: 10, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <YAxis domain={[0, 1]} tickFormatter={v => `${(v*100).toFixed(0)}%`}
                       tick={{ fontSize: 10, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-md)', borderRadius: 8, fontSize: 12, color: 'var(--text-1)' }}
                  formatter={(v) => [`${(v*100).toFixed(1)}%`, 'Threat Score']} />
                <Area type="monotone" dataKey="predicted_score" stroke="#7c3aed" fill="url(#forecastGrad)"
                      strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </motion.div>

          {/* Recommendations */}
          <motion.div className="card" style={{ padding: 20 }}
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <div className="section-title" style={{ marginBottom: 12 }}>AI RECOMMENDATIONS</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(forecast.recommendations || []).map((rec, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, color: 'var(--text-2)' }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700, flexShrink: 0 }}>›</span>
                  <span style={{ lineHeight: 1.55 }}>{rec}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      )}

      {/* ── Log insights ── */}
      {tab === 'log_insights' && insights && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {!insights.log_insights?.length ? (
            <div className="empty-state" style={{ padding: '48px 0' }}>
              <div style={{ fontSize: 28 }}>✓</div>
              <p style={{ color: 'var(--success)', fontWeight: 600 }}>Clean</p>
              <p style={{ fontSize: 13, color: 'var(--text-3)' }}>No log correlation insights yet — collecting data</p>
            </div>
          ) : insights.log_insights.map((insight, i) => (
            <motion.div key={i} className="card" style={{ padding: 16 }}
              initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                <span className={`badge badge-${insight.severity}`}>
                  {insight.severity?.toUpperCase()}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                  {insight.event_count} events · {insight.timespan_minutes}min window
                </span>
              </div>
              <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>
                {insight.title}
              </p>
              <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8, lineHeight: 1.55 }}>
                {insight.description}
              </p>
              {insight.affected_ips?.length > 0 && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {insight.affected_ips.slice(0, 5).map((ip, j) => (
                    <span key={j} style={{
                      fontSize: 12, fontFamily: 'var(--font-mono)', padding: '2px 8px', borderRadius: 6,
                      background: 'var(--accent-muted)', color: 'var(--accent)',
                      border: '1px solid var(--border-md)',
                    }}>
                      {ip}
                    </span>
                  ))}
                </div>
              )}
            </motion.div>
          ))}
        </div>
      )}

      {/* ── IDS alerts ── */}
      {tab === 'ids_alerts' && insights && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {!insights.ids_alerts?.length ? (
            <div className="empty-state" style={{ padding: '48px 0' }}>
              <div style={{ fontSize: 28 }}>🛡</div>
              <p style={{ color: 'var(--success)', fontWeight: 600 }}>Quiet</p>
              <p style={{ fontSize: 13, color: 'var(--text-3)' }}>No IDS alerts detected</p>
            </div>
          ) : insights.ids_alerts.map((alert, i) => (
            <motion.div key={i} className="card" style={{ padding: 16 }}
              initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)',
                  color: alert.threat_score >= 8 ? 'var(--danger)' : alert.threat_score >= 6 ? 'var(--warning)' : '#d29922',
                }}>
                  ⚡ {alert.attack_type?.replace(/_/g, ' ').toUpperCase()}
                </span>
                {alert.mitre_technique && (
                  <span style={{
                    fontSize: 11, padding: '2px 7px', borderRadius: 6, fontFamily: 'var(--font-mono)',
                    background: 'rgba(124,58,237,0.12)', color: '#a78bfa',
                    border: '1px solid rgba(124,58,237,0.2)',
                  }}>
                    MITRE {alert.mitre_technique}
                  </span>
                )}
                <span style={{ marginLeft: 'auto', fontSize: 13, fontWeight: 700, color: 'var(--danger)', fontFamily: 'var(--font-mono)' }}>
                  {alert.threat_score?.toFixed(1)}/10
                </span>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8, lineHeight: 1.55 }}>
                {alert.description?.slice(0, 180)}
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontWeight: 600 }}>
                  {alert.source_ip}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  {new Date(alert.timestamp).toLocaleString()}
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </motion.div>
  )
}
