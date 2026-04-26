import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar } from 'recharts'
import { dashboardAPI } from '../utils/api'

export default function AIInsights() {
  const [forecast, setForecast] = useState(null)
  const [insights, setInsights] = useState(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('forecast')

  useEffect(() => {
    Promise.all([
      dashboardAPI.forecast(),
      dashboardAPI.insights(),
    ]).then(([f, i]) => {
      setForecast(f.data)
      setInsights(i.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="inline-block w-12 h-12 border-2 rounded-full animate-spin mb-4"
             style={{ borderColor: 'rgba(0,255,179,0.2)', borderTopColor: '#00ffb3' }} />
        <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>AI MODELS PROCESSING...</p>
      </div>
    </div>
  )

  const riskColor = (r) => ({ critical: '#ff3d5a', high: '#ff6b35', medium: '#ffd700', low: '#00ffb3' }[r] || '#00ffb3')

  return (
    <motion.div className="p-6 space-y-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div>
        <h1 className="font-display text-lg tracking-widest" style={{ color: 'var(--accent-cyan)' }}>AI INSIGHTS</h1>
        <p className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Machine learning analysis & predictive threat forecasting
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl w-fit" style={{ background: 'rgba(0,0,0,0.3)' }}>
        {['forecast', 'log_insights', 'ids_alerts'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className="px-4 py-1.5 rounded-lg text-xs font-mono tracking-wide transition-all"
            style={tab === t ? { background: 'rgba(0,255,179,0.12)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,255,179,0.2)' } : { color: 'var(--text-muted)' }}>
            {t.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      {/* ── Forecast tab ── */}
      {tab === 'forecast' && forecast && (
        <div className="space-y-4">
          {/* Summary card */}
          <motion.div className="card-glow rounded-2xl p-5" style={{ background: 'var(--bg-card)' }}
                       initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="text-xs font-mono tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>
                  24-HOUR THREAT FORECAST
                </p>
                <div className="flex items-center gap-3">
                  <span className="font-display text-2xl font-bold"
                        style={{ color: riskColor(forecast.overall_risk) }}>
                    {forecast.overall_risk?.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded"
                        style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                    {forecast.trend?.toUpperCase()} TREND
                  </span>
                </div>
                <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
                  {forecast.summary}
                </p>
              </div>
              <div className="text-right flex-shrink-0 ml-4">
                <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>PEAK AT</p>
                <p className="font-display text-xl" style={{ color: '#ff6b35' }}>
                  {forecast.peak_threat_hour?.toString().padStart(2,'0')}:00
                </p>
                <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  score: {(forecast.peak_threat_score * 100)?.toFixed(0)}%
                </p>
              </div>
            </div>

            {/* Forecast chart */}
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={forecast.hourly_predictions}>
                <defs>
                  <linearGradient id="forecastGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,200,150,0.06)" />
                <XAxis dataKey="hour" tickFormatter={h => `${h.toString().padStart(2,'0')}h`}
                       tick={{ fontSize: 9, fill: '#4a6278' }} tickLine={false} />
                <YAxis domain={[0, 1]} tickFormatter={v => `${(v*100).toFixed(0)}%`}
                       tick={{ fontSize: 9, fill: '#4a6278' }} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#0d1a2a', border: '1px solid rgba(124,58,237,0.3)', borderRadius: 8, fontSize: 11 }}
                  formatter={(v, n) => [`${(v*100).toFixed(1)}%`, 'Threat Score']} />
                <Area type="monotone" dataKey="predicted_score" stroke="#7c3aed" fill="url(#forecastGrad)"
                      strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </motion.div>

          {/* Recommendations */}
          <motion.div className="card-glow rounded-2xl p-5" style={{ background: 'var(--bg-card)' }}
                       initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
            <h3 className="text-xs font-mono tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              AI RECOMMENDATIONS
            </h3>
            <div className="space-y-2">
              {(forecast.recommendations || []).map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <span style={{ color: 'var(--accent-cyan)' }}>›</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{rec}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      )}

      {/* ── Log insights ── */}
      {tab === 'log_insights' && insights && (
        <div className="space-y-3">
          {insights.log_insights?.length === 0 ? (
            <div className="text-center py-12">
              <p className="font-display text-xl mb-2" style={{ color: 'var(--accent-cyan)' }}>CLEAN</p>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                No log correlation insights yet — collecting data
              </p>
            </div>
          ) : insights.log_insights?.map((insight, i) => (
            <motion.div key={i}
              initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              className="card-glow rounded-xl p-4" style={{ background: 'var(--bg-card)' }}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`badge-${insight.severity} text-xs px-2 py-0.5 rounded font-mono`}>
                  {insight.severity?.toUpperCase()}
                </span>
                <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  {insight.event_count} events · {insight.timespan_minutes}min window
                </span>
              </div>
              <p className="font-mono text-sm mb-1" style={{ color: 'var(--text-primary)' }}>
                {insight.title}
              </p>
              <p className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>
                {insight.description}
              </p>
              {insight.affected_ips?.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {insight.affected_ips.slice(0,5).map((ip, j) => (
                    <span key={j} className="text-xs font-mono px-1.5 py-0.5 rounded"
                          style={{ background: 'rgba(0,255,179,0.06)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,255,179,0.15)' }}>
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
        <div className="space-y-3">
          {insights.ids_alerts?.length === 0 ? (
            <div className="text-center py-12">
              <p className="font-display text-xl mb-2" style={{ color: 'var(--accent-cyan)' }}>QUIET</p>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>No IDS alerts detected</p>
            </div>
          ) : insights.ids_alerts?.map((alert, i) => (
            <motion.div key={i}
              initial={{ opacity: 0, x: -15 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
              className="card-glow rounded-xl p-4" style={{ background: 'var(--bg-card)' }}>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-mono font-bold"
                      style={{ color: alert.threat_score >= 8 ? '#ff3d5a' : alert.threat_score >= 6 ? '#ff6b35' : '#ffd700' }}>
                  ⚡ {alert.attack_type?.replace(/_/g, ' ').toUpperCase()}
                </span>
                {alert.mitre_technique && (
                  <span className="text-xs font-mono px-1.5 py-0.5 rounded"
                        style={{ background: 'rgba(124,58,237,0.15)', color: '#a78bfa', border: '1px solid rgba(124,58,237,0.2)' }}>
                    MITRE {alert.mitre_technique}
                  </span>
                )}
                <span className="ml-auto text-xs font-mono font-bold"
                      style={{ color: '#ff3d5a' }}>
                  {alert.threat_score?.toFixed(1)}/10
                </span>
              </div>
              <p className="text-xs font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>
                {alert.description?.slice(0, 180)}
              </p>
              <div className="flex items-center gap-3 mt-1">
                <span className="text-xs font-mono" style={{ color: 'var(--accent-cyan)' }}>
                  {alert.source_ip}
                </span>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
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
