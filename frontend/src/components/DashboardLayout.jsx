import React, { useState, useEffect, useCallback } from 'react'
import { Routes, Route, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useWebSocket } from '../hooks/useWebSocket'
import { useTheme } from '../App'
import Overview from './Overview'
import AlertsPanel from './AlertsPanel'
import AIInsights from './AIInsights'
import NetworkPanel from './NetworkPanel'
import BlockedIPs from './BlockedIPs'
import FIMPanel from './FIMPanel'
import VulnPanel from './VulnPanel'
import HardeningPanel from './HardeningPanel'
import HoneypotPanel from './HoneypotPanel'
import Settings from './Settings'

const NAV = [
  { path: '/',          label: 'Overview',       icon: <GridIcon />,    exact: true },
  { path: '/alerts',    label: 'Alerts',          icon: <BellIcon />,    badge: 'alerts' },
  { path: '/ai',        label: 'AI Insights',     icon: <BrainIcon /> },
  { path: '/network',   label: 'Network',         icon: <NetIcon /> },
  { path: '/fim',       label: 'File Integrity',  icon: <FileIcon /> },
  { path: '/vulns',     label: 'Vulnerabilities', icon: <BugIcon />,     badge: 'vulns' },
  { path: '/hardening', label: 'Hardening',       icon: <ShieldIcon /> },
  { path: '/honeypot',  label: 'Honeypot',        icon: <HoneyIcon /> },
  { path: '/blocked',   label: 'Blocked IPs',     icon: <BlockIcon /> },
  { path: '/settings',  label: 'Settings',        icon: <GearIcon /> },
]

export default function DashboardLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, toggle } = useTheme()
  const { lastMessage, status } = useWebSocket()
  const [live, setLive] = useState({})
  const [badges, setBadges] = useState({ alerts: 0, vulns: 0 })
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    if (!lastMessage) return
    if (lastMessage.type === 'live_update' || lastMessage.type === 'metrics_update') {
      setLive(m => ({ ...m, ...lastMessage.metrics, ...lastMessage.network, ...lastMessage.ai }))
    }
    if (lastMessage.type === 'ids_alert') {
      setBadges(b => ({ ...b, alerts: b.alerts + 1 }))
    }
  }, [lastMessage])

  const logout = () => { localStorage.clear(); navigate('/login', { replace: true }) }

  const currentPage = NAV.find(n => n.exact ? location.pathname === n.path : location.pathname.startsWith(n.path))?.label || ''

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg)' }}>

      {/* ── Sidebar ── */}
      <motion.aside
        animate={{ width: collapsed ? 56 : 220 }}
        transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
        style={{
          flexShrink: 0, display: 'flex', flexDirection: 'column',
          background: 'var(--bg-surface)', borderRight: '1px solid var(--border)',
          overflow: 'hidden', position: 'relative',
        }}
      >
        {/* Logo row */}
        <div style={{ padding: '16px 12px 12px', display: 'flex', alignItems: 'center', gap: 10,
          borderBottom: '1px solid var(--border)', minHeight: 56 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--accent-muted)',
            border: '1px solid var(--border-md)', display: 'flex', alignItems: 'center',
            justifyContent: 'center', flexShrink: 0 }}>
            <svg width="18" height="18" viewBox="0 0 40 40" fill="none">
              <path d="M20 3L5 9v10c0 9.4 6.4 18.2 15 20.6C29.6 37.2 36 28.4 36 19V9L20 3z"
                fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinejoin="round"/>
              <path d="M14 20l4 4 8-8" stroke="var(--accent)" strokeWidth="2.2"
                strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }} style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.01em' }}>
                  AI SBC Security
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>
                  v1.0 · Open Source
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '8px 6px', overflowY: 'auto', overflowX: 'hidden' }}>
          <div style={{ marginBottom: 4 }}>
            {NAV.map(item => (
              <NavLink key={item.path} to={item.path} end={item.exact} style={{ textDecoration: 'none' }}>
                {({ isActive }) => (
                  <div className={`nav-item ${isActive ? 'active' : ''}`}
                    style={{ marginBottom: 2, justifyContent: collapsed ? 'center' : 'flex-start' }}
                    title={collapsed ? item.label : undefined}>
                    <span style={{ flexShrink: 0, width: 18, height: 18,
                      color: isActive ? 'var(--accent)' : 'var(--text-3)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      {item.icon}
                    </span>
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                          transition={{ duration: 0.12 }} style={{ flex: 1, fontSize: 13, fontWeight: 500 }}>
                          {item.label}
                        </motion.span>
                      )}
                    </AnimatePresence>
                    {item.badge && badges[item.badge] > 0 && !collapsed && (
                      <span style={{
                        fontSize: 11, fontWeight: 700, padding: '1px 6px',
                        borderRadius: 99, background: 'var(--danger-muted)',
                        color: 'var(--danger)', minWidth: 20, textAlign: 'center',
                      }}>
                        {badges[item.badge] > 99 ? '99+' : badges[item.badge]}
                      </span>
                    )}
                  </div>
                )}
              </NavLink>
            ))}
          </div>
        </nav>

        {/* Bottom */}
        <div style={{ padding: '8px 6px', borderTop: '1px solid var(--border)' }}>
          {/* Connection status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', marginBottom: 2 }}
               title={collapsed ? (status === 'connected' ? 'Live' : 'Reconnecting') : undefined}>
            <span className={`dot ${status === 'connected' ? 'dot-green' : 'dot-yellow'}`} />
            <AnimatePresence>
              {!collapsed && (
                <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  {status === 'connected' ? 'Live' : 'Reconnecting…'}
                </motion.span>
              )}
            </AnimatePresence>
          </div>

          {/* Theme toggle */}
          <button onClick={toggle}
            className="nav-item" style={{ width: '100%', border: 'none', background: 'none', cursor: 'pointer',
              justifyContent: collapsed ? 'center' : 'flex-start' }}
            title={collapsed ? 'Toggle theme' : undefined}>
            <span style={{ fontSize: 16, flexShrink: 0, width: 18, textAlign: 'center' }}>
              {theme === 'dark' ? '☀' : '☾'}
            </span>
            <AnimatePresence>
              {!collapsed && (
                <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ fontSize: 13 }}>
                  {theme === 'dark' ? 'Light mode' : 'Dark mode'}
                </motion.span>
              )}
            </AnimatePresence>
          </button>

          {/* Logout */}
          <button onClick={logout}
            className="nav-item" style={{ width: '100%', border: 'none', background: 'none', cursor: 'pointer',
              color: 'var(--text-3)', justifyContent: collapsed ? 'center' : 'flex-start' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--danger)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-3)'}
            title={collapsed ? 'Sign out' : undefined}>
            <span style={{ fontSize: 15, flexShrink: 0, width: 18, textAlign: 'center' }}>↗</span>
            <AnimatePresence>
              {!collapsed && (
                <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ fontSize: 13 }}>
                  Sign out
                </motion.span>
              )}
            </AnimatePresence>
          </button>
        </div>

        {/* Collapse toggle */}
        <button onClick={() => setCollapsed(c => !c)}
          style={{
            position: 'absolute', bottom: 120, right: -11,
            width: 22, height: 22, borderRadius: '50%', border: '1px solid var(--border-md)',
            background: 'var(--bg-card)', cursor: 'pointer', display: 'flex',
            alignItems: 'center', justifyContent: 'center', zIndex: 10,
            color: 'var(--text-3)', fontSize: 11,
          }}>
          {collapsed ? '›' : '‹'}
        </button>
      </motion.aside>

      {/* ── Main ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>

        {/* Topbar */}
        <header style={{
          height: 52, flexShrink: 0, display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', padding: '0 24px',
          background: 'var(--bg-surface)', borderBottom: '1px solid var(--border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{currentPage}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {/* Live metrics */}
            <div style={{ display: 'flex', gap: 16 }}>
              <LiveChip label="CPU" value={`${(live.cpu_percent || 0).toFixed(0)}%`}
                high={live.cpu_percent > 80} />
              <LiveChip label="RAM" value={`${(live.ram_percent || 0).toFixed(0)}%`}
                high={live.ram_percent > 85} />
              {live.cpu_temp > 0 && (
                <LiveChip label="Temp" value={`${live.cpu_temp?.toFixed(0)}°C`}
                  high={live.cpu_temp > 75} />
              )}
            </div>

            {/* IDS alert indicator */}
            {live.critical_alerts > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px',
                borderRadius: 99, background: 'var(--danger-muted)',
                border: '1px solid rgba(248,81,73,0.25)', fontSize: 12, fontWeight: 600,
                color: 'var(--danger)',
              }}>
                <span className="dot dot-red" style={{ animation: 'pulse-dot 1s infinite' }} />
                {live.critical_alerts} critical
              </div>
            )}
          </div>
        </header>

        {/* Page */}
        <main style={{ flex: 1, overflow: 'hidden' }}>
          <AnimatePresence mode="wait">
            <motion.div key={location.pathname} style={{ height: '100%' }}
              initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>
              <div style={{ height: '100%', overflowY: 'auto', overflowX: 'hidden' }}>
                <Routes>
                  <Route path="/"          element={<Overview liveMetrics={live} lastMessage={lastMessage} />} />
                  <Route path="/alerts"    element={<AlertsPanel />} />
                  <Route path="/ai"        element={<AIInsights />} />
                  <Route path="/network"   element={<NetworkPanel liveMetrics={live} />} />
                  <Route path="/fim"       element={<FIMPanel />} />
                  <Route path="/vulns"     element={<VulnPanel />} />
                  <Route path="/hardening" element={<HardeningPanel />} />
                  <Route path="/honeypot"  element={<HoneypotPanel />} />
                  <Route path="/blocked"   element={<BlockedIPs />} />
                  <Route path="/settings"  element={<Settings />} />
                </Routes>
              </div>
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}

function LiveChip({ label, value, high }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)',
        color: high ? 'var(--danger)' : 'var(--text-1)' }}>{value}</span>
    </div>
  )
}

// ── Icons (minimal SVG) ───────────────────────────────────────────────────────
const ico = (d, vb = '0 0 18 18') => () => (
  <svg width="16" height="16" viewBox={vb} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    {d}
  </svg>
)
function GridIcon()   { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="2" y="2" width="6" height="6" rx="1"/><rect x="10" y="2" width="6" height="6" rx="1"/><rect x="2" y="10" width="6" height="6" rx="1"/><rect x="10" y="10" width="6" height="6" rx="1"/></svg> }
function BellIcon()   { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M9 2a5 5 0 0 1 5 5v3l1.5 2H2.5L4 10V7a5 5 0 0 1 5-5z"/><path d="M7.5 14.5a1.5 1.5 0 0 0 3 0"/></svg> }
function BrainIcon()  { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M6 9a3 3 0 0 1 6 0v1a3 3 0 0 1-6 0V9z"/><path d="M6 9C6 6.8 4.5 5 3 5s-2 1.5-1 3c-1 1.5 0 3 1.5 3"/><path d="M12 9c0-2.2 1.5-4 3-4s2 1.5 1 3c1 1.5 0 3-1.5 3"/><line x1="9" y1="12" x2="9" y2="16"/></svg> }
function NetIcon()    { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><circle cx="9" cy="9" r="7"/><line x1="2" y1="9" x2="16" y2="9"/><path d="M9 2a9 9 0 0 1 3 7 9 9 0 0 1-3 7A9 9 0 0 1 6 9a9 9 0 0 1 3-7z"/></svg> }
function FileIcon()   { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M10 2H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7l-5-5z"/><polyline points="10 2 10 7 15 7"/><line x1="6" y1="11" x2="12" y2="11"/><line x1="6" y1="14" x2="12" y2="14"/></svg> }
function BugIcon()    { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M9 14A5 5 0 0 1 4 9V7a5 5 0 0 1 10 0v2a5 5 0 0 1-5 5z"/><path d="M9 14v3M4 9H1M14 9h3M4 7l-2-2M14 7l2-2"/><path d="M6 5a3 3 0 0 1 6 0"/></svg> }
function ShieldIcon() { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M9 2L2 5v5c0 4.4 3 8.2 7 9.2C13 18.2 16 14.4 16 10V5L9 2z"/><polyline points="6.5 9.5 8.5 11.5 12 8"/></svg> }
function BlockIcon()  { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><circle cx="9" cy="9" r="7"/><line x1="4" y1="4" x2="14" y2="14"/></svg> }
function HoneyIcon()  { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M9 2L3 5.5v7L9 16l6-3.5v-7L9 2z"/><path d="M9 2v14M3 5.5l6 3.5 6-3.5"/></svg> }
function GearIcon()   { return <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><circle cx="9" cy="9" r="2.5"/><path d="M9 1v2M9 15v2M1 9h2M15 9h2M3.2 3.2l1.4 1.4M13.4 13.4l1.4 1.4M3.2 14.8l1.4-1.4M13.4 4.6l1.4-1.4"/></svg> }
