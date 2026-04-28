import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { authAPI, dashboardAPI } from '../utils/api'
import toast from 'react-hot-toast'

const stagger = (i) => ({ initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { delay: i * 0.04, duration: 0.22 } })

const TABS = [
  { id: 'security', label: 'Security' },
  { id: 'account', label: 'Account' },
  { id: 'ai', label: 'AI & Privacy' },
]

export default function Settings() {
  const [user, setUser]         = useState(null)
  const [tab, setTab]           = useState('security')
  const [qrCode, setQrCode]     = useState(null)
  const [totpToken, setTotpToken] = useState('')
  const [totpPhase, setTotpPhase] = useState('idle')
  const [pwForm, setPwForm]     = useState({ current: '', new: '', confirm: '' })
  const [loading, setLoading]   = useState(false)
  const [flStatus, setFlStatus] = useState(null)
  const [flLoading, setFlLoading] = useState(false)

  useEffect(() => {
    authAPI.me().then(r => setUser(r.data)).catch(() => {})
    loadFLStatus()
  }, [])

  const loadFLStatus = async () => {
    try {
      const { data } = await dashboardAPI.get('/federated/status')
      setFlStatus(data)
    } catch {}
  }

  // ── 2FA handlers ──────────────────────────────────────────────────────────
  const startTOTP = async () => {
    setLoading(true)
    try {
      const { data } = await authAPI.setupTOTP()
      setQrCode(data); setTotpPhase('scanning')
    } catch { toast.error('Failed to start 2FA setup') }
    setLoading(false)
  }

  const verifyTOTP = async () => {
    setLoading(true)
    try {
      await authAPI.verifyTOTP(totpToken)
      toast.success('2FA enabled')
      setTotpPhase('idle'); setQrCode(null); setTotpToken('')
      const { data } = await authAPI.me(); setUser(data)
    } catch { toast.error('Invalid code') }
    setLoading(false)
  }

  const disableTOTP = async () => {
    if (!totpToken) { toast.error('Enter your current 2FA code to disable'); return }
    setLoading(true)
    try {
      await authAPI.disableTOTP(totpToken)
      toast.success('2FA disabled'); setTotpToken('')
      const { data } = await authAPI.me(); setUser(data)
    } catch { toast.error('Invalid code') }
    setLoading(false)
  }

  const changePassword = async (e) => {
    e.preventDefault()
    if (pwForm.new !== pwForm.confirm) { toast.error('Passwords do not match'); return }
    if (pwForm.new.length < 8) { toast.error('Password must be at least 8 characters'); return }
    setLoading(true)
    try {
      await authAPI.changePassword({ current_password: pwForm.current, new_password: pwForm.new })
      toast.success('Password updated'); setPwForm({ current: '', new: '', confirm: '' })
    } catch (err) { toast.error(err.response?.data?.detail || 'Failed to update password') }
    setLoading(false)
  }

  // ── Federated Learning ────────────────────────────────────────────────────
  const toggleFL = async (enabled) => {
    setFlLoading(true)
    try {
      await dashboardAPI.post('/federated/enable', { enabled })
      toast.success(enabled ? 'Federated learning enabled' : 'Federated learning disabled')
      await loadFLStatus()
    } catch { toast.error('Failed to update setting') }
    setFlLoading(false)
  }

  return (
    <div style={{ padding: 24, maxWidth: 680 }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Settings</h2>
        <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 3 }}>Account security and system configuration</p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, padding: 4, background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)', width: 'fit-content', border: '1px solid var(--border)' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{
              padding: '6px 16px', borderRadius: 'var(--radius-sm)',
              fontSize: 13, fontWeight: 500, cursor: 'pointer',
              border: 'none', transition: 'all 0.15s',
              background: tab === t.id ? 'var(--bg-card)' : 'transparent',
              color: tab === t.id ? 'var(--text-1)' : 'var(--text-3)',
              boxShadow: tab === t.id ? 'var(--shadow-sm)' : 'none',
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Security Tab ─────────────────────────────────────────────── */}
      {tab === 'security' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* 2FA */}
          <motion.div {...stagger(0)} className="card" style={{ padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>
                  Two-Factor Authentication
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  TOTP via authenticator app (Google Authenticator, Authy, 1Password, etc.)
                </div>
              </div>
              <span className={`badge badge-${user?.totp_enabled ? 'info' : 'high'}`} style={{ marginTop: 2 }}>
                {user?.totp_enabled ? '✓ Enabled' : '✗ Disabled'}
              </span>
            </div>

            {/* QR setup flow */}
            {totpPhase === 'scanning' && qrCode && (
              <div style={{
                padding: 20, borderRadius: 'var(--radius-md)', marginBottom: 16,
                background: 'var(--bg-surface)', border: '1px solid var(--border)',
                textAlign: 'center',
              }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16 }}>
                  Scan this QR code with your authenticator app
                </p>
                <div style={{ display: 'inline-block', padding: 10, background: '#fff', borderRadius: 8, lineHeight: 0, marginBottom: 16 }}>
                  <img src={`data:image/png;base64,${qrCode.qr_code_b64}`} alt="QR Code" style={{ width: 140, height: 140 }} />
                </div>
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>Manual key</div>
                  <div className="code-block" style={{ textAlign: 'center', letterSpacing: '0.12em', color: 'var(--accent)', fontSize: 13 }}>
                    {qrCode.secret}
                  </div>
                </div>
                <input
                  value={totpToken}
                  onChange={e => setTotpToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000 000" maxLength={6} autoFocus
                  className="input font-mono"
                  style={{ textAlign: 'center', letterSpacing: '0.4em', fontSize: 22, fontWeight: 700, padding: '12px', maxWidth: 180, display: 'block', margin: '0 auto 12px' }}
                />
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                  <button onClick={verifyTOTP} disabled={loading || totpToken.length !== 6}
                    className="btn btn-primary">
                    {loading ? 'Verifying…' : 'Enable 2FA'}
                  </button>
                  <button onClick={() => { setTotpPhase('idle'); setQrCode(null) }}
                    className="btn btn-ghost">Cancel</button>
                </div>
              </div>
            )}

            {totpPhase === 'idle' && (
              user?.totp_enabled ? (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input value={totpToken}
                    onChange={e => setTotpToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="Disable code" maxLength={6}
                    className="input font-mono"
                    style={{ width: 160, flex: '0 0 160px', letterSpacing: '0.2em', textAlign: 'center' }} />
                  <button onClick={disableTOTP} disabled={loading} className="btn btn-danger" style={{ flexShrink: 0 }}>
                    {loading ? 'Disabling…' : 'Disable 2FA'}
                  </button>
                </div>
              ) : (
                <button onClick={startTOTP} disabled={loading} className="btn btn-primary">
                  {loading ? 'Setting up…' : 'Set up 2FA'}
                </button>
              )
            )}
          </motion.div>

          {/* Change password */}
          <motion.div {...stagger(1)} className="card" style={{ padding: 24 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', marginBottom: 16 }}>
              Change Password
            </div>
            <form onSubmit={changePassword} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[
                { key: 'current', label: 'Current password', placeholder: '••••••••' },
                { key: 'new', label: 'New password', placeholder: 'Minimum 8 characters' },
                { key: 'confirm', label: 'Confirm new password', placeholder: '••••••••' },
              ].map(field => (
                <div key={field.key}>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>
                    {field.label}
                  </label>
                  <input type="password" value={pwForm[field.key]}
                    onChange={e => setPwForm(f => ({ ...f, [field.key]: e.target.value }))}
                    placeholder={field.placeholder} required
                    className="input" />
                </div>
              ))}
              <div>
                <button type="submit" disabled={loading} className="btn btn-primary">
                  {loading ? 'Updating…' : 'Update password'}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}

      {/* ── Account Tab ──────────────────────────────────────────────── */}
      {tab === 'account' && user && (
        <motion.div {...stagger(0)} className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', marginBottom: 20 }}>
            Account Details
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {[
              { label: 'Username', value: user.username },
              { label: 'Email', value: user.email },
              { label: 'Role', value: user.is_admin ? 'Administrator' : 'User' },
              { label: '2FA', value: user.totp_enabled ? 'Enabled' : 'Disabled' },
              { label: 'Account created', value: new Date(user.created_at).toLocaleString() },
              { label: 'Last login', value: user.last_login ? new Date(user.last_login).toLocaleString() : 'N/A' },
            ].map((item, i) => (
              <div key={item.label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '12px 0',
                borderBottom: i < 5 ? '1px solid var(--border)' : 'none',
              }}>
                <span style={{ fontSize: 13, color: 'var(--text-3)' }}>{item.label}</span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', fontFamily: 'var(--font-mono)' }}>{item.value}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* ── AI & Privacy Tab ─────────────────────────────────────────── */}
      {tab === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Federated Learning */}
          <motion.div {...stagger(0)} className="card" style={{ padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>
                  Federated Learning
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.6 }}>
                  Help improve the community AI model. <strong>Opt-in only.</strong>
                </div>
              </div>
              <span className={`badge badge-${flStatus?.enabled ? 'info' : 'low'}`}>
                {flStatus?.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>

            {/* Privacy explanation */}
            <div style={{
              padding: '12px 14px', borderRadius: 'var(--radius-sm)', marginBottom: 16,
              background: 'var(--accent)11', border: '1px solid var(--accent)33',
            }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.7 }}>
                <strong style={{ color: 'var(--accent)' }}>What is shared:</strong> Only model weight tensors with Gaussian differential privacy noise applied.
                <br />
                <strong style={{ color: 'var(--success)' }}>Never shared:</strong> Raw logs, IP addresses, usernames, hostnames, system data, or any identifiable information.
                <br />
                <strong style={{ color: 'var(--text-2)' }}>How it works:</strong> Local model weights are privatized with DP noise, then uploaded to the aggregation server which runs FedAvg to improve the global model. Your data never leaves your system.
              </div>
            </div>

            {/* FL Status */}
            {flStatus && flStatus.enabled && (() => {
              // Pick the dominant status banner: failed > warming-up > waiting > ok
              const upStat = flStatus.last_upload_status
              const downStat = flStatus.last_download_status
              const isNoServer = (s) => s === 'no_server_configured'
              const noServerConfigured = isNoServer(upStat) || isNoServer(downStat)
              const isFailed = (s) => s === 'server_unreachable' || s === 'deserialization_failed'
                                       || s === 'apply_failed' || s?.startsWith('server_error_')
              const anyFailed = !noServerConfigured && (isFailed(upStat) || isFailed(downStat))
              const anyWarming = upStat === 'model_not_trained' || downStat === 'model_not_trained'
              const allWaiting = (!upStat || upStat === 'never_attempted')
                                  && (!downStat || downStat === 'never_attempted')

              const upMin = Math.round((flStatus.upload_interval_seconds || 86400) / 60)
              const downMin = Math.round((flStatus.download_interval_seconds || 43200) / 60)

              const banner = noServerConfigured
                ? { tone: 'warning', title: 'No aggregation server configured',
                    body: 'Set FEDERATED_SERVER_URL in /etc/ai-sbc-security/env to point to your own server, or deploy the bundled federated-server.' }
                : anyFailed
                ? { tone: 'danger', title: 'Sync failing',
                    body: flStatus.last_upload_message || flStatus.last_download_message }
                : anyWarming
                ? { tone: 'warning', title: 'AI model warming up',
                    body: 'First federated sync happens after the local anomaly detector has trained on enough data — typically ~40 minutes after install.' }
                : allWaiting
                ? { tone: 'info', title: 'Waiting for first sync',
                    body: `Uploads scheduled every ${upMin} min, downloads every ${downMin} min. Set FL_UPLOAD_INTERVAL in /etc/ai-sbc-security/env to override during testing.` }
                : null

              const toneColor = banner && {
                danger: 'var(--danger)', warning: 'var(--warning)', info: 'var(--accent)',
              }[banner.tone]

              return (
                <>
                  {banner && (
                    <div style={{
                      padding: '10px 14px', borderRadius: 'var(--radius-sm)', marginBottom: 12,
                      background: `${toneColor}11`,
                      border: `1px solid ${toneColor}55`,
                      display: 'flex', alignItems: 'flex-start', gap: 10,
                    }}>
                      <span style={{ fontSize: 14, color: toneColor, flexShrink: 0, marginTop: 1 }}>
                        {banner.tone === 'danger' ? '⚠' : banner.tone === 'warning' ? '◐' : 'ⓘ'}
                      </span>
                      <div style={{ fontSize: 12, lineHeight: 1.55 }}>
                        <div style={{ fontWeight: 700, color: toneColor, marginBottom: 2 }}>{banner.title}</div>
                        <div style={{ color: 'var(--text-2)' }}>{banner.body}</div>
                        {banner.tone === 'danger' && flStatus.server_url && (
                          <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                            Server: {flStatus.server_url}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                    {[
                      { label: 'Node ID', value: flStatus.node_id_prefix },
                      { label: 'Total Uploads', value: flStatus.total_uploads },
                      { label: 'Total Downloads', value: flStatus.total_downloads },
                      { label: 'Privacy Budget (ε)', value: flStatus.privacy_budget_used_epsilon?.toFixed(6) || '0' },
                      { label: 'Last Upload', value: flStatus.last_upload_iso ? new Date(flStatus.last_upload_iso).toLocaleString() : 'Never' },
                      { label: 'Last Download', value: flStatus.last_download_iso ? new Date(flStatus.last_download_iso).toLocaleString() : 'Never' },
                      { label: 'Last Upload Attempt',
                        value: flStatus.last_upload_attempt_iso
                          ? `${new Date(flStatus.last_upload_attempt_iso).toLocaleString()} — ${flStatus.last_upload_message}`
                          : flStatus.last_upload_message },
                      { label: 'Last Download Attempt',
                        value: flStatus.last_download_attempt_iso
                          ? `${new Date(flStatus.last_download_attempt_iso).toLocaleString()} — ${flStatus.last_download_message}`
                          : flStatus.last_download_message },
                    ].map(item => (
                      <div key={item.label} style={{
                        padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                        background: 'var(--bg-surface)', border: '1px solid var(--border)',
                      }}>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 3 }}>{item.label}</div>
                        <div style={{ fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--text-1)', wordBreak: 'break-word' }}>{item.value}</div>
                      </div>
                    ))}
                  </div>
                </>
              )
            })()}

            <div style={{ display: 'flex', gap: 8 }}>
              {!flStatus?.enabled ? (
                <button onClick={() => toggleFL(true)} disabled={flLoading} className="btn btn-primary">
                  {flLoading ? 'Enabling…' : 'Enable federated learning'}
                </button>
              ) : (
                <button onClick={() => toggleFL(false)} disabled={flLoading} className="btn btn-ghost"
                  style={{ color: 'var(--danger)', borderColor: 'var(--danger)' }}>
                  {flLoading ? 'Disabling…' : 'Disable'}
                </button>
              )}
            </div>
          </motion.div>

          {/* Telemetry notice */}
          <motion.div {...stagger(1)} className="card" style={{ padding: 24 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', marginBottom: 12 }}>
              Privacy Policy
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.8 }}>
              AI SBC Security is designed with privacy as a core principle:
              <ul style={{ paddingLeft: 16, margin: '8px 0', display: 'flex', flexDirection: 'column', gap: 4 }}>
                <li>All monitoring data stays on your device</li>
                <li>No analytics, telemetry, or crash reports without explicit consent</li>
                <li>Federated learning is entirely opt-in and uses differential privacy</li>
                <li>Open source — every line of code is auditable</li>
                <li>No accounts, no cloud dependency for core functionality</li>
              </ul>
              <a href="https://github.com/fahimrahmanbooom/ai-sbc-security" target="_blank" rel="noopener noreferrer"
                style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                View source on GitHub →
              </a>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
