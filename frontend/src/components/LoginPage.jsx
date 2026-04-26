import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import toast from 'react-hot-toast'
import { authAPI } from '../utils/api'
import { useTheme } from '../App'

// Shield SVG icon
function ShieldIcon({ size = 40 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <path d="M20 3L5 9v10c0 9.4 6.4 18.2 15 20.6C29.6 37.2 36 28.4 36 19V9L20 3z"
            fill="var(--accent-muted)" stroke="var(--accent)" strokeWidth="1.5"
            strokeLinejoin="round"/>
      <path d="M14 20l4 4 8-8" stroke="var(--accent)" strokeWidth="2"
            strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

export default function LoginPage() {
  const navigate = useNavigate()
  const { theme, toggle } = useTheme()
  const [phase, setPhase] = useState('login') // login | totp | setup_totp
  const [loading, setLoading] = useState(false)
  const [isRegister, setIsRegister] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', email: '', totp: '' })
  const [qrCode, setQrCode] = useState(null)
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (localStorage.getItem('access_token')) navigate('/', { replace: true })
  }, [])

  const showError = (err) => {
    const detail = err?.response?.data?.detail
    const msg = Array.isArray(detail)
      ? detail.map(d => String(d.msg || d).replace('Value error, ', '')).join(' · ')
      : (typeof detail === 'string' ? detail : 'Something went wrong')
    setError(msg)
    setLoading(false)
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const payload = { username: form.username, password: form.password }
      if (phase === 'totp') payload.totp_token = form.totp
      const { data } = await authAPI.login(payload)
      if (data.requires_totp && !form.totp) { setPhase('totp'); setLoading(false); return }
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      if (data.totp_setup_required) {
        setPhase('setup_totp')
        const { data: totpData } = await authAPI.setupTOTP()
        setQrCode(totpData); setLoading(false); return
      }
      navigate('/', { replace: true })
    } catch (err) {
      showError(err)
    }
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await authAPI.register({ username: form.username, email: form.email, password: form.password })
      setError('')
      setIsRegister(false)
      setLoading(false)
    } catch (err) {
      showError(err)
    }
  }

  const handleTOTPVerify = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await authAPI.verifyTOTP(form.totp)
      toast.success('Two-factor authentication enabled')
      navigate('/', { replace: true })
    } catch {
      toast.error('Invalid code — please try again')
      setLoading(false)
    }
  }

  const f = (k) => (v) => setForm(p => ({ ...p, [k]: v }))

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg)', position: 'relative',
    }}>
      {/* Subtle grid background */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, opacity: theme === 'dark' ? 0.4 : 0.25,
        backgroundImage: `
          linear-gradient(var(--border) 1px, transparent 1px),
          linear-gradient(90deg, var(--border) 1px, transparent 1px)`,
        backgroundSize: '40px 40px',
      }} />

      {/* Accent glow */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 600, height: 300, borderRadius: '50%', zIndex: 0,
        background: 'radial-gradient(ellipse, var(--accent-muted) 0%, transparent 70%)',
        filter: 'blur(40px)', pointerEvents: 'none',
      }} />

      {/* Theme toggle */}
      <button onClick={toggle}
        style={{
          position: 'fixed', top: 20, right: 20, zIndex: 10,
          background: 'var(--bg-card)', border: '1px solid var(--border-md)',
          borderRadius: 'var(--radius-md)', padding: '7px 10px',
          color: 'var(--text-2)', cursor: 'pointer', fontSize: 16,
        }}>
        {theme === 'dark' ? '☀' : '☾'}
      </button>

      <AnimatePresence mode="wait">
        <motion.div key={phase + String(isRegister)}
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.25 }}
          style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: 400, padding: '0 16px' }}
        >
          {/* Logo */}
          <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              width: 64, height: 64, borderRadius: 16,
              background: 'var(--bg-card)', border: '1px solid var(--border-md)',
              marginBottom: 16, boxShadow: 'var(--shadow-md)' }}>
              <ShieldIcon size={36} />
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.02em' }}>
              AI SBC Security
            </h1>
            <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              {phase === 'setup_totp' ? 'Secure your account with 2FA' :
               phase === 'totp' ? 'Two-factor verification' :
               isRegister ? 'Create your account' : 'Sign in to your dashboard'}
            </p>
          </div>

          {/* Card */}
          <div className="card" style={{ padding: 28 }}>

            {/* ── 2FA Setup ── */}
            {phase === 'setup_totp' && qrCode && (
              <form onSubmit={handleTOTPVerify}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 20, lineHeight: 1.6 }}>
                  Scan this QR code with Google Authenticator, Authy, or any TOTP app.
                </p>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
                  <div style={{ padding: 10, background: '#fff', borderRadius: 10, lineHeight: 0 }}>
                    <img src={`data:image/png;base64,${qrCode.qr_code_b64}`} alt="2FA QR" style={{ width: 150, height: 150 }} />
                  </div>
                </div>
                <div style={{ marginBottom: 20 }}>
                  <p style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6, textAlign: 'center' }}>Manual entry key</p>
                  <div className="code-block" style={{ textAlign: 'center', letterSpacing: '0.15em', color: 'var(--accent)' }}>
                    {qrCode.secret}
                  </div>
                </div>
                <OTPField value={form.totp} onChange={f('totp')} />
                <SubmitBtn loading={loading} label="Enable two-factor auth" />
              </form>
            )}

            {/* ── TOTP verify ── */}
            {phase === 'totp' && (
              <form onSubmit={handleLogin}>
                <div style={{ textAlign: 'center', marginBottom: 24 }}>
                  <div style={{ fontSize: 32, marginBottom: 8 }}>🔐</div>
                  <p style={{ fontSize: 13, color: 'var(--text-2)' }}>
                    Enter the 6-digit code from your authenticator app
                  </p>
                </div>
                <OTPField value={form.totp} onChange={f('totp')} />
                <SubmitBtn loading={loading} label="Verify" />
                <button type="button" onClick={() => setPhase('login')}
                  style={{ display: 'block', width: '100%', textAlign: 'center', marginTop: 12,
                    fontSize: 13, color: 'var(--text-3)', cursor: 'pointer',
                    background: 'none', border: 'none' }}>
                  ← Back to sign in
                </button>
              </form>
            )}

            {/* ── Login / Register ── */}
            {phase === 'login' && (
              <form onSubmit={isRegister ? handleRegister : handleLogin}>
                <Field label="Username" value={form.username} onChange={f('username')}
                  placeholder="your-username" autoFocus />
                {isRegister && (
                  <Field label="Email address" value={form.email} onChange={f('email')}
                    placeholder="you@example.com" type="email" />
                )}
                <Field label="Password" value={form.password} onChange={f('password')}
                  placeholder="••••••••" type={showPw ? 'text' : 'password'}
                  suffix={
                    <button type="button" onClick={() => setShowPw(s => !s)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer',
                        color: 'var(--text-3)', fontSize: 13, padding: '0 4px' }}>
                      {showPw ? 'Hide' : 'Show'}
                    </button>
                  } />
                {isRegister && (
                  <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: -8, marginBottom: 16 }}>
                    Minimum 8 characters
                  </p>
                )}
                {error && (
                  <div style={{
                    padding: '10px 14px', borderRadius: 8, marginBottom: 14,
                    background: 'rgba(255,80,80,0.1)', border: '1px solid rgba(255,80,80,0.3)',
                    fontSize: 13, color: '#ff6b6b', lineHeight: 1.4,
                  }}>
                    {error}
                  </div>
                )}
                <SubmitBtn loading={loading} label={isRegister ? 'Create account' : 'Sign in'} />

                <div style={{ marginTop: 16, textAlign: 'center' }}>
                  <button type="button" onClick={() => setIsRegister(!isRegister)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer',
                      fontSize: 13, color: 'var(--accent)' }}>
                    {isRegister ? 'Already have an account? Sign in' : "New installation? Create account"}
                  </button>
                </div>
              </form>
            )}
          </div>

          <p style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-3)', marginTop: 20 }}>
            AI SBC Security · Open Source ·{' '}
            <a href="https://github.com/fahimrahmanbooom/ai-sbc-security"
               style={{ color: 'var(--accent)' }} target="_blank" rel="noopener noreferrer">
              GitHub
            </a>
          </p>
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

function Field({ label, value, onChange, placeholder, type = 'text', autoFocus, suffix }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', fontSize: 12, fontWeight: 600,
        color: 'var(--text-2)', marginBottom: 6 }}>{label}</label>
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        <input type={type} value={value} onChange={e => onChange(e.target.value)}
          placeholder={placeholder} required autoFocus={autoFocus}
          className="input" style={{ paddingRight: suffix ? 60 : 12 }} />
        {suffix && (
          <div style={{ position: 'absolute', right: 8 }}>{suffix}</div>
        )}
      </div>
    </div>
  )
}

function OTPField({ value, onChange }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <input type="text" value={value}
        onChange={e => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))}
        placeholder="000 000" maxLength={6} required autoFocus
        className="input font-mono"
        style={{
          textAlign: 'center', letterSpacing: '0.4em', fontSize: 24, fontWeight: 700,
          padding: '14px 12px',
        }} />
    </div>
  )
}

function SubmitBtn({ loading, label }) {
  return (
    <button type="submit" disabled={loading}
      className="btn btn-primary btn-lg"
      style={{ width: '100%', marginTop: 4 }}>
      {loading ? (
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
          <span style={{
            width: 15, height: 15, border: '2px solid rgba(255,255,255,0.3)',
            borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite',
          }} />
          Please wait...
        </span>
      ) : label}
    </button>
  )
}

// Inject spin keyframe
const style = document.createElement('style')
style.textContent = '@keyframes spin { to { transform: rotate(360deg) } }'
document.head.appendChild(style)
