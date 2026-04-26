import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { authAPI } from '../utils/api'
import { useTheme } from '../App'

export default function LoginPage() {
  const navigate = useNavigate()
  const { theme, toggle } = useTheme()

  const [mode, setMode] = useState('login')   // login | register | totp | setup2fa
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [qrData, setQrData] = useState(null)

  useEffect(() => {
    if (localStorage.getItem('access_token')) navigate('/', { replace: true })
  }, [])

  const apiError = (err) => {
    const d = err?.response?.data?.detail
    if (Array.isArray(d)) return d.map(x => String(x.msg || x).replace('Value error, ', '')).join(' · ')
    if (typeof d === 'string') return d
    return 'Something went wrong. Please try again.'
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    if (!username || !email || !password) { setError('All fields are required'); return }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return }
    setError(''); setSuccess(''); setLoading(true)
    try {
      await authAPI.register({ username, email, password })
      setSuccess('Account created! Sign in below.')
      setPassword('')
      setMode('login')
    } catch (err) {
      setError(apiError(err))
    } finally {
      setLoading(false)
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError(''); setSuccess(''); setLoading(true)
    try {
      const payload = { username, password }
      if (mode === 'totp') payload.totp_token = totpCode
      const { data } = await authAPI.login(payload)
      if (data.requires_totp && !totpCode) {
        setMode('totp'); setLoading(false); return
      }
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      if (data.totp_setup_required) {
        const { data: t } = await authAPI.setupTOTP()
        setQrData(t); setMode('setup2fa'); setLoading(false); return
      }
      navigate('/', { replace: true })
    } catch (err) {
      setError(apiError(err))
      setLoading(false)
    }
  }

  const handleTOTPVerify = async (e) => {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      await authAPI.verifyTOTP(totpCode)
      navigate('/', { replace: true })
    } catch {
      setError('Invalid code — please try again')
      setLoading(false)
    }
  }

  const switchMode = (m) => { setMode(m); setError(''); setSuccess('') }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg)', position: 'relative', padding: 16,
    }}>
      {/* Grid bg */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, opacity: theme === 'dark' ? 0.4 : 0.2,
        backgroundImage: `linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)`,
        backgroundSize: '40px 40px', pointerEvents: 'none',
      }} />

      {/* Glow */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 500, height: 250, borderRadius: '50%', zIndex: 0,
        background: 'radial-gradient(ellipse, var(--accent-muted) 0%, transparent 70%)',
        filter: 'blur(40px)', pointerEvents: 'none',
      }} />

      {/* Theme toggle */}
      <button onClick={toggle} style={{
        position: 'fixed', top: 20, right: 20, zIndex: 10,
        background: 'var(--bg-card)', border: '1px solid var(--border-md)',
        borderRadius: 'var(--radius-md)', padding: '7px 10px',
        color: 'var(--text-2)', cursor: 'pointer', fontSize: 16,
      }}>
        {theme === 'dark' ? '☀' : '☾'}
      </button>

      <div style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: 400 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 64, height: 64, borderRadius: 16,
            background: 'var(--bg-card)', border: '1px solid var(--border-md)',
            marginBottom: 16, boxShadow: 'var(--shadow-md)',
          }}>
            <svg width="36" height="36" viewBox="0 0 40 40" fill="none">
              <path d="M20 3L5 9v10c0 9.4 6.4 18.2 15 20.6C29.6 37.2 36 28.4 36 19V9L20 3z"
                fill="var(--accent-muted)" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round"/>
              <path d="M14 20l4 4 8-8" stroke="var(--accent)" strokeWidth="2"
                strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.02em', margin: 0 }}>
            AI SBC Security
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
            {mode === 'register' ? 'Create your account' :
             mode === 'totp'     ? 'Two-factor verification' :
             mode === 'setup2fa' ? 'Set up two-factor auth' :
             'Sign in to your dashboard'}
          </p>
        </div>

        {/* Card */}
        <div className="card" style={{ padding: 28 }}>

          {/* ── 2FA Setup ── */}
          {mode === 'setup2fa' && qrData && (
            <form onSubmit={handleTOTPVerify}>
              <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, lineHeight: 1.6 }}>
                Scan this QR code with Google Authenticator, Authy, or any TOTP app.
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
                <div style={{ padding: 10, background: '#fff', borderRadius: 10 }}>
                  <img src={`data:image/png;base64,${qrData.qr_code_b64}`} alt="2FA QR" style={{ width: 150, height: 150, display: 'block' }} />
                </div>
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-3)', textAlign: 'center', marginBottom: 4 }}>Manual key</p>
              <div className="code-block" style={{ textAlign: 'center', letterSpacing: '0.15em', color: 'var(--accent)', marginBottom: 20 }}>
                {qrData.secret}
              </div>
              <InputField label="6-digit code" value={totpCode}
                onChange={e => setTotpCode(e.target.value.replace(/\D/g,'').slice(0,6))}
                placeholder="000000" inputMode="numeric" autoFocus />
              {error && <ErrorBox msg={error} />}
              <SubmitBtn loading={loading} label="Enable two-factor auth" />
            </form>
          )}

          {/* ── TOTP verify ── */}
          {mode === 'totp' && (
            <form onSubmit={handleLogin}>
              <div style={{ textAlign: 'center', marginBottom: 24 }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>🔐</div>
                <p style={{ fontSize: 13, color: 'var(--text-2)' }}>
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
              <InputField label="Authenticator code" value={totpCode}
                onChange={e => setTotpCode(e.target.value.replace(/\D/g,'').slice(0,6))}
                placeholder="000000" inputMode="numeric" autoFocus />
              {error && <ErrorBox msg={error} />}
              <SubmitBtn loading={loading} label="Verify" />
              <button type="button" onClick={() => switchMode('login')}
                style={{ display: 'block', width: '100%', textAlign: 'center', marginTop: 12,
                  fontSize: 13, color: 'var(--text-3)', cursor: 'pointer', background: 'none', border: 'none' }}>
                ← Back to sign in
              </button>
            </form>
          )}

          {/* ── Register ── */}
          {mode === 'register' && (
            <form onSubmit={handleRegister}>
              <InputField label="Username" value={username} onChange={e => setUsername(e.target.value)}
                placeholder="your-username" autoFocus />
              <InputField label="Email address" value={email} onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com" type="email" />
              <InputField label="Password" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Min 8 characters"
                type={showPw ? 'text' : 'password'}
                suffix={<button type="button" onClick={() => setShowPw(s => !s)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-3)', fontSize: 13 }}>
                  {showPw ? 'Hide' : 'Show'}
                </button>} />
              {error && <ErrorBox msg={error} />}
              {success && <SuccessBox msg={success} />}
              <SubmitBtn loading={loading} label="Create account" />
              <LinkBtn onClick={() => switchMode('login')} label="Already have an account? Sign in" />
            </form>
          )}

          {/* ── Login ── */}
          {mode === 'login' && (
            <form onSubmit={handleLogin}>
              <InputField label="Username" value={username} onChange={e => setUsername(e.target.value)}
                placeholder="your-username" autoFocus />
              <InputField label="Password" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                type={showPw ? 'text' : 'password'}
                suffix={<button type="button" onClick={() => setShowPw(s => !s)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-3)', fontSize: 13 }}>
                  {showPw ? 'Hide' : 'Show'}
                </button>} />
              {error && <ErrorBox msg={error} />}
              {success && <SuccessBox msg={success} />}
              <SubmitBtn loading={loading} label="Sign in" />
              <LinkBtn onClick={() => switchMode('register')} label="New installation? Create account" />
            </form>
          )}
        </div>

        <p style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-3)', marginTop: 20 }}>
          AI SBC Security · Open Source ·{' '}
          <a href="https://github.com/fahimrahmanbooom/ai-sbc-security"
            style={{ color: 'var(--accent)' }} target="_blank" rel="noopener noreferrer">GitHub</a>
        </p>
      </div>
    </div>
  )
}

function InputField({ label, value, onChange, placeholder, type = 'text', autoFocus, suffix, inputMode, inputStyle }) {
  const isNumeric = inputMode === 'numeric'
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>
        {label}
      </label>
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        <input type={type} value={value} onChange={onChange} placeholder={placeholder}
          required autoFocus={autoFocus} inputMode={inputMode}
          className="input"
          style={{
            width: '100%',
            paddingRight: suffix ? 56 : 14,
            paddingLeft: 14,
            ...(isNumeric ? {
              textAlign: 'center',
              letterSpacing: '0.4em',
              fontSize: 22,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
            } : {}),
            ...inputStyle,
          }} />
        {suffix && <div style={{ position: 'absolute', right: 8 }}>{suffix}</div>}
      </div>
    </div>
  )
}

function ErrorBox({ msg }) {
  return (
    <div style={{
      padding: '10px 14px', borderRadius: 8, marginBottom: 14,
      background: 'rgba(255,80,80,0.1)', border: '1px solid rgba(255,80,80,0.3)',
      fontSize: 13, color: '#ff6b6b', lineHeight: 1.4,
    }}>{msg}</div>
  )
}

function SuccessBox({ msg }) {
  return (
    <div style={{
      padding: '10px 14px', borderRadius: 8, marginBottom: 14,
      background: 'rgba(0,200,100,0.1)', border: '1px solid rgba(0,200,100,0.3)',
      fontSize: 13, color: '#00c864', lineHeight: 1.4,
    }}>{msg}</div>
  )
}

function SubmitBtn({ loading, label }) {
  return (
    <button type="submit" disabled={loading} className="btn btn-primary btn-lg"
      style={{ width: '100%', marginTop: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
      {loading
        ? <><Spinner />&nbsp;Please wait...</>
        : label}
    </button>
  )
}

function LinkBtn({ onClick, label }) {
  return (
    <button type="button" onClick={onClick}
      style={{ display: 'block', width: '100%', textAlign: 'center', marginTop: 16,
        fontSize: 13, color: 'var(--accent)', cursor: 'pointer', background: 'none', border: 'none' }}>
      {label}
    </button>
  )
}

function Spinner() {
  return (
    <span style={{
      width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)',
      borderTopColor: '#fff', borderRadius: '50%',
      display: 'inline-block', animation: 'spin 0.7s linear infinite',
    }} />
  )
}

const _s = document.createElement('style')
_s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}'
document.head.appendChild(_s)
