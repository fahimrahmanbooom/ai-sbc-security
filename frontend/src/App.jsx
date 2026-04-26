import React, { useState, useEffect, createContext, useContext } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import LoginPage from './components/LoginPage'
import DashboardLayout from './components/DashboardLayout'

// ── Theme Context ──────────────────────────────────────────────────────────────
export const ThemeContext = createContext({ theme: 'dark', toggle: () => {} })
export const useTheme = () => useContext(ThemeContext)

function PrivateRoute({ children }) {
  return localStorage.getItem('access_token') ? children : <Navigate to="/login" replace />
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: 'var(--bg-card)',
              color: 'var(--text-1)',
              border: '1px solid var(--border-md)',
              fontFamily: 'var(--font-sans)',
              fontSize: '13px',
              borderRadius: 'var(--radius-md)',
              boxShadow: 'var(--shadow-md)',
            },
            duration: 3500,
          }}
        />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*" element={
            <PrivateRoute><DashboardLayout /></PrivateRoute>
          } />
        </Routes>
      </BrowserRouter>
    </ThemeContext.Provider>
  )
}
