import { useEffect, useRef, useState, useCallback } from 'react'

export function useWebSocket() {
  const [lastMessage, setLastMessage] = useState(null)
  const [status, setStatus] = useState('connecting')
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  const connect = useCallback(() => {
    const token = localStorage.getItem('access_token')
    if (!token) return

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/api/ws`)

    ws.onopen = () => {
      setStatus('connected')
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    }
    ws.onmessage = (e) => {
      try { setLastMessage(JSON.parse(e.data)) } catch {}
    }
    ws.onclose = () => {
      setStatus('disconnected')
      reconnectTimer.current = setTimeout(connect, 4000)
    }
    ws.onerror = () => setStatus('error')
    wsRef.current = ws
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (wsRef.current) wsRef.current.close()
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    }
  }, [connect])

  return { lastMessage, status }
}
