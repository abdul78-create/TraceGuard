import React from 'react'
import { ShieldAlert, RefreshCw } from 'lucide-react'
import type { HealthResponse, ModelStatusResponse } from '../types/api'

interface HeaderProps {
  health: HealthResponse | null
  modelStatus: ModelStatusResponse | null
  loading: boolean
  onRefresh: () => void
}

export const Header: React.FC<HeaderProps> = ({
  health,
  modelStatus,
  loading,
  onRefresh,
}) => {
  const isApiOnline = Boolean(health && health.status === 'healthy')
  const isModelReady = Boolean(modelStatus && modelStatus.lifecycle_status === 'READY')

  return (
    <header className="app-header">
      <div className="header-inner">
        <div className="brand-section">
          <div className="brand-icon-wrapper" aria-hidden="true">
            <ShieldAlert size={18} />
          </div>
          <div>
            <h1 className="brand-title">
              TraceGuard
              {isModelReady && (
                <span className="badge badge-ok" style={{ fontSize: '0.65rem' }}>
                  Stage 5: Live Integration
                </span>
              )}
            </h1>
            <p className="brand-subtitle">Adaptive Network Threat Detection &amp; Triage</p>
          </div>
        </div>

        <div className="header-controls">
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {/* API Status */}
            <div
              title={
                isApiOnline
                  ? `Backend connected — ${health?.app} v${health?.version}`
                  : 'Backend not reachable at 127.0.0.1:8000'
              }
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '9999px',
                border: '1px solid',
                borderColor: isApiOnline ? '#0a0a0a' : '#cccccc',
                background: isApiOnline ? '#0a0a0a' : 'transparent',
                fontSize: '0.7rem',
                fontWeight: 600,
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
                color: isApiOnline ? '#ffffff' : '#888888',
                cursor: 'default',
              }}
            >
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: isApiOnline ? '#ffffff' : '#aaaaaa',
                  animation: isApiOnline ? 'pulse-ring 2s ease-in-out infinite' : 'none',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
              {isApiOnline ? 'API Online' : 'API Offline'}
            </div>

            {/* Model Status */}
            <div
              title={modelStatus?.message || 'Detection model not loaded'}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '9999px',
                border: '1px solid',
                borderColor: isModelReady ? '#0a0a0a' : '#cccccc',
                background: isModelReady ? '#f8f8f8' : 'transparent',
                fontSize: '0.7rem',
                fontWeight: 600,
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
                color: isModelReady ? '#0a0a0a' : '#888888',
                cursor: 'default',
              }}
            >
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: isModelReady ? '#0a0a0a' : '#aaaaaa',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
              {modelStatus?.lifecycle_status || 'UNCONFIGURED'}
            </div>
          </div>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="btn btn-secondary"
            title="Refresh system status"
            aria-label="Refresh status"
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
          >
            <RefreshCw
              size={13}
              style={{
                animation: loading ? 'spin 0.8s linear infinite' : 'none',
              }}
            />
            <span>Refresh</span>
          </button>
        </div>
      </div>
    </header>
  )
}
