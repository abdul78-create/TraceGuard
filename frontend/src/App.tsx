import React, { useEffect, useState, useCallback } from 'react'
import { Header } from './components/Header'
import { Navigation } from './components/Navigation'
import type { NavTabId } from './components/Navigation'
import { ModelStatusBanner } from './components/ModelStatusBanner'
import { OverviewTab } from './components/OverviewTab'
import { TrafficTab } from './components/TrafficTab'
import { ThreatsTab } from './components/ThreatsTab'
import { EvaluationTab } from './components/EvaluationTab'
import { DriftTab } from './components/DriftTab'
import type {
  HealthResponse,
  ModelStatusResponse,
  DriftStatusResponse,
  EvaluationMetricsResponse,
} from './types/api'
import {
  fetchHealth,
  fetchModelStatus,
  fetchDriftTelemetry,
  fetchEvaluationMetrics,
} from './services/api'
import { AlertCircle, RefreshCw } from 'lucide-react'

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTabId>('overview')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [modelStatus, setModelStatus] = useState<ModelStatusResponse | null>(null)
  const [drift, setDrift] = useState<DriftStatusResponse | null>(null)
  const [evaluation, setEvaluation] = useState<EvaluationMetricsResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  const loadAllData = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [healthData, modelData, driftData, evalData] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchModelStatus().catch(() => null),
        fetchDriftTelemetry().catch(() => null),
        fetchEvaluationMetrics().catch(() => null),
      ])

      setHealth(healthData)
      setModelStatus(modelData)
      setDrift(driftData)
      setEvaluation(evalData)

      if (!healthData) {
        setError(
          'Could not connect to TraceGuard FastAPI backend on http://127.0.0.1:8000. Ensure the backend server is running.'
        )
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error during initialization')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadAllData()
  }, [loadAllData])

  return (
    <div className="app-container">
      <Header
        health={health}
        modelStatus={modelStatus}
        loading={loading}
        onRefresh={loadAllData}
      />

      <main className="main-content">
        {error && (
          <div
            style={{
              background: 'rgba(244, 63, 94, 0.1)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              borderRadius: '8px',
              padding: '14px 18px',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
            role="alert"
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <AlertCircle size={20} color="var(--status-rose)" />
              <span style={{ fontSize: '0.85rem', color: '#fecdd3' }}>{error}</span>
            </div>
            <button
              onClick={loadAllData}
              className="btn btn-secondary"
              style={{ fontSize: '0.78rem', padding: '6px 12px' }}
            >
              <RefreshCw size={12} />
              <span>Retry</span>
            </button>
          </div>
        )}

        <ModelStatusBanner modelStatus={modelStatus} />

        <Navigation activeTab={activeTab} onSelectTab={setActiveTab} />

        {activeTab === 'overview' && (
          <OverviewTab health={health} modelStatus={modelStatus} />
        )}
        {activeTab === 'traffic' && <TrafficTab />}
        {activeTab === 'threats' && <ThreatsTab />}
        {activeTab === 'evaluation' && <EvaluationTab evaluation={evaluation} />}
        {activeTab === 'drift' && <DriftTab drift={drift} />}
      </main>

      <footer className="app-footer">
        <p>
          TraceGuard • Adaptive Network Threat Detection System • Stage 1 Foundation
        </p>
      </footer>
    </div>
  )
}

export default App
