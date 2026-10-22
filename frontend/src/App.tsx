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
  NetworkFlowRecord,
  PredictionResult,
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
  const [lastSubmittedFlow, setLastSubmittedFlow] = useState<{
    flow: NetworkFlowRecord
    result?: PredictionResult
  } | null>(null)
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
            className="notice-banner notice-banner-warn"
            role="alert"
            style={{ justifyContent: 'space-between', marginBottom: '20px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
            <button
              onClick={loadAllData}
              className="btn btn-secondary"
              style={{ fontSize: '0.78rem', padding: '6px 12px', flexShrink: 0 }}
            >
              <RefreshCw size={12} />
              <span>Retry</span>
            </button>
          </div>
        )}

        <ModelStatusBanner modelStatus={modelStatus} />

        <Navigation activeTab={activeTab} onSelectTab={setActiveTab} />

        <div className="tab-content" key={activeTab}>
          {activeTab === 'overview' && (
            <OverviewTab
              health={health}
              modelStatus={modelStatus}
              evaluation={evaluation}
              onNavigate={setActiveTab}
            />
          )}
          {activeTab === 'traffic' && (
            <TrafficTab lastSubmittedFlow={lastSubmittedFlow} />
          )}
          {activeTab === 'threats' && (
            <ThreatsTab
              onFlowEvaluated={(flow, result) => setLastSubmittedFlow({ flow, result })}
              onNavigate={setActiveTab}
            />
          )}
          {activeTab === 'evaluation' && <EvaluationTab evaluation={evaluation} />}
          {activeTab === 'drift' && <DriftTab drift={drift} />}
        </div>
      </main>

      <footer className="app-footer">
        <p>
          TraceGuard · Adaptive Network Threat Detection &amp; Triage System · Research Prototype
        </p>
      </footer>
    </div>
  )
}

export default App

