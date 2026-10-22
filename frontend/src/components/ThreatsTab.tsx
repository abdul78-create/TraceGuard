import React, { useEffect, useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  AlertTriangle,
  Zap,
  Loader2,
  RefreshCw,
  Sliders,
  ChevronDown,
  ChevronUp,
  BarChart2,
} from 'lucide-react'
import type {
  NetworkFlowRecord,
  PredictionResult,
  SampleFlowItem,
  BatchPredictionResponse,
} from '../types/api'
import type { NavTabId } from './Navigation'
import { fetchSampleFlows, predictFlow, predictBatch } from '../services/api'

interface ThreatsTabProps {
  onFlowEvaluated?: (flow: NetworkFlowRecord, result: PredictionResult) => void
  onNavigate?: (tab: NavTabId) => void
}

/* Animated monochrome progress bar */
const ProgressBar: React.FC<{ value: number; dark?: boolean }> = ({ value, dark }) => {
  const pct = Math.min(100, Math.max(0, value * 100)).toFixed(1)
  return (
    <div className="progress-track" style={{ height: '8px', background: '#e5e5e5' }}>
      <div
        className="progress-fill"
        style={{
          width: `${pct}%`,
          background: dark ? '#0a0a0a' : '#555555',
          transition: 'width 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      />
    </div>
  )
}

export const ThreatsTab: React.FC<ThreatsTabProps> = ({ onFlowEvaluated, onNavigate }) => {
  const [sampleFlows, setSampleFlows] = useState<SampleFlowItem[]>([])
  const [selectedArchetype, setSelectedArchetype] = useState<'benign' | 'known' | 'heldout'>('heldout')
  const [activePolicy, setActivePolicy] = useState<'POLICY_A' | 'POLICY_B' | 'POLICY_C'>('POLICY_B')
  const [currentFlow, setCurrentFlow] = useState<NetworkFlowRecord | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [batchLoading, setBatchLoading] = useState<boolean>(false)
  const [predictionResult, setPredictionResult] = useState<PredictionResult | null>(null)
  const [batchResult, setBatchResult] = useState<BatchPredictionResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [showAdvancedParams, setShowAdvancedParams] = useState<boolean>(false)

  /* Primary 3 archetypes */
  const archetypes = [
    {
      id: 'benign' as const,
      sampleId: 'sample-benign-web',
      badge: 'Normal Traffic Test',
      title: 'Normal Web Traffic',
      demonstrates: 'Tests whether the model recognizes an example of typical, harmless traffic without raising a false alarm.',
      expected: 'Likely Benign under all policies',
    },
    {
      id: 'known' as const,
      sampleId: 'sample-dos-hulk',
      badge: 'Known Attack Test',
      title: 'Known DoS Attack',
      demonstrates: 'Tests how the model handles an attack represented in its training classes (DoS Hulk HTTP flood).',
      expected: 'Threat Suspected (high attack probability)',
    },
    {
      id: 'heldout' as const,
      sampleId: 'sample-heldout-bot',
      badge: 'Unseen Bot Research Test',
      title: 'Unseen Botnet Attack',
      demonstrates: 'Investigates whether the model handles a Botnet family (ARES) intentionally excluded from training.',
      expected: 'Needs Human Review under Policy B (Abstain via Anomaly Detector)',
      recommended: true,
    },
  ]

  const policies = [
    {
      id: 'POLICY_A' as const,
      name: 'Policy A — Permissive',
      threshold: '0.6001 (5% target FPR)',
      tradeoff: 'Less likely to send traffic for review. Minimizes analyst workload on normal traffic, but misses stealthy attacks.',
      heldoutBotResult: 'Misses 97.8% of Bot flows',
    },
    {
      id: 'POLICY_B' as const,
      name: 'Policy B — Balanced',
      threshold: '0.1873 (25% target FPR)',
      tradeoff: 'An intermediate review strategy that balances false alarms with catching anomalous attacks like the held-out Bot.',
      heldoutBotResult: 'Flags 5.33% of Bot flows for review (104 of 1,953)',
      recommended: true,
    },
    {
      id: 'POLICY_C' as const,
      name: 'Policy C — Conservative',
      threshold: '0.0756 (50% target FPR)',
      tradeoff: 'Maximum vigilance. Sends more traffic for human review, catching more anomalies at the cost of higher benign false alarms.',
      heldoutBotResult: 'Flags 58.9% of Bot flows for review (1,151 of 1,953)',
    },
  ]

  useEffect(() => {
    let mounted = true
    fetchSampleFlows()
      .then((flows) => {
        if (mounted && flows && flows.length > 0) {
          setSampleFlows(flows)
          // Default to held-out bot for strongest pedagogical demonstration
          const botFlow = flows.find((f) => f.id === 'sample-heldout-bot') || flows[0]
          setCurrentFlow(botFlow.record)
          setSelectedArchetype(
            botFlow.category === 'HELDOUT_ATTACK'
              ? 'heldout'
              : botFlow.category === 'BENIGN'
              ? 'benign'
              : 'known'
          )
        }
      })
      .catch(() => {
        if (mounted) {
          const fallback: NetworkFlowRecord = {
            flow_id: 'demo-heldout-bot',
            protocol: 6,
            flow_duration_ms: 2500.0,
            src_port: 49160,
            dst_port: 8080,
            total_fwd_packets: 10,
            total_bwd_packets: 8,
            total_fwd_bytes: 840,
            total_bwd_bytes: 3200,
            fwd_packet_length_mean: 84.0,
            bwd_packet_length_mean: 400.0,
            flow_bytes_per_sec: 1616.0,
            flow_packets_per_sec: 7.2,
            flow_iat_mean: 147.0,
            flow_iat_std: 32.0,
            syn_flag_count: 1,
            rst_flag_count: 0,
            ack_flag_count: 1,
            fin_flag_count: 0,
          }
          setCurrentFlow(fallback)
        }
      })
    return () => { mounted = false }
  }, [])

  const handleSelectArchetype = (archId: 'benign' | 'known' | 'heldout') => {
    setSelectedArchetype(archId)
    setPredictionResult(null)
    setErrorMessage(null)
    const targetSampleId =
      archId === 'benign'
        ? 'sample-benign-web'
        : archId === 'known'
        ? 'sample-dos-hulk'
        : 'sample-heldout-bot'
    const found = sampleFlows.find((s) => s.id === targetSampleId)
    if (found) setCurrentFlow({ ...found.record })
  }

  const handleSelectPolicy = (polId: 'POLICY_A' | 'POLICY_B' | 'POLICY_C') => {
    setActivePolicy(polId)
    setPredictionResult(null)
    setErrorMessage(null)
  }

  const handleFieldChange = (field: keyof NetworkFlowRecord, value: number) => {
    if (!currentFlow) return
    const updated = { ...currentFlow, [field]: value }
    if (updated.features && field === 'dst_port') updated.features['Destination Port'] = value
    setCurrentFlow(updated)
  }

  const handleRunSinglePrediction = async () => {
    if (!currentFlow) return
    setLoading(true)
    setErrorMessage(null)
    setPredictionResult(null)
    try {
      const result = await predictFlow(currentFlow, activePolicy)
      setPredictionResult(result)
      if (onFlowEvaluated) onFlowEvaluated(currentFlow, result)
    } catch (err: unknown) {
      setErrorMessage(
        err instanceof Error
          ? err.message
          : 'Could not reach backend API at http://127.0.0.1:8000. Ensure server is running.'
      )
    } finally {
      setLoading(false)
    }
  }

  const handleRunBatchPrediction = async () => {
    if (!sampleFlows || sampleFlows.length === 0) return
    setBatchLoading(true)
    setErrorMessage(null)
    setBatchResult(null)
    try {
      const records = sampleFlows.map((s) => s.record)
      const res = await predictBatch(records, activePolicy)
      setBatchResult(res)
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Batch prediction request failed')
    } finally {
      setBatchLoading(false)
    }
  }

  return (
    <div>
      {/* Intro Header */}
      <div style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, letterSpacing: '-0.03em', margin: 0 }}>
            Threat Detection Workbench
          </h2>
          <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
            Adaptive Triage &amp; Inference Workbench
          </span>
        </div>
        <p style={{ fontSize: '0.86rem', color: '#555555', maxWidth: '720px', lineHeight: 1.6, margin: 0 }}>
          Follow this 4-step sequence to test the model on network traffic records. Select a sample, choose
          a triage review policy, click <strong>Analyze this traffic</strong>, and inspect the automated decision.
        </p>
      </div>

      {/* STEP 1: Choose a Test Scenario */}
      <div className="card" style={{ marginBottom: '20px', padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
          <div
            style={{
              width: '26px',
              height: '26px',
              borderRadius: '50%',
              background: '#0a0a0a',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8rem',
            }}
          >
            1
          </div>
          <div>
            <h3 style={{ fontSize: '0.98rem', fontWeight: 700, margin: 0, color: '#0a0a0a' }}>
              Step 1 — Choose a Test Scenario
            </h3>
            <p style={{ fontSize: '0.76rem', color: '#666666', margin: 0 }}>
              Select which traffic archetype you want to submit to the model.
            </p>
          </div>
        </div>

        <div className="grid-cols-3" style={{ marginBottom: 0 }}>
          {archetypes.map((arch) => {
            const isSelected = selectedArchetype === arch.id
            return (
              <div
                key={arch.id}
                onClick={() => handleSelectArchetype(arch.id)}
                style={{
                  background: isSelected ? '#0a0a0a' : '#ffffff',
                  color: isSelected ? '#ffffff' : '#0a0a0a',
                  border: isSelected ? '2px solid #0a0a0a' : '1px solid #d0d0d0',
                  borderRadius: '8px',
                  padding: '16px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span
                      style={{
                        fontSize: '0.66rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                        padding: '2px 6px',
                        borderRadius: '9999px',
                        border: '1px solid',
                        borderColor: isSelected ? '#ffffff' : '#aaaaaa',
                        color: isSelected ? '#ffffff' : '#555555',
                      }}
                    >
                      {arch.badge}
                    </span>
                    {arch.recommended && (
                      <span
                        style={{
                          fontSize: '0.62rem',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 5px',
                          borderRadius: '3px',
                          background: isSelected ? '#ffffff' : '#0a0a0a',
                          color: isSelected ? '#0a0a0a' : '#ffffff',
                        }}
                      >
                        Recommended Demo
                      </span>
                    )}
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '0.92rem', marginBottom: '6px' }}>
                    {arch.title}
                  </div>
                  <p style={{ fontSize: '0.77rem', opacity: isSelected ? 0.9 : 0.8, lineHeight: 1.45, margin: 0, marginBottom: '12px' }}>
                    {arch.demonstrates}
                  </p>
                </div>
                <div
                  style={{
                    fontSize: '0.7rem',
                    padding: '6px 8px',
                    borderRadius: '4px',
                    background: isSelected ? 'rgba(255,255,255,0.12)' : '#f5f5f5',
                    color: isSelected ? '#ffffff' : '#333333',
                    border: isSelected ? '1px solid rgba(255,255,255,0.2)' : '1px solid #e5e5e5',
                  }}
                >
                  <strong>Expected:</strong> {arch.expected}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* STEP 2: Choose a Detection Policy */}
      <div className="card" style={{ marginBottom: '20px', padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
          <div
            style={{
              width: '26px',
              height: '26px',
              borderRadius: '50%',
              background: '#0a0a0a',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8rem',
            }}
          >
            2
          </div>
          <div>
            <h3 style={{ fontSize: '0.98rem', fontWeight: 700, margin: 0, color: '#0a0a0a' }}>
              Step 2 — Select Active Triage Policy
            </h3>
            <p style={{ fontSize: '0.76rem', color: '#666666', margin: 0 }}>
              Control the threshold for when unusual traffic is sent for human review rather than cleared.
            </p>
          </div>
        </div>

        <div className="grid-cols-3" style={{ marginBottom: 0 }}>
          {policies.map((pol) => {
            const isSelected = activePolicy === pol.id
            return (
              <div
                key={pol.id}
                onClick={() => handleSelectPolicy(pol.id)}
                style={{
                  background: isSelected ? '#0a0a0a' : '#ffffff',
                  color: isSelected ? '#ffffff' : '#0a0a0a',
                  border: isSelected ? '2px solid #0a0a0a' : '1px solid #d0d0d0',
                  borderRadius: '8px',
                  padding: '16px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>
                      {pol.name}
                    </div>
                    {pol.recommended && (
                      <span
                        style={{
                          fontSize: '0.62rem',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 5px',
                          borderRadius: '3px',
                          background: isSelected ? '#ffffff' : '#0a0a0a',
                          color: isSelected ? '#0a0a0a' : '#ffffff',
                        }}
                      >
                        Recommended
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.7rem', opacity: isSelected ? 0.75 : 0.6, marginBottom: '8px', fontFamily: 'var(--font-mono)' }}>
                    Threshold: {pol.threshold}
                  </div>
                  <p style={{ fontSize: '0.76rem', opacity: isSelected ? 0.9 : 0.8, lineHeight: 1.45, margin: 0, marginBottom: '10px' }}>
                    {pol.tradeoff}
                  </p>
                </div>
                <div
                  style={{
                    fontSize: '0.7rem',
                    padding: '5px 8px',
                    borderRadius: '4px',
                    background: isSelected ? 'rgba(255,255,255,0.1)' : '#f8f8f8',
                    color: isSelected ? '#ffffff' : '#444444',
                    border: isSelected ? '1px solid rgba(255,255,255,0.2)' : '1px solid #e5e5e5',
                  }}
                >
                  {pol.heldoutBotResult}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* STEP 3: Analyze */}
      <div className="card" style={{ marginBottom: '20px', padding: '22px 24px', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <div
            style={{
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              background: '#0a0a0a',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.78rem',
            }}
          >
            3
          </div>
          <span style={{ fontWeight: 700, fontSize: '0.94rem', color: '#0a0a0a' }}>
            Step 3 — Submit &amp; Analyze
          </span>
        </div>
        <p style={{ fontSize: '0.8rem', color: '#555555', maxWidth: '520px', margin: '0 auto 16px auto', lineHeight: 1.5 }}>
          Submits this 69-feature network flow record to the FastAPI backend at{' '}
          <code style={{ background: '#f0f0f0', padding: '2px 4px', borderRadius: 3 }}>
            POST /api/model/predict?policy={activePolicy}
          </code>
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            className="btn btn-primary"
            onClick={handleRunSinglePrediction}
            disabled={loading}
            style={{
              fontSize: '0.94rem',
              padding: '12px 28px',
              minWidth: '280px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            {loading ? (
              <>
                <Loader2 size={16} style={{ animation: 'spin 0.8s linear infinite' }} />
                <span>Analyzing traffic with backend…</span>
              </>
            ) : (
              <>
                <Zap size={16} />
                <span>Analyze this traffic (Evaluate Flow Record)</span>
              </>
            )}
          </button>
        </div>

        {/* In-flight Loading Overlay */}
        {loading && (
          <div
            className="scan-overlay"
            style={{
              marginTop: '16px',
              borderRadius: '8px',
              border: '1px solid #e5e5e5',
              padding: '18px',
              background: '#fafafa',
              maxWidth: '520px',
              margin: '16px auto 0 auto',
            }}
          >
            <div className="skeleton skeleton-title" style={{ width: '50%', margin: '0 auto 10px auto' }} />
            <div className="skeleton skeleton-text" style={{ width: '80%', margin: '0 auto 6px auto' }} />
            <div className="skeleton skeleton-text" style={{ width: '60%', margin: '0 auto' }} />
          </div>
        )}

        {/* Error notice */}
        {errorMessage && (
          <div
            className="notice-banner notice-banner-warn"
            style={{ marginTop: '16px', maxWidth: '580px', margin: '16px auto 0 auto', textAlign: 'left' }}
          >
            <AlertTriangle size={16} style={{ flexShrink: 0 }} />
            <span style={{ fontSize: '0.8rem' }}>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* STEP 4: Understand the Result */}
      {predictionResult && !loading && (
        <div
          className={`card ${
            predictionResult.decision === 'THREAT_SUSPECTED'
              ? 'decision-threat'
              : predictionResult.decision === 'ABSTAIN'
              ? 'decision-abstain'
              : 'decision-benign'
          }`}
          style={{
            marginBottom: '20px',
            padding: '24px',
            animation: 'fadeUp 300ms ease both',
          }}
        >
          {/* Step 4 Badge */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div
                style={{
                  width: '22px',
                  height: '22px',
                  borderRadius: '50%',
                  background: predictionResult.decision === 'THREAT_SUSPECTED' ? '#ffffff' : '#0a0a0a',
                  color: predictionResult.decision === 'THREAT_SUSPECTED' ? '#0a0a0a' : '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '0.75rem',
                }}
              >
                4
              </div>
              <span
                style={{
                  fontWeight: 700,
                  fontSize: '0.84rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                  opacity: 0.8,
                }}
              >
                Step 4 — Understand the Result
              </span>
            </div>

            <div style={{ fontSize: '0.74rem', opacity: 0.7 }}>
              {predictionResult.flow_id} · Triage Policy: {predictionResult.policy_version || activePolicy}
            </div>
          </div>

          {/* Decision Verdict Banner */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              background:
                predictionResult.decision === 'THREAT_SUSPECTED'
                  ? 'rgba(255,255,255,0.1)'
                  : '#f8f8f8',
              border: '1px solid',
              borderColor:
                predictionResult.decision === 'THREAT_SUSPECTED'
                  ? 'rgba(255,255,255,0.2)'
                  : '#c8c8c8',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
            }}
          >
            <div>
              {predictionResult.decision === 'THREAT_SUSPECTED' ? (
                <ShieldAlert size={32} />
              ) : predictionResult.decision === 'ABSTAIN' ? (
                <ShieldQuestion size={32} />
              ) : (
                <ShieldCheck size={32} />
              )}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '2px' }}>
                {predictionResult.decision === 'THREAT_SUSPECTED'
                  ? 'Threat Suspected'
                  : predictionResult.decision === 'ABSTAIN'
                  ? 'Needs Human Review'
                  : 'Likely Benign'}
              </div>
              <p style={{ fontSize: '0.8rem', opacity: 0.85, margin: 0 }}>
                {predictionResult.decision === 'THREAT_SUSPECTED'
                  ? 'The model detected characteristics closely matching known attack training data.'
                  : predictionResult.decision === 'ABSTAIN'
                  ? 'The model refused an automated decision because anomaly scores exceeded the review threshold.'
                  : 'Traffic characteristics align with normal benign baseline behavior.'}
              </p>
            </div>
            <span
              className={`badge ${
                predictionResult.decision === 'THREAT_SUSPECTED'
                  ? 'badge-neutral'
                  : predictionResult.decision === 'ABSTAIN'
                  ? 'badge-neutral'
                  : 'badge-neutral'
              }`}
              style={{
                fontSize: '0.72rem',
                border: '1px solid currentColor',
                padding: '4px 10px',
              }}
            >
              {predictionResult.decision}
            </span>
          </div>

          {/* Score Breakdown Cards */}
          <div className="grid-cols-2" style={{ marginBottom: '16px' }}>
            {/* Threat Probability */}
            <div
              style={{
                padding: '14px 16px',
                borderRadius: '8px',
                background:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.06)'
                    : '#f8f8f8',
                border: '1px solid',
                borderColor:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.15)'
                    : '#e5e5e5',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '0.74rem', fontWeight: 600, opacity: 0.75 }}>
                  Calibrated Threat Probability
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.05rem' }}>
                  {(predictionResult.calibrated_confidence * 100).toFixed(1)}%
                </span>
              </div>
              <ProgressBar
                value={predictionResult.calibrated_confidence}
                dark={predictionResult.decision === 'THREAT_SUSPECTED'}
              />
              <div style={{ fontSize: '0.7rem', opacity: 0.65, marginTop: '6px' }}>
                Decision Threshold: 50.0% · Raw RF Score: {(predictionResult.raw_confidence * 100).toFixed(1)}%
              </div>
            </div>

            {/* Anomaly Score */}
            <div
              style={{
                padding: '14px 16px',
                borderRadius: '8px',
                background:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.06)'
                    : '#f8f8f8',
                border: '1px solid',
                borderColor:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.15)'
                    : '#e5e5e5',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '0.74rem', fontWeight: 600, opacity: 0.75 }}>
                  Isolation Forest Anomaly Score
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.05rem' }}>
                  {predictionResult.anomaly_score.toFixed(4)}
                </span>
              </div>
              <ProgressBar
                value={predictionResult.anomaly_score}
                dark={predictionResult.decision === 'THREAT_SUSPECTED'}
              />
              <div style={{ fontSize: '0.7rem', opacity: 0.65, marginTop: '6px' }}>
                Abstention Reason: <code>{predictionResult.abstention_reason || 'NONE'}</code>
              </div>
            </div>
          </div>

          {/* Model Explanation */}
          {predictionResult.explanation && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: '6px',
                background:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.07)'
                    : '#f5f5f5',
                border: '1px solid',
                borderColor:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.15)'
                    : '#e0e0e0',
                fontSize: '0.78rem',
                lineHeight: 1.5,
                marginBottom: '14px',
              }}
            >
              <strong>Why this verdict?</strong> {predictionResult.explanation}
            </div>
          )}

          {/* Safety Notice */}
          {predictionResult.safety_notice && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: '6px',
                background:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.05)'
                    : '#ffffff',
                border: '1px solid',
                borderColor:
                  predictionResult.decision === 'THREAT_SUSPECTED'
                    ? 'rgba(255,255,255,0.12)'
                    : '#e5e5e5',
                fontSize: '0.76rem',
                opacity: 0.85,
                lineHeight: 1.5,
              }}
            >
              <strong>Safety Notice:</strong> {predictionResult.safety_notice}
            </div>
          )}
        </div>
      )}

      {/* STEP 5: What to do next / Explore Further */}
      {predictionResult && !loading && (
        <div className="card" style={{ marginBottom: '20px', padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div
              style={{
                width: '24px',
                height: '24px',
                borderRadius: '50%',
                background: '#0a0a0a',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '0.78rem',
              }}
            >
              5
            </div>
            <div>
              <h3 style={{ fontSize: '0.94rem', fontWeight: 700, margin: 0, color: '#0a0a0a' }}>
                Step 5 — Explore Further
              </h3>
              <p style={{ fontSize: '0.76rem', color: '#666666', margin: 0 }}>
                Compare this flow against other policies or explore the broader research results.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '16px' }}>
            <button
              className="btn btn-secondary"
              onClick={() => {
                const nextArch = selectedArchetype === 'heldout' ? 'benign' : selectedArchetype === 'benign' ? 'known' : 'heldout'
                handleSelectArchetype(nextArch)
              }}
              style={{ fontSize: '0.8rem' }}
            >
              <RefreshCw size={14} />
              <span>Try another test scenario</span>
            </button>

            {/* Quick Policy Switchers */}
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: '#666666', marginRight: '4px' }}>Compare:</span>
              {(['POLICY_A', 'POLICY_B', 'POLICY_C'] as const).map((pol) => (
                <button
                  key={pol}
                  className={`btn ${activePolicy === pol ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ fontSize: '0.72rem', padding: '4px 8px' }}
                  onClick={() => {
                    setActivePolicy(pol)
                    // Automatically run prediction with selected policy
                    if (currentFlow) {
                      setLoading(true)
                      predictFlow(currentFlow, pol)
                        .then((res) => {
                          setPredictionResult(res)
                          if (onFlowEvaluated) onFlowEvaluated(currentFlow, res)
                        })
                        .catch((err) => setErrorMessage(err.message))
                        .finally(() => setLoading(false))
                    }
                  }}
                >
                  {pol === 'POLICY_A' ? 'Policy A' : pol === 'POLICY_B' ? 'Policy B' : 'Policy C'}
                </button>
              ))}
            </div>

            <button
              className="btn btn-secondary"
              onClick={() => onNavigate && onNavigate('evaluation')}
              style={{ fontSize: '0.8rem', marginLeft: 'auto' }}
            >
              <BarChart2 size={14} />
              <span>Explore research results →</span>
            </button>
          </div>
        </div>
      )}

      {/* Collapsible Technical Details (Hidden by default for simplicity) */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <div
          onClick={() => setShowAdvancedParams(!showAdvancedParams)}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sliders size={15} />
            <span style={{ fontWeight: 600, fontSize: '0.84rem' }}>
              Advanced Configuration &amp; Feature Inspector (Technical)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#666' }}>
            <span>{showAdvancedParams ? 'Hide Details' : 'Show Details'}</span>
            {showAdvancedParams ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </div>
        </div>

        {showAdvancedParams && currentFlow && (
          <div style={{ marginTop: '16px', borderTop: '1px solid #e5e5e5', paddingTop: '16px' }}>
            <p style={{ fontSize: '0.76rem', color: '#666', marginBottom: '12px' }}>
              Adjust raw flow metrics below to test sensitivity. The API requires a valid 69-feature vector.
            </p>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                gap: '10px',
                padding: '14px',
                background: '#f8f8f8',
                border: '1px solid #e5e5e5',
                borderRadius: '8px',
                marginBottom: '16px',
              }}
            >
              {[
                { key: 'dst_port', label: 'Destination Port', type: 'int', tip: 'Target port number (e.g. 443 HTTPS, 80 HTTP)' },
                { key: 'flow_duration_ms', label: 'Flow Duration (ms)', type: 'float', tip: 'Duration of connection in ms' },
                { key: 'total_fwd_packets', label: 'Fwd Packets', type: 'int', tip: 'Client to server packet count' },
                { key: 'total_bwd_packets', label: 'Bwd Packets', type: 'int', tip: 'Server to client packet count' },
                { key: 'flow_packets_per_sec', label: 'Packets / sec', type: 'float', tip: 'Volumetric rate' },
                { key: 'flow_bytes_per_sec', label: 'Bytes / sec', type: 'float', tip: 'Byte transfer rate' },
              ].map(({ key, label, type, tip }) => (
                <div key={key}>
                  <label className="field-label" title={tip}>{label}</label>
                  <input
                    className="field-input"
                    type="number"
                    value={(currentFlow as unknown as Record<string, unknown>)[key] as number ?? 0}
                    onChange={(e) =>
                      handleFieldChange(
                        key as keyof NetworkFlowRecord,
                        type === 'int' ? parseInt(e.target.value) || 0 : parseFloat(e.target.value) || 0
                      )
                    }
                  />
                  <div style={{ fontSize: '0.67rem', color: '#888', marginTop: '2px' }}>{tip}</div>
                </div>
              ))}
            </div>

            {/* Batch mode toggle */}
            <div style={{ borderTop: '1px solid #e5e5e5', paddingTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.78rem', color: '#555' }}>
                Batch Evaluation Mode (Evaluate all {sampleFlows.length} curated flows at once)
              </span>
              <button
                className="btn btn-secondary"
                onClick={handleRunBatchPrediction}
                disabled={batchLoading}
                style={{ fontSize: '0.75rem', padding: '5px 12px' }}
              >
                {batchLoading ? 'Evaluating Batch…' : 'Run Batch Analysis'}
              </button>
            </div>

            {batchResult && (
              <div style={{ marginTop: '12px', padding: '12px', background: '#f5f5f5', borderRadius: '6px', fontSize: '0.76rem' }}>
                <strong>Batch Result:</strong> Processed {batchResult.processed} / {batchResult.total_records} flows.
                <div style={{ marginTop: '6px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {batchResult.predictions.map((p) => (
                    <span
                      key={p.flow_id}
                      className="badge badge-neutral"
                      style={{ fontSize: '0.7rem' }}
                    >
                      {p.flow_id}: {p.decision}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
