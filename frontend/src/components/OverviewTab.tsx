import React, { useState } from 'react'
import {
  Server,
  Cpu,
  Radio,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Layers,
} from 'lucide-react'
import type { HealthResponse, ModelStatusResponse, EvaluationMetricsResponse } from '../types/api'
import type { NavTabId } from './Navigation'

interface OverviewTabProps {
  health: HealthResponse | null
  modelStatus: ModelStatusResponse | null
  evaluation?: EvaluationMetricsResponse | null
  onNavigate?: (tab: NavTabId) => void
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  health,
  modelStatus,
  evaluation,
  onNavigate,
}) => {
  const [showRoadmap, setShowRoadmap] = useState(false)
  const isModelReady = modelStatus?.lifecycle_status === 'READY'
  const isEvalAvailable = Boolean(evaluation?.evaluation_available)

  const polB = evaluation?.triage_policies?.policy_b_balanced
  const totalBot = evaluation?.unseen_attack_metrics?.total_bot_flows ?? 1953

  /* Subsystem cards */
  const subsystems = [
    {
      name: 'FastAPI Backend',
      desc: 'Checks whether the inference server is running and responding to requests.',
      icon: Server,
      statusText: health?.services?.api_server?.status === 'up' ? 'Online' : 'Offline',
      detail: health?.services?.api_server?.message || 'Connecting to backend…',
      ok: health?.services?.api_server?.status === 'up',
    },
    {
      name: 'ML Detection Engine',
      desc: 'Checks whether the threat detection model and calibrators are loaded into memory.',
      icon: Cpu,
      statusText: modelStatus?.lifecycle_status || 'Unconfigured',
      detail: isModelReady
        ? `69-feature RF + Platt calibrator + benign Isolation Forest loaded. Configured policy: ${modelStatus?.active_policy_name || 'A'}.`
        : 'Model artifacts not yet loaded. Predictions will be refused.',
      ok: isModelReady,
      warn: !isModelReady,
    },
    {
      name: 'Live Network Ingestion',
      desc: 'Checks for live packet tap. TraceGuard is an offline research prototype that operates on exported flows.',
      icon: Radio,
      statusText: 'Disconnected',
      detail: 'No live packet tap connected. The system analyzes prepared sample flows and exported records.',
      ok: false,
      neutral: true,
    },
  ]

  /* Research findings */
  const metrics = [
    {
      label: 'Known-Attack Macro-F1',
      tooltip: 'Average F1 across all trained attack types (DoS, PortScan, DDoS). Near-perfect on known traffic.',
      value: isEvalAvailable && evaluation?.metrics?.macro_f1 != null
        ? `${(evaluation.metrics.macro_f1 * 100).toFixed(2)}%`
        : 'Unavailable',
      sub: isEvalAvailable
        ? `Precision ${((evaluation?.metrics?.attack_precision ?? 0) * 100).toFixed(2)}% · Recall ${((evaluation?.metrics?.attack_recall ?? 0) * 100).toFixed(2)}%`
        : 'Offline research report not loaded',
      emphasis: isEvalAvailable,
    },
    {
      label: 'Calibrated ECE',
      tooltip: 'Expected Calibration Error: measures how well confidence scores match true probability. Lower is better.',
      value: isEvalAvailable && evaluation?.calibration_summary?.calibrated_ece != null
        ? evaluation.calibration_summary.calibrated_ece.toFixed(6)
        : 'Unavailable',
      sub: isEvalAvailable ? '92.3% error reduction via Platt sigmoid calibration' : 'Backend offline',
      emphasis: isEvalAvailable,
    },
    {
      label: 'Unseen Bot Family Recall',
      tooltip: 'Recall on the Bot attack family that was intentionally excluded from training. 0% means the classifier alone missed every Bot flow.',
      value: isEvalAvailable ? '0.00%' : 'Unavailable',
      sub: isEvalAvailable
        ? `Supervised classifier missed all ${totalBot.toLocaleString()} held-out Bot flows (mean P=0.02%)`
        : 'Backend offline',
      emphasis: false,
      limitation: true,
    },
    {
      label: 'Anomaly Catch (Policy B)',
      tooltip: 'The Isolation Forest anomaly detector flagged 5.33% of held-out Bot flows for human review under Policy B.',
      value: isEvalAvailable && polB?.heldout_bot_safety_rate != null
        ? `${(polB.heldout_bot_safety_rate * 100).toFixed(2)}%`
        : isEvalAvailable ? '5.33%' : 'Unavailable',
      sub: isEvalAvailable
        ? `${polB?.heldout_bot_abstain_count ?? 104} / ${totalBot.toLocaleString()} Bot flows routed to human review`
        : 'Backend offline',
      emphasis: false,
      tradeoff: true,
    },
  ]

  const tabGuides = [
    {
      tab: 'threats' as NavTabId,
      name: 'Threat Detection',
      role: 'Primary Interactive Tool',
      desc: 'Run live predictions on sample network flows (benign, known attack, held-out Bot) under different policies.',
      actionLabel: 'Open Workbench',
    },
    {
      tab: 'traffic' as NavTabId,
      name: 'Traffic Analysis',
      role: 'Schema & Contract',
      desc: 'Understand what a network flow record is and inspect the 69 required statistical features.',
      actionLabel: 'Inspect Schema',
    },
    {
      tab: 'evaluation' as NavTabId,
      name: 'Model Evaluation',
      role: 'Empirical Benchmark',
      desc: 'Explore frozen research results showing how the model performed and where supervised learning failed on unseen Bots.',
      actionLabel: 'View Benchmark',
    },
    {
      tab: 'drift' as NavTabId,
      name: 'Drift Monitoring',
      role: 'Covariate Shift Analysis',
      desc: 'Examine how feature distributions changed across recording days (Mon–Fri) in historical experiments.',
      actionLabel: 'View Shift Study',
    },
  ]

  const roadmapSteps = [
    { stage: 'Stage 1', title: 'Project Foundation', status: 'completed', desc: 'Project architecture, FastAPI backend, health probes, and dashboard shell.' },
    { stage: 'Stage 2', title: 'Dataset Selection & Exploration', status: 'completed', desc: 'Audited 2.83M CIC-IDS2017 flow records. Documented 9.06% duplicates and severe class imbalance.' },
    { stage: 'Stage 3', title: 'Baseline ML Model', status: 'completed', desc: 'Leakage-resistant 5-fold feature-hash partitions and Random Forest classifier for known attacks.' },
    { stage: 'Stage 4', title: 'Anomaly Detection & Abstention', status: 'completed', desc: 'Benign-only Isolation Forest, held-out Bot evaluation, Platt calibration, triage policies.' },
    { stage: 'Stage 5', title: 'Full Application Integration', status: 'active', desc: 'Connected live FastAPI inference, triage workbench, sample flows, evaluation reports, and drift telemetry.' },
    { stage: 'Stage 6', title: 'Deployment & Packaging', status: 'pending', desc: 'Containerisation, SOC telemetry connectors, and reproducible evaluation packaging.' },
  ]

  return (
    <div>
      {/* 1. Welcoming Hero with Clear Starting Action */}
      <div
        className="card"
        style={{
          padding: '28px 32px',
          marginBottom: '28px',
          border: '2px solid #0a0a0a',
          background: '#ffffff',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div style={{ maxWidth: '640px' }}>
            <div
              style={{
                display: 'inline-block',
                fontSize: '0.72rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                padding: '3px 8px',
                borderRadius: '9999px',
                border: '1px solid #0a0a0a',
                background: '#0a0a0a',
                color: '#ffffff',
                marginBottom: '12px',
              }}
            >
              Interactive Security Assistant
            </div>
            <h2 style={{ fontSize: '1.65rem', fontWeight: 800, letterSpacing: '-0.03em', lineHeight: 1.25, marginBottom: '10px' }}>
              Understand network threat detection through guided tests.
            </h2>
            <p style={{ fontSize: '0.9rem', color: '#555555', lineHeight: 1.6, marginBottom: '18px' }}>
              TraceGuard is a research application that analyzes statistical records of network traffic and estimates
              whether a flow looks <strong>normal</strong>, resembles a <strong>known attack</strong>, or{' '}
              <strong>needs human review</strong>. Test the model using prepared scenarios or explore frozen research data.
            </p>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
              <button
                className="btn btn-primary"
                onClick={() => onNavigate && onNavigate('threats')}
                style={{ fontSize: '0.88rem', padding: '10px 20px', gap: '8px' }}
              >
                <span>Start a traffic analysis</span>
                <ArrowRight size={16} />
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => onNavigate && onNavigate('evaluation')}
                style={{ fontSize: '0.88rem', padding: '10px 18px' }}
              >
                Explore research results
              </button>
            </div>
          </div>

          <div
            style={{
              padding: '16px 20px',
              background: '#f8f8f8',
              border: '1px solid #e5e5e5',
              borderRadius: '8px',
              maxWidth: '300px',
              fontSize: '0.8rem',
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: '6px', color: '#0a0a0a' }}>
              Demonstration Note
            </div>
            <p style={{ color: '#555555', lineHeight: 1.5, margin: 0 }}>
              TraceGuard runs against prepared sample flows. It does not inspect your Wi-Fi, browser activity, or live local adapter traffic.
            </p>
          </div>
        </div>
      </div>

      {/* 2. How TraceGuard Works: Simple 4-Step Mental Model */}
      <div style={{ marginBottom: '28px' }}>
        <p className="section-heading" style={{ marginBottom: '12px' }}>
          How TraceGuard Works in 4 Steps
        </p>
        <div className="grid-cols-4" style={{ marginBottom: 0 }}>
          {[
            {
              num: '1',
              title: 'Choose a Traffic Sample',
              desc: 'Select a normal flow, a known attack (DoS), or a held-out Botnet flow never seen in training.',
            },
            {
              num: '2',
              title: 'Pick a Triage Policy',
              desc: 'Select Policy A, B (Recommended), or C to set how aggressively unusual flows trigger review.',
            },
            {
              num: '3',
              title: 'Analyze via Backend API',
              desc: 'The backend evaluates the 69-feature record using a Random Forest classifier and Isolation Forest.',
            },
            {
              num: '4',
              title: 'Inspect the Decision',
              desc: 'Get an automated verdict: Likely Benign, Threat Suspected, or Needs Human Review with explanation.',
            },
          ].map(({ num, title, desc }) => (
            <div
              key={num}
              className="card"
              style={{
                padding: '16px',
                border: '1px solid #e5e5e5',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '50%',
                    background: '#0a0a0a',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '0.82rem',
                    marginBottom: '10px',
                  }}
                >
                  {num}
                </div>
                <div style={{ fontWeight: 700, fontSize: '0.86rem', color: '#0a0a0a', marginBottom: '6px' }}>
                  {title}
                </div>
                <p style={{ fontSize: '0.78rem', color: '#555555', lineHeight: 1.5, margin: 0 }}>
                  {desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. System Status Cards */}
      <div style={{ marginBottom: '28px' }}>
        <p className="section-heading" style={{ marginBottom: '12px' }}>System Readiness</p>
        <div className="grid-cols-3" style={{ marginBottom: 0 }}>
          {subsystems.map((sub, i) => {
            const Icon = sub.icon
            return (
              <div
                key={sub.name}
                className="card"
                style={{
                  borderLeft: sub.ok ? '3px solid #0a0a0a' : sub.warn ? '3px solid #666666' : '3px solid #c8c8c8',
                  animation: `fadeUp 250ms ease both ${i * 60}ms`,
                }}
              >
                <div className="card-header" style={{ marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Icon size={16} style={{ color: '#0a0a0a' }} />
                    <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#0a0a0a' }}>
                      {sub.name}
                    </span>
                  </div>
                  <span
                    className={`badge ${
                      sub.ok ? 'badge-ok' : sub.warn ? 'badge-warn' : 'badge-neutral'
                    }`}
                  >
                    {sub.statusText}
                  </span>
                </div>
                <p style={{ fontSize: '0.78rem', color: '#666666', lineHeight: 1.45, marginBottom: '8px' }}>
                  {sub.desc}
                </p>
                <div
                  style={{
                    fontSize: '0.74rem',
                    padding: '6px 10px',
                    background: '#f8f8f8',
                    borderRadius: '4px',
                    border: '1px solid #e5e5e5',
                    color: '#333333',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {sub.detail}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* 4. Module Guide: What Each Tab is For */}
      <div style={{ marginBottom: '28px' }}>
        <p className="section-heading" style={{ marginBottom: '12px' }}>
          Module Guide: What Each Tab Does
        </p>
        <div className="grid-cols-2" style={{ marginBottom: 0 }}>
          {tabGuides.map((g) => (
            <div
              key={g.tab}
              className="card"
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: '16px',
                padding: '16px 20px',
              }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.9rem', color: '#0a0a0a' }}>
                    {g.name}
                  </span>
                  <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                    {g.role}
                  </span>
                </div>
                <p style={{ fontSize: '0.78rem', color: '#555555', lineHeight: 1.5, margin: 0 }}>
                  {g.desc}
                </p>
              </div>
              <button
                className="btn btn-secondary"
                onClick={() => onNavigate && onNavigate(g.tab)}
                style={{ fontSize: '0.75rem', padding: '6px 12px', flexShrink: 0 }}
              >
                {g.actionLabel} →
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Key Research Benchmark Findings */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '12px' }}>
          <p className="section-heading" style={{ margin: 0 }}>
            Key Research Findings (CIC-IDS2017 Benchmark)
          </p>
          <span style={{ fontSize: '0.74rem', color: '#666666' }}>
            Offline partition evaluations · Frozen baseline
          </span>
        </div>
        <div className="grid-cols-4" style={{ marginBottom: 0 }}>
          {metrics.map((m, i) => (
            <div
              key={m.label}
              className="metric-card"
              style={{
                borderLeft: m.limitation
                  ? '3px solid #888888'
                  : m.tradeoff
                  ? '3px solid #0a0a0a'
                  : '3px solid #0a0a0a',
                animation: `fadeUp 250ms ease both ${i * 50}ms`,
              }}
            >
              <div className="metric-label">
                {m.label}
              </div>
              <div
                className="metric-value"
                style={{
                  color: m.limitation ? '#555555' : '#0a0a0a',
                }}
              >
                {m.value}
              </div>
              <div className="metric-desc" style={{ fontSize: '0.72rem', color: '#666666', lineHeight: 1.4 }}>
                {m.sub}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 6. Collapsible Project Roadmap */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <div
          onClick={() => setShowRoadmap(!showRoadmap)}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={16} />
            <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>
              Project Lifecycle Roadmap (Stages 1 – 6)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: '#666' }}>
            <span>{showRoadmap ? 'Hide Roadmap' : 'Show Roadmap'}</span>
            {showRoadmap ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </div>
        </div>

        {showRoadmap && (
          <div style={{ marginTop: '16px', borderTop: '1px solid #e5e5e5', paddingTop: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              {roadmapSteps.map((step) => (
                <div
                  key={step.stage}
                  style={{
                    padding: '12px',
                    borderRadius: '6px',
                    background: step.status === 'active' ? '#0a0a0a' : '#f8f8f8',
                    color: step.status === 'active' ? '#ffffff' : '#0a0a0a',
                    border: '1px solid',
                    borderColor: step.status === 'active' ? '#0a0a0a' : '#e5e5e5',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase' }}>
                      {step.stage}
                    </span>
                    <span
                      style={{
                        fontSize: '0.65rem',
                        padding: '1px 5px',
                        borderRadius: '3px',
                        background: step.status === 'active' ? '#ffffff' : '#e5e5e5',
                        color: step.status === 'active' ? '#0a0a0a' : '#333333',
                        fontWeight: 600,
                      }}
                    >
                      {step.status}
                    </span>
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '0.82rem', marginBottom: '4px' }}>
                    {step.title}
                  </div>
                  <div style={{ fontSize: '0.73rem', opacity: 0.85, lineHeight: 1.4 }}>
                    {step.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
