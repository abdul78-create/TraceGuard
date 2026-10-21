import React from 'react'
import {
  Server,
  Cpu,
  Layers,
  HelpCircle,
  Clock,
  Shield,
  Activity,
} from 'lucide-react'
import type { HealthResponse, ModelStatusResponse } from '../types/api'

interface OverviewTabProps {
  health: HealthResponse | null
  modelStatus: ModelStatusResponse | null
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  health,
  modelStatus,
}) => {
  const subsystems = [
    {
      name: 'FastAPI Backend Core',
      icon: Server,
      status: health?.services?.api_server?.status || 'checking',
      detail: health?.services?.api_server?.message || 'Connecting to local API...',
      healthy: health?.services?.api_server?.status === 'up',
    },
    {
      name: 'ML Inference Engine',
      icon: Cpu,
      status: modelStatus?.lifecycle_status || 'UNCONFIGURED',
      detail: 'Pydantic flow schemas verified. Model training scheduled for Stages 3-4.',
      healthy: false,
      warning: true,
    },
    {
      name: 'Telemetry & Drift Stream',
      icon: Activity,
      status: health?.services?.telemetry_stream?.status || 'idle',
      detail: 'Awaiting reference baseline distribution in Stage 2.',
      healthy: false,
      neutral: true,
    },
  ]

  const roadmapSteps = [
    {
      stage: 'Stage 1',
      title: 'Project Foundation',
      status: 'active',
      desc: 'Project architecture, clean contracts, backend API, health probes, test suite, and responsive dashboard shell.',
    },
    {
      stage: 'Stage 2',
      title: 'Dataset Selection & Exploration',
      status: 'pending',
      desc: 'Evaluate public intrusion datasets (CIC-IDS2017/2018, UNSW-NB15). Document limitations and class imbalance.',
    },
    {
      stage: 'Stage 3',
      title: 'Baseline Machine Learning',
      status: 'pending',
      desc: 'Leakage-resistant train/val/test splits, baseline classifier, class imbalance handling, PR-AUC and Macro-F1 evaluation.',
    },
    {
      stage: 'Stage 4',
      title: 'Adaptive Detection & Abstention',
      status: 'pending',
      desc: 'Anomaly detection (Isolation Forest), unseen attack holdout experiment, Platt/isotonic calibration, and abstention policy.',
    },
    {
      stage: 'Stage 5',
      title: 'Live Dashboard Integration',
      status: 'pending',
      desc: 'Connect real-time API predictions, alert triage feed, confidence indicators, and interactive drift visualizers.',
    },
    {
      stage: 'Stage 6',
      title: 'Verification & Deployment',
      status: 'pending',
      desc: 'End-to-end security audit, reproducible evaluation benchmarks, and artifact export.',
    },
  ]

  return (
    <div>
      {/* Subsystems Matrix */}
      <div className="grid-cols-3">
        {subsystems.map((sub, i) => {
          const Icon = sub.icon
          return (
            <div key={i} className="card">
              <div className="card-header">
                <span className="card-title">
                  <Icon size={18} color="var(--accent-cyan)" />
                  {sub.name}
                </span>
                <span
                  className={`badge ${
                    sub.healthy
                      ? 'badge-emerald'
                      : sub.warning
                      ? 'badge-amber'
                      : 'badge-blue'
                  }`}
                >
                  <span
                    className={`pulse-dot ${
                      sub.healthy
                        ? 'pulse-emerald'
                        : sub.warning
                        ? 'pulse-amber'
                        : 'pulse-blue'
                    }`}
                  />
                  {sub.status}
                </span>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {sub.detail}
              </p>
            </div>
          )
        })}
      </div>

      {/* Research Question & Architecture */}
      <div className="grid-cols-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <HelpCircle size={18} color="var(--accent-cyan)" />
              Core Research Objective
            </span>
          </div>
          <div
            style={{
              background: 'rgba(56, 189, 248, 0.05)',
              border: '1px solid rgba(56, 189, 248, 0.2)',
              borderRadius: '8px',
              padding: '16px',
              marginBottom: '16px',
            }}
          >
            <p
              style={{
                fontSize: '0.92rem',
                fontWeight: 500,
                color: '#fff',
                lineHeight: 1.6,
              }}
            >
              "Can TraceGuard detect threats reliably when attack categories are unseen or network traffic changes, and can it recognize when it should not trust its own prediction?"
            </p>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Unlike naive network IDS that attempt binary classification on standard benchmarks, TraceGuard incorporates <strong>selective prediction (abstention)</strong>, <strong>probability calibration</strong>, and <strong>unsupervised anomaly scoring</strong> to avoid silently misclassifying unfamiliar zero-day attacks as benign.
          </p>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Layers size={18} color="var(--accent-cyan)" />
              Adaptive Triage Architecture
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 14px',
                background: 'var(--bg-surface-elevated)',
                borderRadius: '6px',
                fontSize: '0.82rem',
              }}
            >
              <Activity size={16} color="var(--accent-cyan)" />
              <span>1. Network Flow Feature Vector (20 normalized flow metrics)</span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 14px',
                background: 'var(--bg-surface-elevated)',
                borderRadius: '6px',
                fontSize: '0.82rem',
              }}
            >
              <Cpu size={16} color="var(--accent-cyan)" />
              <span>2. Multi-class Classifier + Unsupervised Isolation Forest</span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 14px',
                background: 'var(--bg-surface-elevated)',
                borderRadius: '6px',
                fontSize: '0.82rem',
              }}
            >
              <Shield size={16} color="var(--status-amber)" />
              <span>3. Confidence Calibration & Abstention Policy Engine</span>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '8px',
                marginTop: '4px',
              }}
            >
              <div
                style={{
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  padding: '8px',
                  borderRadius: '6px',
                  textAlign: 'center',
                  fontSize: '0.75rem',
                  color: 'var(--status-emerald)',
                  fontWeight: 600,
                }}
              >
                Likely Benign
              </div>
              <div
                style={{
                  background: 'rgba(244, 63, 94, 0.1)',
                  border: '1px solid rgba(244, 63, 94, 0.3)',
                  padding: '8px',
                  borderRadius: '6px',
                  textAlign: 'center',
                  fontSize: '0.75rem',
                  color: 'var(--status-rose)',
                  fontWeight: 600,
                }}
              >
                Threat Suspected
              </div>
              <div
                style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  padding: '8px',
                  borderRadius: '6px',
                  textAlign: 'center',
                  fontSize: '0.75rem',
                  color: 'var(--status-amber)',
                  fontWeight: 600,
                }}
              >
                Abstain (Review)
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Roadmap Progression */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={18} color="var(--accent-cyan)" />
            Engineering & Research Roadmap
          </span>
          <span className="badge badge-blue">Stage 1 Active</span>
        </div>

        <div>
          {roadmapSteps.map((step, idx) => {
            const isActive = step.status === 'active'
            return (
              <div
                key={idx}
                className={`roadmap-step ${isActive ? 'active' : ''}`}
              >
                <div
                  className={`step-num ${
                    isActive ? 'active' : 'pending'
                  }`}
                >
                  {idx + 1}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="step-title">{step.title}</span>
                    <span
                      className={`badge ${
                        isActive ? 'badge-blue' : 'badge-amber'
                      }`}
                      style={{ fontSize: '0.7rem', padding: '2px 8px' }}
                    >
                      {step.stage}
                    </span>
                  </div>
                  <p className="step-desc">{step.desc}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
