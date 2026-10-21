import React from 'react'
import {
  BarChart3,
  Scale,
  Crosshair,
  TrendingUp,
  FileCheck2,
  AlertTriangle,
} from 'lucide-react'
import type { EvaluationMetricsResponse } from '../types/api'

interface EvaluationTabProps {
  evaluation: EvaluationMetricsResponse | null
}

export const EvaluationTab: React.FC<EvaluationTabProps> = ({ evaluation }) => {
  const protocols = [
    {
      title: 'Precision-Recall AUC (PR-AUC)',
      icon: Crosshair,
      desc: 'In network security, 99%+ of flows are benign. Standard ROC-AUC produces inflated, misleading scores. We will report PR-AUC for minority attack classes.',
    },
    {
      title: 'Unseen-Attack Holdout Experiment',
      icon: Scale,
      desc: 'Deliberately withhold entire attack families (e.g., Botnets or Infiltration) during training. Evaluate if anomaly scoring triggers abstention rather than false benign.',
    },
    {
      title: 'Confidence Calibration (ECE)',
      icon: TrendingUp,
      desc: 'Softmax probabilities are frequently overconfident. We will measure Expected Calibration Error (ECE) before and after Platt Scaling/Isotonic Regression.',
    },
    {
      title: 'Coverage vs. Risk Analysis',
      icon: FileCheck2,
      desc: 'Evaluate detector error rate as a function of the abstention coverage threshold to quantify the benefit of routing uncertain flows to review.',
    },
  ]

  return (
    <div>
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">
            <BarChart3 size={18} color="var(--accent-cyan)" />
            Empirical Evaluation Benchmarks
          </span>
          <span className="badge badge-amber">No Evaluation Active</span>
        </div>

        {/* Empty state */}
        <div className="empty-state">
          <div className="empty-state-icon">
            <AlertTriangle size={28} color="var(--status-amber)" />
          </div>
          <h3 className="empty-state-title">No Evaluation Benchmark Results Available</h3>
          <p className="empty-state-description">
            {evaluation?.message ||
              'Evaluation benchmarks will be executed during Stage 3 (Baseline) and Stage 4 (Adaptive Detection). No fake accuracy values or synthetic confusion matrices are shown.'}
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="badge badge-blue">Stage 1 Foundation Active</span>
            <span className="badge badge-amber">Awaiting Stage 3-4 Experiments</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Scale size={18} color="var(--accent-cyan)" />
            Planned Scientific Evaluation Protocols
          </span>
          <span className="badge badge-blue">Methodology Specs</span>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          To ensure TraceGuard is evaluated as a rigorous research system rather than a generic demo, our evaluation pipeline will implement four critical experiments:
        </p>

        <div className="grid-cols-2">
          {protocols.map((proto, idx) => {
            const Icon = proto.icon
            return (
              <div
                key={idx}
                style={{
                  background: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '16px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <Icon size={18} color="var(--accent-cyan)" />
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#fff' }}>
                    {proto.title}
                  </span>
                </div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {proto.desc}
                </p>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
