import React from 'react'
import {
  Scale,
  Crosshair,
  ShieldAlert,
  Sliders,
  Info,
  AlertCircle,
} from 'lucide-react'
import type { EvaluationMetricsResponse } from '../types/api'

interface EvaluationTabProps {
  evaluation: EvaluationMetricsResponse | null
}

/* Mini bar for policy comparison */
const PolicyBar: React.FC<{ value: number; label: string; emphasis?: boolean }> = ({ value, label, emphasis }) => (
  <div>
    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.73rem', marginBottom: '3px' }}>
      <span style={{ color: '#666' }}>{label}</span>
      <span style={{ fontWeight: 700, color: emphasis ? '#0a0a0a' : '#888' }}>{value.toFixed(2)}%</span>
    </div>
    <div className="progress-track">
      <div
        className="progress-fill"
        style={{
          width: `${Math.min(100, value)}%`,
          background: emphasis ? '#0a0a0a' : '#bbb',
        }}
      />
    </div>
  </div>
)

export const EvaluationTab: React.FC<EvaluationTabProps> = ({ evaluation }) => {
  const isAvailable = evaluation ? evaluation.evaluation_available : false
  const polA = evaluation?.triage_policies?.policy_a_permissive
  const polB = evaluation?.triage_policies?.policy_b_balanced
  const polC = evaluation?.triage_policies?.policy_c_conservative
  const totalBot = evaluation?.unseen_attack_metrics?.total_bot_flows ?? 1953

  return (
    <div>
      {/* Intro */}
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.3rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '6px' }}>
          Model Evaluation
        </h2>
        <p style={{ fontSize: '0.85rem', color: '#555', maxWidth: '680px', lineHeight: 1.6 }}>
          These are frozen research measurements from a controlled offline experiment on the{' '}
          <strong>CIC-IDS2017 dataset</strong>. They reflect how the model performed on data it was
          never trained on — not live production performance.
        </p>
      </div>

      {/* API error notice */}
      {evaluation && !isAvailable && (
        <div className="notice-banner notice-banner-warn" style={{ marginBottom: '20px' }}>
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Evaluation Data Unavailable</strong>
            <div style={{ fontSize: '0.78rem', marginTop: '2px' }}>
              {evaluation.message || 'The offline Stage 4.1 evaluation benchmark report could not be loaded.'}
            </div>
          </div>
        </div>
      )}

      {/* Offline Disclaimer */}
      <div className="info-callout" style={{ marginBottom: '20px' }}>
        <strong>Offline Research Benchmark:</strong>{' '}
        {evaluation?.offline_disclaimer || 'These metrics reflect offline research experiments evaluated on CIC-IDS2017 leakage-free partitions and do not represent live production performance.'}
        {!evaluation && (
          <span style={{ marginLeft: '8px', fontStyle: 'italic', color: '#666' }}>
            · API Offline — Reference Data
          </span>
        )}
      </div>

      {!evaluation && (
        <div className="notice-banner notice-banner-neutral" style={{ marginBottom: '20px' }}>
          <AlertCircle size={16} style={{ flexShrink: 0 }} />
          <span>
            <strong>Historical Reference Baseline:</strong> The backend API is unreachable. The figures
            below are frozen offline reference measurements from the CIC-IDS2017 research evaluation
            and must not be interpreted as live production performance.
          </span>
        </div>
      )}

      {/* 4 headline metrics */}
      <p className="section-heading">Key Findings</p>
      <div className="grid-cols-4" style={{ marginBottom: '24px' }}>
        <div className="metric-card" style={{ borderLeft: '3px solid #0a0a0a' }}>
          <div className="metric-label">
            Known-Traffic Macro-F1
            {' '}<span title="Average F1 across all classes. Near-perfect on seen attack types."><Info size={12} style={{ display: 'inline', marginLeft: 2, color: '#aaa', cursor: 'help' }} /></span>
          </div>
          <div className="metric-value">
            {evaluation?.metrics?.macro_f1 ? `${(evaluation.metrics.macro_f1 * 100).toFixed(2)}%` : '99.89%'}
          </div>
          <div className="metric-desc">
            Recall {evaluation?.metrics?.attack_recall ? `${(evaluation.metrics.attack_recall * 100).toFixed(2)}%` : '99.81%'} · FPR 0.038%
          </div>
        </div>

        <div className="metric-card" style={{ borderLeft: '3px solid #888' }}>
          <div className="metric-label">
            Unseen Bot Family Recall
            {' '}<span title="0% means the classifier missed every Bot flow — a critical security gap that justifies the anomaly detector."><Info size={12} style={{ display: 'inline', marginLeft: 2, color: '#aaa', cursor: 'help' }} /></span>
          </div>
          <div className="metric-value" style={{ color: '#444' }}>0.00%</div>
          <div className="metric-desc">
            0 / {totalBot.toLocaleString()} detected by classifier alone (mean P ≈ 0.02%)
          </div>
        </div>

        <div className="metric-card" style={{ borderLeft: '3px solid #bbb' }}>
          <div className="metric-label">
            Platt Calibrated ECE
            {' '}<span title="Expected Calibration Error: how well probabilities match actual accuracy. Lower is better. Platt scaling reduced this by 92%."><Info size={12} style={{ display: 'inline', marginLeft: 2, color: '#aaa', cursor: 'help' }} /></span>
          </div>
          <div className="metric-value" style={{ fontSize: '1.4rem' }}>
            {evaluation?.calibration_summary?.calibrated_ece
              ? evaluation.calibration_summary.calibrated_ece.toFixed(6)
              : '0.000151'}
          </div>
          <div className="metric-desc">92.3% error reduction from raw ECE via Platt sigmoid</div>
        </div>

        <div className="metric-card" style={{ borderLeft: '3px solid #0a0a0a' }}>
          <div className="metric-label">
            Anomaly Catch — Policy B
            {' '}<span title="Policy B (Balanced) flagged 5.33% of unseen Bot flows for human review — the rest were silently cleared as benign."><Info size={12} style={{ display: 'inline', marginLeft: 2, color: '#aaa', cursor: 'help' }} /></span>
          </div>
          <div className="metric-value">
            {polB?.heldout_bot_safety_rate != null
              ? `${(polB.heldout_bot_safety_rate * 100).toFixed(2)}%`
              : '5.33%'}
          </div>
          <div className="metric-desc">
            {polB?.heldout_bot_abstain_count ?? 104} / {totalBot.toLocaleString()} Bot flows flagged for human review
          </div>
        </div>
      </div>

      {/* Two analytical pillars */}
      <div className="grid-cols-2" style={{ marginBottom: '24px' }}>
        {/* Known attack discrimination */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Crosshair size={16} />
              Known-Attack Discrimination
            </span>
            <span className="badge badge-ok">Near-Perfect</span>
          </div>
          <p className="card-subtitle" style={{ marginBottom: '12px' }}>
            Tested on 377,853 known-traffic flows (DoS Hulk, PortScan, DDoS, Brute Force).
            The model achieves high accuracy on familiar attack patterns.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '12px' }}>
            {[
              { label: 'PR-AUC', value: evaluation?.metrics?.pr_auc ?? 0.999901, fmt: (v: number) => v.toFixed(6) },
              { label: 'ROC-AUC', value: evaluation?.metrics?.roc_auc ?? 0.99998, fmt: (v: number) => v.toFixed(6) },
              { label: 'False Positive Rate', value: evaluation?.metrics?.fpr ?? 0.000382, fmt: (v: number) => `${(v * 100).toFixed(4)}%` },
              { label: 'Calibration Brier', value: evaluation?.calibration_summary?.calibrated_brier ?? 0.00054, fmt: (v: number) => v.toFixed(5) },
            ].map(({ label, value, fmt }) => (
              <div key={label} style={{ background: '#f8f8f8', padding: '10px', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#888', marginBottom: '2px' }}>{label}</div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#0a0a0a' }}>{fmt(value)}</div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: '0.74rem', color: '#aaa' }}>
            * Evaluated on an untouched known-test partition with zero feature-hash overlap with training splits.
          </p>
        </div>

        {/* Zero-day failure */}
        <div className="card" style={{ borderColor: '#c8c8c8' }}>
          <div className="card-header">
            <span className="card-title">
              <ShieldAlert size={16} />
              Held-Out Attack Failure (Botnet Ares)
            </span>
            <span className="badge badge-danger">Critical Finding</span>
          </div>
          <p className="card-subtitle" style={{ marginBottom: '12px' }}>
            To simulate a real zero-day threat, all 1,953 Bot flows were removed from training
            and evaluated as unknown traffic.
          </p>

          <div style={{
            background: '#f8f8f8',
            border: '1px solid #e5e5e5',
            borderRadius: '8px',
            padding: '12px 14px',
            marginBottom: '12px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.82rem' }}>
              <span style={{ color: '#555' }}>Supervised Classifier Recall:</span>
              <strong>0.00% — 0 / 1,953 flows caught</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#666' }}>
              <span>Mean Predicted Attack Probability:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>0.0002 (0.02%)</span>
            </div>
            <div className="divider" style={{ margin: '10px 0' }} />
            <p style={{ fontSize: '0.76rem', color: '#333', lineHeight: 1.5 }}>
              <strong>Silent Failure:</strong> The supervised model was extremely confident that Bot C2
              traffic was benign. This proves high benchmark accuracy does not translate to zero-day threat detection.
            </p>
          </div>

          <p style={{ fontSize: '0.78rem', color: '#555', lineHeight: 1.5 }}>
            <strong>Mitigation:</strong> The Isolation Forest anomaly detector scores Bot flows as
            atypical. Triage policies can route them to human review instead of silently clearing them.
          </p>
        </div>
      </div>

      {/* Triage policy comparison table */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">
            <Scale size={16} />
            Selective Prediction Triage Policy Comparison
          </span>
          <span className="badge badge-neutral">3 Versioned Policies</span>
        </div>
        <p style={{ fontSize: '0.82rem', color: '#555', marginBottom: '14px', lineHeight: 1.5 }}>
          Each policy sets a different anomaly score threshold (τ). A higher threshold lets more traffic
          through automatically; a lower threshold routes more traffic to human analysts. The table shows
          the trade-off on held-out Bot flows.
        </p>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Policy</th>
                <th>Threshold (τ)</th>
                <th>Known Coverage</th>
                <th>Bot Falsely Cleared</th>
                <th>Bot Caught / Abstained</th>
                <th>Use Case</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <strong>A — Permissive</strong>
                  <div style={{ fontSize: '0.7rem', color: '#888', marginTop: 2 }}>Default baseline</div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>0.6001</td>
                <td>
                  {polA?.known_test_coverage != null
                    ? `${(polA.known_test_coverage * 100).toFixed(2)}%`
                    : '95.88%'}
                </td>
                <td style={{ fontWeight: 600 }}>
                  {polA
                    ? `${polA.heldout_bot_falsely_cleared_benign_count.toLocaleString()} (${(polA.heldout_bot_false_clearance_rate * 100).toFixed(2)}%)`
                    : '1,909 (97.75%)'}
                </td>
                <td>
                  {polA
                    ? `${polA.heldout_bot_abstain_count.toLocaleString()} (${(polA.heldout_bot_safety_rate * 100).toFixed(2)}%)`
                    : '44 (2.25%)'}
                </td>
                <td style={{ fontSize: '0.76rem', color: '#666' }}>High-throughput SOC, minimal analyst queue</td>
              </tr>
              <tr style={{ background: '#fafafa', fontWeight: 500 }}>
                <td>
                  <strong>B — Balanced</strong>
                  <div style={{ fontSize: '0.7rem', color: '#555', marginTop: 2 }}>✓ Recommended</div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>0.1873</td>
                <td>
                  {polB?.known_test_coverage != null
                    ? `${(polB.known_test_coverage * 100).toFixed(2)}%`
                    : '79.20%'}
                </td>
                <td style={{ fontWeight: 600 }}>
                  {polB
                    ? `${polB.heldout_bot_falsely_cleared_benign_count.toLocaleString()} (${(polB.heldout_bot_false_clearance_rate * 100).toFixed(2)}%)`
                    : '1,849 (94.67%)'}
                </td>
                <td style={{ fontWeight: 700 }}>
                  {polB
                    ? `${polB.heldout_bot_abstain_count.toLocaleString()} (${(polB.heldout_bot_safety_rate * 100).toFixed(2)}%)`
                    : '104 (5.33%)'}
                </td>
                <td style={{ fontSize: '0.76rem', color: '#555' }}>Balanced security — catches 2.4× more Bot flows than A</td>
              </tr>
              <tr>
                <td>
                  <strong>C — Zero-Trust</strong>
                  <div style={{ fontSize: '0.7rem', color: '#888', marginTop: 2 }}>Maximum caution</div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>0.0756</td>
                <td>
                  {polC?.known_test_coverage != null
                    ? `${(polC.known_test_coverage * 100).toFixed(2)}%`
                    : '58.34%'}
                </td>
                <td>
                  {polC
                    ? `${polC.heldout_bot_falsely_cleared_benign_count.toLocaleString()} (${(polC.heldout_bot_false_clearance_rate * 100).toFixed(2)}%)`
                    : '802 (41.07%)'}
                </td>
                <td style={{ fontWeight: 700 }}>
                  {polC
                    ? `${polC.heldout_bot_abstain_count.toLocaleString()} (${(polC.heldout_bot_safety_rate * 100).toFixed(2)}%)`
                    : '1,151 (58.93%)'}
                </td>
                <td style={{ fontSize: '0.76rem', color: '#666' }}>Critical infrastructure — routes all median outliers to analysts</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Visual policy comparison bars */}
        <div style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div>
            <p className="section-heading" style={{ marginBottom: '8px' }}>Bot Flows Caught (Higher = Safer)</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <PolicyBar value={polA?.heldout_bot_safety_rate != null ? polA.heldout_bot_safety_rate * 100 : 2.25} label="Policy A" />
              <PolicyBar value={polB?.heldout_bot_safety_rate != null ? polB.heldout_bot_safety_rate * 100 : 5.33} label="Policy B" emphasis />
              <PolicyBar value={polC?.heldout_bot_safety_rate != null ? polC.heldout_bot_safety_rate * 100 : 58.93} label="Policy C" />
            </div>
          </div>
          <div>
            <p className="section-heading" style={{ marginBottom: '8px' }}>Known Traffic Auto-Cleared (Higher = More Efficient)</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <PolicyBar value={polA?.known_test_coverage != null ? polA.known_test_coverage * 100 : 95.88} label="Policy A" />
              <PolicyBar value={polB?.known_test_coverage != null ? polB.known_test_coverage * 100 : 79.20} label="Policy B" emphasis />
              <PolicyBar value={polC?.known_test_coverage != null ? polC.known_test_coverage * 100 : 58.34} label="Policy C" />
            </div>
          </div>
        </div>
      </div>

      {/* Anomaly Operating Points table */}
      {evaluation?.operating_points && evaluation.operating_points.length > 0 && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Sliders size={16} />
              Benign-Only Anomaly Detector Operating Points
            </span>
            <span className="badge badge-neutral">Isolation Forest Calibration</span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#555', marginBottom: '14px', lineHeight: 1.5 }}>
            Each row shows a different anomaly threshold (τ) and the resulting trade-off between
            false alarms on benign traffic and Bot flow detection. Lower τ = more Bot flows caught,
            but more normal traffic also gets flagged.
          </p>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target Benign FPR</th>
                  <th>Threshold (τ)</th>
                  <th>Measured Benign FPR</th>
                  <th>Known Attack Recall</th>
                  <th>Bot Recall</th>
                  <th>Bot Flagged</th>
                </tr>
              </thead>
              <tbody>
                {evaluation.operating_points.map((pt, idx) => (
                  <tr key={idx}>
                    <td><span className="badge badge-neutral">{pt.target_fpr}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{pt.threshold.toFixed(6)}</td>
                    <td>{(pt.measured_test_benign_fpr * 100).toFixed(2)}%</td>
                    <td style={{ fontWeight: 600 }}>{(pt.test_known_attack_recall * 100).toFixed(2)}%</td>
                    <td style={{ fontWeight: pt.heldout_bot_recall > 0.05 ? 700 : 400 }}>
                      {(pt.heldout_bot_recall * 100).toFixed(2)}%
                    </td>
                    <td>{pt.heldout_bot_detected_count} / {pt.heldout_bot_total_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
