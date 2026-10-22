import React from 'react'
import {
  TrendingDown,
  Sliders,
  Info,
  Calendar,
  AlertCircle,
  Radio,
} from 'lucide-react'
import type { DriftStatusResponse } from '../types/api'

interface DriftTabProps {
  drift: DriftStatusResponse | null
}

export const DriftTab: React.FC<DriftTabProps> = ({ drift }) => {
  const isAvailable = drift
    ? Boolean(drift.monitoring_active || drift.historical_analysis_available)
    : false

  const dailyFprData = [
    { day: 'Monday', role: 'Early Train Split', fpr: 4.04, label: 'Baseline Reference', barWidth: 40.4 },
    { day: 'Tuesday', role: 'Early Train Split', fpr: 4.25, label: 'Nominal (+0.21%)', barWidth: 42.5 },
    { day: 'Wednesday', role: 'Mid Validation Split', fpr: 5.05, label: 'Nominal (+1.01%)', barWidth: 50.5 },
    { day: 'Thursday', role: 'Late Test Split', fpr: 3.57, label: 'Suppressed (-0.47%)', barWidth: 35.7 },
    { day: 'Friday', role: 'Late Test Split', fpr: 8.07, label: 'Elevated (+4.03%)*', barWidth: 80.7, dark: true },
  ]

  return (
    <div>
      {/* Intro */}
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.3rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '6px' }}>
          Drift Monitoring
        </h2>
        <p style={{ fontSize: '0.85rem', color: '#555555', maxWidth: '700px', lineHeight: 1.6 }}>
          Checks whether network traffic patterns differ from the baseline data used to train the system.
          In this controlled research experiment, we measure covariate shift across different capture days.
          Continuous real-time stream ingestion is currently inactive.
        </p>
      </div>

      {/* If API explicitly returned historical_analysis_available === false, show notice */}
      {drift && !isAvailable && (
        <div className="notice-banner notice-banner-warn" style={{ marginBottom: '20px' }}>
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600, color: '#0a0a0a', marginBottom: '2px' }}>
              Traffic Drift Telemetry Unavailable
            </div>
            <div style={{ fontSize: '0.78rem', color: '#555555' }}>
              {drift.message ||
                'Traffic drift monitoring is currently inactive. No live stream or historical covariate shift analysis is available.'}
            </div>
          </div>
        </div>
      )}

      {/* Prominent Offline Study Banner & Stream Status */}
      <div
        style={{
          background: '#f8f8f8',
          border: '1px solid #c8c8c8',
          borderRadius: '8px',
          padding: '12px 18px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Info size={16} style={{ color: '#0a0a0a', flexShrink: 0 }} />
          <span style={{ fontSize: '0.84rem', color: '#222222' }}>
            <strong>Historical Covariate Shift Analysis:</strong>{' '}
            {drift?.offline_disclaimer ||
              'Historical dataset-specific covariate shift analysis across CIC-IDS2017 capture days. Continuous real-time streaming is inactive.'}
            {!drift && (
              <span style={{ marginLeft: '8px', color: '#555555', fontWeight: 600, fontSize: '0.78rem' }}>
                [API Offline — Displaying Reference Study]
              </span>
            )}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '3px 8px',
              borderRadius: '9999px',
              border: '1px solid #888888',
              background: '#f0f0f0',
              fontSize: '0.72rem',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: '#333333',
            }}
          >
            <Radio size={10} style={{ animation: 'none' }} />
            Live Stream: Inactive
          </span>
        </div>
      </div>

      {/* Prominent Reference Baseline Warning when API is offline */}
      {!drift && (
        <div className="notice-banner notice-banner-neutral" style={{ marginBottom: '20px' }}>
          <AlertCircle size={16} style={{ flexShrink: 0 }} />
          <span>
            <strong>Historical Reference Baseline Notice:</strong> The backend API is unreachable. The PSI
            distributions and daily FPR measurements below are frozen historical reference figures from the
            CIC-IDS2017 dataset experiments. Real-time production telemetry is disconnected.
          </span>
        </div>
      )}

      {/* Primary PSI & Stability Cards (3 Cards) */}
      <p className="section-heading">Population Stability Index (PSI) Overview</p>
      <div className="grid-cols-3" style={{ marginBottom: '24px' }}>
        <div className="card" style={{ borderLeft: '3px solid #0a0a0a' }}>
          <div className="card-header" style={{ marginBottom: '4px' }}>
            <span className="field-label" style={{ marginBottom: 0 }}>
              Stable Features (PSI &lt; 0.10)
            </span>
            <span title="Features whose statistical distribution stayed stable across capture days.">
              <Info size={13} style={{ color: '#888888', cursor: 'help' }} />
            </span>
          </div>
          <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#0a0a0a', letterSpacing: '-0.02em', marginBottom: '4px' }}>
            {drift?.psi_summary?.stable_count_psi_under_0_1 ?? 67} / 69
          </div>
          <div style={{ fontSize: '0.75rem', color: '#555555' }}>
            97.1% of features exhibit negligible distribution shift across recording days
          </div>
        </div>

        <div className="card" style={{ borderLeft: '3px solid #555555' }}>
          <div className="card-header" style={{ marginBottom: '4px' }}>
            <span className="field-label" style={{ marginBottom: 0 }}>
              Moderate Drift Features (0.10 &le; PSI &lt; 0.25)
            </span>
            <span title="Features showing moderate distribution shifts between early and late days.">
              <Info size={13} style={{ color: '#888888', cursor: 'help' }} />
            </span>
          </div>
          <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#0a0a0a', letterSpacing: '-0.02em', marginBottom: '4px' }}>
            {drift?.psi_summary?.moderate_count_psi_0_1_to_0_25 ?? 2}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#555555' }}>
            Max Packet Length (0.1148) • Bwd Pkt Length Max (0.1058)
          </div>
        </div>

        <div className="card" style={{ borderLeft: '3px solid #c8c8c8' }}>
          <div className="card-header" style={{ marginBottom: '4px' }}>
            <span className="field-label" style={{ marginBottom: 0 }}>
              Significant Drift Features (PSI &ge; 0.25)
            </span>
            <span title="Features undergoing major distribution collapse. None observed.">
              <Info size={13} style={{ color: '#888888', cursor: 'help' }} />
            </span>
          </div>
          <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#0a0a0a', letterSpacing: '-0.02em', marginBottom: '4px' }}>
            {drift?.psi_summary?.significant_count_psi_ge_0_25 ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#555555' }}>
            No catastrophic feature collapse observed across the dataset
          </div>
        </div>
      </div>

      {/* Two Columns: Daily FPR Shift & Population Stability Index */}
      <div className="grid-cols-2" style={{ marginBottom: '24px' }}>
        {/* Daily Anomaly FPR Shift */}
        <div className="card">
          <div className="card-header">
            <div>
              <span className="card-title" style={{ gap: '8px' }}>
                <Calendar size={16} />
                Daily False-Positive Rate Variation (Covariate Shift)
              </span>
              <p className="card-subtitle">
                False alarm rate on normal traffic across distinct days at fixed threshold (τ_5% = 0.6001)
              </p>
            </div>
            <span className="badge badge-neutral">Dataset Variance</span>
          </div>

          <p style={{ fontSize: '0.8rem', color: '#555555', lineHeight: 1.5, marginBottom: '14px' }}>
            Shows how often harmless traffic was flagged as unusual on each recording day. Heavier video and download activity on Friday naturally elevated anomaly scores.
          </p>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Capture Day</th>
                  <th>Partition Role</th>
                  <th>Benign FPR</th>
                  <th>Visual Distribution</th>
                  <th>Shift Status</th>
                </tr>
              </thead>
              <tbody>
                {dailyFprData.map((row) => (
                  <tr key={row.day}>
                    <td style={{ fontWeight: 600 }}>{row.day}</td>
                    <td style={{ fontSize: '0.76rem', color: '#666666' }}>{row.role}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{row.fpr.toFixed(2)}%</td>
                    <td style={{ minWidth: '90px' }}>
                      <div className="progress-track" style={{ height: '6px' }}>
                        <div
                          className="progress-fill"
                          style={{
                            width: `${row.barWidth}%`,
                            background: row.dark ? '#0a0a0a' : '#888888',
                          }}
                        />
                      </div>
                    </td>
                    <td>
                      <span
                        className="badge badge-neutral"
                        style={{
                          fontSize: '0.68rem',
                          background: row.dark ? '#0a0a0a' : '#f0f0f0',
                          color: row.dark ? '#ffffff' : '#333333',
                          border: `1px solid ${row.dark ? '#0a0a0a' : '#c8c8c8'}`,
                        }}
                      >
                        {row.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: '0.73rem', color: '#777777', marginTop: '10px' }}>
            * Friday benign traffic included heavy file downloads and media streaming, causing an expected rise in baseline anomaly detections.
          </div>
        </div>

        {/* Top Drifted Features by PSI */}
        <div className="card">
          <div className="card-header">
            <div>
              <span className="card-title" style={{ gap: '8px' }}>
                <Sliders size={16} />
                Top Drifted Features (Population Stability Index)
              </span>
              <p className="card-subtitle">
                Early capture days (Mon–Tue: 903k flows) vs. late days (Thu–Fri: 795k flows)
              </p>
            </div>
            <span className="badge badge-neutral">Early vs. Late</span>
          </div>

          <p style={{ fontSize: '0.8rem', color: '#555555', lineHeight: 1.5, marginBottom: '14px' }}>
            Population Stability Index (PSI) measures how much a feature's distribution shifted. Values below 0.10 indicate high stability.
          </p>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature Name</th>
                  <th>PSI Score</th>
                  <th>Distribution Bar</th>
                  <th>Shift Classification</th>
                </tr>
              </thead>
              <tbody>
                {drift?.psi_summary?.top_10_drifted_features?.slice(0, 6).map((item, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.77rem', color: '#0a0a0a' }}>
                      {item.feature}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {item.psi.toFixed(4)}
                    </td>
                    <td style={{ minWidth: '80px' }}>
                      <div className="progress-track" style={{ height: '6px' }}>
                        <div
                          className="progress-fill"
                          style={{
                            width: `${Math.min(100, (item.psi / 0.25) * 100)}%`,
                            background: item.psi >= 0.1 ? '#0a0a0a' : '#aaaaaa',
                          }}
                        />
                      </div>
                    </td>
                    <td>
                      <span
                        className="badge badge-neutral"
                        style={{
                          fontSize: '0.68rem',
                          background: item.psi >= 0.1 ? '#f5f5f5' : '#ffffff',
                          border: `1px solid ${item.psi >= 0.1 ? '#555555' : '#c8c8c8'}`,
                          color: '#111111',
                        }}
                      >
                        {item.psi >= 0.1 ? 'Moderate Covariate Shift' : 'Stable Distribution'}
                      </span>
                    </td>
                  </tr>
                )) || (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: '#777777', padding: '16px' }}>
                      Loading PSI feature distribution data…
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: '0.73rem', color: '#777777', marginTop: '10px' }}>
            Threshold guide: PSI &lt; 0.10: Stable · 0.10 &le; PSI &lt; 0.25: Moderate Shift · PSI &ge; 0.25: Significant Drift.
          </div>
        </div>
      </div>

      {/* Scientific Distinction: Covariate Shift vs Concept Drift */}
      <div className="grid-cols-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title" style={{ gap: '8px' }}>
              <Info size={16} />
              Covariate Shift vs. True Concept Drift
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#555555', lineHeight: 1.6, marginBottom: '12px' }}>
            <strong>Methodological Rigor:</strong> In CIC-IDS2017, day-to-day feature differences reflect shifts in
            background user activity (different users browsing, file downloads, video streams). This is{' '}
            <em>covariate shift</em> P(X), not proof that attack definitions or network concepts have changed P(Y|X).
          </p>
          <div
            style={{
              background: '#f8f8f8',
              border: '1px solid #e5e5e5',
              borderRadius: '8px',
              padding: '12px 14px',
              fontSize: '0.78rem',
              color: '#333333',
              lineHeight: 1.5,
            }}
          >
            TraceGuard treats day-to-day distribution variation cautiously and does not claim continuous adaptive
            retraining without human-in-the-loop ground truth verification.
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title" style={{ gap: '8px' }}>
              <TrendingDown size={16} />
              Abstention Protection Under Shift
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#555555', lineHeight: 1.6, marginBottom: '12px' }}>
            When traffic shifts away from the training distribution, standard classifiers make overconfident errors.
            In TraceGuard, the benign Isolation Forest anomaly score naturally rises on shifted flows:
          </p>
          <div
            style={{
              background: '#f8f8f8',
              border: '1px solid #e5e5e5',
              borderRadius: '8px',
              padding: '12px 14px',
              fontSize: '0.78rem',
              color: '#333333',
              lineHeight: 1.5,
            }}
          >
            Under <strong>Policy B (Balanced Anomaly Guard)</strong>, atypical shifted traffic is safely routed to{' '}
            <code>ABSTAIN</code> (Needs Human Review) rather than generating false benign classifications.
          </div>
        </div>
      </div>
    </div>
  )
}
