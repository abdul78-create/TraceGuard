import React, { useState } from 'react'
import {
  Activity,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertCircle,
  Info,
} from 'lucide-react'
import type { NetworkFlowRecord, PredictionResult } from '../types/api'

interface TrafficTabProps {
  lastSubmittedFlow?: {
    flow: NetworkFlowRecord
    result?: PredictionResult
  } | null
}

export const TrafficTab: React.FC<TrafficTabProps> = ({ lastSubmittedFlow }) => {
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null)

  const featureGroups = [
    {
      group: 'Transport & Addressing',
      count: '4 features',
      features: [
        { name: 'Destination Port', example: '443, 80, 22', desc: 'Which port the traffic is directed to.' },
        { name: 'Source Port', example: '54321', desc: 'Which port the sender used.' },
        { name: 'Protocol', example: '6 = TCP, 17 = UDP', desc: 'Transport protocol number.' },
        { name: 'Flow Duration', example: '150,000 µs', desc: 'How long the connection lasted (microseconds).' },
      ],
      desc: 'Basic identifiers: where traffic came from, where it went, and how long it lasted.',
    },
    {
      group: 'Packet & Byte Volume Metrics',
      count: '10 features',
      features: [
        { name: 'Total Fwd Packets', example: '12', desc: 'Packets sent in the forward direction (client → server).' },
        { name: 'Total Backward Packets', example: '9', desc: 'Packets sent in the backward direction (server → client).' },
        { name: 'Fwd Packet Length Mean/Std/Max/Min', example: '118.3 / 42.1 / 200 / 60', desc: 'Statistics about forward packet sizes.' },
        { name: 'Bwd Packet Length Mean/Std/Max/Min', example: '840 / 200 / 1400 / 60', desc: 'Statistics about backward (response) packet sizes.' },
      ],
      desc: 'How much data was transferred in each direction, and how packet sizes were distributed.',
    },
    {
      group: 'Inter-Arrival Time (IAT) Dynamics',
      count: '9 features',
      features: [
        { name: 'Flow IAT Mean / Std / Max / Min', example: '104 / 18 / 500 / 10 ms', desc: 'Gaps between consecutive packets in the flow.' },
        { name: 'Fwd IAT Total / Mean / Std / Max / Min', example: 'Forward timing statistics', desc: 'Timing gaps for forward packets only.' },
        { name: 'Bwd IAT Total / Mean / Std / Max / Min', example: 'Backward timing statistics', desc: 'Timing gaps for backward (response) packets only.' },
      ],
      desc: 'IAT (Inter-Arrival Time) measures the gaps between packets — burst attacks often show very small or very uniform gaps.',
    },
    {
      group: 'TCP Control Flags',
      count: '12 features',
      features: [
        { name: 'SYN / FIN / RST Flag Count', example: '1 / 1 / 0', desc: 'Connection setup, teardown, and reset counts.' },
        { name: 'PSH / ACK / URG / ECE Flag Count', example: 'Various', desc: 'Data push, acknowledgement, urgent, and congestion flag counts.' },
        { name: 'Fwd PSH Flags', example: '2', desc: 'Push flags in forward direction.' },
        { name: 'Down/Up Ratio', example: '1.5', desc: 'Ratio of backward to forward bytes.' },
      ],
      desc: 'TCP (Transmission Control Protocol) flags indicate how a connection was opened, maintained, and closed. Unusual flag patterns are a classic attack signature.',
    },
    {
      group: 'Segment Sizes & Window Parameters',
      count: '14 features',
      features: [
        { name: 'Average Packet Size', example: '350 bytes', desc: 'Mean size of all packets in the flow.' },
        { name: 'Avg Fwd / Bwd Segment Size', example: '118 / 840 bytes', desc: 'Average usable data per packet, in each direction.' },
        { name: 'Fwd / Bwd Header Length', example: '20 / 20 bytes', desc: 'TCP/IP header overhead in each direction.' },
        { name: 'Init_Win_bytes_forward / backward', example: '65535 / 8192', desc: 'Initial TCP receive window size — used for flow control.' },
        { name: 'act_data_pkt_fwd', example: '5', desc: 'Packets with at least 1 byte of data in forward direction.' },
        { name: 'min_seg_size_forward', example: '20 bytes', desc: 'Smallest forward segment (excluding empty ACKs).' },
      ],
      desc: 'Window and segment parameters describe how two hosts negotiated data transfer capacity.',
    },
    {
      group: 'Flow Rates & Throughput',
      count: '4 features',
      features: [
        { name: 'Flow Bytes/s', example: '7,856', desc: 'Total bytes transferred per second.' },
        { name: 'Flow Packets/s', example: '17.6', desc: 'Total packets per second. DoS attacks often show extremely high values.' },
        { name: 'Fwd Header Length', example: '240 bytes', desc: 'Total header bytes in forward direction.' },
        { name: 'Bwd Header Length', example: '180 bytes', desc: 'Total header bytes in backward direction.' },
      ],
      desc: 'How fast is this flow? High packet rates often indicate volumetric attacks.',
    },
    {
      group: 'Subflows & Active/Idle Periods',
      count: '16 features',
      features: [
        { name: 'Subflow Fwd / Bwd Packets', example: '12 / 9', desc: 'Packets in the first detected subflow.' },
        { name: 'Subflow Fwd / Bwd Bytes', example: '1,420 / 8,400', desc: 'Bytes in the first detected subflow.' },
        { name: 'Active Mean / Std / Max / Min', example: 'Active burst statistics', desc: 'How long the flow is actively sending data.' },
        { name: 'Idle Mean / Std / Max / Min', example: 'Idle pause statistics', desc: 'How long the flow is silent between bursts.' },
      ],
      desc: 'Subflows and active/idle periods capture the bursty nature of real traffic. Slow-and-stealthy attacks may show unusual idle patterns.',
    },
  ]

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.3rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '6px' }}>
          Traffic Analysis
        </h2>
        <p style={{ fontSize: '0.85rem', color: '#555', maxWidth: '700px', lineHeight: 1.6 }}>
          A <strong>network flow</strong> is a summary of one conversation between two computers — it records
          statistics like how many packets were sent, how large they were, and how quickly they arrived.
          TraceGuard does not read raw packet content (payloads). It analyses 69 statistical features
          extracted by a flow exporter such as CICFlowMeter.
        </p>
      </div>

      {/* Ingestion status — real packet capture */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">
            <Activity size={16} />
            Real-time Packet Ingestion Stream
          </span>
          <span className="badge badge-outline">No Live Packet Tap Connected</span>
        </div>
        <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
          <div>
            <div className="metric-label">Status</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#888' }}>Inactive</div>
          </div>
          <div>
            <div className="metric-label">Flows Captured</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#888' }}>0 / s</div>
          </div>
          <div>
            <div className="metric-label">Interface</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#888' }}>None</div>
          </div>
        </div>
        <div className="info-callout" style={{ marginTop: '14px', marginBottom: 0 }}>
          <AlertCircle size={14} style={{ marginRight: 6, flexShrink: 0, display: 'inline' }} />
          TraceGuard is an <strong>offline research prototype</strong>. It does not tap live network interfaces.
          To use the prediction API, generate 69-feature flow records using a compatible exporter and submit
          them via <code style={{ background: '#f0f0f0', padding: '1px 4px', borderRadius: 3 }}>POST /api/model/predict</code>.
        </div>
      </div>

      {/* 69-Feature Contract */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">Learned 69-Feature Schema Contract</span>
          <span className="badge badge-ok">69 Features</span>
        </div>
        <p style={{ fontSize: '0.82rem', color: '#555', marginBottom: '16px', lineHeight: 1.5 }}>
          Every prediction requires exactly these 69 statistical features, derived from one bidirectional
          network flow. The model was trained on flows from the{' '}
          <strong>CIC-IDS2017 dataset</strong>. Features are grouped below. Click any group to see individual fields.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {featureGroups.map((group, idx) => {
            const isOpen = expandedGroup === group.group
            return (
              <div
                key={group.group}
                style={{
                  border: '1px solid',
                  borderColor: isOpen ? '#0a0a0a' : '#e5e5e5',
                  borderRadius: '8px',
                  overflow: 'hidden',
                  transition: 'border-color 0.15s ease',
                  animationDelay: `${idx * 40}ms`,
                }}
              >
                <button
                  className="collapsible-trigger"
                  onClick={() => setExpandedGroup(isOpen ? null : group.group)}
                  style={{
                    width: '100%',
                    padding: '12px 16px',
                    justifyContent: 'space-between',
                    color: isOpen ? '#0a0a0a' : '#444',
                    fontWeight: isOpen ? 600 : 500,
                  }}
                  aria-expanded={isOpen}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span>{group.group}</span>
                    <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>{group.count}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.74rem', color: '#888', fontWeight: 400, maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {group.desc}
                    </span>
                    {isOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </div>
                </button>

                {isOpen && (
                  <div
                    className="collapsible-body"
                    style={{ borderTop: '1px solid #e5e5e5', padding: '14px 16px', background: '#fafafa' }}
                  >
                    <p style={{ fontSize: '0.78rem', color: '#555', marginBottom: '12px', lineHeight: 1.5 }}>
                      {group.desc}
                    </p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '8px' }}>
                      {group.features.map((f) => (
                        <div
                          key={f.name}
                          style={{
                            background: '#fff',
                            border: '1px solid #e5e5e5',
                            borderRadius: '6px',
                            padding: '8px 12px',
                          }}
                        >
                          <div style={{ fontWeight: 600, fontSize: '0.8rem', marginBottom: '2px', color: '#111' }}>
                            {f.name}
                          </div>
                          <div style={{ fontSize: '0.73rem', color: '#888', marginBottom: '2px' }}>
                            Example: <code style={{ background: '#f0f0f0', padding: '0 3px', borderRadius: 2 }}>{f.example}</code>
                          </div>
                          <div style={{ fontSize: '0.73rem', color: '#666', lineHeight: 1.4 }}>{f.desc}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Last submitted flow inspector */}
      {lastSubmittedFlow ? (
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <CheckCircle2 size={16} />
              Last Submitted Flow Inspector
            </span>
            {lastSubmittedFlow.result && (
              <span
                className={`badge ${
                  lastSubmittedFlow.result.decision === 'THREAT_SUSPECTED'
                    ? 'badge-danger'
                    : lastSubmittedFlow.result.decision === 'ABSTAIN'
                    ? 'badge-warn'
                    : 'badge-ok'
                }`}
              >
                {lastSubmittedFlow.result.decision === 'THREAT_SUSPECTED'
                  ? 'Threat Suspected'
                  : lastSubmittedFlow.result.decision === 'ABSTAIN'
                  ? 'Needs Review'
                  : 'Likely Benign'}
              </span>
            )}
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: '10px',
          }}>
            {Object.entries(lastSubmittedFlow.flow)
              .filter(([k]) => k !== 'features')
              .slice(0, 12)
              .map(([key, val]) => (
                <div key={key} style={{ background: '#f8f8f8', borderRadius: '6px', padding: '8px 10px' }}>
                  <div className="metric-label">{key.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 600, fontFamily: 'var(--font-mono)', color: '#111' }}>
                    {typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(3)) : String(val)}
                  </div>
                </div>
              ))}
          </div>
          {lastSubmittedFlow.result && (
            <div className="info-callout" style={{ marginTop: '12px', marginBottom: 0 }}>
              <Info size={13} style={{ marginRight: 6, display: 'inline' }} />
              <strong>Result:</strong> {lastSubmittedFlow.result.explanation}
            </div>
          )}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-state-icon">
            <Activity size={22} />
          </div>
          <p className="empty-state-title">No Flow Submitted Yet</p>
          <p className="empty-state-description">
            Submit a flow from the <strong>Threat Detection</strong> tab to see its parsed
            field values and triage result here.
          </p>
        </div>
      )}
    </div>
  )
}
