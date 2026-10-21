import React from 'react'
import { Activity, Network, FileCode, CheckCircle2, AlertCircle } from 'lucide-react'

export const TrafficTab: React.FC = () => {
  const schemaFields = [
    { name: 'flow_id', type: 'string (optional)', desc: 'Unique flow identifier or packet sequence hash' },
    { name: 'protocol', type: 'integer (0-255)', desc: 'Transport protocol (6 = TCP, 17 = UDP, 1 = ICMP)' },
    { name: 'flow_duration_ms', type: 'float (>= 0)', desc: 'Total active flow duration in milliseconds' },
    { name: 'src_port / dst_port', type: 'integer (0-65535)', desc: 'Source and destination transport ports' },
    { name: 'total_fwd_packets', type: 'integer (>= 0)', desc: 'Total packets transmitted in forward direction' },
    { name: 'total_bwd_packets', type: 'integer (>= 0)', desc: 'Total packets transmitted in backward direction' },
    { name: 'total_fwd_bytes', type: 'integer (>= 0)', desc: 'Total payload bytes transmitted forward' },
    { name: 'total_bwd_bytes', type: 'integer (>= 0)', desc: 'Total payload bytes transmitted backward' },
    { name: 'fwd_packet_length_mean', type: 'float (>= 0)', desc: 'Mean size of forward packets in bytes' },
    { name: 'bwd_packet_length_mean', type: 'float (>= 0)', desc: 'Mean size of backward packets in bytes' },
    { name: 'flow_bytes_per_sec', type: 'float (>= 0)', desc: 'Byte transmission rate over the flow duration' },
    { name: 'flow_packets_per_sec', type: 'float (>= 0)', desc: 'Packet transmission rate per second' },
    { name: 'flow_iat_mean / std', type: 'float (>= 0)', desc: 'Inter-arrival time mean and standard deviation (ms)' },
    { name: 'syn / rst / ack / fin flags', type: 'integer (0 or 1)', desc: 'TCP control flags for handshake and teardown telemetry' },
  ]

  return (
    <div>
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">
            <Activity size={18} color="var(--accent-cyan)" />
            Real-time Flow Capture & Stream Ingestion
          </span>
          <span className="badge badge-amber">Stream Idle</span>
        </div>

        {/* Empty state */}
        <div className="empty-state">
          <div className="empty-state-icon">
            <Network size={28} />
          </div>
          <h3 className="empty-state-title">No Network Flow Stream Connected</h3>
          <p className="empty-state-description">
            Live packet capture and flow replay will connect during <strong>Stage 2 (Dataset Selection)</strong> and <strong>Stage 5 (Dashboard Integration)</strong>. In Stage 1, data structures and schema validation contracts are finalized.
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="badge badge-blue">
              <CheckCircle2 size={12} />
              Pydantic Validation Active
            </span>
            <span className="badge badge-amber">
              <AlertCircle size={12} />
              Awaiting Dataset Ingestion
            </span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <FileCode size={18} color="var(--accent-cyan)" />
            Standardized Network Flow Schema Contract
          </span>
          <span className="badge badge-blue">20 Feature Fields</span>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
          To prevent synthetic bias and data leakage, TraceGuard standardizes all incoming network sessions into the following schema matching standard flow exporters (e.g. CICFlowMeter, Argus, NetFlow v9):
        </p>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Type Constraint</th>
                <th>Cybersecurity Context</th>
              </tr>
            </thead>
            <tbody>
              {schemaFields.map((field, idx) => (
                <tr key={idx}>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-code)' }}>
                    {field.name}
                  </td>
                  <td>
                    <span className="badge badge-blue" style={{ fontSize: '0.72rem' }}>
                      {field.type}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{field.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
