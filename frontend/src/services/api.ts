import type {
  HealthResponse,
  ReadinessResponse,
  ModelStatusResponse,
  DriftStatusResponse,
  EvaluationMetricsResponse,
  NetworkFlowRecord,
  PredictionResult,
  SampleFlowItem,
  BatchPredictionResponse,
  ProbeErrorDetail,
} from '../types/api'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({ detail: res.statusText }))
    const message =
      typeof errorBody.detail === 'string'
        ? errorBody.detail
        : errorBody.detail?.message || JSON.stringify(errorBody.detail || errorBody)
    throw new Error(message)
  }
  return res.json()
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/api/health`)
  return handleResponse<HealthResponse>(res)
}

export async function fetchReadiness(): Promise<ReadinessResponse> {
  const res = await fetch(`${API_BASE_URL}/api/health/ready`)
  return handleResponse<ReadinessResponse>(res)
}

export async function fetchModelStatus(): Promise<ModelStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/api/model/status`)
  return handleResponse<ModelStatusResponse>(res)
}

export async function fetchDriftTelemetry(): Promise<DriftStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/api/telemetry/drift`)
  return handleResponse<DriftStatusResponse>(res)
}

export async function fetchEvaluationMetrics(): Promise<EvaluationMetricsResponse> {
  const res = await fetch(`${API_BASE_URL}/api/telemetry/evaluation`)
  return handleResponse<EvaluationMetricsResponse>(res)
}

export async function fetchSampleFlows(): Promise<SampleFlowItem[]> {
  const res = await fetch(`${API_BASE_URL}/api/model/sample-flows`)
  return handleResponse<SampleFlowItem[]>(res)
}

export async function predictFlow(
  flow: NetworkFlowRecord,
  policy?: string
): Promise<PredictionResult> {
  const url = policy
    ? `${API_BASE_URL}/api/model/predict?policy=${encodeURIComponent(policy)}`
    : `${API_BASE_URL}/api/model/predict`

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(flow),
  })

  return handleResponse<PredictionResult>(res)
}

export async function predictBatch(
  records: NetworkFlowRecord[],
  policy?: string
): Promise<BatchPredictionResponse> {
  const url = policy
    ? `${API_BASE_URL}/api/model/predict-batch?policy=${encodeURIComponent(policy)}`
    : `${API_BASE_URL}/api/model/predict-batch`

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ records }),
  })

  return handleResponse<BatchPredictionResponse>(res)
}

export async function probePredictionEndpoint(
  sampleFlow: NetworkFlowRecord,
  policy?: string
): Promise<{ status: number; ok: boolean; data?: PredictionResult | unknown; error?: ProbeErrorDetail }> {
  try {
    const url = policy
      ? `${API_BASE_URL}/api/model/predict?policy=${encodeURIComponent(policy)}`
      : `${API_BASE_URL}/api/model/predict`

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sampleFlow),
    })

    const body = await res.json()
    if (!res.ok) {
      return {
        status: res.status,
        ok: false,
        error: (body.detail || body) as ProbeErrorDetail,
      }
    }
    return {
      status: res.status,
      ok: true,
      data: body,
    }
  } catch (err: unknown) {
    return {
      status: 0,
      ok: false,
      error: {
        error: 'NETWORK_ERROR',
        message: err instanceof Error ? err.message : 'Failed to reach API endpoint',
        stage: 'Stage 5: Live Integration',
      },
    }
  }
}

