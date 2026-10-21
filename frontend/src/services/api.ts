import type {
  HealthResponse,
  ReadinessResponse,
  ModelStatusResponse,
  DriftStatusResponse,
  EvaluationMetricsResponse,
  NetworkFlowRecord,
  ProbeErrorDetail,
} from '../types/api'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(
      typeof errorBody.detail === 'string'
        ? errorBody.detail
        : JSON.stringify(errorBody.detail || errorBody)
    )
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

export async function probePredictionEndpoint(
  sampleFlow: NetworkFlowRecord
): Promise<{ status: number; ok: boolean; data?: unknown; error?: ProbeErrorDetail }> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/model/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sampleFlow),
    })

    const body = await res.json()
    if (res.status === 503) {
      return {
        status: res.status,
        ok: false,
        error: body.detail as ProbeErrorDetail,
      }
    }
    return {
      status: res.status,
      ok: res.ok,
      data: body,
    }
  } catch (err: unknown) {
    return {
      status: 0,
      ok: false,
      error: {
        error: 'NETWORK_ERROR',
        message: err instanceof Error ? err.message : 'Failed to reach API endpoint',
        stage: 'Stage 1: Project Foundation',
      },
    }
  }
}
