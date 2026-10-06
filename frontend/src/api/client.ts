export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8080/api'

export class ApiError extends Error {
  constructor( message: string, readonly status: number,){
    super(message)
  }
}

export async function apiRequest<T>( path: string, options: RequestInit = {}, token?: string,): Promise<T> {
  const headers = new Headers(options.headers)
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  if (typeof options.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  })
  const contentType = response.headers.get('Content-Type') ?? ''
  const body = contentType.includes('application/json')
    ? ((await response.json()) as T & { message?: string })
    : null

  if (!response.ok) {
    throw new ApiError(
      body?.message ?? `API вернуло статус ${response.status}`,
      response.status,
    )
  }
  return body as T
}
