/**
 * Origin of the meiliNG API. Empty when the UI is served by the API itself
 * (the embedded build). Set VITE_API_ORIGIN at build time to host this UI as
 * a static app on another origin; that origin must be listed in the server's
 * server.frontendOrigins.
 */
const API_ORIGIN = (import.meta.env.VITE_API_ORIGIN ?? "").replace(/\/+$/, "")

export class ApiError extends Error {
  readonly type?: string

  constructor(message: string, type?: string) {
    super(message)
    this.name = "ApiError"
    this.type = type
  }
}

type ErrorBody = {
  message?: string
  type?: string
  detail?: string
  title?: string
  errors?: { message?: string }[]
}

function errorMessageFromBody(err: ErrorBody | null, fallback: string): string {
  if (!err) return fallback
  if (err.message) return err.message
  if (err.detail) return err.detail
  const first = err.errors?.find((e) => e.message)?.message
  if (first) return first
  if (err.title) return err.title
  return fallback
}

export async function apiJson<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers)
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const res = await fetch(API_ORIGIN + path, {
    ...init,
    headers,
    credentials: "same-origin",
  })

  const text = await res.text()
  const body = text ? (JSON.parse(text) as T | ErrorBody) : null

  if (!res.ok) {
    const err = body as ErrorBody | null
    throw new ApiError(errorMessageFromBody(err, res.statusText), err?.type)
  }

  return body as T
}
