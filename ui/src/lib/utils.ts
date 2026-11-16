import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Parses a URL the browser may open or load: http and https only, so a value
 * from a query parameter or the API never runs as script. Relative values
 * resolve against `base`; without one they are refused.
 */
export function httpUrl(value?: string | null, base?: string): URL | null {
  if (!value) return null
  try {
    const url = new URL(value, base)
    return url.protocol === "http:" || url.protocol === "https:" ? url : null
  } catch {
    return null
  }
}
