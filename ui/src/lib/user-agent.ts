/** Client / device helpers for session history rows. */

export type DeviceKind = "desktop" | "mobile" | "tablet" | "unknown"

export type ClientDescription = {
  label: string
  summary: string
  device: DeviceKind
}

function matchVersion(ua: string, re: RegExp): string | null {
  const m = ua.match(re)
  return m?.[1] ?? null
}

export function describeClient(ua: string | undefined): ClientDescription {
  const raw = ua?.trim()
  if (!raw) {
    return {
      label: "Unknown client",
      summary: "No user agent",
      device: "unknown",
    }
  }

  const browserPair =
    (
      [
        [/Edg\/([\d.]+)/i, "Edge"],
        [/OPR\/([\d.]+)/i, "Opera"],
        [/Firefox\/([\d.]+)/i, "Firefox"],
        [/Chrome\/([\d.]+)/i, "Chrome"],
        [/CriOS\/([\d.]+)/i, "Chrome"],
        [/Version\/([\d.]+).*Safari/i, "Safari"],
        [/Safari\/([\d.]+)/i, "Safari"],
      ] as [RegExp, string][]
    )
      .map(([re, name]) => {
        const version = matchVersion(raw, re)
        return version ? ({ name, version } as const) : null
      })
      .find(Boolean) ?? null

  const osName =
    (
      [
        [/Android/i, "Android"],
        [/iPhone|iPad|iPod/i, "iOS"],
        [/Mac OS X|Macintosh/i, "macOS"],
        [/Windows NT/i, "Windows"],
        [/CrOS/i, "ChromeOS"],
        [/Linux/i, "Linux"],
      ] as [RegExp, string][]
    ).find(([re]) => re.test(raw))?.[1] ?? "Unknown OS"

  const osVersion =
    matchVersion(raw, /Android ([\d.]+)/i) ||
    matchVersion(raw, /iPhone OS ([\d_]+)/i)?.replace(/_/g, ".") ||
    matchVersion(raw, /CPU OS ([\d_]+)/i)?.replace(/_/g, ".") ||
    matchVersion(raw, /Mac OS X ([\d_]+)/i)?.replace(/_/g, ".") ||
    matchVersion(raw, /Windows NT ([\d.]+)/i) ||
    null

  let device: DeviceKind = "desktop"
  if (/iPad|Tablet|Android(?!.*Mobile)/i.test(raw)) device = "tablet"
  else if (/Mobile|iPhone|Android.*Mobile|webOS|BlackBerry/i.test(raw))
    device = "mobile"

  const browserName = browserPair?.name ?? "Browser"
  const label = `${browserName} on ${osName}`
  const summary = [
    browserPair ? `${browserPair.name} ${browserPair.version}` : browserName,
    osVersion ? `${osName} ${osVersion}` : osName,
  ].join(" · ")

  return { label, summary, device }
}

export function formatDateTime(iso: string | undefined): string {
  if (!iso) return "—"
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  const y = date.getFullYear()
  const mo = String(date.getMonth() + 1).padStart(2, "0")
  const d = String(date.getDate()).padStart(2, "0")
  const h = String(date.getHours()).padStart(2, "0")
  const mi = String(date.getMinutes()).padStart(2, "0")
  const s = String(date.getSeconds()).padStart(2, "0")
  return `${y}-${mo}-${d} ${h}:${mi}:${s}`
}

export function formatLocation(log: {
  country?: string
  countryCode?: string
}): string {
  const { country, countryCode: code } = log

  if (country && code) return `${country} (${code})`
  if (country) return country
  if (code) return code
  return "—"
}
