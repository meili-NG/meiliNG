import { useEffect, useState } from "react"

import { apiJson } from "@/lib/api"
import { httpUrl } from "@/lib/utils"

/** The instance identity configured under `instance.*`. */
export type Branding = {
  name: string
  /** Absolute URL of the instance logo, shown in place of the default mark. */
  logoUrl?: string
  /** Where users are pointed for help. */
  supportUrl?: string
  /** Identifiers the sign-in form accepts. */
  signIn: SignInOptions
}

export type SignInOptions = { username: boolean; email: boolean }

type InstanceResponse = {
  name?: string
  description?: string
  logoUrl?: string
  supportUrl?: string
  signIn?: Partial<SignInOptions>
}

const DEFAULT_BRANDING: Branding = {
  name: "meiliNG",
  signIn: { username: true, email: true },
}

let request: Promise<Branding> | undefined
let current = DEFAULT_BRANDING

/** Fetch the instance branding, once per page load. */
export function fetchBranding(): Promise<Branding> {
  request ??= apiJson<InstanceResponse>("/v2/instance")
    .then((data) => {
      current = {
        name: data.name?.trim() || DEFAULT_BRANDING.name,
        logoUrl: httpUrl(data.logoUrl, window.location.href)?.href,
        supportUrl: httpUrl(data.supportUrl, window.location.href)?.href,
        signIn: {
          username: data.signIn?.username ?? true,
          email: data.signIn?.email ?? true,
        },
      }
      if (current.logoUrl) setFavicon(current.logoUrl)
      return current
    })
    .catch((err) => {
      request = undefined
      throw err
    })
  return request
}

export async function fetchInstanceName(): Promise<string> {
  return (await fetchBranding()).name
}

/**
 * The instance branding, starting from the defaults and updating once
 * /v2/instance answers. A failed fetch keeps the defaults.
 */
export function useBranding(): Branding {
  const [branding, setBranding] = useState(current)
  useEffect(() => {
    let cancelled = false
    fetchBranding()
      .then((b) => {
        if (!cancelled) setBranding(b)
      })
      .catch(() => {
        // Keep the defaults; the instance stays usable without branding.
      })
    return () => {
      cancelled = true
    }
  }, [])
  return branding
}

function setFavicon(href: string) {
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!link) {
    link = document.createElement("link")
    link.rel = "icon"
    document.head.appendChild(link)
  }
  link.removeAttribute("type")
  link.href = href
}
