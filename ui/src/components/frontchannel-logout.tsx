import { useEffect, useRef } from "react"

/** How long to wait for the applications' logout pages before moving on. */
const FRONTCHANNEL_TIMEOUT_MS = 3000

type FrontchannelLogoutProps = {
  /** Front-channel logout URIs, already carrying iss and sid. */
  uris: string[]
  /** Called once every page loaded, or after the timeout. */
  onDone?: () => void
}

/**
 * Loads each application's front-channel logout URI in a hidden iframe, so
 * the applications end their own sessions too (OpenID Connect Front-Channel
 * Logout 1.0).
 */
export function FrontchannelLogout({ uris, onDone }: FrontchannelLogoutProps) {
  useEffect(() => {
    if (!onDone) return
    if (uris.length === 0) {
      onDone()
      return
    }
    const timer = window.setTimeout(onDone, FRONTCHANNEL_TIMEOUT_MS)
    return () => window.clearTimeout(timer)
  }, [uris, onDone])

  const loaded = useRef(0)
  return (
    <div hidden aria-hidden="true">
      {uris.map((uri) => (
        <iframe
          key={uri}
          src={uri}
          title="Signing out of an application"
          onLoad={() => {
            loaded.current += 1
            if (loaded.current === uris.length) onDone?.()
          }}
        />
      ))}
    </div>
  )
}
