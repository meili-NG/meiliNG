import { useCallback, useEffect, useRef, useState } from "react"
import { CheckIcon, CopyIcon } from "lucide-react"

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

type CopyableIdProps = {
  /** The full value copied to the clipboard. */
  value: string
  /** Optional shorter label to display; defaults to the full value. */
  display?: string
  /** Truncate the displayed value to this many leading chars + ellipsis. */
  truncate?: number
  className?: string
}

/**
 * A monospace identifier that copies its full value to the clipboard on click,
 * with tooltip feedback ("Click to copy" → "Copied!"). Used for UUIDs and
 * secrets in admin tables and detail views so operators can grab an id without
 * manual text selection.
 */
export function CopyableId({
  value,
  display,
  truncate,
  className,
}: CopyableIdProps) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current)
    }
  }, [])

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard may be unavailable (insecure context); ignore */
    }
  }, [value])

  const shown =
    display ??
    (truncate && value.length > truncate
      ? `${value.slice(0, truncate)}…`
      : value)

  return (
    <Tooltip>
      <TooltipTrigger
        // A span (not button) keeps it inline inside table cells and dt/dd
        // without inheriting button layout, while staying keyboard-operable.
        render={
          <span
            role="button"
            tabIndex={0}
            title={undefined}
            onClick={(e) => {
              e.stopPropagation()
              void onCopy()
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault()
                e.stopPropagation()
                void onCopy()
              }
            }}
          />
        }
        className={cn(
          "inline-flex max-w-full cursor-pointer items-center gap-1 rounded font-mono text-xs text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
          className,
        )}
      >
        <span className="truncate">{shown}</span>
        {copied ? (
          <CheckIcon className="size-3 shrink-0 text-success" />
        ) : (
          <CopyIcon className="size-3 shrink-0 opacity-60" />
        )}
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copied!" : "Click to copy"}</TooltipContent>
    </Tooltip>
  )
}
