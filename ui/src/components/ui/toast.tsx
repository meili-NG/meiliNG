import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"
import { XIcon } from "lucide-react"

import {
  Alert,
  AlertAction,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { cn } from "@/lib/utils"

export type ToastVariant = "default" | "success" | "warning" | "destructive" | "info"

export type ToastOptions = {
  title?: string
  description?: string
  variant?: ToastVariant
  /** Auto-dismiss delay in ms. 0 keeps it until dismissed. Defaults to 4000. */
  duration?: number
}

type ToastEntry = ToastOptions & { id: number }

type ToastContextValue = {
  toast: (options: ToastOptions) => number
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

let nextId = 1

/**
 * Toast provider backed by the ReUI Alert component. Toasts stack in a fixed
 * corner, auto-dismiss, and reuse the same variants as inline alerts so
 * transient feedback matches the rest of the UI.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([])
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>())

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
    const timer = timers.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timers.current.delete(id)
    }
  }, [])

  const toast = useCallback(
    (options: ToastOptions) => {
      const id = nextId++
      setToasts((prev) => [...prev, { ...options, id }])
      const duration = options.duration ?? 4000
      if (duration > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), duration),
        )
      }
      return id
    },
    [dismiss],
  )

  useEffect(() => {
    const pending = timers.current
    return () => {
      for (const timer of pending.values()) clearTimeout(timer)
      pending.clear()
    }
  }, [])

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: ToastEntry[]
  onDismiss: (id: number) => void
}) {
  if (toasts.length === 0) return null
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-0 z-[100] flex flex-col items-center gap-2 p-4 sm:inset-x-auto sm:right-0 sm:items-end">
      {toasts.map((t) => (
        <Alert
          key={t.id}
          variant={t.variant === "default" ? undefined : t.variant}
          className={cn(
            "pointer-events-auto w-full max-w-sm bg-background shadow-lg",
            "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:slide-in-from-bottom-2",
          )}
          data-state="open"
        >
          {t.title ? <AlertTitle>{t.title}</AlertTitle> : null}
          {t.description ? (
            <AlertDescription>{t.description}</AlertDescription>
          ) : null}
          <AlertAction>
            <button
              type="button"
              aria-label="Dismiss"
              className="rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              onClick={() => onDismiss(t.id)}
            >
              <XIcon className="size-4" />
            </button>
          </AlertAction>
        </Alert>
      ))}
    </div>
  )
}

/** Access the toast dispatcher. Must be used within a ToastProvider. */
export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error("useToast must be used within a ToastProvider")
  }
  return ctx
}
