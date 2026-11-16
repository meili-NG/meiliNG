import type { ComponentProps } from "react"
import {
  AlertTriangleIcon,
  CircleAlertIcon,
  CircleCheckIcon,
  InfoIcon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"

type AuthAlertVariant = "destructive" | "warning" | "success" | "info"

const ALERT_ICON: Record<AuthAlertVariant, typeof InfoIcon> = {
  destructive: CircleAlertIcon,
  warning: AlertTriangleIcon,
  success: CircleCheckIcon,
  info: InfoIcon,
}

export function AuthAlert({
  message,
  title,
  variant = "destructive",
}: {
  message: string
  title?: string
  variant?: AuthAlertVariant
}) {
  const Icon = ALERT_ICON[variant]
  return (
    <Alert variant={variant}>
      <Icon />
      {title ? <AlertTitle>{title}</AlertTitle> : null}
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

export function PendingButton({
  pending,
  pendingLabel,
  children,
  disabled,
  ...props
}: ComponentProps<typeof Button> & {
  pending?: boolean
  pendingLabel?: string
}) {
  return (
    <Button disabled={pending || disabled} {...props}>
      {pending ? (
        <>
          <Spinner data-icon="inline-start" />
          {pendingLabel ?? children}
        </>
      ) : (
        children
      )}
    </Button>
  )
}
