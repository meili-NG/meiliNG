import type { ReactNode } from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { InstanceMark } from "@/components/app-shell"
import { useBranding } from "@/lib/branding"
import { cn } from "@/lib/utils"

type AuthCardProps = {
  instanceName: string
  title: string
  description?: string
  children: ReactNode
  footer?: ReactNode
  /** Optional artwork shown above the title, such as an app icon. */
  media?: ReactNode
  className?: string
}

// Sign-in is the one screen every user sees, often on a phone, so its controls
// are larger than the dashboard's compact ones.
const AUTH_CONTROL_SIZE =
  "[&_[data-slot=input]]:h-11 [&_[data-slot=input]]:px-3 [&_[data-slot=input]]:text-base [&_[data-slot=input-group]]:h-11 [&_[data-slot=input-group-control]]:px-3 [&_[data-slot=input-group-control]]:text-base [&_[data-slot=button].w-full]:h-11 [&_[data-slot=button].w-full]:text-base"

export function AuthCard({
  instanceName,
  title,
  description,
  children,
  footer,
  media,
  className,
}: AuthCardProps) {
  const { supportUrl } = useBranding()
  return (
    <div className="flex min-h-svh flex-col items-center bg-card sm:justify-center sm:bg-muted sm:px-4 sm:py-10">
      <div
        className={cn("flex w-full max-w-[26rem] flex-col gap-5", className)}
      >
        {/* On a phone the card fills the screen; from sm up it floats. */}
        <Card className="w-full gap-7 rounded-none border-0 px-2 py-10 shadow-none ring-0 sm:rounded-2xl sm:px-4 sm:shadow-sm sm:ring-1">
          <div className="flex items-center justify-center gap-2.5 px-4">
            <InstanceMark className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground" />
            <span className="text-lg font-semibold tracking-tight">
              {instanceName}
            </span>
          </div>
          {/* Keyed by title so each step of a flow slides in. */}
          <div
            key={title}
            className="flex flex-col gap-6 motion-safe:animate-in motion-safe:duration-300 motion-safe:fade-in motion-safe:slide-in-from-right-4"
          >
            <CardHeader className="text-center">
              {media ? (
                <div className="mb-2 flex flex-col items-center gap-2">
                  {media}
                </div>
              ) : null}
              <CardTitle className="text-2xl font-semibold tracking-tight">
                {title}
              </CardTitle>
              <CardDescription className="text-base">
                {description ?? `Continue to ${instanceName}.`}
              </CardDescription>
            </CardHeader>
            <CardContent className={AUTH_CONTROL_SIZE}>{children}</CardContent>
            {footer ? (
              <p className="px-4 text-center text-sm text-muted-foreground">
                {footer}
              </p>
            ) : null}
          </div>
        </Card>

        {supportUrl ? (
          <p className="pb-6 text-center text-xs text-muted-foreground">
            <a
              href={supportUrl}
              target="_blank"
              rel="noreferrer"
              className="underline underline-offset-4 hover:text-foreground"
            >
              Need help?
            </a>
          </p>
        ) : null}
      </div>
    </div>
  )
}
