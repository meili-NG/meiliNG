import { AuthCard } from "@/components/auth-card"
import { FrontchannelLogout } from "@/components/frontchannel-logout"
import { Button } from "@/components/ui/button"

type SignOutViewProps = {
  instanceName: string
  onSignIn: () => void
  /** Applications' front-channel logout URIs to load. */
  frontchannelLogoutUris?: string[]
}

export function SignOutView({
  instanceName,
  onSignIn,
  frontchannelLogoutUris = [],
}: SignOutViewProps) {
  return (
    <AuthCard
      instanceName={instanceName}
      title="Signed out"
      description="You have been signed out."
    >
      <FrontchannelLogout uris={frontchannelLogoutUris} />
      <Button type="button" className="w-full" onClick={onSignIn}>
        Sign in
      </Button>
    </AuthCard>
  )
}
