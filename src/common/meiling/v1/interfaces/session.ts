import { ExtendedAuthMethods, SigninType } from './query';

export interface MeilingSession {
  user?: LoggedInUser[];
  extendedAuthentication?: ExtendedAuthentication;
  previouslyLoggedIn?: PreviouslyLoggedInUser[];
  authenticationStatus?: SessionAuthenticationStatus;
  passwordReset?: SessionPasswordReset;
  registering?: SessionRegistering;
  ips?: string[];
}

export interface SessionRegistering {
  webAuthn?: RegisteringWebAuthn;
  otp?: RegisteringOTP;
}

export interface RegisteringWebAuthn {
  origin: string;
  hostname: string;
  challenge: string;
}

export interface RegisteringOTP {
  secret: string;
  issuedAt: number;
}

export interface LoggedInUser {
  id: string;
}

export interface PreviouslyLoggedInUser {
  id: string;
  remember2FA?: boolean;
}

export interface SessionPasswordReset extends SessionChallengeBody {
  method?: ExtendedAuthMethods;
  passwordResetUser?: string;
  isVerified?: boolean;
  failedAttempts?: number;
}

interface SessionTwoFactor extends SessionChallengeBody {
  id: string;
  type: SigninType.TWO_FACTOR_AUTH;
  method?: ExtendedAuthMethods;
  failedAttempts?: number;
}

interface SessionPasswordLess extends SessionChallengeBody {
  type: SigninType.PASSWORDLESS;
  userId?: string;
  method?: ExtendedAuthMethods;
  failedAttempts?: number;
}

interface SessionChallengeBody {
  challenge?: string;
  challengeCreatedAt?: Date;
}

interface SessionChallengeStatus<T> {
  to: T;
  challenge: SessionChallengeBody;
  isVerified: boolean;
  failedAttempts?: number;
}

export interface SessionAuthenticationStatus {
  email?: SessionChallengeStatus<string>;
  phone?: SessionChallengeStatus<string>;
}

export type ExtendedAuthentication = SessionPasswordLess | SessionTwoFactor;
