import { OAuthClientRedirectUris } from '@prisma/client';

const unsafeRedirectProtocols = new Set([
  'javascript:',
  'vbscript:',
  'data:',
  'blob:',
  'file:',
  'filesystem:',
  'about:',
]);

export function isSafeRedirectURI(redirectUri: string): boolean {
  if (typeof redirectUri !== 'string') return false;

  try {
    // Parse first so scheme casing and embedded tabs/newlines cannot bypass the check.
    const url = new URL(redirectUri);
    return !unsafeRedirectProtocols.has(url.protocol);
  } catch (e) {
    return false;
  }
}

export function getMatchingRedirectURIs(
  redirectUri: string,
  redirectUris: (OAuthClientRedirectUris | string)[],
): (OAuthClientRedirectUris | string)[] {
  if (!isSafeRedirectURI(redirectUri)) return [];

  let adequateRedirectUris;

  if (redirectUri.startsWith('urn:ietf:wg:oauth:2.0')) {
    adequateRedirectUris = redirectUris.filter((n) => {
      if (typeof n === 'string') {
        return n === redirectUri;
      } else {
        return n.redirectUri === redirectUri;
      }
    });
  } else {
    const redirectURL = new URL(redirectUri);

    adequateRedirectUris = redirectUris.filter((n) => {
      const thisRedirectUri = typeof n === 'string' ? n : n.redirectUri;

      let url;
      try {
        url = new URL(thisRedirectUri);
      } catch (e) {
        return false;
      }

      return (
        url.protocol === redirectURL.protocol &&
        url.port === redirectURL.port &&
        url.hostname === redirectURL.hostname &&
        url.pathname === redirectURL.pathname
      );
    });
  }

  return adequateRedirectUris;
}
