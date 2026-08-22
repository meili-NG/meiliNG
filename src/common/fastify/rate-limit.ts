import ipaddr from 'ipaddr.js';

export const rateLimitCacheSize = 2_500;
export const rateLimitDefaults = {
  authentication: { max: 30, timeframe: 600 },
  recovery: { max: 10, timeframe: 3600 },
  signup: { max: 10, timeframe: 3600 },
};

export function normalizeRateLimitIP(ip: string): string {
  const address = ipaddr.process(ip);

  if (address.kind() === 'ipv6') {
    const bytes = address.toByteArray();
    bytes.fill(0, 8);
    return ipaddr.fromByteArray(bytes).toString();
  }

  return address.toString();
}
