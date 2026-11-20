import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const TRIAL_COOKIE = "scamshield_trial";
export const LICENSE_COOKIE = "scamshield_license";
export const USAGE_COOKIE = "scamshield_usage";

const DEMO_LICENSE_KEY = "SCAMSHIELD-PRO-2026";

function signingSecret(): string | null {
  if (process.env.SCAMSHIELD_TRIAL_SECRET) return process.env.SCAMSHIELD_TRIAL_SECRET;
  return process.env.NODE_ENV === "development" ? "scamshield-local-development-secret" : null;
}

export function hasSigningSecret(): boolean {
  return signingSecret() !== null;
}

export function signValue(value: string): string | null {
  const secret = signingSecret();
  if (!secret) return null;
  const payload = Buffer.from(value).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function readSignedCookie(request: Request, name: string): string | null {
  const secret = signingSecret();
  if (!secret) return null;

  const cookie = request.headers.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
  if (!cookie) return null;

  const [payload, signature] = cookie.split(".");
  if (!payload || !signature) return null;

  const expected = createHmac("sha256", secret).update(payload).digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;

  try {
    return Buffer.from(payload, "base64url").toString();
  } catch {
    return null;
  }
}

export function trialStartTime(request: Request): number | null {
  const payload = readSignedCookie(request, TRIAL_COOKIE);
  if (!payload) return null;
  const timestamp = Number(payload);
  return Number.isSafeInteger(timestamp) && timestamp > 0 && timestamp <= Date.now() + 300_000
    ? timestamp
    : null;
}

export function isTrialActive(request: Request): boolean {
  const startedAt = trialStartTime(request);
  return startedAt !== null && Date.now() < startedAt + 30 * 86_400_000;
}

function acceptedLicenseHashes(): Set<string> {
  const keys = (process.env.SCAMSHIELD_PRO_LICENSE_KEYS ?? "")
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);
  if (process.env.NODE_ENV !== "production") keys.push(DEMO_LICENSE_KEY);
  return new Set(keys.map((key) => createHash("sha256").update(key).digest("hex")));
}

export function licenseHash(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function isLicenseAccepted(key: string): boolean {
  const hash = Buffer.from(licenseHash(key), "hex");
  return Array.from(acceptedLicenseHashes()).some((accepted) =>
    timingSafeEqual(hash, Buffer.from(accepted, "hex")),
  );
}

export function hasProAccess(request: Request): boolean {
  if (isTrialActive(request)) return true;
  const payload = readSignedCookie(request, LICENSE_COOKIE);
  if (!payload) return false;
  const hash = Buffer.from(payload, "hex");
  if (hash.length !== 32) return false;
  return Array.from(acceptedLicenseHashes()).some((accepted) =>
    timingSafeEqual(hash, Buffer.from(accepted, "hex")),
  );
}

export function isProLicenseActive(request: Request): boolean {
  const payload = readSignedCookie(request, LICENSE_COOKIE);
  if (!payload) return false;
  const hash = Buffer.from(payload, "hex");
  return hash.length === 32 && Array.from(acceptedLicenseHashes()).some((accepted) =>
    timingSafeEqual(hash, Buffer.from(accepted, "hex")),
  );
}
