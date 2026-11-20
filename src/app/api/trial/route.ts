import { NextResponse } from "next/server";
import {
  hasProAccess,
  hasSigningSecret,
  isProLicenseActive,
  signValue,
  trialStartTime,
  TRIAL_COOKIE,
} from "@/lib/entitlements";

const TRIAL_LENGTH_MS = 30 * 86_400_000;

export async function POST(request: Request) {
  if (!hasSigningSecret()) {
    return NextResponse.json(
      { error: "Trial service is not configured. Set SCAMSHIELD_TRIAL_SECRET." },
      { status: 503 },
    );
  }

  const startedAt = trialStartTime(request) ?? Date.now();
  const signedTrial = signValue(String(startedAt));
  if (!signedTrial) {
    return NextResponse.json({ error: "Trial service is not configured." }, { status: 503 });
  }

  const response = NextResponse.json({
    trialStartDate: new Date(startedAt).toISOString(),
    trialActive: Date.now() < startedAt + TRIAL_LENGTH_MS,
    isPro: Date.now() < startedAt + TRIAL_LENGTH_MS || hasProAccess(request),
    isLicense: isProLicenseActive(request),
  });
  response.cookies.set(TRIAL_COOKIE, signedTrial, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 10 * 365 * 86_400,
  });
  return response;
}
