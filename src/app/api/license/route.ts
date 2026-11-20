import { NextResponse } from "next/server";
import {
  hasSigningSecret,
  isLicenseAccepted,
  licenseHash,
  LICENSE_COOKIE,
  signValue,
} from "@/lib/entitlements";

export async function POST(request: Request) {
  if (!hasSigningSecret()) {
    return NextResponse.json(
      { error: "License activation is not configured. Set SCAMSHIELD_TRIAL_SECRET." },
      { status: 503 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Enter a valid license key." }, { status: 400 });
  }

  const key = typeof body === "object" && body !== null && "licenseKey" in body &&
    typeof body.licenseKey === "string"
    ? body.licenseKey.trim()
    : "";
  if (!key || key.length > 128 || !isLicenseAccepted(key)) {
    return NextResponse.json({ error: "That license key is not valid." }, { status: 400 });
  }

  const signedLicense = signValue(licenseHash(key));
  if (!signedLicense) {
    return NextResponse.json({ error: "License activation is not configured." }, { status: 503 });
  }

  const response = NextResponse.json({ isPro: true });
  response.cookies.set(LICENSE_COOKIE, signedLicense, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 365 * 86_400,
  });
  return response;
}
