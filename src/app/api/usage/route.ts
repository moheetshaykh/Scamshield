import { NextResponse } from "next/server";
import {
  hasProAccess,
  hasSigningSecret,
  readSignedCookie,
  signValue,
  USAGE_COOKIE,
} from "@/lib/entitlements";

const DAILY_SCAN_LIMIT = 3;

type Usage = { day: string; count: number };

function parseUsage(value: string | null): Usage | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "day" in parsed &&
      typeof parsed.day === "string" &&
      "count" in parsed &&
      typeof parsed.count === "number" &&
      Number.isInteger(parsed.count) &&
      parsed.count >= 0
    ) {
      return { day: parsed.day, count: parsed.count };
    }
  } catch {
    return null;
  }
  return null;
}

export async function POST(request: Request) {
  if (!hasSigningSecret()) {
    return NextResponse.json(
      { error: "Usage limits are not configured. Set SCAMSHIELD_TRIAL_SECRET." },
      { status: 503 },
    );
  }

  if (hasProAccess(request)) {
    return NextResponse.json({ plan: "pro", remaining: null, limit: null });
  }

  const day = new Date().toISOString().slice(0, 10);
  const stored = parseUsage(readSignedCookie(request, USAGE_COOKIE));
  const count = stored?.day === day ? stored.count : 0;
  if (count >= DAILY_SCAN_LIMIT) {
    return NextResponse.json(
      { error: "You’ve used all 3 free scans for today.", remaining: 0, limit: DAILY_SCAN_LIMIT },
      { status: 429 },
    );
  }

  const signedUsage = signValue(JSON.stringify({ day, count: count + 1 }));
  if (!signedUsage) {
    return NextResponse.json({ error: "Usage limits are not configured." }, { status: 503 });
  }
  const response = NextResponse.json({
    plan: "free",
    remaining: DAILY_SCAN_LIMIT - count - 1,
    limit: DAILY_SCAN_LIMIT,
  });
  response.cookies.set(USAGE_COOKIE, signedUsage, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 2 * 86_400,
  });
  return response;
}
