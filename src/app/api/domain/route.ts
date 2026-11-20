import { NextResponse } from "next/server";
import { hasProAccess } from "@/lib/entitlements";

const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)$/i;

type RdapEvent = {
  eventAction?: string;
  eventDate?: string;
};

export async function GET(request: Request) {
  const searchParams = new URL(request.url).searchParams;
  const domain = searchParams.get("domain")?.toLowerCase();
  const deepForensics = searchParams.get("deep") === "1";

  if (!domain || !DOMAIN_PATTERN.test(domain)) {
    return NextResponse.json({ error: "Enter a valid public domain." }, { status: 400 });
  }
  if (deepForensics && !hasProAccess(request)) {
    return NextResponse.json(
      { error: "Extended domain forensics are a Pro feature." },
      { status: 403 },
    );
  }

  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(7000),
      cache: "no-store",
    });

    if (response.status === 404) {
      return NextResponse.json({
        registeredAt: null,
        ageDays: null,
        status: "not_found",
        ...(deepForensics ? { forensics: { nameservers: [], statuses: [] } } : {}),
      });
    }

    if (!response.ok) {
      return NextResponse.json(
        { error: "The public domain registration lookup is temporarily unavailable." },
        { status: 502 },
      );
    }

    const record = (await response.json()) as {
      events?: RdapEvent[];
      nameservers?: unknown;
      status?: unknown;
    };
    const forensics = deepForensics
      ? {
          nameservers: (Array.isArray(record.nameservers) ? record.nameservers : [])
            .flatMap((nameserver) =>
              typeof nameserver === "object" &&
              nameserver !== null &&
              "ldhName" in nameserver &&
              typeof nameserver.ldhName === "string"
                ? [nameserver.ldhName]
                : [],
            )
            .slice(0, 12),
          statuses: (Array.isArray(record.status) ? record.status : [])
            .filter((status): status is string => typeof status === "string")
            .slice(0, 12),
        }
      : undefined;
    const registration = record.events?.find(
      (event) => event.eventAction?.toLowerCase() === "registration",
    )?.eventDate;

    if (!registration || Number.isNaN(Date.parse(registration))) {
      return NextResponse.json({
        registeredAt: null,
        ageDays: null,
        status: "unknown",
        ...(forensics ? { forensics } : {}),
      });
    }

    const ageDays = Math.max(
      0,
      Math.floor((Date.now() - new Date(registration).getTime()) / 86_400_000),
    );

    return NextResponse.json({
      registeredAt: registration,
      ageDays,
      status: "ok",
      ...(forensics ? { forensics } : {}),
    });
  } catch {
    return NextResponse.json(
      { error: "The public domain registration lookup timed out or could not be reached." },
      { status: 502 },
    );
  }
}
