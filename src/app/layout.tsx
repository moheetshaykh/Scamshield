import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  ...(process.env.NEXT_PUBLIC_SITE_URL
    ? { metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL) }
    : {}),
  title: "ScamShield — Check before you click",
  description: "Check suspicious messages and links with local URL checks, domain registration data, and AI-assisted scam analysis.",
  openGraph: {
    title: "ScamShield — Check before you click",
    description: "Check suspicious messages and links before you take action.",
    siteName: "ScamShield",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary",
    title: "ScamShield — Check before you click",
    description: "Check suspicious messages and links before you take action.",
  },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
