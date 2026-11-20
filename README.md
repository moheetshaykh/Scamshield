# ScamShield

ScamShield checks suspicious messages and links with local URL heuristics, public RDAP registration data, browser-based screenshot OCR, and structured AI analysis from Groq.

## Get started

1. Install Node.js LTS and run `npm install`.
2. Copy `.env.example` to `.env.local`.
3. Add a Groq API key to `.env.local` to enable AI analysis.
4. Run `npm run dev` and open `http://localhost:3000`.

The demo Pro license key `SCAMSHIELD-PRO-2026` works in local development. Trial/license signing uses a development-only local secret by default; production deployments must set `SCAMSHIELD_TRIAL_SECRET`.

## Plans and usage

- Each browser starts a 30-day Pro trial on its first app visit. The signed, HTTP-only trial cookie is the server's entitlement source; `trialStartDate` and `isPro` are also mirrored in local storage for the UI.
- After the trial, the Free plan allows 3 basic scans per day, with local URL checks and RDAP domain registration lookups.
- Pro is priced at $4.99/month or PKR 999/month and includes unlimited AI Deep Scans, screenshot OCR, English/Roman Urdu AI explanations, WhatsApp warning sharing, and extended RDAP forensics (registration statuses and nameservers).
- The checkout button redirects to `NEXT_PUBLIC_CHECKOUT_URL`. Local Easypaisa, JazzCash, and bank transfer are presented as manual payment options; provide verified payment details through your own support channel and issue customers valid keys.
- License activation is backed by a signed HTTP-only cookie. Add issued keys to `SCAMSHIELD_PRO_LICENSE_KEYS` as a comma-separated server-side list. The demo key is intentionally disabled in production.

This repository includes a configurable checkout handoff and manual license activation, not a payment processor or subscription-management service. Connect a payment provider and validate subscription status through server-side webhooks before using this as a paid production service.

### Trial and free-plan limits

Trial and license entitlements are verified by API routes, and the free-scan endpoint applies a signed daily usage cookie. No account database is included: clearing browser cookies/storage can restart an anonymous trial or free quota, and stateless cookie limits are not an identity-grade abuse control. Add authentication and persistent server-side usage/billing records if strict per-user limits or cross-device entitlements are required.

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GROQ_API_KEY` | For AI analysis | — | Secret Groq API key. Keep it server-side; never use a `NEXT_PUBLIC_` prefix. |
| `GROQ_MODEL` | No | `llama-3.3-70b-versatile` | Groq model that supports structured JSON output. |
| `SCAMSHIELD_TRIAL_SECRET` | Production | Development-only local secret | Random secret used to sign trial, license, and usage cookies. Generate one with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. |
| `SCAMSHIELD_PRO_LICENSE_KEYS` | For paid manual activation | — | Comma-separated issued license keys. Store only in server environment settings. |
| `NEXT_PUBLIC_CHECKOUT_URL` | For card/global checkout | — | HTTPS checkout URL for your payment provider. |
| `NEXT_PUBLIC_SITE_URL` | Recommended for SEO | — | Public canonical site origin, for example `https://scamshield.example`. |

`.env.local` is ignored by Git. Never commit API keys, signing secrets, or customer license keys.

## Data and safety

- Screenshot OCR runs in the visitor's browser; the image is not uploaded. Tesseract.js downloads worker/language data as needed.
- URL heuristics run in the browser. The app does not open or follow submitted links.
- RDAP lookups go through the fixed `rdap.org` endpoint. Domain registration records and name-server data can be incomplete or unavailable.
- Text submitted for AI analysis and extracted URL signals are sent from the server route to Groq. Avoid pasting passwords, PINs, verification codes, or private information.
- AI output and heuristic signals are informational, can be wrong, and are not a safety guarantee.

## GitHub and Vercel

1. Push the repository to GitHub without `.env.local`.
2. Import it into Vercel as a Next.js project.
3. Add the production environment variables from the table above in Vercel Project Settings. Set a strong `SCAMSHIELD_TRIAL_SECRET`, the Groq key, valid production license keys, and HTTPS checkout/site URLs as applicable.
4. Redeploy after changing environment variables.

Before deploying, run:

```bash
npm run lint
npm run build
```
