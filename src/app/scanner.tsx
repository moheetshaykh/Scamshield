"use client";

import { createWorker } from "tesseract.js";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import type { ChangeEvent } from "react";

type Severity = "low" | "medium" | "high";
type Signal = { label: string; detail: string; severity: Severity };
type Indicator = { title: string; detail: string; severity: Severity };
type Analysis = {
  language: "en" | "roman-urdu";
  riskLevel: "low" | "medium" | "high";
  score: number;
  summary: string;
  indicators: Indicator[];
  actions: string[];
};
type DomainResult = {
  domain: string;
  registeredAt: string | null;
  ageDays: number | null;
  status: "ok" | "not_found" | "unknown" | "error";
  forensics?: { nameservers: string[]; statuses: string[] };
  error?: string;
};
type AccountState = {
  ready: boolean;
  trialStartDate: string | null;
  trialActive: boolean;
  isLicense: boolean;
  error: string;
};

const DAY_MS = 86_400_000;
const SAMPLE_MESSAGES = [
  {
    label: "Fake overseas job",
    text: "Congratulations! You have been selected for an overseas job. Pay a refundable processing fee today to secure your visa: https://overseas-careers.example/apply",
  },
  {
    label: "Fake Easypaisa / bank OTP",
    text: "Your wallet will be blocked in 30 minutes. Share your OTP to verify your account now: https://easypaisa-verify.example/secure",
  },
  {
    label: "Fake courier fee",
    text: "Your parcel is on hold due to an unpaid customs fee. Pay a small delivery charge now: https://parcel-fee-check.example/track",
  },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function parseDomainForensics(value: unknown): DomainResult["forensics"] | null {
  if (!isRecord(value) || !isStringArray(value.nameservers) || !isStringArray(value.statuses)) {
    return null;
  }
  return { nameservers: value.nameservers, statuses: value.statuses };
}

function isSeverity(value: unknown): value is Severity {
  return value === "low" || value === "medium" || value === "high";
}

function isAnalysis(value: unknown): value is Analysis {
  if (
    !isRecord(value) ||
    (value.language !== "en" && value.language !== "roman-urdu") ||
    (value.riskLevel !== "low" && value.riskLevel !== "medium" && value.riskLevel !== "high") ||
    typeof value.score !== "number" ||
    !Number.isInteger(value.score) ||
    value.score < 0 ||
    value.score > 100 ||
    typeof value.summary !== "string" ||
    !Array.isArray(value.indicators) ||
    !Array.isArray(value.actions)
  ) {
    return false;
  }

  return (
    value.indicators.every(
      (item) =>
        isRecord(item) &&
        typeof item.title === "string" &&
        typeof item.detail === "string" &&
        isSeverity(item.severity),
    ) && value.actions.every((action) => typeof action === "string")
  );
}

function isDomainStatus(value: unknown): value is DomainResult["status"] {
  return value === "ok" || value === "not_found" || value === "unknown" || value === "error";
}

const shorteners = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "ow.ly",
  "buff.ly",
  "rb.gy",
]);
const riskyTlds = new Set([
  "click",
  "country",
  "gq",
  "loan",
  "ml",
  "rest",
  "shop",
  "tk",
  "top",
  "work",
  "xyz",
  "zip",
]);
const knownDomains = [
  "amazon.com",
  "apple.com",
  "axisbank.com",
  "dhl.com",
  "facebook.com",
  "google.com",
  "hdfcbank.com",
  "icicibank.com",
  "instagram.com",
  "microsoft.com",
  "netflix.com",
  "paypal.com",
  "sbi.co.in",
  "whatsapp.com",
];
const multiPartSuffixes = new Set(["co.in", "co.uk", "com.au", "com.br", "com.cn", "com.jp"]);

function getUrlFromText(text: string): string | null {
  const match = text.match(
    /(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/i,
  );
  return match?.[0].replace(/[.,!?;:)\]}]+$/, "") ?? null;
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return null;
  }
}

function getRootDomain(hostname: string): string {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const suffix = labels.slice(-2).join(".");
  return multiPartSuffixes.has(suffix) ? labels.slice(-3).join(".") : suffix;
}

function editDistance(left: string, right: string): number {
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i++) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= right.length; j++) {
      const old = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1));
      previous = old;
    }
  }
  return row[right.length];
}

function getLocalSignals(url: URL): Signal[] {
  const signals: Signal[] = [];
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const rootDomain = getRootDomain(host);
  const tld = host.split(".").pop() ?? "";

  if (url.protocol !== "https:") {
    signals.push({
      label: "Connection is not encrypted",
      detail: "This link uses HTTP, so information sent to it may not be protected in transit.",
      severity: "medium",
    });
  }
  if (url.username || url.password) {
    signals.push({
      label: "Login-like text in the URL",
      detail: "The address contains credentials before the hostname, a pattern sometimes used to disguise the real destination.",
      severity: "high",
    });
  }
  if (host.startsWith("xn--") || host.split(".").some((part) => part.startsWith("xn--"))) {
    signals.push({
      label: "Internationalized domain",
      detail: "The hostname contains punycode. Check for look-alike characters before trusting it.",
      severity: "medium",
    });
  }
  if (riskyTlds.has(tld)) {
    signals.push({
      label: `Uncommon .${tld} domain ending`,
      detail: "This domain ending is sometimes used in low-cost or disposable registrations. It is a clue, not proof of fraud.",
      severity: "low",
    });
  }
  if (shorteners.has(rootDomain)) {
    signals.push({
      label: "Shortened link",
      detail: "The destination is hidden behind a URL shortener. ScamShield does not open or follow the link.",
      severity: "medium",
    });
  }

  const firstLabel = host.split(".")[0].replace(/[^a-z0-9]/g, "");
  const lookalike = knownDomains.find((known) => {
    if (host === known || host.endsWith(`.${known}`)) return false;
    const knownLabel = known.split(".")[0];
    return (
      firstLabel.length >= 5 &&
      Math.abs(firstLabel.length - knownLabel.length) <= 1 &&
      editDistance(firstLabel, knownLabel) <= 1
    );
  });
  if (lookalike) {
    signals.push({
      label: "Possible brand look-alike",
      detail: `The hostname resembles ${lookalike}, but is not that organization's exact domain.`,
      severity: "high",
    });
  }

  const redirectParameters = ["continue", "dest", "destination", "next", "redirect", "return", "target", "url"];
  const redirectParameter = Array.from(url.searchParams.keys()).find((key) =>
    redirectParameters.includes(key.toLowerCase()),
  );
  if (redirectParameter) {
    signals.push({
      label: "Redirect-style parameter",
      detail: `The URL includes a "${redirectParameter}" parameter that may send visitors to another address. The redirect was not followed.`,
      severity: "medium",
    });
  }
  if (url.href.length > 200) {
    signals.push({
      label: "Unusually long URL",
      detail: "Long addresses can hide the actual destination or carry extensive tracking parameters.",
      severity: "low",
    });
  }

  if (signals.length === 0) {
    signals.push({
      label: "No obvious URL pattern found",
      detail: "Basic local checks did not flag this address. This is not a guarantee that it is safe.",
      severity: "low",
    });
  }
  return signals;
}

function friendlyDate(value: string | null): string {
  if (!value) return "Not available";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value));
}

export default function Scanner() {
  const [mode, setMode] = useState<"message" | "screenshot">("message");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [ocrText, setOcrText] = useState("");
  const [ocrProgress, setOcrProgress] = useState<number | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [domainResult, setDomainResult] = useState<DomainResult | null>(null);
  const [error, setError] = useState("");
  const [lookupNote, setLookupNote] = useState("");
  const [language, setLanguage] = useState<"en" | "roman-urdu">("en");
  const [account, setAccount] = useState<AccountState>({
    ready: false,
    trialStartDate: null,
    trialActive: false,
    isLicense: false,
    error: "",
  });
  const [pricingOpen, setPricingOpen] = useState(false);
  const [licenseInput, setLicenseInput] = useState("");
  const [licenseError, setLicenseError] = useState("");
  const [isActivating, setIsActivating] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [remainingScans, setRemainingScans] = useState<number | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const [now, setNow] = useState(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const isPro = account.isLicense || account.trialActive;

  useEffect(() => {
    let active = true;
    async function loadAccount() {
      try {
        const response = await fetch("/api/trial", { method: "POST" });
        const result: unknown = await response.json();
        if (
          !response.ok ||
          !isRecord(result) ||
          typeof result.trialStartDate !== "string" ||
          typeof result.trialActive !== "boolean" ||
          typeof result.isPro !== "boolean" ||
          typeof result.isLicense !== "boolean"
        ) {
          const message = isRecord(result) && typeof result.error === "string"
            ? result.error
            : "Could not load your plan.";
          throw new Error(message);
        }
        if (!active) return;
        const startDate = result.trialStartDate;
        const trialActive = result.trialActive;
        const isLicense = result.isLicense;
        setNow(Date.now());
        window.localStorage.setItem("trialStartDate", startDate);
        window.localStorage.setItem("isPro", String(result.isPro));
        if (!isLicense) window.localStorage.removeItem("licenseKey");
        setAccount({ ready: true, trialStartDate: startDate, trialActive, isLicense, error: "" });
        const today = new Date().toISOString().slice(0, 10);
        const usedToday = window.localStorage.getItem("dailyScanDate") === today
          ? Number(window.localStorage.getItem("dailyScanCount") ?? 0)
          : 0;
        setRemainingScans(Math.max(0, 3 - usedToday));
        if (!trialActive && !isLicense) setPricingOpen(true);
      } catch (accountError) {
        if (!active) return;
        const message = accountError instanceof Error ? accountError.message : "Could not load your plan.";
        setAccount({
          ready: true,
          trialStartDate: null,
          trialActive: false,
          isLicense: false,
          error: message,
        });
      }
    }
    void loadAccount();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const trialStartDate = account.trialStartDate;
    if (!trialStartDate || account.isLicense || !account.trialActive) return;
    const timer = window.setInterval(() => {
      const currentTime = Date.now();
      setNow(currentTime);
      if (currentTime >= new Date(trialStartDate).getTime() + 30 * DAY_MS) {
        window.localStorage.setItem("isPro", "false");
        setAccount((current) => ({ ...current, trialActive: false }));
        setPricingOpen(true);
      }
    }, 60_000);
    return () => window.clearInterval(timer);
  }, [account.isLicense, account.trialActive, account.trialStartDate]);

  useEffect(() => {
    if (!pricingOpen) return;
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setPricingOpen(false);
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [pricingOpen]);

  async function activateLicense() {
    setIsActivating(true);
    setLicenseError("");
    try {
      const response = await fetch("/api/license", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ licenseKey: licenseInput }),
      });
      const result: unknown = await response.json();
      if (!response.ok || !isRecord(result) || result.isPro !== true) {
        throw new Error(isRecord(result) && typeof result.error === "string"
          ? result.error
          : "Could not activate this license key.");
      }
      window.localStorage.setItem("isPro", "true");
      window.localStorage.setItem("licenseKey", licenseInput.trim());
      setAccount((current) => ({ ...current, isLicense: true, error: "" }));
      setPricingOpen(false);
      setLicenseInput("");
    } catch (activationError) {
      setLicenseError(activationError instanceof Error ? activationError.message : "Could not activate this license key.");
    } finally {
      setIsActivating(false);
    }
  }

  async function consumeScan(): Promise<boolean> {
    const response = await fetch("/api/usage", { method: "POST" });
    const result: unknown = await response.json();
    if (response.status === 429) {
      setRemainingScans(0);
      setPricingOpen(true);
      throw new Error(isRecord(result) && typeof result.error === "string"
        ? result.error
        : "You’ve used all 3 free scans for today.");
    }
    if (!response.ok || !isRecord(result)) {
      throw new Error(isRecord(result) && typeof result.error === "string"
        ? result.error
        : "Could not verify today’s scan limit.");
    }
    if (result.plan !== "pro" && result.plan !== "free") {
      throw new Error("The scan usage service returned an unexpected response.");
    }
    if (result.plan === "free") {
      if (
        typeof result.remaining !== "number" ||
        result.remaining < 0 ||
        result.remaining > 2
      ) {
        throw new Error("The scan usage service returned an unexpected response.");
      }
      const remaining = result.remaining;
      const today = new Date().toISOString().slice(0, 10);
      window.localStorage.setItem("dailyScanDate", today);
      window.localStorage.setItem("dailyScanCount", String(3 - remaining));
      setRemainingScans(remaining);
      if (account.trialActive && !account.isLicense) {
        window.localStorage.setItem("isPro", "false");
        setAccount((current) => ({ ...current, trialActive: false }));
        setPricingOpen(true);
      }
    }
    return result.plan === "pro";
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null;
    setError("");
    setAnalysis(null);
    setOcrText("");
    setOcrProgress(null);

    if (!selected) {
      setFile(null);
      return;
    }
    if (!["image/png", "image/jpeg", "image/webp", "image/bmp"].includes(selected.type)) {
      setError("Choose a PNG, JPG, WebP or BMP screenshot.");
      event.target.value = "";
      return;
    }
    if (selected.size > 8 * 1024 * 1024) {
      setError("Screenshot must be smaller than 8 MB.");
      event.target.value = "";
      return;
    }

    setFile(selected);
    let worker: Awaited<ReturnType<typeof createWorker>> | undefined;
    try {
      worker = await createWorker("eng", 1, {
        logger: (message) => {
          if (message.status === "recognizing text") {
            setOcrProgress(Math.round(message.progress * 100));
          }
        },
      });
      const result = await worker.recognize(selected);
      const recognized = result.data.text.trim();
      setOcrText(recognized);
      if (!recognized) setError("No readable text was found. Try a clearer screenshot.");
    } catch {
      setError("Could not read text from this image. Try another screenshot.");
    } finally {
      await worker?.terminate();
      setOcrProgress(null);
    }
  }

  async function runAnalysis() {
    const sourceText = mode === "screenshot" ? ocrText : text.trim();
    if (!sourceText.trim()) {
      setError(mode === "screenshot" ? "Select a screenshot with readable text first." : "Paste a message or URL to check.");
      return;
    }
    if (!account.ready) {
      setError("Your plan is still loading. Please try again in a moment.");
      return;
    }

    setIsAnalyzing(true);
    setError("");
    setLookupNote("");
    setAnalysis(null);
    setDomainResult(null);
    setScanComplete(false);
    let scanIsPro: boolean;
    try {
      scanIsPro = await consumeScan();
    } catch (usageError) {
      setError(usageError instanceof Error ? usageError.message : "Could not verify today’s scan limit.");
      setIsAnalyzing(false);
      return;
    }
    if (!scanIsPro && mode === "screenshot") {
      setPricingOpen(true);
      setError("Screenshot OCR is a Pro feature.");
      setIsAnalyzing(false);
      return;
    }

    const extracted = getUrlFromText(sourceText);
    const parsedUrl = extracted ? parseUrl(extracted) : null;
    let localSignals = parsedUrl ? getLocalSignals(parsedUrl) : [];
    if (extracted && !parsedUrl) {
      localSignals = [{
        label: "URL could not be parsed",
        detail: "The extracted address could not be checked. Treat it with caution.",
        severity: "medium",
      }];
    }

    let registrationSignal: Signal | null = null;
    if (parsedUrl) {
      const rootDomain = getRootDomain(parsedUrl.hostname);
      try {
        const response = await fetch(
          `/api/domain?domain=${encodeURIComponent(rootDomain)}${scanIsPro ? "&deep=1" : ""}`,
        );
        const result: unknown = await response.json();
        if (!response.ok) {
          const message = isRecord(result) && typeof result.error === "string"
            ? result.error
            : "Domain age lookup failed.";
          throw new Error(message);
        }
        if (
          !isRecord(result) ||
          !(result.registeredAt === null || typeof result.registeredAt === "string") ||
          !(result.ageDays === null || typeof result.ageDays === "number") ||
          !isDomainStatus(result.status) ||
          (result.forensics !== undefined && !parseDomainForensics(result.forensics))
        ) {
          throw new Error("The domain age service returned an unexpected response.");
        }

        const forensics = parseDomainForensics(result.forensics);
        const record: DomainResult = {
          domain: rootDomain,
          registeredAt: result.registeredAt,
          ageDays: result.ageDays,
          status: result.status,
          ...(forensics ? { forensics } : {}),
        };
        setDomainResult(record);
        if (record.ageDays !== null && record.ageDays < 180) {
          registrationSignal = {
            label: "Recently registered domain",
            detail: `The public registration record is about ${record.ageDays} days old. New domains deserve extra care, but age alone does not establish intent.`,
            severity: record.ageDays < 30 ? "high" : "medium",
          };
        }
      } catch (lookupError) {
        const message = lookupError instanceof Error ? lookupError.message : "Domain age lookup failed.";
        setLookupNote(message);
        setDomainResult({
          domain: rootDomain,
          registeredAt: null,
          ageDays: null,
          status: "error",
          error: message,
        });
      }
    }

    const allSignals = registrationSignal ? [...localSignals, registrationSignal] : localSignals;
    setSignals(allSignals);
    setScanComplete(true);

    if (!scanIsPro) {
      if (mode === "screenshot" || language !== "en") {
        setPricingOpen(true);
        setError("Screenshot OCR and Roman Urdu AI explanations are Pro features.");
      }
      setIsAnalyzing(false);
      return;
    }

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: sourceText,
          url: parsedUrl?.href ?? extracted ?? "",
          signals: allSignals,
          language,
        }),
      });
      const result: unknown = await response.json();
      if (!response.ok) {
        const message = isRecord(result) && typeof result.error === "string"
          ? result.error
          : "AI analysis failed.";
        throw new Error(message);
      }
      if (!isAnalysis(result) || result.language !== language) {
        throw new Error("The AI provider returned an unexpected analysis format or language.");
      }
      setAnalysis(result);
    } catch (analysisError) {
      setError(analysisError instanceof Error ? analysisError.message : "AI analysis failed.");
    } finally {
      setIsAnalyzing(false);
    }
  }

  function reset() {
    setText("");
    setFile(null);
    setOcrText("");
    setAnalysis(null);
    setSignals([]);
    setDomainResult(null);
    setScanComplete(false);
    setError("");
    setLookupNote("");
    if (fileInput.current) fileInput.current.value = "";
  }

  const scoreColor =
    analysis?.riskLevel === "high" ? "danger" : analysis?.riskLevel === "medium" ? "warning" : "safe";
  const trialDaysLeft = account.trialStartDate
    ? Math.max(0, Math.ceil((new Date(account.trialStartDate).getTime() + 30 * DAY_MS - now) / DAY_MS))
    : 0;
  const alertText = analysis
    ? `⚠️ ScamShield warning — ${analysis.riskLevel.toUpperCase()} RISK\n\n${analysis.summary}\n\n${analysis.indicators.map((item) => `• ${item.title}: ${item.detail}`).join("\n")}\n\nDo not share passwords, PINs, or verification codes. Verify through the organization’s official app or website.`
    : "";

  async function copyWhatsAppAlert() {
    try {
      await navigator.clipboard.writeText(alertText);
      setError("");
      setCopyStatus("WhatsApp warning copied. Paste it into a chat to share.");
    } catch {
      setError("Could not copy the warning. Check your browser clipboard permissions.");
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <Link className="brand" href="/" aria-label="ScamShield home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>scam<span className="brand-light">shield</span></span>
        </Link>
        <div className="header-actions">
          <button type="button" className={`plan-badge ${isPro ? "active" : ""}`} onClick={() => setPricingOpen(true)}>
            {account.isLicense
              ? "Pro member"
              : account.trialActive
                ? `Pro Trial: ${trialDaysLeft} days left`
                : account.ready
                  ? "Free plan · Upgrade"
                  : "Loading plan…"}
          </button>
          <div className="privacy-pill"><span className="privacy-dot" /> Private by design</div>
        </div>
      </header>

      <section className="hero">
        <div className="eyebrow"><span className="eyebrow-line" /> YOUR EVERYDAY SCAM CHECKER</div>
        <h1>Pause. Check.<br /><span>Stay protected.</span></h1>
        <p>Suspicious message or link? Get a clear, practical read before you take action.</p>
        <div className="trust-row">
          <span><b>01</b> Local URL checks</span>
          <span><b>02</b> Screenshot OCR</span>
          <span><b>03</b> AI-assisted review</span>
        </div>
      </section>

      <section className="workspace" aria-label="Scam check">
        <div className="input-card">
          <div className="card-heading">
            <div>
              <span className="step-label">START A CHECK</span>
              <h2>What would you like to check?</h2>
            </div>
            <span className="lock-label"><span aria-hidden="true">⌑</span> Secure check</span>
          </div>

          <div className="mode-tabs" role="tablist" aria-label="Choose input type">
            <button
              className={`mode-tab ${mode === "message" ? "active" : ""}`}
              onClick={() => { setMode("message"); setError(""); }}
              role="tab"
              aria-selected={mode === "message"}
              type="button"
            >
              <span aria-hidden="true">↗</span> Link or message
            </button>
            <button
              className={`mode-tab ${mode === "screenshot" ? "active" : ""}`}
              onClick={() => {
                if (!isPro) {
                  setPricingOpen(true);
                  return;
                }
                setMode("screenshot");
                setError("");
              }}
              role="tab"
              aria-selected={mode === "screenshot"}
              type="button"
            >
              <span aria-hidden="true">▧</span> Screenshot
              <span className="free-tag">PRO</span>
            </button>
          </div>

          <div className="sample-row" aria-label="Try a sample scam">
            <span>Try a sample:</span>
            {SAMPLE_MESSAGES.map((sample) => (
              <button
                type="button"
                key={sample.label}
                onClick={() => {
                  setMode("message");
                  setText(sample.text);
                  setError("");
                  setAnalysis(null);
                  setSignals([]);
                  setDomainResult(null);
                  setScanComplete(false);
                  setCopyStatus("");
                }}
              >
                {sample.label}
              </button>
            ))}
          </div>

          {mode === "message" ? (
            <label className="input-label" htmlFor="message-input">
              Paste the message or URL here
              <textarea
                id="message-input"
                className="message-input"
                placeholder={"Example: Your parcel is on hold. Pay a small fee now: https://..."}
                value={text}
                onChange={(event) => { setText(event.target.value); setError(""); }}
                maxLength={16_000}
              />
            </label>
          ) : (
            <div className="upload-area">
              <input
                ref={fileInput}
                className="visually-hidden"
                type="file"
                accept="image/png,image/jpeg,image/webp,image/bmp"
                onChange={handleFileChange}
                aria-label="Choose screenshot"
              />
              <button className="upload-button" type="button" onClick={() => fileInput.current?.click()}>
                <span className="upload-icon" aria-hidden="true">↑</span>
                <span className="upload-title">{file ? file.name : "Choose a screenshot"}</span>
                <span className="upload-hint">PNG, JPG, WebP or BMP · up to 8 MB</span>
              </button>
              {ocrProgress !== null && <p className="processing-note">Reading text in your browser… {ocrProgress}%</p>}
              {ocrText && (
                <label className="input-label extracted-label" htmlFor="ocr-text">
                  Extracted text <span>You can edit it before checking.</span>
                  <textarea id="ocr-text" className="message-input" value={ocrText} onChange={(event) => setOcrText(event.target.value)} />
                </label>
              )}
            </div>
          )}

          <div className="language-row">
            <span>AI explanation</span>
            <div className="language-toggle" role="group" aria-label="AI explanation language">
              <button
                type="button"
                className={language === "en" ? "selected" : ""}
                onClick={() => setLanguage("en")}
              >
                English
              </button>
              <button
                type="button"
                className={language === "roman-urdu" ? "selected" : ""}
                onClick={() => {
                  if (!isPro) {
                    setPricingOpen(true);
                    return;
                  }
                  setLanguage("roman-urdu");
                }}
              >
                Roman Urdu <span>PRO</span>
              </button>
            </div>
          </div>

          <div className="form-footer">
            <p><span className="info-icon" aria-hidden="true">i</span> {isPro ? "Unlimited Pro scans" : `${remainingScans ?? 3} free scans left today`} · Never enter passwords, PINs or verification codes.</p>
            <button className="analyze-button" type="button" onClick={runAnalysis} disabled={!account.ready || isAnalyzing || ocrProgress !== null}>
              {isAnalyzing ? <><span className="spinner" /> Checking…</> : <>Check for scams <span aria-hidden="true">→</span></>}
            </button>
          </div>
          {error && <p className="error-message" role="alert">{error}</p>}
          {account.error && <p className="error-message" role="alert">{account.error}</p>}
        </div>

        <div className="side-note">
          <div className="side-note-icon" aria-hidden="true">✳</div>
          <div><strong>Not sure? That’s a good reason to check.</strong><p>ScamShield never opens suspicious links. Your screenshot text is read locally in your browser.</p></div>
        </div>

        {(scanComplete || analysis || signals.length > 0) && (
          <section className="results-card" aria-live="polite">
            <div className="result-header">
              <div>
                <span className="step-label">YOUR CHECK RESULTS</span>
                <h2>Here’s what we found</h2>
              </div>
              <button type="button" className="text-button" onClick={reset}>New check <span aria-hidden="true">↗</span></button>
            </div>

            {analysis ? (
              <>
                <div className={`risk-summary ${scoreColor}`}>
                  <div className={`score-ring ${scoreColor}`}><strong>{analysis.score}</strong><span>/100</span></div>
                  <div>
                    <span className="result-kicker">AI-ASSISTED ASSESSMENT</span>
                    <h3>{analysis.riskLevel === "high" ? "High risk detected" : analysis.riskLevel === "medium" ? "Use extra caution" : "No strong warning signs found"}</h3>
                    <p>{analysis.summary}</p>
                  </div>
                </div>
                <p className="disclaimer">This is an automated assessment, not a guarantee. When in doubt, verify through the organization’s official app or website.</p>
              </>
            ) : (
              <div className="local-only-note">
                {isPro
                  ? "Local checks are ready. AI assessment is still in progress or unavailable."
                  : "Free checks look for URL patterns and public domain registration details. Upgrade for AI Deep Scans and message analysis."}
              </div>
            )}

            {domainResult && (
              <div className="domain-row">
                <span className="domain-icon" aria-hidden="true">⌘</span>
                <div><strong>Domain registration</strong><span>{domainResult.domain} · {domainResult.ageDays === null ? domainResult.error ? "Lookup unavailable" : "Age not available" : `Registered ${friendlyDate(domainResult.registeredAt)} · ${domainResult.ageDays} days old`}</span></div>
                <span className={`status-tag ${domainResult.status === "error" || domainResult.status === "not_found" ? "muted" : ""}`}>
                  {domainResult.status === "error"
                    ? "Unavailable"
                    : domainResult.status === "not_found"
                      ? "No registration"
                      : domainResult.ageDays !== null && domainResult.ageDays < 180
                        ? "Recently registered"
                        : domainResult.ageDays !== null
                          ? "Record found"
                          : "Age unavailable"}
                </span>
              </div>
            )}
            {domainResult?.forensics && (
              <div className="forensics-row">
                <strong>Pro domain forensics</strong>
                <span>Nameservers: {domainResult.forensics.nameservers.length
                  ? domainResult.forensics.nameservers.join(", ")
                  : "Not listed"}</span>
                <span>RDAP statuses: {domainResult.forensics.statuses.length
                  ? domainResult.forensics.statuses.join(", ")
                  : "Not listed"}</span>
              </div>
            )}
            {lookupNote && <p className="lookup-note">{lookupNote}</p>}

            {signals.length > 0 && (
              <div className="findings-section">
                <h3>URL checks <span>{signals.length} {signals.length === 1 ? "signal" : "signals"}</span></h3>
                <div className="finding-list">
                  {signals.map((signal, index) => (
                    <article className="finding" key={`${signal.label}-${index}`}>
                      <span className={`finding-marker ${signal.severity}`} aria-hidden="true">
                        {signal.severity === "high" ? "!" : signal.severity === "medium" ? "△" : "·"}
                      </span>
                      <div><strong>{signal.label}</strong><p>{signal.detail}</p></div>
                      <span className={`severity-label ${signal.severity}`}>{signal.severity}</span>
                    </article>
                  ))}
                </div>
              </div>
            )}

            {analysis && analysis.indicators.length > 0 && (
              <div className="findings-section">
                <h3>Message indicators <span>{analysis.indicators.length} {analysis.indicators.length === 1 ? "finding" : "findings"}</span></h3>
                <div className="finding-list">
                  {analysis.indicators.map((indicator, index) => (
                    <article className="finding" key={`${indicator.title}-${index}`}>
                      <span className={`finding-marker ${indicator.severity}`} aria-hidden="true">
                        {indicator.severity === "high" ? "!" : indicator.severity === "medium" ? "△" : "·"}
                      </span>
                      <div><strong>{indicator.title}</strong><p>{indicator.detail}</p></div>
                      <span className={`severity-label ${indicator.severity}`}>{indicator.severity}</span>
                    </article>
                  ))}
                </div>
              </div>
            )}

            {analysis && analysis.actions.length > 0 && (
              <div className="actions-box">
                <h3>What to do next</h3>
                <ul>{analysis.actions.map((action, index) => <li key={`${action}-${index}`}>{action}</li>)}</ul>
              </div>
            )}
            {analysis && (
              <>
                <article className={`whatsapp-card ${scoreColor}`} aria-label="Shareable WhatsApp warning card preview">
                  <div className="whatsapp-card-brand"><span className="brand-mark" aria-hidden="true">S</span> SCAMSHIELD COMMUNITY ALERT</div>
                  <strong>{analysis.riskLevel.toUpperCase()} RISK</strong>
                  <p>{analysis.summary}</p>
                  <small>Verify with the organization’s official app or website. Never share passwords, PINs, or OTPs.</small>
                </article>
                <div className="share-actions">
                  <button type="button" className="share-button" onClick={copyWhatsAppAlert}>
                    Copy WhatsApp Alert
                  </button>
                  <a
                    className="share-button secondary"
                    href={`https://wa.me/?text=${encodeURIComponent(alertText)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Share on WhatsApp
                  </a>
                  {copyStatus && <span className="copy-status" role="status">{copyStatus}</span>}
                </div>
              </>
            )}
          </section>
        )}

        <div className="method-note">
          <span className="method-icon" aria-hidden="true">◈</span>
          <p><strong>A helpful second opinion, not a verdict.</strong> URL checks use local patterns and public RDAP registration data. Screenshots are OCR-processed on your device. Text sent for AI analysis goes to Groq; never include private information.</p>
        </div>
      </section>

      <footer className="footer">
        <span>© 2026 ScamShield</span>
        <span>Built for safer clicks, not certainty.</span>
      </footer>
      {pricingOpen && (
        <div className="modal-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setPricingOpen(false);
        }}>
          <section className="pricing-modal" role="dialog" aria-modal="true" aria-labelledby="pricing-title">
            <button type="button" className="modal-close" aria-label="Close pricing" onClick={() => setPricingOpen(false)}>×</button>
            <span className="step-label">SCAMSHIELD PRO</span>
            <h2 id="pricing-title">More confidence, fewer limits.</h2>
            <p className="pricing-intro">Unlock stronger scam checks and shareable warnings for <strong>$4.99/month</strong> or <strong>PKR 999/month</strong>.</p>
            <ul className="pro-benefits">
              <li>Unlimited AI Deep Scans</li>
              <li>Screenshot OCR and Roman Urdu + English explanations</li>
              <li>One-tap WhatsApp warning cards</li>
              <li>Priority domain forensics</li>
            </ul>
            <a
              className={`checkout-button ${process.env.NEXT_PUBLIC_CHECKOUT_URL ? "" : "disabled"}`}
              href={process.env.NEXT_PUBLIC_CHECKOUT_URL || undefined}
              target="_blank"
              rel="noreferrer"
              aria-disabled={!process.env.NEXT_PUBLIC_CHECKOUT_URL}
              onClick={(event) => {
                if (!process.env.NEXT_PUBLIC_CHECKOUT_URL) event.preventDefault();
              }}
            >
              {process.env.NEXT_PUBLIC_CHECKOUT_URL ? "Continue to secure checkout" : "Card checkout — configure checkout URL"}
            </a>
            <div className="local-payment">
              <h3>Pay locally</h3>
              <p>For Easypaisa, JazzCash, or bank transfer, contact your support team for verified payment details. After payment, enter the license key you receive below. Never share an OTP or PIN as proof of payment.</p>
            </div>
            <form className="license-form" onSubmit={(event) => {
              event.preventDefault();
              void activateLicense();
            }}>
              <label htmlFor="license-key">Have a Pro License Key?</label>
              <div>
                <input
                  id="license-key"
                  value={licenseInput}
                  onChange={(event) => setLicenseInput(event.target.value)}
                  autoComplete="off"
                  maxLength={128}
                  placeholder="Enter license key"
                />
                <button type="submit" disabled={isActivating || !licenseInput.trim()}>
                  {isActivating ? "Checking…" : "Unlock Pro"}
                </button>
              </div>
              {process.env.NODE_ENV !== "production" && (
                <p className="demo-key-note">Local demo key: <code>SCAMSHIELD-PRO-2026</code></p>
              )}
              {licenseError && <p className="error-message" role="alert">{licenseError}</p>}
            </form>
            <p className="pricing-footnote">Free plan includes 3 basic URL and RDAP scans per day after the 30-day Pro trial.</p>
          </section>
        </div>
      )}
    </main>
  );
}
