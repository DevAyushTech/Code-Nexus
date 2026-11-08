import { useState, type FormEvent } from "react";
import {
  analyzeMessage,
  analyzeUrl,
  verifyBlockchain,
  type AnalysisResponse,
  type BlockchainVerificationResponse,
} from "../services/apiClient";

type AnalysisMode = "url" | "message";
type RequestState = "idle" | "loading" | "complete" | "error";
type VerificationState = "idle" | "loading" | "complete" | "error";

interface TelemetryEntry {
  id: string;
  time: string;
  stage: string;
  message: string;
}

function createId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeUrl(value: string) {
  const trimmed = value.trim();
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  const parsed = new URL(candidate);
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    !parsed.hostname
  ) {
    throw new Error("Enter a valid HTTP or HTTPS URL.");
  }
  return parsed.toString();
}

function classificationKey(classification: string) {
  return classification.trim().toUpperCase().replace(/[\s-]+/g, "_");
}

function classificationStyle(classification: string) {
  switch (classificationKey(classification)) {
    case "SAFE":
      return "border-emerald-300/40 bg-emerald-300/10 text-emerald-100";
    case "INCONCLUSIVE":
      return "border-amber-300/40 bg-amber-300/10 text-amber-100";
    case "MALICIOUS":
    case "SUSPICIOUS":
      return "border-rose-300/40 bg-rose-300/10 text-rose-100";
    default:
      return "border-white/25 bg-white/5 text-white/85";
  }
}

function displayClassification(classification: string) {
  return classification.trim().replace(/[_-]+/g, " ").toUpperCase();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function verificationLabel(result: BlockchainVerificationResponse) {
  if (result.verified && result.on_chain) return "Verified on-chain";
  if (result.verified) return "Verified";
  if (!result.on_chain) return "No on-chain registration";
  return "Not verified";
}

export default function ThreatScanner() {
  const [mode, setMode] = useState<AnalysisMode>("url");
  const [url, setUrl] = useState("");
  const [content, setContent] = useState("");
  const [state, setState] = useState<RequestState>("idle");
  const [telemetry, setTelemetry] = useState<TelemetryEntry[]>([]);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [verificationState, setVerificationState] = useState<VerificationState>("idle");
  const [verification, setVerification] =
    useState<BlockchainVerificationResponse | null>(null);
  const [verificationError, setVerificationError] = useState("");

  const addTelemetry = (stage: string, message: string) => {
    setTelemetry((entries) =>
      [
        {
          id: createId(),
          time: new Date().toLocaleTimeString(),
          stage,
          message,
        },
        ...entries,
      ].slice(0, 12),
    );
  };

  const changeMode = (nextMode: AnalysisMode) => {
    setMode(nextMode);
    setState("idle");
    setResult(null);
    setError("");
    setVerification(null);
    setVerificationError("");
  };

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);
    setVerification(null);
    setVerificationError("");

    let input: string;
    try {
      input = mode === "url" ? normalizeUrl(url) : content.trim();
      if (mode === "message" && !input) {
        throw new Error("Enter a message to analyze.");
      }
    } catch (validationError) {
      setState("error");
      setError(errorMessage(validationError));
      return;
    }

    if (mode === "url") setUrl(input);
    setState("loading");
    setTelemetry([]);
    addTelemetry(
      "Request accepted",
      mode === "url" ? "Submitting URL for backend analysis." : "Submitting message for backend analysis.",
    );

    try {
      const analysis = mode === "url"
        ? await analyzeUrl(input)
        : await analyzeMessage(input);
      setResult(analysis);
      setState("complete");
      addTelemetry(
        "Analysis complete",
        `Backend returned report ${analysis.id}.`,
      );
    } catch (requestError) {
      const message = errorMessage(requestError);
      setState("error");
      setError(message);
      addTelemetry("Request failed", message);
    }
  }

  async function handleVerifyBlockchain() {
    if (!result) return;
    setVerificationState("loading");
    setVerification(null);
    setVerificationError("");

    try {
      const status = await verifyBlockchain(result.id);
      setVerification(status);
      setVerificationState("complete");
    } catch (requestError) {
      setVerificationError(errorMessage(requestError));
      setVerificationState("error");
    }
  }

  const inputValue = mode === "url" ? url : content;
  const hasInput = Boolean(inputValue.trim());

  return (
    <section className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(20rem,0.95fr)]">
      <div className="space-y-6">
        <section className="glass rounded-2xl p-5 sm:p-7" aria-labelledby="analysis-input-title">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <span className="tag-chip">Public API / 01</span>
              <h2 id="analysis-input-title" className="mt-2 font-display text-2xl font-light uppercase text-white">
                Analyze a target
              </h2>
            </div>
            <span className="rounded-full border border-white/15 px-3 py-1 font-mono text-[0.62rem] uppercase tracking-[0.16em] text-white/55">
              No account required
            </span>
          </div>

          <div className="mt-6 grid grid-cols-2 gap-2" aria-label="Analysis type">
            {(["url", "message"] as const).map((nextMode) => (
              <button
                key={nextMode}
                type="button"
                aria-pressed={mode === nextMode}
                disabled={state === "loading"}
                onClick={() => changeMode(nextMode)}
                className={`min-h-11 rounded-lg border px-4 font-mono text-xs uppercase tracking-[0.14em] transition ${
                  mode === nextMode
                    ? "border-white bg-white text-black"
                    : "border-white/15 bg-black/35 text-white/65 hover:border-white/35"
                }`}
              >
                {nextMode === "url" ? "Analyze URL" : "Analyze message"}
              </button>
            ))}
          </div>

          <form className="mt-6 space-y-5" onSubmit={handleSubmit} noValidate>
            <div>
              {mode === "url" ? (
                <>
                  <label htmlFor="threat-target" className="tag-chip">
                    Target URL
                  </label>
                  <input
                    id="threat-target"
                    name="url"
                    type="url"
                    autoComplete="url"
                    spellCheck={false}
                    placeholder="https://example.com"
                    value={url}
                    disabled={state === "loading"}
                    aria-invalid={state === "error"}
                    aria-describedby={error ? "analysis-error" : "analysis-hint"}
                    onChange={(event) => {
                      setUrl(event.target.value);
                      setError("");
                      setResult(null);
                      if (state !== "loading") setState("idle");
                    }}
                    className="mt-2 w-full rounded-xl border border-white/15 bg-black/55 px-4 py-3.5 font-mono text-sm text-white outline-none transition placeholder:text-white/30 focus:border-white/55 disabled:opacity-60"
                  />
                </>
              ) : (
                <>
                  <label htmlFor="threat-message" className="tag-chip">
                    Message content
                  </label>
                  <textarea
                    id="threat-message"
                    name="content"
                    rows={5}
                    placeholder="Paste a message you'd like to inspect..."
                    value={content}
                    disabled={state === "loading"}
                    aria-invalid={state === "error"}
                    aria-describedby={error ? "analysis-error" : "analysis-hint"}
                    onChange={(event) => {
                      setContent(event.target.value);
                      setError("");
                      setResult(null);
                      if (state !== "loading") setState("idle");
                    }}
                    className="mt-2 w-full resize-y rounded-xl border border-white/15 bg-black/55 px-4 py-3.5 text-sm leading-relaxed text-white outline-none transition placeholder:text-white/30 focus:border-white/55 disabled:opacity-60"
                  />
                </>
              )}
              <p id="analysis-hint" className="mt-2 text-xs leading-relaxed text-white/45">
                {mode === "url"
                  ? "Enter a URL or domain; missing schemes default to HTTPS."
                  : "Message content is sent to the public analysis API for inspection."}
              </p>
              {error && (
                <p id="analysis-error" role="alert" className="mt-2 text-sm text-rose-100">
                  {error}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={state === "loading" || !hasInput}
              className="flex min-h-12 w-full items-center justify-between rounded-xl border border-white/70 bg-white px-5 font-mono text-xs uppercase tracking-[0.18em] text-black transition hover:bg-transparent hover:text-white disabled:cursor-not-allowed disabled:opacity-55"
            >
              <span>{state === "loading" ? "Analyzing..." : "Run analysis"}</span>
              {state === "loading" ? (
                <span aria-hidden="true" className="size-4 animate-spin rounded-full border-2 border-black/25 border-t-black" />
              ) : (
                <span aria-hidden="true">↗</span>
              )}
            </button>
          </form>
        </section>

        <section className="glass rounded-2xl p-5 sm:p-7" aria-labelledby="telemetry-title">
          <div className="flex items-center justify-between gap-4">
            <div>
              <span className="tag-chip">Execution / 02</span>
              <h2 id="telemetry-title" className="mt-2 font-display text-2xl font-light uppercase text-white">
                Request status
              </h2>
            </div>
            {state === "loading" && (
              <span className="font-mono text-xs uppercase tracking-wider text-white/55" aria-live="polite">
                In progress
              </span>
            )}
          </div>

          <ol className="mt-5 max-h-64 space-y-2 overflow-y-auto" aria-live="polite" aria-relevant="additions">
            {telemetry.length === 0 ? (
              <li className="rounded-lg border border-white/10 bg-black/35 p-3 font-mono text-xs text-white/40">
                Request status will appear here when an analysis starts.
              </li>
            ) : (
              telemetry.map((entry) => (
                <li key={entry.id} className="grid grid-cols-[auto_1fr] gap-x-3 rounded-lg border border-white/10 bg-black/35 p-3">
                  <time className="font-mono text-[0.62rem] text-white/35">{entry.time}</time>
                  <span className="font-mono text-[0.62rem] uppercase tracking-[0.1em] text-white/75">
                    {entry.stage}
                  </span>
                  <span className="col-start-2 mt-1 text-xs leading-relaxed text-white/55">
                    {entry.message}
                  </span>
                </li>
              ))
            )}
          </ol>
        </section>
      </div>

      <section className="glass h-fit rounded-2xl p-5 sm:p-7" aria-labelledby="verdict-title">
        <span className="tag-chip">Assessment / 03</span>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
          <h2 id="verdict-title" className="font-display text-2xl font-light uppercase text-white">
            Analysis report
          </h2>
          {result && (
            <span className={`rounded-full border px-3 py-1 font-mono text-[0.65rem] uppercase tracking-[0.14em] ${classificationStyle(result.classification)}`}>
              {displayClassification(result.classification)}
            </span>
          )}
        </div>

        {!result ? (
          <div className="mt-6 rounded-xl border border-dashed border-white/15 bg-black/25 p-6 text-sm leading-relaxed text-white/45" aria-live="polite">
            {state === "loading"
              ? "Waiting for the backend analysis response..."
              : "Submit a URL or message to receive a backend analysis report."}
          </div>
        ) : (
          <div className="mt-6 space-y-5">
            <div className="flex items-end justify-between gap-4 border-b border-white/10 pb-4">
              <div className="min-w-0">
                <p className="tag-chip">{result.kind} / report {result.id}</p>
                <p className="mt-2 break-all font-mono text-xs text-white/75" title={result.target}>
                  {result.target}
                </p>
              </div>
              <div className="shrink-0 text-right">
                <p className="tag-chip">Risk score</p>
                <p className="mt-1 font-display text-4xl font-light text-white">
                  {result.risk_score}<span className="text-lg text-white/40">/100</span>
                </p>
              </div>
            </div>

            {classificationKey(result.classification) === "INCONCLUSIVE" && (
              <p className="rounded-lg border border-amber-200/20 bg-amber-200/5 p-3 text-sm leading-relaxed text-amber-100/80">
                The result is inconclusive, not a safe verdict. Some evidence or integrations may be unavailable.
              </p>
            )}
            {classificationKey(result.classification) === "SAFE" && (
              <p className="text-sm leading-relaxed text-white/60">
                The backend classified this analysis as safe. Review the available evidence and source status below.
              </p>
            )}

            {result.evidence_quality && (
              <p className="text-xs text-white/55">
                Evidence quality: <span className="text-white/80">{result.evidence_quality}</span>
              </p>
            )}

            <div>
              <h3 className="tag-chip">Findings</h3>
              {result.findings.length ? (
                <ul className="mt-3 space-y-3">
                  {result.findings.map((finding, index) => (
                    <li key={`${finding.name}-${index}`} className="rounded-lg border border-white/10 bg-black/35 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-sm text-white/85">{finding.name}</span>
                        <span className="font-mono text-[0.62rem] uppercase tracking-[0.12em] text-white/50">
                          {finding.severity}
                        </span>
                      </div>
                      <p className="mt-2 text-xs leading-relaxed text-white/60">{finding.explanation}</p>
                      {finding.evidence && (
                        <p className="mt-2 break-words text-xs leading-relaxed text-white/45">
                          Evidence: {finding.evidence}
                        </p>
                      )}
                      {finding.recommendation && (
                        <p className="mt-2 text-xs leading-relaxed text-white/70">
                          Recommendation: {finding.recommendation}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 rounded-lg border border-white/10 bg-black/35 p-3 text-sm text-white/50">
                  The API returned no findings for this analysis.
                </p>
              )}
            </div>

            <div>
              <h3 className="tag-chip">Signal sources</h3>
              {result.integrations.length ? (
                <ul className="mt-3 space-y-2">
                  {result.integrations.map((integration, index) => (
                    <li key={`${integration.source ?? "source"}-${index}`} className="rounded-lg border border-white/10 bg-black/35 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-sm text-white/80">{integration.source ?? "Analysis source"}</span>
                        <span className="font-mono text-[0.62rem] uppercase tracking-[0.12em] text-white/55">
                          {integration.status}
                        </span>
                      </div>
                      {integration.evidence && (
                        <p className="mt-2 text-xs leading-relaxed text-white/50">{integration.evidence}</p>
                      )}
                      {integration.error && (
                        <p className="mt-2 text-xs leading-relaxed text-amber-100/70">{integration.error}</p>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 rounded-lg border border-white/10 bg-black/35 p-3 text-sm text-white/50">
                  No integration results were returned; third-party sources are not assumed to be active.
                </p>
              )}
            </div>

            <div className="border-t border-white/10 pt-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h3 className="tag-chip">Blockchain verification</h3>
                <button
                  type="button"
                  onClick={handleVerifyBlockchain}
                  disabled={verificationState === "loading"}
                  className="rounded-lg border border-white/25 px-3 py-2 font-mono text-[0.62rem] uppercase tracking-[0.1em] text-white/75 transition hover:border-white/60 hover:text-white disabled:opacity-50"
                >
                  {verificationState === "loading" ? "Checking..." : "Verify report"}
                </button>
              </div>
              {!verification && !verificationError && (
                <p className="mt-2 text-xs leading-relaxed text-white/45">
                  Verification is optional. This report is not assumed to have blockchain registration.
                </p>
              )}
              {verification && (
                <div className="mt-3 rounded-lg border border-white/10 bg-black/35 p-3 text-xs leading-relaxed text-white/65">
                  <p>{verificationLabel(verification)} · {verification.status}</p>
                  <p className="mt-1">Mode: {verification.mode} · Source: {verification.verification_source}</p>
                  {verification.tx_hash && <p className="mt-1 break-all">Transaction: {verification.tx_hash}</p>}
                  <p className="mt-1 break-all">Report hash: {verification.report_hash}</p>
                </div>
              )}
              {verificationError && (
                <p className="mt-2 text-sm text-rose-100" role="alert">{verificationError}</p>
              )}
            </div>
          </div>
        )}
      </section>
    </section>
  );
}
