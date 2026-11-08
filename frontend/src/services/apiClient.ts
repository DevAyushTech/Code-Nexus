const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ||
  "https://code-nexus-3ocs.onrender.com"
).replace(/\/+$/, "");

export interface AnalysisFinding {
  name: string;
  severity: string;
  evidence: string;
  source: string;
  explanation: string;
  recommendation: string;
  confidence?: number;
}

export interface AnalysisIntegration {
  source?: string;
  status: string;
  evidence?: string;
  error?: string;
  confidence?: number;
  checked_at?: string;
}

export interface EvidenceSummary {
  confirmed_matches: AnalysisIntegration[];
  technical_indicators: AnalysisIntegration[];
  heuristic_findings: AnalysisFinding[];
  inconclusive_or_unavailable: AnalysisIntegration[];
}

export interface AnalysisResponse {
  id: string;
  kind: string;
  target: string;
  classification: string;
  risk_score: number;
  findings: AnalysisFinding[];
  integrations: AnalysisIntegration[];
  evidence_quality?: string;
  evidence_summary?: EvidenceSummary;
  ai_analysis?: unknown;
}

export interface BlockchainVerificationResponse {
  verified: boolean;
  status: string;
  mode: string;
  verification_source: string;
  on_chain: boolean;
  report_hash: string;
  tx_hash?: string | null;
  chain_id?: string | number | null;
  contract_address?: string | null;
  reporter?: string | null;
  on_chain_timestamp?: string | null;
  confirmations?: number | null;
  receipt_status?: string | null;
  block_number?: number | null;
  error_code?: string | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw new Error(`The API response is missing a valid "${key}" field.`);
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function parseFinding(value: unknown): AnalysisFinding {
  if (!isRecord(value)) {
    throw new Error("The API returned an invalid finding.");
  }

  const confidence = value.confidence;
  return {
    name: requiredString(value, "name"),
    severity: requiredString(value, "severity"),
    evidence: requiredString(value, "evidence"),
    source: requiredString(value, "source"),
    explanation: requiredString(value, "explanation"),
    recommendation: requiredString(value, "recommendation"),
    ...(typeof confidence === "number" ? { confidence } : {}),
  };
}

function parseIntegration(value: unknown): AnalysisIntegration {
  if (!isRecord(value)) {
    throw new Error("The API returned an invalid integration result.");
  }

  const confidence = value.confidence;
  return {
    source: optionalString(value.source),
    status: requiredString(value, "status"),
    evidence: optionalString(value.evidence),
    error: optionalString(value.error),
    checked_at: optionalString(value.checked_at),
    ...(typeof confidence === "number" ? { confidence } : {}),
  };
}

function parseArray<T>(
  value: unknown,
  field: string,
  parseItem: (item: unknown) => T,
): T[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`The API returned an invalid "${field}" list.`);
  }
  return value.map(parseItem);
}

function parseRequiredArray<T>(
  value: unknown,
  field: string,
  parseItem: (item: unknown) => T,
): T[] {
  if (!Array.isArray(value)) {
    throw new Error(`The API response is missing a valid "${field}" list.`);
  }
  return value.map(parseItem);
}

function parseEvidenceSummary(value: unknown): EvidenceSummary | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) {
    throw new Error("The API returned an invalid evidence summary.");
  }
  return {
    confirmed_matches: parseArray(value.confirmed_matches, "confirmed_matches", parseIntegration),
    technical_indicators: parseArray(value.technical_indicators, "technical_indicators", parseIntegration),
    heuristic_findings: parseArray(value.heuristic_findings, "heuristic_findings", parseFinding),
    inconclusive_or_unavailable: parseArray(
      value.inconclusive_or_unavailable,
      "inconclusive_or_unavailable",
      parseIntegration,
    ),
  };
}

function parseAnalysis(value: unknown): AnalysisResponse {
  if (!isRecord(value)) {
    throw new Error("The API returned an invalid analysis response.");
  }

  const riskScore = value.risk_score;
  if (typeof riskScore !== "number" || !Number.isFinite(riskScore)) {
    throw new Error("The API response is missing a valid risk score.");
  }

  return {
    id: requiredString(value, "id"),
    kind: requiredString(value, "kind"),
    target: requiredString(value, "target"),
    classification: requiredString(value, "classification"),
    risk_score: riskScore,
    findings: parseRequiredArray(value.findings, "findings", parseFinding),
    integrations: parseArray(value.integrations, "integrations", parseIntegration),
    evidence_quality: optionalString(value.evidence_quality),
    evidence_summary: parseEvidenceSummary(value.evidence_summary),
    ai_analysis: value.ai_analysis,
  };
}

function parseVerification(value: unknown): BlockchainVerificationResponse {
  if (!isRecord(value)) {
    throw new Error("The API returned an invalid blockchain verification response.");
  }
  if (typeof value.verified !== "boolean" || typeof value.on_chain !== "boolean") {
    throw new Error("The API response is missing blockchain verification status.");
  }

  return {
    verified: value.verified,
    status: requiredString(value, "status"),
    mode: requiredString(value, "mode"),
    verification_source: requiredString(value, "verification_source"),
    on_chain: value.on_chain,
    report_hash: requiredString(value, "report_hash"),
    tx_hash: typeof value.tx_hash === "string" ? value.tx_hash : null,
    chain_id:
      typeof value.chain_id === "string" || typeof value.chain_id === "number"
        ? value.chain_id
        : null,
    contract_address:
      typeof value.contract_address === "string" ? value.contract_address : null,
    reporter: typeof value.reporter === "string" ? value.reporter : null,
    on_chain_timestamp:
      typeof value.on_chain_timestamp === "string" ? value.on_chain_timestamp : null,
    confirmations:
      typeof value.confirmations === "number" ? value.confirmations : null,
    receipt_status:
      typeof value.receipt_status === "string" ? value.receipt_status : null,
    block_number: typeof value.block_number === "number" ? value.block_number : null,
    error_code: typeof value.error_code === "string" ? value.error_code : null,
  };
}

function getErrorMessage(body: unknown, status: number): string {
  if (isRecord(body)) {
    const detail = body.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const messages = detail
        .filter(isRecord)
        .map((item) => item.msg)
        .filter((message): message is string => typeof message === "string");
      if (messages.length) return messages.join(" ");
    }
    if (typeof body.message === "string") return body.message;
  }
  return `The analysis service returned an error (${status}).`;
}

function retryAfterSeconds(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds);
  const retryDate = Date.parse(value);
  return Number.isNaN(retryDate)
    ? undefined
    : Math.max(0, Math.ceil((retryDate - Date.now()) / 1000));
}

async function requestJson(path: string, init?: RequestInit): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
      credentials: "omit",
    });
  } catch {
    throw new Error(
      "Could not reach the analysis service. Check the connection and backend CORS configuration, then try again.",
    );
  }

  const responseText = await response.text();
  let body: unknown;
  if (responseText) {
    try {
      body = JSON.parse(responseText);
    } catch {
      if (response.ok) {
        throw new Error("The analysis service returned an unreadable response.");
      }
    }
  }

  if (!response.ok) {
    const message = getErrorMessage(body, response.status);
    if (response.status === 422) {
      throw new ApiError(`Please check your input. ${message}`, response.status);
    }
    if (response.status === 429) {
      const retrySeconds = retryAfterSeconds(response.headers.get("Retry-After"));
      throw new ApiError(
        retrySeconds === undefined
          ? `The service is rate limited. Please try again later. ${message}`
          : `The service is rate limited. Try again in about ${retrySeconds} seconds. ${message}`,
        response.status,
        retrySeconds,
      );
    }
    throw new ApiError(message, response.status);
  }

  return body;
}

export async function analyzeUrl(url: string): Promise<AnalysisResponse> {
  const response = await requestJson("/api/v1/analyze/url", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
  return parseAnalysis(response);
}

export async function analyzeMessage(content: string): Promise<AnalysisResponse> {
  const response = await requestJson("/api/v1/analyze/message", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
  return parseAnalysis(response);
}

export async function verifyBlockchain(
  reportId: string,
): Promise<BlockchainVerificationResponse> {
  const response = await requestJson(
    `/api/v1/blockchain/verify/${encodeURIComponent(reportId)}`,
  );
  return parseVerification(response);
}
