export type View = "home" | "scanner";

export type Severity = "low" | "medium" | "high" | "critical";

/** A single scan target entered by the operator. */
export interface ScanInput {
  id: string;
  url: string;
  submittedAt: string; // ISO timestamp
}

/** A threat log entry. Populated manually or by a future backend. */
export interface ThreatLog {
  id: string;
  target: string;
  category: string; // e.g. phishing, TLS weakness, deceptive ad
  severity: Severity;
  notes: string;
  recordedAt: string; // ISO timestamp
}

/** Tunable parameters for the scanner. Values are set by the operator. */
export interface ScanParameters {
  checkPhishing: boolean;
  checkTls: boolean;
  checkAds: boolean;
  checkCredentialHarvesting: boolean;
  timeoutSeconds: number;
}
