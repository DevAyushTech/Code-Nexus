import type { ScanInput, ScanParameters, ThreatLog } from "./types";

/**
 * Data placeholders. Nothing here is mock data:
 * every collection starts empty and is filled through the UI (or later by an API).
 */
export const emptyScanInputs: ScanInput[] = [];
export const emptyThreatLogs: ThreatLog[] = [];

export const defaultScanParameters: ScanParameters = {
  checkPhishing: true,
  checkTls: true,
  checkAds: true,
  checkCredentialHarvesting: true,
  timeoutSeconds: 30,
};

export const newId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : String(Date.now()) + Math.random().toString(16).slice(2);