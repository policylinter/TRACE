/**
 * TRACE domain model.
 *
 * A `Finding` is the collapsed representation of many raw scanner records:
 * scanners emit one row per (artifact, file, matcher); TRACE groups them by
 * (package, version, CVE) and then decides contextual exploitability.
 *
 * Types only — the live data is served by the TRACE API (see `lib/api.ts`).
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export type Reachability = 'reachable' | 'unreachable' | 'suppressed' | 'unknown';

/** Is the vulnerable dependency referenced in first-party code? */
export type Usage = 'imported' | 'referenced' | 'absent' | 'unknown';

export type Verdict = 'affected' | 'not_affected' | 'needs_review';

/** Ordered along the call graph, from the outermost entrypoint to the sink. */
export type FrameKind =
  | 'entrypoint'
  | 'controller'
  | 'service'
  | 'internal'
  | 'library'
  | 'sink'
  | 'barrier';

export interface CallFrame {
  symbol: string;
  /** Repo-relative path for first-party frames, `pkg:Class#member` for library frames. */
  location: string;
  line: number | null;
  kind: FrameKind;
  /** What happens at this node — shown under the symbol. */
  note?: string;
  /** Edge annotation rendered on the connector to the *next* frame. */
  edge?: string;
  vulnerable?: boolean;
}

export interface EvidenceSignal {
  label: string;
  value: string;
  tone: 'positive' | 'negative' | 'neutral';
}

export interface DeepAnalysis {
  schemaVersion: number;
  source: string;
  generatedAt: string;
  observations: {statement: string; evidenceRefs: string[]}[];
  exploitationConditions: string[];
  assumptions: string[];
  missingEvidence: string[];
  impact: string;
  verificationSteps: string[];
  remediationPlan: {action: string; rationale: string; verification: string}[];
  evidenceIndex: {id: string; label: string}[];
}
export interface AiEvidence {
  webObservations?: {url:string;method:string;ruleId:string;title:string;description:string;solution:string}[];
  nativeObservations?: {path:string;line:number;message:string}[];
  deepAnalysis?: DeepAnalysis;
  analysisDepth?: string;
  guardNote?: string | null;
  model: string;
  runtime: string;
  confidence: number;
  headline: string;
  reasoning: string;
  taintSource?: string;
  taintPropagation?: string[];
  sink?: string;
  counterfactual?: string;
  usage?: Usage;
  usageHits?: string[];
  usageNote?: string;
  signals: EvidenceSignal[];
  remediation: string[];
}

export interface Finding {
  assignee?: string;
  workflowStatus?: 'new' | 'in_progress' | 'resolved' | 'accepted_risk';
  dueDate?: string;
  triageNote?: string;
  id: string;
  cve: string;
  packageName: string;
  version: string;
  ecosystem: string;
  /** Number of raw scanner records collapsed into this finding. */
  rawCount: number;
  severity: Severity;
  cvss: number;
  reachability: Reachability;
  verdict: Verdict;
  usage: Usage;
  confidence: number;
  cwe: string[];
  fixedIn: string;
  dependencyPath: string[];
  /** First-party frames + library frames + sink. Empty path root for barriers. */
  frames: CallFrame[];
  /** Why the reachable subgraph stops short of the vulnerable symbol. */
  blocker?: string | null;
  suppressReason?: string | null;
  evidence: AiEvidence;
  /** Persisted analyst review flag. */
  reviewed?: boolean;
}
