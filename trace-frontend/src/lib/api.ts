/**
 * TRACE API client.
 *
 * Thin, typed wrapper around the FastAPI backend (see `trace_api/main.py`).
 * All URLs are relative (`/api/v1/...`) so the same build works both behind the
 * Vite dev proxy and when served as static files by the API itself.
 */

import type { Finding } from '@/data/findings';
import type { VexScope } from '@/lib/vex';

const BASE = (import.meta.env.VITE_API_BASE ?? '/api/v1').replace(/\/+$/, '');
export interface DastTarget {id:string;name:string;url:string;projectId:number;}
export const getDastTargets=()=>req<{mode:string;targets:DastTarget[]}>('/platform/dast/targets');
export const runDastBaseline=(targetId:string)=>req<Scan>('/platform/dast/checks',{method:'POST',body:JSON.stringify({targetId})});

// --------------------------------------------------------------------------- //
// Transport
// --------------------------------------------------------------------------- //
export class ApiError extends Error {
  constructor(message:string, public readonly status:number) { super(`${message} (HTTP ${status})`); this.name='ApiError'; }
}
async function req<T>(path: string, init?: RequestInit, responseType:'json'|'blob'='json'): Promise<T> {
  const tokenAtRequest = getAdminToken();
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...adminHeaders(),
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init?.headers ?? {}),
    },
  }).catch(() => { throw new Error('Нет соединения с TRACE API. Проверьте подключение и повторите действие.'); });

  if (!res.ok) {
    const message = res.status === 401 || res.status === 403
      ? 'Недостаточно прав. Проверьте доступ в настройках.'
      : res.status === 404 ? 'Объект не найден. Обновите данные и повторите действие.'
      : res.status === 422 || res.status === 400 ? 'Проверьте параметры запроса и формат загруженного отчёта.'
      : res.status === 409 ? 'Действие конфликтует с текущим состоянием. Обновите данные.'
      : res.status === 429 ? 'Слишком много запросов. Повторите позже.'
      : 'Сервис не выполнил запрос. Повторите действие или проверьте сервер.';
    if (res.status === 401 && path !== '/auth/login' && getAdminToken() === tokenAtRequest) window.dispatchEvent(new Event('trace:auth-expired'));
    throw new ApiError(message, res.status);
  }

  if (res.status === 204) return undefined as T;
  if (responseType === 'blob') return (await res.blob()) as T;
  return (await res.json()) as T;
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const out = search.toString();
  return out ? `?${out}` : '';
}

// --------------------------------------------------------------------------- //
// Domain types (mirror `trace_api/serializers.py`)
// --------------------------------------------------------------------------- //
export interface ScanCounts {
  total: number;
  reachable: number;
  unreachable: number;
  suppressed: number;
  actionable: number;
  affected: number;
  notAffected: number;
  needsReview: number;
  reviewed: number;
  usageImported: number;
  usageAbsent: number;
  rawTotal: number;
}

export interface FunnelStage {
  key: string;
  label: string;
  value: number;
  engine: string;
  operation: string;
}

export interface ScanEngine {
  name: string;
  version: string;
}

export interface AiRuntime {
  model?: string;
  quantisation?: string;
  egress?: string;
  device?: string;
  host?: string;
  [key: string]: unknown;
}

export interface Scan {
  id: string;
  projectId: number | null;
  repository: string;
  branch: string;
  commit: string;
  commitLong: string;
  pipeline: string;
  triggeredBy: string;
  sbom: string;
  duration: string;
  status: string;
  scannedAt: string;
  rawCount: number;
  engines: ScanEngine[];
  scannerResults?: { id: string; label: string; role: string; status: string; detail: string }[];
  aiRuntime: AiRuntime;
  aiEngine: string;
  profile: string;
  counts: ScanCounts;
  funnel: FunnelStage[];
}

export interface Health {
  status: string;
  version: string;
  model: string;
  modelAvailable: boolean;
  aiActive?: string;
  scanCount: number;
  projectCount?: number;
}

/** Runtime AI engine configuration (see `trace_api/settings.py`). */
export interface AiSettings {
  analysisDepth?: 'standard' | 'deep';
  responseLanguage?: 'ru' | 'en';
  analystContext?: string;
  reviewPass?: boolean;
  provider: string;
  models: string[];
  baseUrl: string;
  ollamaUrl: string;
  apiKey: string;
  apiKeySet: boolean;
  secretRef?: string;
  secretRefReady?: boolean;
  secretEnvironmentName?: string;
  workspaceId?: string;
  temperature: number;
  timeout: number;
}

export interface AiProviderInfo {
  id: string;
  kind: string;
  label: string;
  available: boolean;
  detail: string;
  knob: string;
  install: string;
}

export interface AiProvidersResponse {
  settings: AiSettings;
  providers: AiProviderInfo[];
  models: { ollama: string[]; openai: string[] };
  active: string;
  available: boolean;
  catalog: { id: string; label: string }[];
}

export interface AiTestResult {
  ok: boolean;
  provider: string;
  model: string;
  detail: string;
}

/** A workspace: one analysed repository (see `trace_api/main.py` `/projects`). */
export interface Project {
  id: number;
  name: string;
  repoUrl: string;
  createdAt: string;
  updatedAt: string;
  scanCount: number;
  lastScanAt: string;
}

export interface SbomNode {
  id: string;
  label: string;
  depth: number;
  kind: string;
  vulnerable: boolean;
  findings: number;
  /** Findings whose dependency path contains this node. */
  findingIds?: string[];
}

export interface SbomEdge {
  source: string;
  target: string;
}

export interface Sbom {
  scan: string;
  components: number;
  nodes: SbomNode[];
  edges: SbomEdge[];
}

export interface VexMeta {
  documentId: string;
  fileName: string;
  count: number;
  affected: number;
  notAffected: number;
  suppressed: number;
}

export interface ScanEvent {
  id: number;
  findingId: string;
  action: string;
  actor: string;
  detail: string;
  createdAt: string;
  cve?: string | null;
  packageName?: string | null;
}

export interface ScanFileInput {
  name: string;
  content?: string;
  json?: unknown;
}

export interface CreateScanBody {
  projectId?: number;
  repository?: string;
  branch?: string;
  commit?: string;
  profile?: string;
  triggeredBy?: string;
  files?: ScanFileInput[];
}

export interface FindingQuery {
  filter?: string;
  sort?: string;
  q?: string;
}

/** Persisted progress of a background rescan. */
export interface ScanProgress {
  scanId: string;
  phase: string;
  progress: number;
  message: string | null;
  active: boolean;
  jobId?: string;
  requiresReview?: boolean;
}

export type BatchAction = 'review' | 'suppress' | 'unsuppress';

// --------------------------------------------------------------------------- //
// Meta
// --------------------------------------------------------------------------- //
export function getHealth(): Promise<Health> {
  return req<Health>('/health');
}

export function getEvents(limit = 20): Promise<ScanEvent[]> {
  return req<ScanEvent[]>(`/events${qs({ limit })}`);
}

// --------------------------------------------------------------------------- //
// Projects (workspaces)
// --------------------------------------------------------------------------- //
export function listProjects(): Promise<Project[]> {
  return req<Project[]>('/projects');
}

export function createProject(body: { name?: string; repoUrl?: string; id?: number }): Promise<Project> {
  return req<Project>('/projects', { method: 'POST', body: JSON.stringify(body) });
}

// --------------------------------------------------------------------------- //
// Scans
// --------------------------------------------------------------------------- //
export function listScans(projectId?: number | null): Promise<Scan[]> {
  return req<Scan[]>(`/scans${qs({ project_id: projectId ?? undefined })}`);
}

export function getScan(scanId: string): Promise<Scan> {
  return req<Scan>(`/scans/${encodeURIComponent(scanId)}`);
}

export interface DeleteScanResult {
  deleted: string;
  findings: number;
  events: number;
}

/** Permanently remove a scan and all of its findings/events (demo scan is protected). */
export function deleteScan(scanId: string): Promise<DeleteScanResult> {
  return req<DeleteScanResult>(`/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
}

export interface DeleteProjectResult {
  deleted: number;
  name: string;
  scans: number;
  findings: number;
  events: number;
}

/** Remove a workspace and every scan under it (default workspace is protected). */
export function deleteProject(projectId: number): Promise<DeleteProjectResult> {
  return req<DeleteProjectResult>(`/projects/${projectId}`, { method: 'DELETE' });
}

export function createScan(body: CreateScanBody): Promise<Scan> {
  return req<Scan>('/scans', { method: 'POST', body: JSON.stringify(body) });
}

export function rescan(scanId: string): Promise<Scan> {
  return req<Scan>(`/scans/${encodeURIComponent(scanId)}/rescan`, { method: 'POST' });
}

/** Kick off a rescan on the backend; the result is polled via `getScanProgress`. */
export function rescanAsync(scanId: string): Promise<{ jobId: string; status: string }> {
  return req<{ jobId: string; status: string }>(
    `/scans/${encodeURIComponent(scanId)}/rescan?wait=false`,
    { method: 'POST' },
  );
}

export function getScanProgress(scanId: string, jobId?: string): Promise<ScanProgress> {
  return req<ScanProgress>(`/scans/${encodeURIComponent(scanId)}/progress${jobId ? `?jobId=${encodeURIComponent(jobId)}` : ''}`);
}

// --------------------------------------------------------------------------- //
// Findings & triage
// --------------------------------------------------------------------------- //
export function getFindings(scanId: string, query: FindingQuery = {}): Promise<Finding[]> {
  return req<Finding[]>(`/scans/${encodeURIComponent(scanId)}/findings${qs({ ...query })}`);
}

export function reviewFinding(findingId: string, reviewed = true): Promise<Finding> {
  return req<Finding>(`/findings/${encodeURIComponent(findingId)}/review`, {
    method: 'POST',
    body: JSON.stringify({ reviewed }),
  });
}

export function suppressFinding(findingId: string, reason: string): Promise<Finding> {
  return req<Finding>(`/findings/${encodeURIComponent(findingId)}/suppress`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export function unsuppressFinding(findingId: string): Promise<Finding> {
  return req<Finding>(`/findings/${encodeURIComponent(findingId)}/unsuppress`, { method: 'POST' });
}

export interface BatchResult {
  updated: number;
}

export function batchReview(ids: string[], reviewed = true): Promise<BatchResult> {
  return req<BatchResult>('/findings/batch-review', {
    method: 'POST',
    body: JSON.stringify({ ids, reviewed }),
  });
}

export function batchSuppress(ids: string[], reason: string): Promise<BatchResult> {
  return req<BatchResult>('/findings/batch-suppress', {
    method: 'POST',
    body: JSON.stringify({ ids, reason }),
  });
}

export function batchUnsuppress(ids: string[]): Promise<BatchResult> {
  return req<BatchResult>('/findings/batch-unsuppress', {
    method: 'POST',
    body: JSON.stringify({ ids }),
  });
}

// --------------------------------------------------------------------------- //
// SBOM
// --------------------------------------------------------------------------- //
export function getSbom(scanId: string): Promise<Sbom> {
  return req<Sbom>(`/scans/${encodeURIComponent(scanId)}/sbom`);
}

// --------------------------------------------------------------------------- //
// VEX (CSAF 2.0) — served as a raw JSON document, not an API envelope.
// --------------------------------------------------------------------------- //
export async function getVex(scanId: string, scope: VexScope, findingId?: string): Promise<string> {
  const res = await fetch(`${BASE}/vex${qs({ scan_id: scanId, scope, finding: findingId })}`, {
    headers: { Accept: 'application/json', ...adminHeaders() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`.trim());
  return res.text();
}

export function getVexMeta(scanId: string, scope: VexScope): Promise<VexMeta> {
  return req<VexMeta>(`/vex/meta${qs({ scan_id: scanId, scope })}`);
}

export function vexDownloadUrl(scanId: string, scope: VexScope, findingId?: string): string {
  return `${BASE}/vex${qs({ scan_id: scanId, scope, finding: findingId, download: 1 })}`;
}

// --------------------------------------------------------------------------- //
// AI engine (runtime settings — see `trace_api/main.py` `/ai/*`)
// --------------------------------------------------------------------------- //
const ADMIN_TOKEN_KEY = 'trace.adminToken';

export function setAdminToken(token: string): void {
  try {
    if (token) window.localStorage.setItem(ADMIN_TOKEN_KEY, token);
    else window.localStorage.removeItem(ADMIN_TOKEN_KEY);
  } catch {
    /* private mode */
  }
}

export function getAdminToken(): string {
  try {
    return window.localStorage.getItem(ADMIN_TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

function adminHeaders(): Record<string, string> {
  const token = getAdminToken();
  return { 'X-Trace-Workspace': getSelectedWorkspace(), ...(token ? { 'X-Admin-Token': token, Authorization: `Bearer ${token}` } : {}) };
}

// --------------------------------------------------------------------------- //
// Authentication (opt-in RBAC v1)
// --------------------------------------------------------------------------- //
export interface AuthUser {
  organizationRole?: string;
  username: string;
  displayName: string;
  role: string;
  isActive: boolean;
  createdAt: string;
}

export interface AuthStatus {
  enabled: boolean;
  tokenRequired?: boolean;
  method: string;
}

export interface LoginResult {
  authenticated: boolean;
  token: string | null;
  method: string;
  user: AuthUser | null;
}

export function getAuthStatus(): Promise<AuthStatus> {
  return req<AuthStatus>('/auth/status');
}

export function login(username: string, password: string): Promise<LoginResult> {
  return req<LoginResult>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
}

export async function logout(): Promise<{ ok: boolean }> {
  try { return await req<{ ok: boolean }>('/auth/logout', { method: 'POST', headers: adminHeaders() }); } finally { setAdminToken(''); }
}

export function getMe(): Promise<{ authenticated: boolean; user?: AuthUser }> {
  return req<{ authenticated: boolean; user?: AuthUser }>('/auth/me', { headers: adminHeaders() });
}

export function getAiProviders(): Promise<AiProvidersResponse> {
  return req<AiProvidersResponse>('/ai/providers');
}

export function updateAiSettings(
  patch: Partial<AiSettings>,
): Promise<{ settings: AiSettings; active: string; available: boolean }> {
  return req('/ai/settings', {
    method: 'PUT',
    body: JSON.stringify(patch),
    headers: adminHeaders(),
  });
}

export function testAi(settings?: Partial<AiSettings>): Promise<AiTestResult> {
  return req<AiTestResult>('/ai/test', {
    method: 'POST',
    body: JSON.stringify(settings ? { settings } : {}),
    headers: adminHeaders(),
  });
}

// --------------------------------------------------------------------------- //
// Release policy & CI gate
// --------------------------------------------------------------------------- //
export interface PolicySettings {
  name: string;
  defaultAction: string;
  blockOn: string[];
  exemptions: string[];
  warnOnReview: boolean;
}

export interface PolicyRule {
  cve: string;
  packageName: string;
  severity: string;
  decision: string;
  reason: string;
}

export interface PolicySummary {
  blocking: number;
  warnings: number;
  passed: number;
  total: number;
}

export interface GateResult {
  scanId: string;
  policy: PolicySettings;
  gate: string;
  exitCode: number;
  summary: PolicySummary;
  rules: PolicyRule[];
  blocking: Array<{ cve: string; packageName: string; severity: string }>;
}

export function getPolicySettings(): Promise<{ policy: PolicySettings }> {
  return req<{ policy: PolicySettings }>('/settings/policy');
}

export function updatePolicySettings(policy: Partial<PolicySettings>): Promise<{ policy: PolicySettings }> {
  return req<{ policy: PolicySettings }>('/settings/policy', {
    method: 'PUT',
    body: JSON.stringify({ policy }),
    headers: adminHeaders(),
  });
}

export function getScanPolicy(scanId: string): Promise<GateResult> {
  return req<GateResult>(`/scans/${encodeURIComponent(scanId)}/policy`);
}

/** Evaluate the release gate at scan time (what CI calls). */
export function gateScan(scanId: string): Promise<GateResult> {
  return req<GateResult>(`/scans/${encodeURIComponent(scanId)}/gate`, { method: 'POST' });
}

// --------------------------------------------------------------------------- //
// Compliance reports
// --------------------------------------------------------------------------- //
export interface ComplianceControl {
  id: string;
  name: string;
  severity: string;
}

export interface ComplianceStandard {
  id: string;
  name: string;
  basis: string;
  controls: ComplianceControl[];
}

export interface ComplianceReport {
  scanId: string;
  repository: string;
  standard: string;
  standardName: string;
  format: 'md' | 'html';
  generatedAt: string;
  report: string;
}

export function getComplianceStandards(): Promise<ComplianceStandard[]> {
  return req<ComplianceStandard[]>('/compliance/standards');
}

export function getScanCompliance(
  scanId: string,
  standard = 'iso-27001',
  format: 'md' | 'html' = 'md',
): Promise<ComplianceReport> {
  return req<ComplianceReport>(
    `/scans/${encodeURIComponent(scanId)}/compliance?standard=${encodeURIComponent(standard)}&format=${format}`,
  );
}

// --------------------------------------------------------------------------- //
// Advisory database
// --------------------------------------------------------------------------- //
export interface AdvisoryObservation {
  scanId: string;
  repository: string;
  commit: string;
  version: string;
  reachability: string;
  verdict: string;
  fixedIn: string;
}

export interface Advisory {
  cve: string;
  packageName: string;
  severity: string;
  cvss: number | null;
  versions: string[];
  fixedIn: string[];
  scanCount: number;
  scannedFrom: string;
  scannedTo: string;
  affected: number;
  observed: AdvisoryObservation[];
  recommendation: string;
}

export function getAdvisories(params?: { scanId?: string; severity?: string }): Promise<Advisory[]> {
  const q = new URLSearchParams();
  if (params?.scanId) q.set('scanId', params.scanId);
  if (params?.severity) q.set('severity', params.severity);
  const s = q.toString();
  return req<Advisory[]>(`/advisories${s ? `?${s}` : ''}`);
}

export function getAdvisory(cve: string): Promise<Finding[]> {
  return req<Finding[]>(`/advisories/${encodeURIComponent(cve)}`);
}

// --------------------------------------------------------------------------- //
// Client-side helpers
// --------------------------------------------------------------------------- //
const ACTIVE_SCAN_KEY = 'trace.activeScan';

/** Persist the analyst's last-selected scan across reloads. */
export function setActiveScan(scanId: string): void {
  try {
    window.localStorage.setItem(ACTIVE_SCAN_KEY, scanId);
  } catch {
    /* storage unavailable (private mode) — non-fatal */
  }
}

export function getActiveScan(): string | null {
  try {
    return window.localStorage.getItem(ACTIVE_SCAN_KEY);
  } catch {
    return null;
  }
}

export interface IntegrationStatus { id: string; kind: string; label: string; available: boolean; role?: string; }
export function getIntegrations(): Promise<{ integrations: IntegrationStatus[] }> { return req('/integrations'); }

export interface SourceJob { jobId: string; status: string; scanId?: string; scanStatus?: string; error?: string; executionState?: 'queued' | 'responsive' | 'heartbeat-lost' | 'unknown' | 'completed' | 'failed' | 'cancelled'; requiresReview?: boolean; lastHeartbeatAt?: number; createdAt?: number; reconciled?: boolean; cancellable?: boolean; kind?: 'source' | 'rescan' | 'sast'; targetScanId?: string; }
export function cancelSourceJob(id: string): Promise<SourceJob> { return req(`/jobs/${encodeURIComponent(id)}/cancel`, {method:'POST', headers:adminHeaders()}); }
export function getSourceJobs(): Promise<SourceJob[]> { return req('/jobs?limit=20'); }
export interface JobRetentionPlan { version: 1; workspaceId: string; days: number; limit: number; cutoff: number; expiresAt: number; counts: Record<string, number>; candidates: { jobId: string; status:'completed' | 'failed'; finishedAt:number; terminalReason:'cancelled' | null }[]; }
export function getJobRetention(days: number): Promise<JobRetentionPlan> { return req(`/access/job-retention?days=${days}&limit=100`); }

export interface FindingResult {
  schemaVersion: 'trace.result/1'; objectType: 'finding'; module: 'appsec'; adapter: string;
  id: string; workspaceId: string; scanId: string; projectId: number | null; demo: boolean;
  recordedAt: string | null; scanRecordedAt: string | null; observedAt: null;
  snapshotSha256: string; reportedConfidence: number | null; limitations: string[];
  evidence: { id: string; category: 'reported_observation' | 'engine_assessment' | 'team_decision'; source: string; verification: 'not_attested'; sha256: string; payload: Record<string,unknown> }[];
}
export function getFindingResult(id: string): Promise<FindingResult> { return req(`/findings/${encodeURIComponent(id)}/result`); }

export interface ResultSource {id:string;workspaceId:string;name:string;module:string;active:boolean;mode:'manual';}
export interface ModuleResultWorkflow {revision:number;status:'new'|'in_progress'|'resolved'|'accepted_risk';assignee:string;dueDate:string|null;note:string;updatedAt:string|null;updatedBy:string|null;}
export interface ImportedModuleResult {id:string;workspaceId:string;receivedAt:string;receivedBy:string;sha256:string;verification:'not_attested';workflow:ModuleResultWorkflow;payload:{analysis?:{origin?:{adapter:'semgrep-json/1';runId:string;commit:string;reportSha256:string;reportState:'no_reported_errors'|'partial'|'unknown';reportedSeverity:string};kind:'sast';scanner:'semgrep';location:{path:string;startLine:number;endLine:number}};externalId:string;sourceId:string;assetId:string;title:string;description:string;severity:string;observedAt:string;ruleId:string;contextAssetId?:string;contextReason?:string;supplyChainSnapshot?:SupplyChainRecord;evidence:{label:string;reference:string;sha256:string}[]};}
export interface ResultRetestLink {id:string;originalId:string;retestId:string;originalSha256:string;retestSha256:string;reason:string;createdAt:string;createdBy:string;withdrawnAt:string|null;withdrawnBy:string|null;withdrawalReason:string|null;verification:'manual_association';}
export interface ModuleResultDetail {result:ImportedModuleResult;retests:ResultRetestLink[];history:{id:string;at:string;actor:string;change:{before:ModuleResultWorkflow;after:ModuleResultWorkflow}}[];}
export function linkModuleRetest(id:string,targetResultId:string,reason:string):Promise<ResultRetestLink> {return req(`/platform/module-results/${encodeURIComponent(id)}/retests`,{method:'POST',headers:adminHeaders(),body:JSON.stringify({targetResultId,reason})});}
export function withdrawModuleRetest(id:string,reason:string):Promise<ResultRetestLink> {return req(`/platform/module-retests/${encodeURIComponent(id)}/withdraw`,{method:'POST',headers:adminHeaders(),body:JSON.stringify({reason})});}
export function getModuleResultDetail(id:string):Promise<ModuleResultDetail> {return req(`/platform/module-results/${encodeURIComponent(id)}`);}
export function updateModuleResultWorkflow(id:string,body:{expectedRevision:number;status:ModuleResultWorkflow['status'];assignee:string;dueDate:string|null;note:string}):Promise<ModuleResultWorkflow> {return req(`/platform/module-results/${encodeURIComponent(id)}/workflow`,{method:'PUT',headers:adminHeaders(),body:JSON.stringify(body)});}
export function getResultSources():Promise<ResultSource[]> {return req('/platform/result-sources');}
export function createResultSource(name:string,module:string):Promise<ResultSource> {return req('/platform/result-sources',{method:'POST',headers:adminHeaders(),body:JSON.stringify({name,module})});}
export function setResultSourceActive(id:string,active:boolean):Promise<ResultSource> {return req(`/platform/result-sources/${encodeURIComponent(id)}`,{method:'PUT',headers:adminHeaders(),body:JSON.stringify({active})});}
export function getModuleResults(assetId='',contextAssetId=''):Promise<ImportedModuleResult[]> {return req('/platform/module-results?limit=100'+(assetId?'&assetId='+encodeURIComponent(assetId):'')+(contextAssetId?'&contextAssetId='+encodeURIComponent(contextAssetId):''));}
export interface SourceWebhook {enabled:boolean;secretRef:string;environmentName:string;secretAvailable:boolean;sourceActive:boolean;endpoint:string;maxBodyBytes:number;maxAgeSeconds:number;acceptedDeliveryCount:number;lastAcceptedAt:string|null;}
export const getSourceWebhook=(id:string)=>req<SourceWebhook>(`/platform/result-sources/${encodeURIComponent(id)}/webhook`);
export const setSourceWebhook=(id:string,body:{enabled:boolean;secretRef:string})=>req<SourceWebhook>(`/platform/result-sources/${encodeURIComponent(id)}/webhook`,{method:'PUT',headers:adminHeaders(),body:JSON.stringify(body)});
export interface ResultProvenance {schemaVersion:'trace.provenance/1';resultId:string;checkedAt:string;report:{sha256:string;status:'hash_matches'|'integrity_error'};source:{id:string;name:string;module:string;active:boolean}|null;initialIntake:{status:'consistent'|'not_recorded'|'integrity_error';record:{method?:string;actor?:string;receivedAt?:string;delivery?:{id:string;bodySha256:string;issuedAt:number}}|null};signedDeliveries:{total:number;offset:number;limit:number;items:{id:string;sourceId:string;issuedAt:number;receivedAt:string;bodySha256:string;reportSha256:string;status:'consistent'|'integrity_error'}[]};evidence:{maxBytes:number;items:StoredEvidence[]};attestation:'not_performed';}
export const getResultProvenance=(id:string,offset=0)=>req<ResultProvenance>(`/platform/module-results/${encodeURIComponent(id)}/provenance?offset=${offset}&limit=20`);
export interface StoredEvidence {index:number;label:string;reference:string;expectedSha256:string;status:'not_stored'|'hash_matches'|'integrity_error';byteCount:number|null;storedAt:string|null;storedBy:string|null;}
export const getResultEvidence=(id:string)=>req<{maxBytes:number;items:StoredEvidence[]}>(`/platform/module-results/${encodeURIComponent(id)}/evidence`);
export const uploadResultEvidence=(id:string,index:number,file:File)=>req<StoredEvidence>(`/platform/module-results/${encodeURIComponent(id)}/evidence/${index}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:file});
export const downloadResultEvidence=(id:string,index:number)=>req<Blob>(`/platform/module-results/${encodeURIComponent(id)}/evidence/${index}/content`,undefined,'blob');
export function importModuleResult(body:unknown):Promise<ImportedModuleResult> {return req('/platform/module-results',{method:'POST',headers:adminHeaders(),body:JSON.stringify(body)});}
export function startSourceScan(body: { projectId: number; source: string; ref: string; wait: false }): Promise<SourceJob> { return req('/scans/from-source', {method:'POST', body:JSON.stringify(body),headers:adminHeaders()}); }
export function getSourceJob(id: string): Promise<SourceJob> { return req(`/jobs/${encodeURIComponent(id)}`); }

export function updateWorkflow(id: string, body: {assignee: string; status: string; dueDate: string | null; note: string}): Promise<Finding> {return req(`/findings/${encodeURIComponent(id)}/workflow`,{method:'PUT',headers:adminHeaders(),body:JSON.stringify(body)});}

export function analyzeFinding(id: string): Promise<{finding: Finding; engine: string; source: string}> {
  return req(`/findings/${encodeURIComponent(id)}/analyze`, {method:'POST',headers:adminHeaders(),body:JSON.stringify({analysisDepth:'deep'})});
}

export type InventoryChangeKind='only_after'|'changed'|'not_in_after'|'not_observed_partial'|'unchanged';
export interface InventoryReviewState {revision:number;status:'open'|'in_progress'|'needs_observation'|'explained';reason:string;updatedAt:string|null;updatedBy:string|null;}
export interface InventoryReconciliation {sourceId:string;externalId:string;assetId:string;observationKind:'not_in_after'|'not_observed_partial';review:InventoryReviewState;historyTotal:number;history:{id:string;revision:number;at:string;actor:string;change:{before:InventoryReviewState;after:InventoryReviewState}}[];}
export const getInventoryReconciliation=(source:string,before:string,after:string,externalId:string)=>req<InventoryReconciliation>(`/platform/inventory/sources/${encodeURIComponent(source)}/reconciliation?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}&externalId=${encodeURIComponent(externalId)}`);
export const saveInventoryReconciliation=(source:string,body:{beforeRunId:string;afterRunId:string;externalId:string;expectedRevision:number;status:InventoryReviewState['status'];reason:string})=>req<InventoryReviewState>(`/platform/inventory/sources/${encodeURIComponent(source)}/reconciliation`,{method:'PUT',body:JSON.stringify(body)});
export interface InventoryComparison {schemaVersion:'trace.inventory-comparison/1';sourceId:string;before:{id:string;externalRunId:string;observedAt:string;sha256:string;status:string};after:{id:string;externalRunId:string;observedAt:string;sha256:string;status:string};status:'compared'|'unavailable';reason:'integrity_error'|'collection_error'|null;counts:Record<InventoryChangeKind,number>|null;total:number;offset:number;limit:number;checkedAt:string;items:{externalId:string;assetId:string|null;kind:InventoryChangeKind;before:{name:string}|null;after:{name:string}|null;changes:{field:string;before:string;after:string}[]}[];}
export const compareInventorySnapshots=(source:string,before:string,after:string,includeUnchanged=false,offset=0)=>req<InventoryComparison>(`/platform/inventory/sources/${encodeURIComponent(source)}/compare?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}&includeUnchanged=${includeUnchanged}&offset=${offset}&limit=50`);
export interface InventoryRun {id:string;externalRunId:string;observedAt:string;status:'complete'|'partial'|'error';itemCount:number;errors:{code:string;message:string}[];sha256:string;receivedAt:string;receivedBy:string;}
export interface InventorySource {id:string;name:string;active:boolean;freshnessHours:number;latestAttempt:InventoryRun|null;}
export interface InventoryDetail {source:InventorySource;items:{assetId:string;externalId:string;observation:{name:string;kind:string;owner:string;platform:string;version:string;provider:string;region:string}|null;observedAt:string|null;runId:string|null;freshness:'current'|'stale'|'unknown'}[];total:number;offset:number;limit:number;recentRuns:InventoryRun[];checkedAt:string;maxSnapshotBytes:number;}
export const listInventorySources=()=>req<InventorySource[]>('/platform/inventory/sources');
export const createInventorySource=(name:string,freshnessHours:number)=>req<InventorySource>('/platform/inventory/sources',{method:'POST',body:JSON.stringify({name,freshnessHours})});
export const configureInventorySource=(id:string,active:boolean,freshnessHours:number)=>req<InventorySource>(`/platform/inventory/sources/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({active,freshnessHours})});
export const getInventorySource=(id:string,offset=0)=>req<InventoryDetail>(`/platform/inventory/sources/${encodeURIComponent(id)}?offset=${offset}`);
export const importInventorySnapshot=(id:string,body:unknown)=>req<InventoryRun>(`/platform/inventory/sources/${encodeURIComponent(id)}/snapshots`,{method:'POST',body:JSON.stringify(body)});
export interface PlatformAsset { id: string; name: string; kind: string; externalKey: string; owner: string; projectId: number | null; source: string }
export interface SupplyChainData {schemaVersion?:string;kind:'build'|'artifact'|'deployment';observedAt:string;evidenceRef:string;repositoryAssetId?:string;commitSha?:string;buildExternalId?:string;buildAssetId?:string;digest?:string;artifactAssetId?:string;environment?:string;deploymentExternalId?:string;buildContextSha256?:string;artifactContextSha256?:string;}
export interface SupplyChainRecord {assetId:string;workspaceId:string;context:SupplyChainData;sha256:string;recordedAt:string;recordedBy:string;verification:'operator_declared';}
export function getSupplyChainContext(id:string):Promise<{context:SupplyChainRecord|null}> {return req(`/platform/assets/${encodeURIComponent(id)}/supply-chain`);}
export function registerSupplyChainContext(id:string,body:SupplyChainData):Promise<SupplyChainRecord> {return req(`/platform/assets/${encodeURIComponent(id)}/supply-chain`,{method:'POST',headers:adminHeaders(),body:JSON.stringify(body)});}
export interface PlatformDetail { asset: PlatformAsset; links: {id:string; sourceId:string; targetId:string; relation:string; evidence:string}[]; scans:{id:string;status:string;commit:string;demo:boolean}[]; findings:{id:string;title:string;severity:string;status:string;scanId:string}[]; history:{action:string;detail:string;at:string;actor?:string}[] }
export const platformAssets = () => req<PlatformAsset[]>('/platform/assets', {headers:adminHeaders()});
export const platformDetail = (id:string) => req<PlatformDetail>(`/platform/assets/${encodeURIComponent(id)}`, {headers:adminHeaders()});
export const platformCreateAsset = (body:unknown) => req<PlatformAsset>('/platform/assets', {method:'POST',headers:adminHeaders(),body:JSON.stringify(body)});
export const platformCreateLink = (body:unknown) => req('/platform/links', {method:'POST',headers:adminHeaders(),body:JSON.stringify(body)});
export const platformModules = () => req<{modules:{id:string;name:string;status:string;mode:string;detail?:string;engines?:{id:string;label:string;available:boolean}[]}[]}>('/platform/modules', {headers:adminHeaders()});

export interface AccessContext { organization:{id:string;name:string}; principal:{actor:string;role:string;kind:string}; authenticationEnabled:boolean; additionalOrganizationsEnabled:boolean; permissions:{write:boolean;admin:boolean} }
export interface AccessMember { id:number; userId:number; username:string; displayName:string; role:string; active:boolean; userActive:boolean }
export interface ServiceAccount { id:string;workspaceId:string;name:string;scopes:string[];expiresAt:string;revoked:boolean;createdBy:string }
export interface AccessAudit { id:string;action:string;objectId:string;actor:string;detail:string;at:string }
export const getAccessContext=()=>req<AccessContext>('/access/context');
export const getAccessMembers=()=>req<AccessMember[]>('/access/members');
export const updateAccessMember=(id:number,role:string,active:boolean)=>req(`/access/members/${id}`,{method:'PUT',body:JSON.stringify({role,active})});
export const getServiceAccounts=()=>req<ServiceAccount[]>('/access/service-accounts');
export const createServiceAccount=(body:{name:string;scopes:string[];expiresInDays:number})=>req<{account:ServiceAccount;token:string}>('/access/service-accounts',{method:'POST',body:JSON.stringify(body)});
export const revokeServiceAccount=(id:string)=>req(`/access/service-accounts/${encodeURIComponent(id)}/revoke`,{method:'POST'});
export const getAccessAudit=()=>req<AccessAudit[]>('/access/audit');

export interface WorkspaceOption { id:string;name:string;role:string;legacy?:boolean }
export interface Team { id:string;name:string }
export interface WorkspaceGrants { members:{userId:number;role:string;active:boolean}[];teams:{teamId:string;role:string;active:boolean}[] }
let activeWorkspaceId: string | undefined;
export function getSelectedWorkspace():string { if(activeWorkspaceId)return activeWorkspaceId;try{activeWorkspaceId=localStorage.getItem('trace.workspace')||'default';}catch{activeWorkspaceId='default';}return activeWorkspaceId;}
export function setSelectedWorkspace(id:string):void {activeWorkspaceId=id;try{localStorage.setItem('trace.workspace',id);}catch{/* private mode */}}
export async function listWorkspaces():Promise<WorkspaceOption[]> {
  try { return await req<WorkspaceOption[]>('/workspaces'); }
  catch(error) {
    if(error instanceof ApiError && error.status===404) return [{id:'default',name:'Контекст установки',role:'legacy',legacy:true}];
    throw error;
  }
}
export const createWorkspace=(name:string)=>req<WorkspaceOption>('/workspaces',{method:'POST',body:JSON.stringify({name})});
export const listTeams=()=>req<Team[]>('/teams');
export const createTeam=(name:string)=>req<Team>('/teams',{method:'POST',body:JSON.stringify({name})});
export const getWorkspaceGrants=(id:string)=>req<WorkspaceGrants>(`/workspaces/${encodeURIComponent(id)}/grants`);
export const grantWorkspaceMember=(space:string,user:number,role:string,active:boolean)=>req(`/workspaces/${encodeURIComponent(space)}/members/${user}`,{method:'PUT',body:JSON.stringify({role,active})});
export const grantWorkspaceTeam=(space:string,team:string,role:string,active:boolean)=>req(`/workspaces/${encodeURIComponent(space)}/teams/${encodeURIComponent(team)}`,{method:'PUT',body:JSON.stringify({role,active})});
export const getTeamMembers=(team:string)=>req<{userId:number;active:boolean}[]>(`/teams/${encodeURIComponent(team)}/members`);
export const assignTeamMember=(team:string,user:number,active:boolean)=>req(`/teams/${encodeURIComponent(team)}/members/${user}`,{method:'PUT',body:JSON.stringify({active})});

export const getSastResults=(ruleId='',path='',offset=0)=>req<ImportedModuleResult[]>('/platform/module-results?'+new URLSearchParams({analysisKind:'sast',ruleId,path,offset:String(offset),limit:'50'}));

export interface SemgrepBatchReceipt {id:string;workspaceId:string;sourceId:string;assetId:string;runId:string;sha256:string;receivedAt:string;receivedBy:string;verification:'not_attested';resultIds:string[];createdCount:number;reusedCount:number;manifest:{reportState:'partial'|'unknown'|'no_reported_errors';ignoredResults:number;commit:string;reportSha256:string};}
export const getSemgrepBatches=(offset=0)=>req<SemgrepBatchReceipt[]>('/platform/semgrep-batches?limit=20&offset='+offset);
export const importSemgrepBatch=(body:unknown)=>req<SemgrepBatchReceipt>('/platform/semgrep-batches',{method:'POST',body:JSON.stringify(body)});

export interface SastTarget {id:string;name:string;sourceId:string;assetId:string;timeout:number;}
export interface SastExecution {id:string;jobId:string;batchId:string;targetId:string;sha256:string;receivedAt:string;receivedBy:string;execution:{reportState:string;source:{commit:string}};}
export const getSastTargets=()=>req<{toolsAvailable:boolean;targets:SastTarget[]}>('/platform/sast/targets');
export const getSastJobs=()=>req<SourceJob[]>('/platform/sast/jobs');
export const getSastExecutions=()=>req<SastExecution[]>('/platform/sast/executions');
export const startSastJob=(targetId:string,commit:string)=>req<SourceJob>('/platform/sast/jobs',{method:'POST',body:JSON.stringify({targetId,commit})});

export interface SastComparison {baselineId:string;currentId:string;baselineCommit:string;currentCommit:string;baselineReportState:string;currentReportState:string;coverageVerified:false;remediationVerified:false;counts:Record<'appeared'|'repeated'|'not_observed',number>;items:{state:'appeared'|'repeated'|'not_observed';ruleId:string;path:string;startLine:number;endLine:number;baselineResultIds:string[];currentResultIds:string[]}[];}
export const compareSastExecutions=(currentId:string,baselineId:string)=>req<SastComparison>('/platform/sast/executions/'+encodeURIComponent(currentId)+'/compare?baselineId='+encodeURIComponent(baselineId));

export type SecurityKind='event'|'detection'|'incident'|'risk'|'control'|'exception'|'task';
export interface SecurityRecord {id:string;kind:SecurityKind;externalKey:string;payload:{title:string;description:string;severity:string;sourceReference:string;dueDate:string|null};state:{status:string;owner:string;reason:string};revision:number;sha256:string;createdAt:string;createdBy:string;expired:boolean;}
export interface SecurityLink {id:string;targetKind:'asset'|'finding'|'result'|'record';targetId:string;reason:string;createdBy:string;createdAt:string;recordId?:string;}
export interface SecurityDetail {record:SecurityRecord;links:SecurityLink[];incoming:SecurityLink[];historyTotal:number;history:{revision:number;actor:string;at:string;change:{before:SecurityRecord['state']|null;after:SecurityRecord['state']}}[];}
export const getSecuritySchema=()=>req<{states:Record<SecurityKind,string[]>}>('/platform/security-records/schema');
export const getSecurityRecords=(kind:SecurityKind,offset=0,q='')=>req<SecurityRecord[]>('/platform/security-records?kind='+encodeURIComponent(kind)+'&offset='+offset+'&q='+encodeURIComponent(q));
export const getSecurityRecord=(id:string)=>req<SecurityDetail>('/platform/security-records/'+encodeURIComponent(id));
export const createSecurityRecord=(body:Record<string,unknown>)=>req<SecurityRecord>('/platform/security-records',{method:'POST',body:JSON.stringify(body)});
export const decideSecurityRecord=(id:string,body:Record<string,unknown>)=>req<SecurityRecord>('/platform/security-records/'+encodeURIComponent(id)+'/decision',{method:'PUT',body:JSON.stringify(body)});
export const linkSecurityRecord=(id:string,body:Record<string,unknown>)=>req('/platform/security-records/'+encodeURIComponent(id)+'/links',{method:'POST',body:JSON.stringify(body)});

export const getRelatedSecurityRecords=(targetKind:string,targetId:string)=>req<SecurityRecord[]>('/platform/security-records/related?targetKind='+encodeURIComponent(targetKind)+'&targetId='+encodeURIComponent(targetId));
