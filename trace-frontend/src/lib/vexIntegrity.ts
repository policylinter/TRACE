import type { Finding } from '@/data/findings';
/** Check the returned document against persisted triage; this is not CSAF schema validation. */
export function vexIntegrityIssue(json: string, findings: Finding[]): string | null {
  if (!json) return null;
  try {
    const document = JSON.parse(json) as { vulnerabilities?: { cve?: string; ids?: {text?:string;system_name?:string}[]; product_status?: Record<string, unknown> }[] };
    if (!Array.isArray(document.vulnerabilities)) return 'Backend вернул документ без списка уязвимостей. Экспорт недоступен.';
    const pending = new Set(findings.filter(f => f.verdict === 'needs_review' && f.reachability !== 'suppressed').map(f => f.cve));
    if (document.vulnerabilities.some(v => [v.cve,...(v.ids??[]).map(id=>id.text)].some(id=>!!id&&pending.has(id)) && ('known_not_affected' in (v.product_status ?? {}) || 'known_affected' in (v.product_status ?? {})))) {
      return 'Ошибка данных VEX: backend присвоил окончательный статус находке, которая требует проверки. Копирование и скачивание заблокированы до исправления генератора. Предпросмотр доступен для разбора.';
    }
    return null;
  } catch { return 'Backend вернул некорректный JSON VEX. Экспорт недоступен.'; }
}
