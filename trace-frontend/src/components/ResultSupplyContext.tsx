import type { ImportedModuleResult } from '@/lib/api';

export function ResultSupplyContext({result}:{result:ImportedModuleResult}) {
  const snapshot=result.payload.supplyChainSnapshot;
  if(!snapshot)return <div className="panel-flat p-3"><h4>Контекст поставки результата</h4><p className="micro">При импорте не зафиксирован. Артефакт и окружение не определяются автоматически по текущему состоянию актива.</p></div>;
  const context=snapshot.context;
  const kinds={build:'Сборка',artifact:'Артефакт',deployment:'Развёртывание'};
  return <div className="panel-flat p-3 space-y-2"><h4>Зафиксированный контекст поставки</h4><p>{kinds[context.kind]} · снимок на момент импорта.</p><p className="whitespace-pre-wrap break-words">Основание привязки: {result.payload.contextReason}</p><code className="block break-all text-xs">Актив контекста: {snapshot.assetId}</code>{context.commitSha&&<p className="break-all">Коммит: {context.commitSha}</p>}{context.digest&&<p className="break-all">Digest: {context.digest}</p>}{context.environment&&<p>Окружение: {context.environment}</p>}{context.buildExternalId&&<p>ID сборки: {context.buildExternalId}</p>}{context.deploymentExternalId&&<p>ID развёртывания: {context.deploymentExternalId}</p>}<p>Наблюдение контекста по основанию: {new Date(context.observedAt).toLocaleString('ru-RU')}.</p><p>Контекст записан: {new Date(snapshot.recordedAt).toLocaleString('ru-RU')} · {snapshot.recordedBy}.</p><p className="break-all">Основание контекста: {context.evidenceRef}</p><code className="block break-all text-xs">SHA-256 контекста: {snapshot.sha256}</code><p className="micro">Снимок включён в контрольную сумму результата и не перечитывается из реестра. Связь заявлена оператором; подпись, содержимое артефакта и его исполнение не удостоверены.</p></div>;
}
