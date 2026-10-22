import {useEffect,useState} from 'react';
import {getResultProvenance,type ResultProvenance} from '@/lib/api';

export function ResultProvenancePanel({resultId}:{resultId:string}) {
  const [open,setOpen]=useState(false);const [data,setData]=useState<ResultProvenance|null>(null);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  useEffect(()=>{if(!open)return;let live=true;setBusy(true);setError('');void getResultProvenance(resultId).then(value=>{if(live)setData(value);}).catch(e=>{if(live)setError(String(e));}).finally(()=>{if(live)setBusy(false);});return()=>{live=false;};},[resultId,open]);
  async function load(offset=0){setBusy(true);setError('');try {
    const value=await getResultProvenance(resultId,offset);
    setData(previous=>offset&&previous?{...value,signedDeliveries:{...value.signedDeliveries,items:[...previous.signedDeliveries.items,...value.signedDeliveries.items]}}:value);
  }catch(e){setError(String(e));}finally{setBusy(false);}}
  const receipt=data?.initialIntake.record;
  return <details onToggle={e=>setOpen(e.currentTarget.open)} className="border-l border-hairline pl-3">
    <summary className="cursor-pointer font-semibold">Происхождение и проверенные связи</summary>
    {open&&<div className="mt-3 space-y-3">
      <p className="micro">Журнал TRACE описывает приём и целостность сохранённых данных. Аттестация сканера и достоверности находки не выполнялась.</p>
      {error&&<p role="alert" className="text-rose-300">{error}</p>}
      <button className="btn" disabled={busy} onClick={()=>void load()}>Обновить цепочку происхождения</button>
      {data&&<>
        <p>Проверено TRACE: {new Date(data.checkedAt).toLocaleString('ru-RU')}.</p>
        <h5>Исходный отчёт</h5><p>{data.report.status==='hash_matches'?'SHA-256 сохранённого отчёта совпадает; связи sourceId, assetId и externalId согласованы.':'Ошибка целостности отчёта или его связей.'}</p>
        <code className="block break-all text-xs">{data.report.sha256}</code>
        <h5>Первичный приём</h5>
        <p>{data.initialIntake.status==='not_recorded'?'Способ первичного приёма не зафиксирован. Для старого отчёта запись задним числом не создаётся.':data.initialIntake.status==='consistent'?'Запись первичного приёма согласована с сохранёнными данными.':'Ошибка согласованности записи первичного приёма.'}</p>
        {receipt&&<><p>{receipt.method==='manual'?'Ручной импорт через API':receipt.method==='signed_hmac'?'API записал успешную HMAC-проверку при первичном приёме':'Способ приёма неизвестен'}</p><p className="break-all">{receipt.actor} · {receipt.receivedAt?new Date(receipt.receivedAt).toLocaleString('ru-RU'):''}</p>{receipt.delivery&&<p className="break-all micro">Первичная доставка: {receipt.delivery.id}. SHA-256 байтов тела: {receipt.delivery.bodySha256}</p>}</>}
        {data.source&&<p>Источник в реестре: {data.source.name} · {data.source.active?'активен сейчас':'выключен сейчас'}. Это текущее состояние регистрации.</p>}
        <h5>Подписанные доставки этого отчёта</h5><p>Записей в журнале: {data.signedDeliveries.total}. Поздняя доставка не меняет первичный способ приёма.</p>
        {data.signedDeliveries.items.map(item=><article key={item.sourceId+':'+item.id} className="border-l border-hairline pl-3 micro"><p className="break-all">{item.id} · {new Date(item.receivedAt).toLocaleString('ru-RU')}</p><p>{item.status==='consistent'?'Связь доставки с отчётом согласована':'Ошибка связи доставки с отчётом'}</p><code className="block break-all">SHA-256 тела запроса: {item.bodySha256}</code></article>)}
        {data.signedDeliveries.items.length<data.signedDeliveries.total&&<button className="btn" disabled={busy} onClick={()=>void load(data.signedDeliveries.items.length)}>Показать следующие доставки</button>}
        <h5>Файлы доказательств</h5>{data.evidence.items.map(item=><p key={item.index}>{item.label}: {item.status==='hash_matches'?'байты сохранены, SHA-256 совпадает':item.status==='not_stored'?'файл отсутствует, есть только сумма из отчёта':'ошибка целостности файла'}</p>)}
        <p className="micro">HMAC подтверждает владение общим ключом при доставке. Журнал не содержит ключа и не позволяет независимо перепроверить старую подпись. Совпадение сумм не подтверждает истинность находки и не закрывает её.</p>
      </>}
    </div>}
  </details>;
}
