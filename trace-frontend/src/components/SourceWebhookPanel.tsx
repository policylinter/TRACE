import {useState} from 'react';
import {getSourceWebhook,setSourceWebhook,type SourceWebhook} from '@/lib/api';

export function SourceWebhookPanel({sourceId}:{sourceId:string}) {
  const [config,setConfig]=useState<SourceWebhook|null>(null);
  const [enabled,setEnabled]=useState(false);
  const [reference,setReference]=useState('');
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [note,setNote]=useState('');
  async function run(save=false){
    setBusy(true);setError('');setNote('');
    try {
      const value=await (save?setSourceWebhook(sourceId,{enabled,secretRef:reference}):getSourceWebhook(sourceId));
      setConfig(value);setEnabled(value.enabled);setReference(value.secretRef);
      if(save)setNote('Настройка сохранена. Фактический приём проверяется подписанной доставкой из CI.');
    } catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}
  }
  return <details className="mt-3" onToggle={e=>{if(e.currentTarget.open&&!config&&!busy)void run();}}>
    <summary className="cursor-pointer font-semibold">CI: подписанный приём</summary>
    <div className="space-y-3 mt-3">
      <p>Приём одного отчёта с подписью HMAC-SHA256. Сканер не запускается. Подпись подтверждает отправителя, а содержимое отчёта требует проверки.</p>
      {error&&<p role="alert" className="text-rose-300">{error}</p>}
      {note&&<p role="status">{note}</p>}
      <button className="btn" disabled={busy} onClick={()=>void run()}>Обновить состояние CI</button>
      {config&&<>
        <p>{config.enabled?'Подписанный приём включён':'Подписанный приём выключен'} · {config.sourceActive?'источник активен':'источник выключен'} · {config.secretAvailable?'ключ доступен серверу':'ключ отсутствует в окружении сервера'}</p>
        <p>Принятых доставок: {config.acceptedDeliveryCount}. Последняя: {config.lastAcceptedAt||'ещё не было'}.</p>
        <code className="block break-all">POST {config.endpoint}</code>
        <p className="micro">Лимит {config.maxBodyBytes} байт. Возраст подписи — до {config.maxAgeSeconds} секунд. Повтор delivery ID с тем же телом не создаёт дубликат.</p>
        <form className="platform-form" onSubmit={e=>{e.preventDefault();void run(true);}}>
          <label><input type="checkbox" checked={enabled} disabled={busy} onChange={e=>setEnabled(e.target.checked)}/> Разрешить подписанный приём</label>
          <label>Ссылка на ключ в окружении<input value={reference} disabled={busy} maxLength={52} placeholder="env:CI_KEY" pattern="env:[A-Z][A-Z0-9_]{0,47}" onChange={e=>setReference(e.target.value)} required={enabled}/></label>
          <button className="btn" disabled={busy}>Сохранить настройку CI</button>
        </form>
        {config.environmentName&&<><p>Имя переменной API:</p><code className="block break-all">{config.environmentName}</code></>}
        <p className="micro">Оператор задаёт общий ключ в окружении API и в хранилище секретов CI. После изменения окружения API нужен перезапуск. Значение ключа здесь не вводится и не возвращается сервером. Настройка включения сама по себе не подтверждает подключение CI.</p>
      </>}
    </div>
  </details>;
}
