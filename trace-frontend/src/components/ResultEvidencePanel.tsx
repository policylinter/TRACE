import {useEffect,useState} from 'react';
import {getResultEvidence,uploadResultEvidence,downloadResultEvidence,type StoredEvidence} from '@/lib/api';

function EvidenceFile({item,resultId,maxBytes,canWrite,onChanged}:{item:StoredEvidence;resultId:string;maxBytes:number;canWrite:boolean;onChanged:()=>Promise<void>}) {
  const [file,setFile]=useState<File|null>(null);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [note,setNote]=useState('');
  async function upload(){if(!file)return;setBusy(true);setError('');setNote('');try {
    if(file.size>maxBytes)throw new Error(`Файл превышает лимит ${maxBytes} байт.`);
    const digest=await crypto.subtle.digest('SHA-256',await file.arrayBuffer());
    const checksum=Array.from(new Uint8Array(digest),byte=>byte.toString(16).padStart(2,'0')).join('');
    if(checksum!==item.expectedSha256)throw new Error('SHA-256 файла не совпадает с суммой в исходном отчёте. Файл не отправлен.');
    await uploadResultEvidence(resultId,item.index,file);await onChanged();setNote('Сервер сверил сумму и сохранил файл. Достоверность находки не подтверждалась.');
  }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function download(){setBusy(true);setError('');try {
    const blob=await downloadResultEvidence(resultId,item.index);const url=URL.createObjectURL(blob);
    const link=document.createElement('a');link.href=url;link.download=`trace-evidence-${item.index}.bin`;link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <article className="border-l border-hairline pl-3 space-y-2">
    <p className="break-all">{item.label} · {item.reference}</p><code className="block break-all text-xs">SHA-256 из отчёта: {item.expectedSha256}</code>
    <p>{item.status==='not_stored'?'Файл не загружен':item.status==='hash_matches'?'Файл сохранён · SHA-256 совпадает с отчётом':'Ошибка целостности · скачивание заблокировано'}</p>
    {item.storedAt&&<p className="micro">{item.byteCount} байт · {new Date(item.storedAt).toLocaleString('ru-RU')} · {item.storedBy}</p>}
    {item.status==='hash_matches'&&<button className="btn" disabled={busy} onClick={()=>void download()}>Скачать проверенные байты</button>}
    {item.status==='not_stored'&&canWrite&&<form onSubmit={e=>{e.preventDefault();void upload();}}><fieldset disabled={busy} className="platform-form"><label>Файл доказательства: {item.label}<input type="file" required onChange={e=>{setFile(e.target.files?.[0]||null);setError('');}}/></label><button className="btn" disabled={!file||busy}>{busy?'Проверка…':'Сверить и сохранить файл'}</button></fieldset></form>}
    {error&&<p role="alert" className="text-rose-300">{error}</p>}{note&&<p role="status">{note}</p>}
  </article>;
}

export function ResultEvidencePanel({resultId,canWrite}:{resultId:string;canWrite:boolean}) {
  const [data,setData]=useState<{maxBytes:number;items:StoredEvidence[]}|null>(null);
  const [error,setError]=useState('');const [busy,setBusy]=useState(false);
  useEffect(()=>{let live=true;void getResultEvidence(resultId).then(value=>{if(live)setData(value);}).catch(e=>{if(live)setError(String(e));});return()=>{live=false;};},[resultId]);
  async function load(){setBusy(true);setError('');try{setData(await getResultEvidence(resultId));}catch(e){setError(String(e));}finally{setBusy(false);}}
  return <section className="space-y-3"><h4>Файлы доказательств</h4>
    <p className="micro">Сохраняются только файлы с SHA-256 из исходного отчёта. Ссылки не загружаются автоматически. Совпадение суммы подтверждает байты, а не достоверность находки. Не загружайте секреты и персональные данные.</p>
    {error&&<p role="alert" className="text-rose-300">{error}</p>}<button className="btn" disabled={busy} onClick={()=>void load()}>Проверить целостность файлов</button>
    {data&&<><p className="micro">До {data.maxBytes} байт на файл. Сохранённый файл нельзя заменить. Скачивание выполняется как вложение .bin без предпросмотра.</p>{data.items.map(item=><EvidenceFile key={item.index} item={item} resultId={resultId} maxBytes={data.maxBytes} canWrite={canWrite} onChanged={load}/>)}</>}
  </section>;
}
