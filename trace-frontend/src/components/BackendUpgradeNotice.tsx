import {useTrace} from '@/state/TraceProvider';
export function BackendUpgradeNotice(){
 const t=useTrace();
 return <section className="panel p-6"><p className="micro">TRACE · Совместимый режим</p><h1 className="text-xl font-semibold">API платформы ещё не обновлён</h1><p className="mt-3">Проекты, проверки и находки доступны через прежний API. Для реестра активов, пространств, команд и управления доступом требуется обновить и перезапустить API TRACE.</p><p className="mt-3 micro">Новые возможности не считаются подключёнными до успешного ответа сервера.</p><button className="btn mt-4" onClick={()=>void t.reload()}>Повторить подключение</button></section>;
}
